"""
admin_tool/app.py  —  admin

admin，負責：
  1. 維護合法選民名冊
  2. 在本地端為每位選民生成高強度 OTP（secrets.token_urlsafe(24)）
  3. 嚴格遵守零知識原則：僅將 H(OTP) 傳送至 CA，CA 端永不接觸 OTP 明文
  4. 產出可列印的 OTP 密碼表，模擬透過實體信件派發給學生

端點：
  GET  /                 Dashboard：選民名冊總覽
  POST /api/add_voter    新增單一選民（生成 OTP，寫入 CA）
  POST /api/add_batch    批次新增選民（JSON 陣列或換行分隔字串）
  POST /api/mark_distributed  標記已派發
  GET  /print            可列印的 OTP 信件頁
  GET  /api/voters       選民清單（JSON）
"""

import os
import io
import sys
import json
import time
import hashlib
import secrets
import datetime
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string, Response
import requests as http_requests
import qrcode
import qrcode.image.svg  # <3 v4.0：純向量、不需要 Pillow，QR 內容完全本地生成，不經過任何第三方服務
from shared.ui_style import UI_HEAD, THEME_TOGGLE

from shared.db_utils import Database
from shared.config_loader import get_admin_api_token, get_service_registration_token  # <3 呼叫 CA/CC 的 Admin 端點需要帶 Bearer Token
from shared.key_manager import load_or_fetch_ca_cert  # <3 v4.0：mTLS
from shared.tls_utils import load_or_request_tls_certificate, build_mtls_server_context, mtls_client_kwargs  # <3 v4.0：mTLS

# ============================================================
# 常數設定
# ============================================================
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR    = os.path.join(SERVICE_DIR, "data")
DB_PATH     = os.path.join(DATA_DIR, "admin.db")
KEYS_DIR    = os.path.join(SERVICE_DIR, "keys")  # <3 v4.0：admin_tool 沒有應用層身分憑證，只快取 CA 根憑證＋TLS 專用金鑰對
os.makedirs(KEYS_DIR, exist_ok=True)
ADMIN_HOSTNAME = os.environ.get("ADMIN_HOSTNAME", "admin")  # <3 v4.0：填入 TLS 憑證的 SAN

CA_URL    = os.environ.get("CA_URL",    "https://localhost:5001")
TA_URL    = os.environ.get("TA_URL",    "https://localhost:5002")
CC_URL    = os.environ.get("CC_URL",    "https://localhost:5003")
TPA_URL   = os.environ.get("TPA_URL",   "https://localhost:5000")  # <3 v4.0：new_round 需重置 TPA 的 issued_tokens


def _admin_headers() -> dict:
    """呼叫 CA /api/admin/* 或 CC /api/tally 時附上的 Admin Bearer Token 標頭。 <3"""
    return {"Authorization": f"Bearer {get_admin_api_token()}"}
BB_URL    = os.environ.get("BB_URL",    "https://localhost:5004")
VOTER_URL = os.environ.get("VOTER_URL", "https://localhost:5005")

# <3 v4.0 新增：選民實際用瀏覽器連上的公開網域（跟 Caddyfile 用同一個
# SITE_ADDRESS），QR code 要靠這個組出「掃了就能直接開啟投票網站」的網址。
SITE_ADDRESS = os.environ.get("SITE_ADDRESS", "localhost:5005")


def _build_register_qr_svg(voter_id: str, otp: str) -> str:
    """產生「掃描後自動開啟投票網站並帶入學號/OTP」的 QR code（inline SVG）。

    刻意把 voter_id/otp 放在網址的 fragment（# 後面），而不是一般的
    ?query= 參數：fragment 天生不會被送到伺服器，Caddy／Flask 的 access
    log 完全看不到裡面的明文 OTP，只存在掃碼裝置自己的網址列。就算之後
    這個網址被看到，OTP 本身在 CA 完成一次註冊後就永久失效，不能重複
    使用。QR 圖檔完全在本機用 qrcode 套件生成（純向量 SVG），不會呼叫
    任何第三方 QR 產生服務，OTP 明文不會離開這台伺服器。 <3
    """
    frag = urllib.parse.urlencode({"vid": voter_id, "otp": otp})
    url = f"https://{SITE_ADDRESS}/register#{frag}"
    img = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage, box_size=6)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode('utf-8')

# v4.0 新增：先快取 CA 根憑證，才有材料驗證 CA 與其他實體的 TLS 憑證，
# 再向 CA 申請本服務專用的 TLS 憑證（admin_tool 沒有應用層身分憑證，這是
# 它唯一持有的一把金鑰對）。
try:
    load_or_fetch_ca_cert(KEYS_DIR, CA_URL)
except Exception as ex:
    print(f"[Admin] 警告：無法取得 CA 憑證（{ex}）")

try:
    _TLS_CERT_PATH, _TLS_KEY_PATH = load_or_request_tls_certificate(
        KEYS_DIR, "ADMIN", ADMIN_HOSTNAME, CA_URL,
        registration_token=get_service_registration_token(),
    )
except Exception as ex:
    print(f"[Admin] 警告：無法取得 TLS 憑證（{ex}）")
    _TLS_CERT_PATH = _TLS_KEY_PATH = None

# 供本檔案所有對外呼叫共用的 mTLS 參數。
_ADMIN_MTLS = mtls_client_kwargs(_TLS_CERT_PATH, _TLS_KEY_PATH, os.path.join(KEYS_DIR, "ca_cert.pem"))

# ============================================================
# 資料庫初始化
# ============================================================
db = Database(DB_PATH)
db.execute("""
    CREATE TABLE IF NOT EXISTS voter_roster (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        voter_id      TEXT NOT NULL UNIQUE,
        otp           TEXT NOT NULL,
        otp_hash      TEXT NOT NULL,
        ca_status     TEXT NOT NULL DEFAULT 'pending',
        created_at    INTEGER NOT NULL,
        distributed   INTEGER NOT NULL DEFAULT 0,
        distributed_at INTEGER
    )
""")

# ============================================================
# 工具函式
# ============================================================

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


def _ts_fmt(ts: int) -> str:
    try:
        return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)


def _register_to_ca(voter_id: str, otp_hash: str) -> dict:
    """送出 (voter_id, otp_hash) 至 CA，CA 端永不接觸明文 OTP。"""
    resp = http_requests.post(
        f"{CA_URL}/api/admin/register_voter",
        json={"voter_id": voter_id, "otp_hash": otp_hash},
        headers=_admin_headers(),  # <3
        timeout=10,
        **_ADMIN_MTLS,
    )
    resp.raise_for_status()
    return resp.json()


# ============================================================
# Flask App
# ============================================================
app = Flask(__name__)

# ── HTML 模板 ──────────────────────────────────────────────
_BASE_CSS = UI_HEAD + """
<style>
  /* OTP 預設模糊，滑鼠移上或點一下（取得焦點）才顯示 */
  .otp-blur { filter: blur(5px); cursor: pointer; border-radius: 4px; }
  .otp-blur:hover, .otp-blur:focus { filter: none; outline: none; }
  .qr-modal { position: fixed; inset: 0; z-index: 50; display: flex; align-items: center; justify-content: center;
              padding: 16px; background: rgba(0, 0, 0, 0.6); }
  .qr-box { width: 100%; max-width: 320px; }
  #qrModalContent { width: 240px; height: 240px; max-width: 100%; margin: 0 auto; background: #fff; padding: 8px; border-radius: 4px; }
  #qrModalContent svg { width: 100%; height: 100%; display: block; }
</style>
"""

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <title>選務管理｜NUTC 線上投票</title>
  """ + _BASE_CSS + """
</head>
<body>
<header class="topbar">
  <div class="container-wide topbar-inner">
    <a class="brand" href="/">
      <span class="brand-name">NUTC 線上投票</span>
      <span class="brand-sub">選務管理</span>
    </a>
    <div class="topbar-actions">
      <a class="btn btn-sm" href="/print" target="_blank" rel="noopener">列印 OTP</a>
      <a class="btn btn-sm" href="/api/export" target="_blank" rel="noopener">匯出資料</a>
      """ + THEME_TOGGLE + """
    </div>
  </div>
</header>

<main>
  <div class="container-wide stack-lg">
    <div class="grid grid-4">
      <div class="stat"><div class="stat-label">名冊人數</div><div class="stat-value">{{ stats.total }}</div></div>
      <div class="stat"><div class="stat-label">待綁定</div><div class="stat-value">{{ stats.pending }}</div></div>
      <div class="stat"><div class="stat-label">已完成綁定</div><div class="stat-value">{{ stats.registered }}</div></div>
      <div class="stat"><div class="stat-label">已派發 OTP</div><div class="stat-value">{{ stats.distributed }}</div></div>
    </div>

    <section class="card stack" aria-labelledby="electionTitle">
      <div class="row-between">
        <h2 id="electionTitle" class="section-title">選舉控制</h2>
        {% if election_state == 'standby' %}
        <span class="badge">待命中</span>
        {% else %}
        <span class="badge badge-ok">投票進行中{% if election_deadline_str %}・截止 {{ election_deadline_str }}{% endif %}</span>
        {% endif %}
      </div>
      <div class="row">
        {% if election_state == 'standby' %}
        <button type="button" class="btn btn-primary" onclick="startElection()">啟動選舉</button>
        <button type="button" class="btn btn-danger" onclick="newRound()">重設名單</button>
        {% else %}
        <button type="button" class="btn btn-primary" onclick="triggerTally()">開票</button>
        <button type="button" class="btn btn-danger" onclick="newRound()">結束本輪並重置</button>
        {% endif %}
      </div>
      <div id="electionMsg" class="alert hidden" role="status" aria-live="polite"></div>
    </section>

    <div class="grid grid-2">
      <section class="card stack" aria-labelledby="addTitle">
        <h2 id="addTitle" class="section-title">新增選民</h2>
        <div class="field">
          <label for="singleVoterId">學號</label>
          <input id="singleVoterId" class="input mono" type="text" placeholder="例如 S11200001" autocomplete="off" spellcheck="false">
        </div>
        <button type="button" class="btn btn-primary btn-block" onclick="addSingleVoter()">產生 OTP 並登錄至 CA</button>
        <div id="singleMsg" class="alert hidden" role="status" aria-live="polite"></div>
      </section>

      <section class="card stack" aria-labelledby="batchTitle">
        <h2 id="batchTitle" class="section-title">批次匯入</h2>
        <div class="field">
          <label for="batchIds">學號清單</label>
          <textarea id="batchIds" class="input mono" rows="5" placeholder="每行一個學號，或以逗號分隔" spellcheck="false"></textarea>
        </div>
        <button type="button" class="btn btn-primary btn-block" onclick="addBatch()">批次產生 OTP 並登錄至 CA</button>
        <div id="batchMsg" class="alert hidden" role="status" aria-live="polite"></div>
      </section>
    </div>

    <section class="card card-flush" aria-labelledby="rosterTitle">
      <div class="card-head">
        <h2 id="rosterTitle" class="section-title">選民名冊</h2>
        <span class="small muted">OTP 預設遮蔽，滑鼠移上或點一下即可顯示</span>
      </div>
      {% if voters %}
      <div class="table-wrap">
        <table class="table table-stack">
          <thead>
            <tr><th class="num">#</th><th>學號</th><th>OTP</th><th>報到 QR</th><th>綁定狀態</th><th>建立時間</th><th>派發</th></tr>
          </thead>
          <tbody>
            {% for v in voters %}
            <tr>
              <td class="num muted hide-sm" data-label="#">{{ loop.index }}</td>
              <td class="mono strong" data-label="學號">{{ v.voter_id }}</td>
              <td data-label="OTP"><span class="otp-blur mono" tabindex="0" title="點一下顯示">{{ v.otp }}</span></td>
              <td data-label="報到 QR">
                {% if v.ca_status != 'registered' %}
                <button type="button" class="btn btn-sm" data-voter-id="{{ v.voter_id }}" onclick="openQrModal(this)">顯示 QR</button>
                {% else %}<span class="muted">—</span>{% endif %}
              </td>
              <td data-label="綁定狀態">
                {% if v.ca_status == 'registered' %}<span class="badge badge-ok">已綁定</span>{% else %}<span class="badge badge-warn">待綁定</span>{% endif %}
              </td>
              <td class="small muted nowrap" data-label="建立時間">{{ v.created_at_str }}</td>
              <td data-label="派發">
                {% if v.distributed %}<span class="small text-ok strong">已派發</span>
                {% else %}<button type="button" class="btn btn-sm" onclick="markDistributed({{ v.id }})">標記已派發</button>{% endif %}
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% else %}
      <div class="card-body muted text-center">尚未新增任何選民，請使用上方表單新增。</div>
      {% endif %}
    </section>
  </div>
</main>

<!-- QR 放大彈窗，供現場選民掃描 -->
<div id="qrModal" class="qr-modal hidden" onclick="closeQrModal()">
  <div class="card qr-box stack text-center" onclick="event.stopPropagation()" role="dialog" aria-modal="true" aria-labelledby="qrModalVoterId">
    <p id="qrModalVoterId" class="mono strong"></p>
    <div id="qrModalContent"></div>
    <p class="small muted">請選民用手機相機掃描，會自動開啟投票網站並帶入學號與 OTP。</p>
    <button type="button" class="btn btn-block" onclick="closeQrModal()">關閉</button>
  </div>
</div>

<script>
// QR 改成點開時才向伺服器要（/qr/<voter_id>），不再隨頁面一次產生全部選民的
// QR——2500 人時整頁會變成約 39MB、伺服器端要花 30 秒以上產生。
async function openQrModal(el) {
  const voterId = el.dataset.voterId;
  const content = document.getElementById('qrModalContent');
  content.textContent = '產生中...';
  document.getElementById('qrModalVoterId').textContent = voterId;
  document.getElementById('qrModal').classList.remove('hidden');
  try {
    const resp = await fetch('/qr/' + encodeURIComponent(voterId), { cache: 'no-store' });
    if (!resp.ok) {
      content.textContent = resp.status === 404 ? '此選民已完成認證，OTP 已失效' : '無法產生 QR（HTTP ' + resp.status + '）';
      return;
    }
    content.innerHTML = await resp.text();
  } catch (e) {
    content.textContent = '無法產生 QR：' + e.message;
  }
}

function closeQrModal() {
  document.getElementById('qrModal').classList.add('hidden');
}

async function newRound() {
  if (!confirm('確定要重置為新一輪投票？\\n\\n此操作將：\\n1. 重置選舉狀態（TA → standby）\\n2. 清除 CA 選民名冊（選民需重新憑 OTP 登記）\\n3. 清除本地 OTP 名冊\\n\\n選民再次造訪投票頁時會自動偵測到重置，導向重新身分綁定。\\n請確認本輪計票與公告已完成。')) return;
  const msg = document.getElementById('electionMsg');
  showMsg(msg, '重置中，請稍候...', 'info');
  try {
    const resp = await fetch('/api/new_round', { method: 'POST', headers: {'Content-Type': 'application/json'} });
    const data = await resp.json();
    if (data.status === 'success') {
      const r = data.results || {};
      // <3 v4.0 修正：原本只顯示 TA/CA 的重置結果，TPA/Voter/CC/BB
      // 就算重置失敗也完全看不出來——這次抓到的「幽靈選票」問題如果
      // 當初就能在這裡看到 voter 那一項失敗，會更快抓到根源。
      const okLabel = r => r && r.status === 'success' ? '[成功]' : '[失敗]';
      showMsg(msg, `[成功] 新一輪重置完成！TA:${okLabel(r.ta)}  TPA:${okLabel(r.tpa)}  Voter:${okLabel(r.voter)}  CA:${okLabel(r.ca)}  CC:${okLabel(r.cc)}  BB:${okLabel(r.bb)}  Admin名冊:[成功]\n請重新新增選民名冊後再啟動選舉。選民造訪投票頁時將自動導向重新身分綁定。`, 'success');
      setTimeout(() => location.reload(), 2500);
    } else {
      showMsg(msg, `[錯誤] ${data.message}`, 'error');
    }
  } catch (e) {
    showMsg(msg, `[錯誤] 請求失敗：${e.message}`, 'error');
  }
}

async function startElection() {
  const msg = document.getElementById('electionMsg');
  showMsg(msg, '正在向 TA 發送啟動指令...', 'info');
  try {
    const resp = await fetch('/api/start_election', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({}),
    });
    const data = await resp.json();
    if (data.status === 'success') {
      showMsg(msg, `[成功] 選舉已啟動！截止時間：${data.deadline_str}（持續 ${data.duration_seconds} 秒）`, 'success');
      setTimeout(() => location.reload(), 1500);
    } else if (data.code === 'ALREADY_STARTED') {
      showMsg(msg, `[資訊] 選舉已在進行中（截止：${data.deadline_str}）`, 'warn');
    } else {
      showMsg(msg, `[錯誤] ${data.message || data.code}`, 'error');
    }
  } catch (e) {
    showMsg(msg, `[錯誤] 請求失敗：${e.message}`, 'error');
  }
}

async function triggerTally() {
  if (!confirm('確定要觸發開票？\\n\\nCC 只有在投票確實已截止時才會真的執行開票，若尚未截止會被拒絕，可放心先試。')) return;
  const msg = document.getElementById('electionMsg');
  showMsg(msg, '正在向 CC 發送開票指令...', 'info');
  try {
    const resp = await fetch('/api/trigger_tally', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({}),
    });
    const data = await resp.json();
    if (data.status === 'already_done') {
      showMsg(msg, '[資訊] 本輪已完成開票，無需重複觸發', 'warn');
    } else if (data.status === 'started' || data.status === 'running') {
      pollTallyStatus(msg);
    } else {
      showMsg(msg, `[錯誤] ${data.message || data.code}`, 'error');
    }
  } catch (e) {
    showMsg(msg, `[錯誤] 請求失敗：${e.message}`, 'error');
  }
}

// 開票在 CC 背景執行，這裡每 2 秒查一次進度，直到完成或失敗
async function pollTallyStatus(msg) {
  while (true) {
    await new Promise(r => setTimeout(r, 2000));
    let data;
    try {
      data = await (await fetch('/api/tally_status', { cache: 'no-store' })).json();
    } catch (e) {
      showMsg(msg, `[警告] 暫時查不到開票進度（${e.message}），重試中...`, 'warn');
      continue;
    }
    if (data.state === 'running') {
      const p = data.progress;
      showMsg(msg, p ? `開票中... 已解密 ${p.processed} / ${p.total} 張` : '開票中...', 'info');
      continue;
    }
    const r = data.result || {};
    if (data.state === 'done' && r.status === 'success') {
      const bbOk = r.bb_published ? '[成功]' : `[警告：${r.bb_publish_warning || '未確認公告成功'}]`;
      showMsg(msg, `[成功] 開票完成！合法選票：${r.valid_count}，Merkle Root：${(r.merkle_root||'').slice(0,20)}...，BB 公告：${bbOk}`, 'success');
    } else if (data.state === 'done') {
      showMsg(msg, '[資訊] 本輪已完成開票', 'warn');
    } else {
      showMsg(msg, `[錯誤] ${r.message || r.code || data.message || '開票失敗'}`, 'error');
    }
    return;
  }
}

async function addSingleVoter() {
  const voterId = document.getElementById('singleVoterId').value.trim();
  const msg = document.getElementById('singleMsg');
  if (!voterId) {
    showMsg(msg, '請輸入學號', 'error');
    return;
  }
  showMsg(msg, '處理中...', 'info');
  try {
    const resp = await fetch('/api/add_voter', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({voter_id: voterId}),
    });
    const data = await resp.json();
    if (data.status === 'success') {
      showMsg(msg, `[成功] ${data.voter_id} 已完成 OTP 生成與 CA 零知識註冊`, 'success');
      document.getElementById('singleVoterId').value = '';
      setTimeout(() => location.reload(), 1200);
    } else {
      showMsg(msg, `[錯誤] ${data.message || data.code}`, 'error');
    }
  } catch (e) {
    showMsg(msg, `[錯誤] 請求失敗：${e.message}`, 'error');
  }
}

async function addBatch() {
  const raw = document.getElementById('batchIds').value.trim();
  const msg = document.getElementById('batchMsg');
  if (!raw) { showMsg(msg, '請輸入學號清單', 'error'); return; }
  const ids = raw.split(/[\\r\\n,]+/).map(s => s.trim()).filter(s => s.length > 0);
  if (ids.length === 0) { showMsg(msg, '未解析到有效學號', 'error'); return; }
  showMsg(msg, `批次處理 ${ids.length} 筆...`, 'info');
  try {
    const resp = await fetch('/api/add_batch', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({voter_ids: ids}),
    });
    const data = await resp.json();
    const ok  = (data.results || []).filter(r => r.status === 'success').length;
    const fail = (data.results || []).filter(r => r.status !== 'success').length;
    showMsg(msg, `完成：${ok} 筆成功，${fail} 筆失敗`, fail > 0 ? 'warn' : 'success');
    document.getElementById('batchIds').value = '';
    setTimeout(() => location.reload(), 1500);
  } catch (e) {
    showMsg(msg, `✗ 請求失敗：${e.message}`, 'error');
  }
}

async function markDistributed(id) {
  await fetch('/api/mark_distributed', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id: id}),
  });
  location.reload();
}

function showMsg(el, text, type) {
  const cls = { success: 'alert-ok', error: 'alert-err', warn: 'alert-warn', info: 'alert-info' };
  el.className = 'alert ' + (cls[type] || 'alert-info');
  // 顏色已表達成功／錯誤，去掉訊息開頭的「[成功]」「✗」等標記
  el.textContent = text.replace(/^(\\[[^\\]]+\\]|[✓✗])\\s*/, '');
}
</script>
</body>
</html>"""

_PRINT_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>選民 OTP 密碼表</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, "PingFang TC", "Noto Sans TC", "Microsoft JhengHei", system-ui, sans-serif;
           background: #f6f5f1; color: #1c1b19; padding: 24px 16px; line-height: 1.5; }
    .wrap { max-width: 900px; margin: 0 auto; }
    .no-print { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; margin-bottom: 24px; }
    .btn { min-height: 44px; padding: 10px 20px; border-radius: 6px; font: inherit; font-weight: 600; cursor: pointer;
           border: 1px solid #1f4e79; background: #1f4e79; color: #fff; }
    a { color: #1f4e79; }
    h1 { font-size: 1.4rem; font-weight: 700; margin-bottom: 4px; }
    .subtitle { color: #5d5a53; font-size: 0.85rem; margin-bottom: 16px; }
    .warning-box { border: 1px solid #a8261b; border-left-width: 4px; border-radius: 6px; padding: 12px 14px;
                   margin-bottom: 24px; background: #fbeae8; font-size: 0.85rem; }
    .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; }
    .card { border: 1px solid #b5afa2; border-radius: 6px; padding: 16px; background: #fff; break-inside: avoid; page-break-inside: avoid; }
    .card-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; margin-bottom: 12px; }
    .card-label, .otp-label { font-size: 0.75rem; color: #5d5a53; font-weight: 600; }
    .voter-id { font-family: ui-monospace, Consolas, monospace; font-size: 1.1rem; font-weight: 700; }
    .otp-value { font-family: ui-monospace, Consolas, monospace; font-size: 1.05rem; font-weight: 700; letter-spacing: 0.04em; word-break: break-all; }
    .otp-hash { font-family: ui-monospace, Consolas, monospace; font-size: 0.65rem; color: #8a867d; word-break: break-all; margin-top: 8px; }
    .footer { font-size: 0.7rem; color: #8a867d; margin-top: 6px; }
    .status-badge { font-size: 0.7rem; padding: 2px 8px; border-radius: 999px; font-weight: 600; border: 1px solid; white-space: nowrap; }
    .status-pending    { color: #875800; background: #fbf1dc; }
    .status-registered { color: #1d6b3a; background: #e7f2ea; }
    @media print {
      body { background: #fff; padding: 0; }
      .no-print { display: none !important; }
      .cards { grid-template-columns: repeat(2, 1fr); }
    }
  </style>
</head>
<body>
<div class="wrap">

<div class="no-print">
  <button class="btn" type="button" onclick="window.print()">列印／儲存 PDF</button>
  <a href="/">返回選務管理</a>
</div>

<h1>NUTC 線上投票｜選民 OTP 密碼表</h1>
<p class="subtitle">列印日期：{{ now_str }}・本文件屬機密，請妥善保管</p>

<div class="warning-box">
  <strong>安全提醒：</strong>OTP 是選民完成身分綁定的唯一憑據，請以實體信件或加密管道派發，不要用明文電子郵件或通訊軟體傳送。每組 OTP <strong>只能使用一次</strong>，使用後自動失效。
</div>

<div class="cards">
{% for v in voters %}
<div class="card">
  <div class="card-header">
    <div>
      <div class="card-label">選民 ID / Student ID</div>
      <div class="voter-id">{{ v.voter_id }}</div>
    </div>
    <span class="status-badge {% if v.ca_status == 'registered' %}status-registered{% else %}status-pending{% endif %}">
      {% if v.ca_status == 'registered' %}已綁定{% else %}未綁定{% endif %}
    </span>
  </div>
  <div class="otp-label">一次性密碼 / OTP（請妥善保管）</div>
  <div class="otp-value">{{ v.otp }}</div>
  <div class="otp-hash">H(OTP) = {{ v.otp_hash[:32] }}...</div>
  <div class="footer">產生時間：{{ v.created_at_str }}</div>
</div>
{% endfor %}
</div>

</div>

</body>
</html>"""

# ── 路由 ──────────────────────────────────────────────────────

@app.route('/')
def dashboard():
    # 從 CA 同步選民認證狀態（把 CA 端已完成的 registered 狀態寫回本地）
    # 原本是對 CA 名冊裡每一位已註冊選民各呼叫一次 db.execute()——每次都
    # 是獨立的連線＋交易＋commit，2500 人實測約 20 秒，期間一直佔著 SQLite
    # 寫入鎖；而且同步排在讀名單之後，畫面上的狀態永遠落後一次重新整理。
    # 改成先算出「CA 已註冊、本地還不是」的差集，只更新這些、一次交易完成，
    # 再讀名單。
    try:
        ca_resp = http_requests.get(f"{CA_URL}/api/admin/voter_registry", headers=_admin_headers(), timeout=3, **_ADMIN_MTLS)  # <3
        ca_data = ca_resp.json()
        if ca_data.get("status") == "success":
            registered_on_ca = {row["voter_id"] for row in ca_data.get("voters", []) if row.get("status") == "registered"}
            local_unregistered = {
                row["voter_id"] for row in db.fetchall("SELECT voter_id FROM voter_roster WHERE ca_status != 'registered'")
            }
            to_update = registered_on_ca & local_unregistered
            if to_update:
                db.executemany(
                    "UPDATE voter_roster SET ca_status = 'registered' WHERE voter_id = ?",
                    [(voter_id,) for voter_id in to_update],
                )
    except Exception:
        pass

    # QR 不在這裡產生，改由 /qr/<voter_id> 在點開時才產生（見 openQrModal）
    voters = db.fetchall(
        "SELECT id, voter_id, otp, otp_hash, ca_status, created_at, distributed FROM voter_roster ORDER BY id DESC"
    )
    for v in voters:
        v['created_at_str'] = _ts_fmt(v['created_at'])

    total      = len(voters)
    pending    = sum(1 for v in voters if v['ca_status'] == 'pending')
    registered = sum(1 for v in voters if v['ca_status'] == 'registered')
    distributed = sum(1 for v in voters if v['distributed'])

    # 查詢選舉狀態（供 UI 顯示）
    election_state = 'standby'
    election_deadline_str = None
    try:
        resp = http_requests.get(f"{TA_URL}/api/deadline", timeout=3, **_ADMIN_MTLS)
        data = resp.json()
        if data.get("status") == "success":
            election_state = data.get("election_state", "standby")
            election_deadline_str = data.get("deadline_str")
    except Exception:
        pass

    return render_template_string(
        _DASHBOARD_HTML,
        voters=voters,
        stats=dict(total=total, pending=pending, registered=registered, distributed=distributed),
        election_state=election_state,
        election_deadline_str=election_deadline_str,
    )


@app.route('/qr/<voter_id>')
def voter_qr(voter_id: str):
    """回傳單一選民的報到 QR（SVG），供儀表板點開時才載入。

    <3 v4.0：只有還沒完成 CA 註冊的選民，QR 裡的 OTP 才還能用；已註冊的
    話 OTP 已經永久失效，回 404。QR 內含明文 OTP，禁止瀏覽器快取。
    """
    row = db.fetchone("SELECT voter_id, otp, ca_status FROM voter_roster WHERE voter_id = ?", (voter_id,))
    if not row or row['ca_status'] == 'registered':
        return jsonify({"status": "error", "message": "查無此選民或已完成認證"}), 404
    return Response(
        _build_register_qr_svg(row['voter_id'], row['otp']),
        mimetype='image/svg+xml',
        headers={"Cache-Control": "no-store"},
    )


@app.route('/api/add_voter', methods=['POST'])
def api_add_voter():
    """新增單一選民：本地端生成 OTP，只送 H(OTP) 至 CA（零知識）。"""
    data = request.get_json()
    # v3.0 修正：`data.get('voter_id', '')` 遇到明確傳 `"voter_id": null`
    # 時會拿到 None（預設值只在完全沒有這個 key 時才生效），對 None 呼叫
    # .strip() 會丟 AttributeError 變成沒處理過的 500。改用 `or ''`。 <3
    if not data or not (data.get('voter_id') or '').strip():  # <3
        return jsonify({"status": "error", "message": "缺少 voter_id"}), 400

    voter_id = str(data['voter_id']).strip()
    now      = int(time.time())

    existing = db.fetchone("SELECT id, ca_status FROM voter_roster WHERE voter_id = ?", (voter_id,))
    if existing and existing['ca_status'] == 'registered':
        return jsonify({"status": "error", "code": "ALREADY_REGISTERED",
                        "message": f"{voter_id} 已完成認證，不可重新派發 OTP"}), 409

    # ── 本地端生成 OTP（零知識原則：CA 永不知曉明文）──
    otp      = secrets.token_urlsafe(24)      # ≥ 144-bit 安全隨機
    otp_hash = _sha256_hex(otp)               # H(OTP) = SHA-256(OTP)

    # ── 傳送 (voter_id, H(OTP)) 至 CA ──
    try:
        ca_resp = _register_to_ca(voter_id, otp_hash)
    except Exception as e:
        return jsonify({"status": "error", "message": f"CA 通訊失敗：{e}"}), 502

    if ca_resp.get('status') != 'success':
        code = ca_resp.get('code', 'CA_ERROR')
        msg  = ca_resp.get('message', str(ca_resp))
        if code == 'ALREADY_REGISTERED':
            # CA 已有該 ID（已完成認證），更新本地記錄
            db.execute("UPDATE voter_roster SET ca_status = 'registered' WHERE voter_id = ?", (voter_id,))
        return jsonify({"status": "error", "code": code, "message": msg}), 409

    # ── 儲存至本地 DB（明文 OTP 供列印派發）──
    if existing:
        db.execute(
            "UPDATE voter_roster SET otp = ?, otp_hash = ?, ca_status = 'pending', created_at = ?, distributed = 0, distributed_at = NULL WHERE voter_id = ?",
            (otp, otp_hash, now, voter_id),
        )
    else:
        db.execute(
            "INSERT INTO voter_roster (voter_id, otp, otp_hash, ca_status, created_at) VALUES (?, ?, ?, 'pending', ?)",
            (voter_id, otp, otp_hash, now),
        )

    print(f"[Admin] 已完成零知識 OTP 註冊：{voter_id}（H(OTP) 已送至 CA）")
    return jsonify({"status": "success", "voter_id": voter_id}), 200


@app.route('/api/add_batch', methods=['POST'])
def api_add_batch():
    """批次新增選民：逐一處理，回傳各別結果。"""
    data = request.get_json()
    # v4.0 修正：原本用 `'voter_ids' not in data` 只擋得住「完全沒帶這個
    # 欄位」，若明確傳 `"voter_ids": null`，這個 key 存在、檢查會放行，
    # 下面 `for v in data['voter_ids']` 對 None 做迭代直接丟未攔截的
    # TypeError、變成沒處理過的 500——跟 /api/add_voter 先前修過的同一種
    # null-crash bug，這裡漏補。改用 `not data.get('voter_ids')` 同時擋
    # 「缺欄位」「欄位是 null」「欄位是空陣列」三種情況。 <3
    if not data or not data.get('voter_ids'):
        return jsonify({"status": "error", "message": "缺少 voter_ids"}), 400

    ids = [str(v).strip() for v in data['voter_ids'] if str(v).strip()]
    results = []
    for voter_id in ids:
        try:
            now      = int(time.time())
            existing = db.fetchone("SELECT ca_status FROM voter_roster WHERE voter_id = ?", (voter_id,))
            if existing and existing['ca_status'] == 'registered':
                results.append({"voter_id": voter_id, "status": "skip", "message": "已完成認證"})
                continue

            otp      = secrets.token_urlsafe(24)
            otp_hash = _sha256_hex(otp)
            ca_resp  = _register_to_ca(voter_id, otp_hash)

            if ca_resp.get('status') == 'success' or ca_resp.get('code') == 'ALREADY_REGISTERED':
                if existing:
                    db.execute(
                        "UPDATE voter_roster SET otp = ?, otp_hash = ?, ca_status = 'pending', created_at = ?, distributed = 0 WHERE voter_id = ?",
                        (otp, otp_hash, now, voter_id),
                    )
                else:
                    db.execute(
                        "INSERT INTO voter_roster (voter_id, otp, otp_hash, ca_status, created_at) VALUES (?, ?, ?, 'pending', ?)",
                        (voter_id, otp, otp_hash, now),
                    )
                results.append({"voter_id": voter_id, "status": "success"})
            else:
                results.append({"voter_id": voter_id, "status": "error", "message": ca_resp.get('message', '')})
        except Exception as e:
            results.append({"voter_id": voter_id, "status": "error", "message": str(e)})

    return jsonify({"status": "done", "results": results}), 200


@app.route('/api/mark_distributed', methods=['POST'])
def api_mark_distributed():
    """標記指定選民 OTP 已透過實體信件派發。"""
    data = request.get_json()
    rid  = data.get('id') if data else None
    if not rid:
        return jsonify({"status": "error", "message": "缺少 id"}), 400

    now = int(time.time())
    db.execute(
        "UPDATE voter_roster SET distributed = 1, distributed_at = ? WHERE id = ?",
        (now, rid),
    )
    return jsonify({"status": "success"}), 200


@app.route('/api/voters', methods=['GET'])
def api_voters():
    """[GET] 回傳完整選民清單（JSON），供外部查詢。"""
    voters = db.fetchall(
        "SELECT id, voter_id, otp_hash, ca_status, created_at, distributed FROM voter_roster ORDER BY id"
    )
    return jsonify({"status": "success", "voters": voters}), 200


@app.route('/api/new_round', methods=['POST'])
def api_new_round():
    """新一輪重置：TA 回到 standby + TPA 清除發票紀錄 + CA 清除名冊 +
    CC 清除開票狀態 + BB 清除公告狀態 + Admin 清除本地名冊。

    v4.0 修正：原本這裡完全沒有重置 CC/BB，導致上一輪開票/公告過一次
    後，CC 的 tally_state.done 與 BB 的 bb_state.published 會一直卡在
    「已完成」，新一輪投票結束後 CC 直接拒絕重新開票、BB 也會拒絕接受
    新結果並繼續顯示上一輪的舊資料——實測發現的真實 bug，過去只能手動
    docker exec 進容器清資料庫繞過，這裡補上正式的重置端點呼叫。 <3

    v4.0 再修正：TPA 也完全沒被重置過。TPA 的 issued_tokens 表記錄每位
    選民「這一輪」是否已消耗過 Voting Token（used=1），/api/auth 用它來
    擋重複投票。這張表如果沒清，任何上一輪真正投過票的選民，到了新一輪
    重新認證時一樣會被判定 ALREADY_VOTED、直接卡在 TPA 認證這關——實測
    發現：選民端明明還沒投這一輪，卻顯示已投票／認證失敗，根源就在這裡
    而不是選民端。補上 TPA 的重置呼叫（步驟 2，緊接在 TA 之後）。 <3

    v4.0 三修：voter_client 自己的 pending_envelope（選民端本地待送出
    信封佇列，湊滿批次或快截止才會送給 CC）也從沒被重置過。實測發現：
    某位選民上一輪投票時信封還卡在佇列裡沒送出，這期間執行了新一輪
    重置，這筆卡住的舊信封完全沒被清掉；等它終於在新一輪送出時，CC
    的防重複機制是全新的空表，會把這筆「其實屬於上一輪」的舊選票當成
    合法新票收下——造成新一輪開票結果多出不屬於這一輪任何一位選民的
    幽靈選票（實測案例：4 人完成認證投票，CC/BB 卻算出 5 張票）。
    補上 voter_client 的重置呼叫（步驟 2，跟 TPA 一起，在 TA 之後、
    CC 之前——一定要在 CC 重置前清空，否則萬一佇列裡剛好湊滿批次，
    有可能在這次重置過程中搶先送進「舊」的 CC）。 <3
    """
    results = {}

    # 1. 重置 TA 選舉狀態
    # v4.0 修正：TA 這兩個端點現在要求 Admin Bearer Token（見
    # ta_server/app.py），補上 headers=_admin_headers()，否則會被 401 擋下。 <3
    try:
        resp = http_requests.post(f"{TA_URL}/api/admin/reset_election", json={}, headers=_admin_headers(), timeout=10, **_ADMIN_MTLS)  # <3
        results['ta'] = resp.json()
    except Exception as e:
        results['ta'] = {"status": "error", "message": str(e)}

    # 2. 清除 TPA 發票／認證紀錄（<3 新增，修正新一輪一開始就被判定已投票的問題）
    try:
        resp = http_requests.post(f"{TPA_URL}/api/admin/reset", json={}, headers=_admin_headers(), timeout=10, **_ADMIN_MTLS)
        results['tpa'] = resp.json()
    except Exception as e:
        results['tpa'] = {"status": "error", "message": str(e)}

    # 3. 清除 voter_client 本地待送出信封佇列（<3 新增，修正幽靈選票問題）
    try:
        resp = http_requests.post(f"{VOTER_URL}/api/admin/reset", json={}, headers=_admin_headers(), timeout=10, **_ADMIN_MTLS)
        results['voter'] = resp.json()
    except Exception as e:
        results['voter'] = {"status": "error", "message": str(e)}

    # 4. 清除 CA 選民名冊
    try:
        resp = http_requests.post(f"{CA_URL}/api/admin/reset_voter_registry", json={}, headers=_admin_headers(), timeout=10, **_ADMIN_MTLS)  # <3
        results['ca'] = resp.json()
    except Exception as e:
        results['ca'] = {"status": "error", "message": str(e)}

    # 5. 清除 CC 開票狀態（<3 新增，修正無法重新開票的問題）
    try:
        resp = http_requests.post(f"{CC_URL}/api/admin/reset_tally", json={}, headers=_admin_headers(), timeout=10, **_ADMIN_MTLS)
        results['cc'] = resp.json()
    except Exception as e:
        results['cc'] = {"status": "error", "message": str(e)}

    # 6. 清除 BB 公告狀態（<3 新增，修正 BB 停留在上一輪結果的問題）
    try:
        resp = http_requests.post(f"{BB_URL}/api/admin/reset", json={}, headers=_admin_headers(), timeout=10, **_ADMIN_MTLS)
        results['bb'] = resp.json()
    except Exception as e:
        results['bb'] = {"status": "error", "message": str(e)}

    # 7. 清除本地名冊
    row = db.fetchone("SELECT COUNT(*) as cnt FROM voter_roster")
    count = row['cnt'] if row else 0
    db.execute("DELETE FROM voter_roster")
    results['admin'] = {"status": "success", "deleted": count}

    print(f"[Admin] 新一輪重置完成。本地刪除 {count} 筆。TA: {results['ta']}  TPA: {results['tpa']}  Voter: {results['voter']}  CA: {results['ca']}  CC: {results['cc']}  BB: {results['bb']}")
    return jsonify({"status": "success", "results": results}), 200


@app.route('/api/start_election', methods=['POST'])
def api_start_election():
    """向 TA 發送啟動選舉指令（管理員操作）。"""
    try:
        resp = http_requests.post(f"{TA_URL}/api/start_election", json={}, headers=_admin_headers(), timeout=10, **_ADMIN_MTLS)  # <3
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"status": "error", "message": f"無法連接 TA：{e}"}), 502


@app.route('/api/election_status', methods=['GET'])
def api_election_status():
    """查詢選舉狀態（從 TA 取得）。"""
    try:
        resp = http_requests.get(f"{TA_URL}/api/deadline", timeout=5, **_ADMIN_MTLS)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"status": "error", "message": f"無法連接 TA：{e}"}), 502


@app.route('/api/trigger_tally', methods=['POST'])
def api_trigger_tally():
    """
    [POST] 向 CC 觸發開票（v4.0 補上）。

    問題：CC 整個 Flask app（含網頁儀表板本身的「觸發開票」按鈕）都被
    mTLS CERT_REQUIRED 保護，不持有這套 PKI 用戶端憑證的瀏覽器連 TLS
    handshake 都過不了——包含管理員自己的瀏覽器。CC_URL 這個常數原本就
    定義在本檔案，但從未真的被用來呼叫 CC，等於管理員完全沒有合法路徑
    能觸發開票，只能 docker exec 進 CC 容器內部呼叫，明顯不是預期行為。

    修法：比照本檔案呼叫 CA/TA 的既有模式，用 Admin 自己已經持有的
    mTLS 用戶端憑證（_ADMIN_MTLS）代為呼叫 CC/api/tally，讓瀏覽器不需要
    持有內部 PKI 憑證，一樣能透過 Admin 這個中介觸發開票。 <3

    改為呼叫 CC 的 /api/tally/start 在背景開票、立即回應，前端再用
    /api/tally_status 輪詢進度。原本同步呼叫 /api/tally 最多只等 120 秒，
    票數上千時 CC 還在開票，Admin 卻先逾時顯示錯誤。
    """
    try:
        resp = http_requests.post(f"{CC_URL}/api/tally/start", json={}, headers=_admin_headers(), timeout=15, **_ADMIN_MTLS)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"status": "error", "message": f"無法連接 CC：{e}"}), 502


@app.route('/api/tally_status', methods=['GET'])
def api_tally_status():
    """[GET] 代為查詢 CC 的開票進度（瀏覽器無法直接連 CC，理由同上）。"""
    try:
        resp = http_requests.get(f"{CC_URL}/api/tally/status", headers=_admin_headers(), timeout=10, **_ADMIN_MTLS)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"status": "error", "message": f"無法連接 CC：{e}"}), 502


@app.route('/api/export', methods=['GET'])
def api_export():
    """匯出本輪完整資料（JSON 下載）。包含選民名冊、投票結果、回執、審計日誌。"""
    import json
    from flask import make_response

    now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    export = {"exported_at": now_str, "sections": {}}

    # 1. Admin 選民名冊
    export["sections"]["admin_voter_roster"] = db.fetchall(
        "SELECT voter_id, otp_hash, ca_status, created_at, distributed FROM voter_roster ORDER BY id"
    )

    # 2. TA 選舉狀態
    try:
        r = http_requests.get(f"{TA_URL}/api/deadline", timeout=5, **_ADMIN_MTLS)
        export["sections"]["election_state"] = r.json()
    except Exception as e:
        export["sections"]["election_state"] = {"error": str(e)}

    # 3. CA 選民名冊狀態
    try:
        r = http_requests.get(f"{CA_URL}/api/admin/voter_registry", headers=_admin_headers(), timeout=5, **_ADMIN_MTLS)  # <3
        export["sections"]["ca_voter_registry"] = r.json().get("voters", [])
    except Exception as e:
        export["sections"]["ca_voter_registry"] = {"error": str(e)}

    # 4. BB 公告結果
    try:
        r = http_requests.get(f"{BB_URL}/api/results", timeout=5, **_ADMIN_MTLS)
        export["sections"]["published_results"] = r.json()
    except Exception as e:
        export["sections"]["published_results"] = {"error": str(e)}

    # 5. 選民投票回執
    try:
        r = http_requests.get(f"{VOTER_URL}/api/all_receipts", timeout=5, **_ADMIN_MTLS)
        export["sections"]["vote_receipts"] = r.json().get("receipts", [])
    except Exception as e:
        export["sections"]["vote_receipts"] = {"error": str(e)}

    filename = f"election_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    resp = make_response(json.dumps(export, ensure_ascii=False, indent=2))
    resp.headers['Content-Type'] = 'application/json; charset=utf-8'
    resp.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    print(f"[Admin] 資料已匯出：{filename}")
    return resp


@app.route('/print')
def print_page():
    """列印友善的 OTP 信件頁（含明文 OTP）。"""
    voters = db.fetchall(
        "SELECT voter_id, otp, otp_hash, ca_status, created_at FROM voter_roster ORDER BY voter_id"
    )
    for v in voters:
        v['created_at_str'] = _ts_fmt(v['created_at'])

    now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template_string(_PRINT_HTML, voters=voters, now_str=now_str)


if __name__ == '__main__':
    # v4.0 修正：Admin 的實際使用情境是系統維運人員直接用瀏覽器操作
    # 儀表板（新增選民、啟動/重置選舉），不是服務對服務的機器呼叫——
    # 目前系統裡也沒有任何東西會主動連進 Admin 並出示用戶端憑證。強制
    # CERT_REQUIRED 只會逼操作者把用戶端憑證匯入瀏覽器才能打開頁面，
    # 增加操作摩擦卻沒有對應的安全效益，所以跟 BB/Voter 一樣改成
    # require_client_cert=False——Admin 本來就不對外開放（沒有 Caddy
    # 代理、沒有對外 port），這一層防護交給網路層存取控制，不依賴傳輸層
    # 用戶端憑證。
    _ca_cert_path = os.path.join(KEYS_DIR, "ca_cert.pem")
    _ssl_ctx = build_mtls_server_context(
        _TLS_CERT_PATH, _TLS_KEY_PATH, _ca_cert_path, require_client_cert=False,
    )
    app.run(host='0.0.0.0', port=5010, debug=False, ssl_context=_ssl_ctx)
