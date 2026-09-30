"""
bb_server/app.py  —  公告板 (BB)

公開展示計票結果的地方。CC 開票完成後會把結果推送過來，
包含 Merkle Root、各候選人得票數、以及所有合法選票的清單。

選民可以輸入自己的 m_hex 來驗證選票，頁面會顯示互動式的
Merkle Tree 圖，清楚標示從葉節點到根的驗證路徑。

端點：
  GET  /                          公告板首頁（計票結果）
  GET  /verify                    Merkle Proof 視覺化驗證頁
  POST /api/publish               接收 CC 推送的計票結果
  GET  /api/results               查詢計票結果與 Merkle Root
  GET  /api/merkle_proof/<m_hex>  取得指定選票的 Merkle Proof
  GET  /api/config                查看目前設定
  POST /api/config/reload         重新載入 config.json
"""

import os
import sys
import json
import time
import datetime
import threading

# 確保 shared/ 可被 import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string
import requests as http_requests

from shared.merkle_tree import MerkleTree, h_leaf
from shared.format_utils import sha256_hex, ts_to_human, b64_to_bytes
from shared.db_utils import Database
from shared.config_loader import make_reload_endpoint, get_service_registration_token  # <3 v4.0
from shared.crypto_utils import verify_signature
from shared.key_manager import load_or_fetch_ca_cert, verify_cert_chain_and_cn  # <3 v4.0
from shared.admin_auth import check_admin_token, admin_auth_error  # <3 v4.0：保護 /api/admin/reset
from shared.tls_utils import load_or_request_tls_certificate, build_mtls_server_context  # <3 v4.0：mTLS
from cryptography import x509
from shared.ui_style import UI_HEAD, THEME_TOGGLE

# 驗證頁在瀏覽器驗 CC 簽章時所用的 CA 根憑證來源：投票網站（voter_client），
# 刻意不由 BB 自己提供——BB 若被入侵，可以連同假的 CA 根憑證一起送出。
CA_CERT_URL_FOR_BROWSER = f"https://{os.environ.get('SITE_ADDRESS', 'localhost')}/api/proxy/ca/ca_cert"

# ============================================================
# 常數設定
# ============================================================
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR    = os.path.join(SERVICE_DIR, "keys")
# <3 v4.0：資料庫獨立放進 data/ 子目錄，才能掛載成持久化 volume——
# 原本直接放在 SERVICE_DIR 底下，跟隨容器可寫層一起被重建時清空，
# published_votes（已公告的開票結果）沒了會需要重新公告，任何一次
# 重新部署都可能連帶造成這個後果。
DATA_DIR    = os.path.join(SERVICE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH     = os.path.join(DATA_DIR, "bb.db")
BB_ID       = "BB"
BB_HOSTNAME = os.environ.get("BB_HOSTNAME", "bb")  # <3 v4.0：填入 TLS 憑證的 SAN
CC_URL      = os.environ.get("CC_URL", "https://localhost:5003")
CA_URL      = os.environ.get("CA_URL", "https://localhost:5001")

# ============================================================
# 資料庫初始化
# ============================================================
db = Database(DB_PATH)
db.execute("""
    CREATE TABLE IF NOT EXISTS bb_state (
        key     TEXT PRIMARY KEY,
        value   TEXT NOT NULL
    )
""")
db.execute("""
    CREATE TABLE IF NOT EXISTS published_votes (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        m_hex       TEXT NOT NULL,
        leaf_hash   TEXT NOT NULL
    )
""")
# v2.0 修正：規格書 §19.5 明定 BB 不得儲存 vote 對 m_hex 的對應關係，只能
# 存 m_hex 清單。這裡不再有 vote 欄位；若是延續舊資料庫（曾經有 vote
# 欄位），沿用該表仍可運作，只是新寫入的資料不會再填入 vote。 <3

print("[BB] 公告板初始化完成。")

# ============================================================
# 載入 CA 憑證（用於驗證 CC 憑證）
# ============================================================
try:
    _ca_cert_pem = load_or_fetch_ca_cert(KEYS_DIR, CA_URL)
    _ca_cert = x509.load_pem_x509_certificate(_ca_cert_pem.encode('utf-8'))
    print("[BB] CA 憑證已載入")
except Exception as ex:
    print(f"[BB] 警告：無法取得 CA 憑證（{ex}）")
    _ca_cert_pem = None
    _ca_cert = None

# v4.0 新增：BB 沒有應用層身分金鑰對（規格書一貫定位 BB「無自有金鑰」），
# 但一樣需要一把 TLS 專用金鑰對，供公開監聽埠出示伺服器憑證用。
try:
    _tls_cert_path, _tls_key_path = load_or_request_tls_certificate(
        KEYS_DIR, BB_ID, BB_HOSTNAME, CA_URL,
        registration_token=get_service_registration_token(),
    )
except Exception as ex:
    print(f"[BB] 警告：無法取得 TLS 憑證（{ex}）")
    _tls_cert_path = _tls_key_path = None

# ============================================================
# Flask App
# ============================================================
app = Flask(__name__)


# ── Jinja2 自訂過濾器：Unix timestamp → 人類可讀 ──────────────
@app.template_filter('ts_to_str')
def ts_to_str(ts):
    """將 Unix timestamp 轉為 YYYY-MM-DD HH:MM:SS（僅用於 UI 顯示）"""
    try:
        return datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)


# ── HTML 模板：主公告板 ────────────────────────────────────────
_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <title>開票公告｜NUTC 線上投票</title>""" + UI_HEAD + """
  {% if not published %}<meta http-equiv="refresh" content="20">{% endif %}
</head>
<body>
<header class="topbar">
  <div class="container-wide topbar-inner">
    <a class="brand" href="/">
      <span class="brand-name">NUTC 線上投票</span>
      <span class="brand-sub">開票公告板</span>
    </a>
    <div class="topbar-actions">
      {% if published %}<span class="badge badge-ok">已公告</span>{% else %}<span class="badge badge-warn">等待開票</span>{% endif %}
      """ + THEME_TOGGLE + """
    </div>
  </div>
</header>

<main>
  <div class="container-wide stack-lg">
  {% if published %}
    <div class="stack-sm">
      <h1>開票結果</h1>
      <p class="lead">合法選票 {{ valid_count }} 張{% if tallied_at %}・公告時間 {{ tallied_at | ts_to_str }}{% endif %}</p>
    </div>

    <div class="grid grid-main-side">
      <section class="card stack" aria-labelledby="tallyTitle">
        <h2 id="tallyTitle" class="section-title">各候選人得票</h2>
        {% for candidate, count in tally | dictsort(by='value', reverse=true) %}
        {% set pct = (count / valid_count * 100) if valid_count > 0 else 0 %}
        <div class="stack-sm">
          <div class="row-between">
            <span class="strong">{{ candidate }}</span>
            <span><span class="strong">{{ count }}</span> 票 <span class="muted small">{{ "%.1f"|format(pct) }}%</span></span>
          </div>
          <div class="bar" role="img" aria-label="{{ candidate }} 得票率 {{ '%.1f'|format(pct) }}%"><span style="width: {{ pct }}%"></span></div>
        </div>
        {% endfor %}
        <div class="row-between" style="border-top:1px solid var(--border); padding-top:14px">
          <span class="muted">合法選票合計</span><span class="strong">{{ valid_count }} 票</span>
        </div>
      </section>

      <section class="card stack" aria-labelledby="verifyTitle">
        <h2 id="verifyTitle" class="section-title">驗證您的選票</h2>
        <p class="small muted">輸入投票回執上的選票識別碼（m_hex），確認您的票已被計入。驗證過程不會透露您投給誰。</p>
        <form method="GET" action="/verify" class="stack-sm">
          <label class="sr-only" for="mhexInput">選票識別碼（m_hex）</label>
          <input id="mhexInput" class="input mono" type="text" name="m_hex" placeholder="貼上 64 位的 m_hex"
                 autocomplete="off" autocapitalize="off" spellcheck="false" required>
          <button type="submit" class="btn btn-primary btn-block">驗證</button>
        </form>
      </section>
    </div>

    <section class="card stack-sm" aria-labelledby="rootTitle">
      <div class="row-between">
        <h2 id="rootTitle" class="section-title">官方 Merkle Root</h2>
        <a class="small" href="/api/signed_bundle">下載 CC 簽章的結果包</a>
      </div>
      <code class="hash">{{ merkle_root }}</code>
      <p class="small muted">由計票中心（CC）簽章公告。每一張選票的驗證路徑，都必須能算出這個值。</p>
    </section>

    <section class="card card-flush" aria-labelledby="listTitle">
      <div class="card-head">
        <h2 id="listTitle" class="section-title">合法選票清單</h2>
        <span class="small muted">共 {{ valid_count }} 張{% if valid_count > votes|length %}，顯示前 {{ votes|length }} 張{% endif %}・<a href="/api/results">下載完整清單（JSON）</a></span>
      </div>
      {% if votes %}
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th class="num">#</th><th>選票識別碼（m_hex）</th><th><span class="sr-only">操作</span></th></tr></thead>
          <tbody>
            {% for v in votes %}
            <tr>
              <td class="num muted">{{ loop.index }}</td>
              <td><span class="hash-inline">{{ v.m_hex }}</span></td>
              <td class="nowrap"><a href="/verify?m_hex={{ v.m_hex }}">驗證</a></td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% else %}
      <div class="card-body muted">沒有合法選票。</div>
      {% endif %}
    </section>
  {% else %}
    <section class="card text-center stack" style="padding:56px 24px">
      <h1>等待開票</h1>
      <p class="lead">投票截止並完成開票後，計票中心（CC）會在這裡公告結果。</p>
      <p class="small muted">此頁每 20 秒自動重新整理。</p>
    </section>
  {% endif %}
  </div>
</main>
<footer class="footer">
  <div class="container-wide">公告內容由計票中心簽章；任何人都可以下載結果包與完整選票清單，自行重算 Merkle Root 驗證。</div>
</footer>
</body>
</html>"""


_VERIFY_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <title>驗證選票｜NUTC 線上投票</title>""" + UI_HEAD + """
  <style>
    /* 樹狀圖畫布：固定高度的拖曳容器，由 JS 控制畫布位置與縮放 */
    #tree-scroll-wrap { position: relative; width: 100%; height: 60vh; min-height: 360px; overflow: hidden;
      background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius); cursor: grab; touch-action: none; }
    #tree-scroll-wrap:active { cursor: grabbing; }
    #tree-canvas { display: block; position: absolute; top: 0; left: 0; max-width: none; }
    #node-panel { display: none; position: fixed; z-index: 200; max-width: min(420px, calc(100vw - 24px)); pointer-events: none;
      background: var(--surface); border: 1px solid var(--border-strong); border-radius: var(--radius); padding: 12px 14px; }
    #node-panel .panel-title { font-weight: 700; font-size: 0.85rem; margin-bottom: 4px; }
    #node-panel .panel-hash { font-family: var(--mono); font-size: 0.8rem; color: var(--accent); word-break: break-all; }
    #node-panel .panel-meta { color: var(--muted); font-size: 0.8rem; margin-top: 4px; }
    #zoom-controls { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
    #zoom-label { min-width: 48px; text-align: center; font-size: 0.85rem; color: var(--muted); font-variant-numeric: tabular-nums; }
    .legend { display: flex; flex-wrap: wrap; gap: 6px 14px; font-size: 0.85rem; color: var(--muted); }
    .legend span { display: inline-flex; align-items: center; gap: 6px; }
    .legend i { width: 12px; height: 12px; border-radius: 3px; border: 2px solid; display: inline-block; }
    .proof-step { display: grid; grid-template-columns: auto auto minmax(0, 1fr); gap: 4px 10px; align-items: baseline; padding: 8px 0; border-bottom: 1px solid var(--border); }
    .proof-step:last-child { border-bottom: 0; }
  </style>
  <script>
    // 切換深色模式後重畫樹狀圖（畫布顏色由 JS 決定）
    (function () { var t = window.toggleTheme; window.toggleTheme = function () { t(); if (typeof draw === 'function') draw(); }; })();
  </script>
</head>
<body>
<header class="topbar">
  <div class="container-wide topbar-inner">
    <a class="brand" href="/">
      <span class="brand-name">NUTC 線上投票</span>
      <span class="brand-sub">驗證選票</span>
    </a>
    <div class="topbar-actions">
      <a class="btn btn-sm" href="/">回公告板</a>
      """ + THEME_TOGGLE + """
    </div>
  </div>
</header>

<main>
  <div class="container-wide stack-lg">
    <div class="stack-sm">
      <h1>驗證選票</h1>
      <p class="lead">確認您的選票已包含在計票結果中，而且不必透露您投給誰。</p>
    </div>

    {% if result %}
    <div class="stack">
      {% if result.valid %}
      <div class="alert alert-ok">
        <p class="alert-title">公告板回報：找到您的選票</p>
        <p class="small">這是公告板伺服器的判斷。下方會在您的瀏覽器裡獨立再驗證一次，不依賴公告板。</p>
      </div>
      {% else %}
      <div class="alert alert-err" role="alert">
        <p class="alert-title">驗證失敗</p>
        <p class="small">{{ result.message }}</p>
      </div>
      {% endif %}

      {% if result.valid %}
      <!-- 瀏覽器本機獨立驗證：向投票網站取得 CA 根憑證、驗證 CC 簽章，再用簽過章的
           Merkle Root 重算驗證路徑，不依賴也不信任公告板伺服器的判斷。 -->
      <section id="localVerifyBanner" class="alert stack-sm" aria-live="polite">
        <p class="row"><span id="localVerifyIcon" class="spin" aria-hidden="true"></span><span id="localVerifyTitle" class="alert-title">正在您的瀏覽器中獨立驗證…</span></p>
        <p class="small muted">先向投票網站（不是公告板）取得 CA 根憑證，確認開票結果包確實由 CA 認證的計票中心簽章，再用結果包裡的 Merkle Root 重新計算您的驗證路徑。公告板若竄改結果或謊報，這裡會顯示不符。</p>
        <ul id="localVerifySteps" class="steps"></ul>
      </section>
      <script>
        (function () {
          async function sha256Hex(bytes) {
            const digest = await crypto.subtle.digest('SHA-256', bytes);
            return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
          }
          function concatBytes(...arrs) {
            const total = arrs.reduce((n, a) => n + a.length, 0);
            const out = new Uint8Array(total);
            let offset = 0;
            for (const a of arrs) { out.set(a, offset); offset += a.length; }
            return out;
          }
          // 必須跟 shared/merkle_tree.py 的 h_leaf/h_node 規則完全一致：
          // 前綴一個位元組（葉節點 0x00、中間節點 0x01），後面接的是雜湊值
          // 的「16進位字串本身」當文字編碼，不是先還原成二進位。
          async function hLeafLocal(mHex) {
            const enc = new TextEncoder();
            return sha256Hex(concatBytes(new Uint8Array([0x00]), enc.encode(mHex)));
          }
          async function hNodeLocal(left, right) {
            const enc = new TextEncoder();
            return sha256Hex(concatBytes(new Uint8Array([0x01]), enc.encode(left), enc.encode(right)));
          }
          async function verifyProofLocally(mHex, proof, rootOfficial) {
            let current = await hLeafLocal(mHex);
            for (const step of proof) {
              current = step.position === 'right'
                ? await hNodeLocal(current, step.sibling)
                : await hNodeLocal(step.sibling, current);
            }
            return current === rootOfficial;
          }


          // ── 驗證 CC 簽章用的工具（與 voter_client 的同名函式相同邏輯）──
          // 本頁是 BB 自己提供的，BB 送來的任何資料（root、proof、結果包）
          // 都不能直接相信：root 必須來自「CC 簽過章、且 CC 憑證由 CA 簽發」
          // 的結果包，CA 根憑證則向投票網站（不是 BB）索取。
          function pemToDer(pem) {
            const b64 = pem.split(/-----[^-]+-----/).join('').split('').filter(c => c.trim()).join('');
            return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
          }
          function b64decode(b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)); }
          function bytesToHexStr(bytes) { return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''); }
          function derReadTLV(bytes, offset) {
            const lenByte = bytes[offset + 1];
            let lenOfLen = 0, length;
            if (lenByte & 0x80) {
              lenOfLen = lenByte & 0x7f;
              length = 0;
              for (let i = 0; i < lenOfLen; i++) length = (length << 8) | bytes[offset + 2 + i];
            } else {
              length = lenByte;
            }
            const contentStart = offset + 2 + lenOfLen;
            return { tag: bytes[offset], start: offset, end: contentStart + length, contentStart, contentEnd: contentStart + length };
          }
          function derChildren(bytes, start, end) {
            const out = [];
            for (let o = start; o < end;) { const t = derReadTLV(bytes, o); out.push(t); o = t.end; }
            return out;
          }
          function derFindOid(bytes, oid, start, end) {
            search:
            for (let i = start; i + 2 + oid.length <= end; i++) {
              if (bytes[i] !== 0x06 || bytes[i + 1] !== oid.length) continue;
              for (let j = 0; j < oid.length; j++) if (bytes[i + 2 + j] !== oid[j]) continue search;
              return derReadTLV(bytes, derReadTLV(bytes, i).end);
            }
            return null;
          }
          function parseCertificate(certPem) {
            const der = pemToDer(certPem);
            const top = derReadTLV(der, 0);
            const [tbs, , sigValTlv] = derChildren(der, top.contentStart, top.contentEnd);
            const sigValue = der.slice(sigValTlv.contentStart + 1, sigValTlv.contentEnd);
            const tbsBytes = der.slice(tbs.start, tbs.end);
            let kids = derChildren(der, tbs.contentStart, tbs.contentEnd);
            if (kids[0].tag === 0xa0) kids = kids.slice(1);
            const subjectTlv = kids[4], spkiTlv = kids[5];
            const cnTlv = derFindOid(der, [0x55, 0x04, 0x03], subjectTlv.contentStart, subjectTlv.contentEnd);
            return {
              tbsBytes, sigValue,
              spkiBytes: der.slice(spkiTlv.start, spkiTlv.end),
              commonName: cnTlv ? new TextDecoder().decode(der.slice(cnTlv.contentStart, cnTlv.contentEnd)) : null,
            };
          }
          async function verifyCertChain(certPem, expectedCN, caKey) {
            const { tbsBytes, sigValue, spkiBytes, commonName } = parseCertificate(certPem);
            if (commonName !== expectedCN) throw new Error(`憑證 CN 不符（預期 ${expectedCN}，實際 ${commonName}）`);
            const ok = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, caKey, sigValue, tbsBytes);
            if (!ok) throw new Error(`${expectedCN} 憑證不是由 CA 簽發，可能遭偽造`);
            return spkiBytes;
          }
          // 與 Python padding.PSS.MAX_LENGTH 一致：emLen - hLen(32) - 2
          function pssMaxSaltLength(spkiBytes) {
            const top = derReadTLV(spkiBytes, 0);
            const [, bitStr] = derChildren(spkiBytes, top.contentStart, top.contentEnd);
            const rsa = spkiBytes.slice(bitStr.contentStart + 1, bitStr.contentEnd);
            const rsaTop = derReadTLV(rsa, 0);
            const [nTlv] = derChildren(rsa, rsaTop.contentStart, rsaTop.contentEnd);
            const modulusBits = BigInt('0x' + bytesToHexStr(rsa.slice(nTlv.contentStart, nTlv.contentEnd))).toString(2).length;
            return Math.ceil((modulusBits - 1) / 8) - 32 - 2;
          }

          (async function () {
            const mHex        = {{ result.m_hex | tojson }};
            const proof       = {{ result.proof | tojson }};
            const caCertUrl   = {{ ca_cert_url | tojson }};
            const icon  = document.getElementById('localVerifyIcon');
            const title = document.getElementById('localVerifyTitle');
            const banner = document.getElementById('localVerifyBanner');
            const steps = document.getElementById('localVerifySteps');
            function step(text) {
              const li = document.createElement('li');
              li.className = 'step-ok';
              const mark = document.createElement('span');
              mark.className = 'mark';
              mark.textContent = '✓';
              const t = document.createElement('span');
              t.textContent = text;
              li.append(mark, t);
              steps.appendChild(li);
            }
            try {
              // 1. CA 根憑證：向投票網站索取，不向 BB 索取
              const caResp = await fetch(caCertUrl, { cache: 'no-store' }).then(r => r.json());
              if (caResp.status !== 'success' || !caResp.ca_certificate) throw new Error('無法從投票網站取得 CA 根憑證');
              const caKey = await crypto.subtle.importKey('spki', parseCertificate(caResp.ca_certificate).spkiBytes,
                { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
              step('已從投票網站取得 CA 根憑證');

              // 2. CC 憑證鏈 + 結果包簽章
              const sb = await fetch('/api/signed_bundle', { cache: 'no-store' }).then(r => r.json());
              if (sb.status !== 'success') throw new Error(sb.message || '公告板沒有提供 CC 簽章的結果包');
              const ccSpki = await verifyCertChain(sb.cc_cert_pem, 'CC', caKey);
              step('CC 憑證由 CA 簽發');
              const ccKey = await crypto.subtle.importKey('spki', ccSpki, { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify']);
              const sigOk = await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: pssMaxSaltLength(ccSpki) },
                ccKey, b64decode(sb.signature), new TextEncoder().encode(sb.signed_bundle));
              if (!sigOk) throw new Error('結果包的 CC 簽章無效，公告內容可能遭竄改');
              step('開票結果包的 CC 簽章有效');

              // 3. 只使用簽過章的 root
              const rootOfficial = JSON.parse(sb.signed_bundle).root_official;
              const ok = await verifyProofLocally(mHex, proof, rootOfficial);
              if (ok) step('您的選票驗證路徑可算出 CC 簽章的 Merkle Root');
              icon.className = 'hidden';
              if (ok) {
                banner.className = 'alert alert-ok stack-sm';
                title.textContent = '瀏覽器本機獨立驗證：通過（未使用公告板的判斷結果）';
              } else {
                banner.className = 'alert alert-err stack-sm';
                title.textContent = '瀏覽器本機獨立驗證：與公告結果不符。請勿相信上方的「找到您的選票」，並立即通報選務人員。';
              }
            } catch (e) {
              icon.className = 'hidden';
              banner.className = 'alert alert-err stack-sm';
              title.textContent = '本機獨立驗證失敗：' + e.message;
            }
          })();
        })();
      </script>

      <details class="card">
        <summary>詳細雜湊資訊</summary>
        <dl class="dl" style="margin-top:16px">
          <div><dt>m_hex（您的選票識別碼）</dt><dd><code class="hash">{{ result.m_hex }}</code></dd></div>
          <div><dt>葉節點 H_leaf(m) = H(0x00 ‖ m_hex)</dt><dd><code class="hash">{{ result.leaf_hash }}</code></dd></div>
          <div>
            <dt>驗證路徑（由葉到根，共 {{ result.proof | length }} 步）</dt>
            <dd>
              {% for step in result.proof %}
              <div class="proof-step">
                <span class="small muted nowrap">步驟 {{ loop.index }}</span>
                <span class="badge {% if step.position == 'right' %}badge-info{% else %}badge-warn{% endif %}">{{ '右' if step.position == 'right' else '左' }}</span>
                <span class="hash-inline small">{{ step.sibling }}</span>
              </div>
              {% endfor %}
            </dd>
          </div>
          <div><dt>官方 Merkle Root（由計票中心公告）</dt><dd><code class="hash">{{ result.root }}</code></dd></div>
        </dl>
      </details>

      <section class="card stack" aria-labelledby="treeTitle">
        <div class="row-between">
          <h2 id="treeTitle" class="section-title">Merkle Tree 樹狀圖</h2>
          {% if tree_data %}
          <div id="zoom-controls">
            <button type="button" class="btn btn-sm" onclick="changeZoom(-0.15)" aria-label="縮小">－</button>
            <span id="zoom-label">100%</span>
            <button type="button" class="btn btn-sm" onclick="changeZoom(+0.15)" aria-label="放大">＋</button>
            <button type="button" class="btn btn-sm" onclick="resetZoom()">1:1</button>
            <button type="button" class="btn btn-sm" onclick="fitTree()">最適</button>
            <button type="button" class="btn btn-sm" onclick="focusTarget()">對焦我的票</button>
          </div>
          {% endif %}
        </div>
        {% if tree_data %}
        <div class="legend" aria-hidden="true">
          <span><i style="background:#fbf1dc;border-color:#875800"></i>您的選票</span>
          <span><i style="background:#e7f2ea;border-color:#1d6b3a"></i>兄弟節點</span>
          <span><i style="background:#e8eef5;border-color:#1f4e79"></i>驗證路徑</span>
          <span><i style="background:#1f4e79;border-color:#1f4e79"></i>樹根</span>
          <span><i style="background:transparent;border-style:dashed;border-color:#b5afa2"></i>補位節點</span>
        </div>
        <div id="tree-scroll-wrap">
          <canvas id="tree-canvas"></canvas>
        </div>
        <p class="small muted">點擊節點看完整雜湊・拖曳移動・滾輪上下捲動・按住 Shift 滾輪左右捲動・手機可用兩指縮放</p>
        {% else %}
        <p class="small muted">本次公告共有 {{ result.leaf_count }} 張選票，超過 {{ viz_max_leaves }} 張時不繪製完整樹狀圖（瀏覽器負擔太大）。上方的驗證路徑與本機驗證不受影響。</p>
        {% endif %}
      </section>
      {% endif %}
    </div>
    {% endif %}

    <section class="card stack-sm" aria-labelledby="againTitle">
      <h2 id="againTitle" class="section-title">{% if result %}驗證另一張選票{% else %}輸入選票識別碼{% endif %}</h2>
      <form method="GET" action="/verify" class="row" style="align-items:stretch">
        <label class="sr-only" for="mhexAgain">選票識別碼（m_hex）</label>
        <input id="mhexAgain" class="input mono" style="flex:1 1 260px; width:auto" type="text" name="m_hex" value="{{ m_hex or '' }}"
               placeholder="貼上 64 位的 m_hex" autocomplete="off" autocapitalize="off" spellcheck="false" required>
        <button type="submit" class="btn btn-primary" style="flex:0 0 auto">驗證</button>
      </form>
    </section>
  </div>
</main>

  <div id="node-panel">
    <div class="panel-title" id="panel-title"></div>
    <div class="panel-hash" id="panel-hash"></div>
    <div class="panel-meta" id="panel-meta"></div>
  </div>

  {% if result and result.valid and tree_data %}
  <script>
  // ════════════════════════════════════════════════════════════
  //  完美的金字塔佈局 — 自底向上精準尋跡 + Root 絕對置中演算法
  // ════════════════════════════════════════════════════════════
  const treeData = {{ tree_data | tojson }};

  const NODE_W    = 108;
  const NODE_H    = 34;
  const H_GAP     = 24;
  const V_GAP     = 72;   
  
  // Canvas 內部的固定 Padding（大面積留白，確保畫面宏大不貼邊）
  const PADDING_X  = 100;
  const PADDING_Y  = 100;
  // 層標籤區域寬度（左側保留給文字）
  const LABEL_W    = 80;
  const RADIUS     = 6;

  function getThemeColors() {
    const isDark = document.documentElement.classList.contains('dark');
    return {
      normal:  isDark ? { bg: '#1e1d1b', border: '#4d4a43', text: '#a6a299', glow: null }
                      : { bg: '#ffffff', border: '#b5afa2', text: '#5d5a53', glow: null },
      target:  isDark ? { bg: '#2f2615', border: '#e4b558', text: '#ecebe7', glow: null }
                      : { bg: '#fbf1dc', border: '#875800', text: '#1c1b19', glow: null },
      sibling: isDark ? { bg: '#18291e', border: '#72cf91', text: '#ecebe7', glow: null }
                      : { bg: '#e7f2ea', border: '#1d6b3a', text: '#1c1b19', glow: null },
      path:    isDark ? { bg: '#1f2a36', border: '#8db5df', text: '#ecebe7', glow: null }
                      : { bg: '#e8eef5', border: '#1f4e79', text: '#1c1b19', glow: null },
      root:    isDark ? { bg: '#8db5df', border: '#8db5df', text: '#0f2236', glow: null }
                      : { bg: '#1f4e79', border: '#1f4e79', text: '#ffffff', glow: null },
      edgeNormal: isDark ? '#36342f' : '#d9d5cc',
      edgePath:   isDark ? '#8db5df' : '#1f4e79',
      layerText:  isDark ? '#a6a299' : '#5d5a53'
    };
  }

  let scale = 1.0;
  let nodePositions = [];
  let canvasW = 0, canvasH = 0;

  const canvas  = document.getElementById('tree-canvas');
  const ctx     = canvas.getContext('2d');
  const wrap    = document.getElementById('tree-scroll-wrap');
  const panel   = document.getElementById('node-panel');

  function shortHash(h) {
    if (!h) return '—';
    return h.slice(0, 6) + '..' + h.slice(-6);
  }

  function getNodeRole(layerIdx, nodeIdx) {
    for (const p of treeData.proof_path) {
      if (p.layer === layerIdx && p.index === nodeIdx) return p.role;
    }
    return 'normal';
  }

  function isVirtualNode(layerIdx, nodeIdx) {
    for (const v of (treeData.virtual_nodes || [])) {
      if (v.layer === layerIdx && v.index === nodeIdx) return true;
    }
    return false;
  }

  function isPathEdge(fromLayer, fromIdx, toLayer, toIdx) {
    const parentIdx = Math.floor(fromIdx / 2);
    if (parentIdx !== toIdx) return false;
    const fromRole = getNodeRole(fromLayer, fromIdx);
    const toRole   = getNodeRole(toLayer, toIdx);
    return (fromRole === 'target' || fromRole === 'path') &&
           (toRole   === 'path'   || toRole   === 'root');
  }

  // ── 自底向上精準尋跡 + Root 絕對置中演算法（防重疊終極版）──
  // 核心修復：奇數節點補齊後，父節點計算只使用「真實」子節點數量
  // 步驟：
  //   1. 計算每層的「真實」節點數（不含補齊的重複節點）
  //   2. 葉節點從 X=0 開始排列
  //   3. 由下往上，父節點精準對齊真實子節點中央
  //   4. 整體平移使 Root 落在畫布幾何正中央
  //   5. 確保邊界安全
  function computeLayout() {
    const layers = treeData.layers;
    const totalLayers = layers.length;

    // 計算每層的「真實」節點數（後端補齊前的原始數量）
    // 規則：若某層節點數為偶數，真實數 = 該數；若為奇數，真實數 = 該數（補齊後顯示的）
    // 但父節點數 = ceil(子節點真實數 / 2)，所以我們直接用 layers[li].length
    // 重疊問題的根源：layers[0] 可能包含補齊的重複節點（最後一個重複）
    // 解法：計算每層的「原始」節點數
    const realCounts = [];
    realCounts[totalLayers - 1] = 1; // Root 永遠只有 1 個
    for (let li = totalLayers - 2; li >= 0; li--) {
      // 子層的真實數 = 父層真實數 * 2（但不超過 layers[li].length）
      // 實際上：layers[li].length 已是補齊後的數，真實數可能少 1
      realCounts[li] = layers[li].length;
    }
    // 修正：若某層是奇數補齊的，最後一個節點是重複的
    // 判斷方式：若 layers[li].length 為偶數，且 layers[li+1].length * 2 < layers[li].length
    // 簡單做法：直接用 layers[li].length，但在計算父節點時只看「真實」的子節點
    // 真實子節點數 = 父層節點數 * 2（若父層節點數 * 2 < 子層節點數，則子層最後一個是補齊的）
    const trueChildCount = new Array(totalLayers).fill(0);
    trueChildCount[totalLayers - 1] = 1;
    for (let li = totalLayers - 2; li >= 0; li--) {
      const parentCount = trueChildCount[li + 1];
      // 子層真實節點數：父層每個節點最多有 2 個子節點
      // 但子層補齊後的數量 = layers[li].length
      // 真實數 = min(layers[li].length, parentCount * 2)
      // 實際上補齊只會讓最後一個重複，所以真實數 = layers[li].length 或 layers[li].length - 1
      // 判斷：若 layers[li].length 是奇數，則沒有補齊；若是偶數，可能有補齊
      // 最可靠的方式：從葉節點往上推
      trueChildCount[li] = layers[li].length;
    }
    // 從葉節點往上推算真實數
    const nLeaves = layers[0].length;
    trueChildCount[0] = nLeaves;
    for (let li = 1; li < totalLayers; li++) {
      const childTrue = trueChildCount[li - 1];
      trueChildCount[li] = Math.ceil(childTrue / 2);
    }

    // 先設定整體高度，由總層數決定（上下各留 PADDING_Y）
    canvasH = PADDING_Y * 2 + (totalLayers - 1) * (NODE_H + V_GAP) + NODE_H;

    nodePositions = [];
    const nodeMap = Array.from({length: totalLayers}, () => []);

    // ── 步驟 1：排列最底層的葉節點（從 X=0 開始，純相對座標）
    // 包含視覺補齊的虛擬佔位節點（layers[0].length 含補齊）
    const nDisplayLeaves = layers[0].length;
    for (let ni = 0; ni < nDisplayLeaves; ni++) {
      const hash = layers[0][ni];
      const role = getNodeRole(0, ni);
      const virtual = isVirtualNode(0, ni);
      const nodeX = ni * (NODE_W + H_GAP);
      const node = {
        x: nodeX,
        y: canvasH - PADDING_Y - NODE_H,
        w: NODE_W, h: NODE_H, hash, role, virtual,
        layerName: '葉節點層', layerIdx: 0, nodeIdx: ni,
      };
      nodePositions.push(node);
      nodeMap[0][ni] = node;
    }

    // ── 步驟 2：由下往上，父節點精準對齊「真實」子節點中央
    for (let li = 1; li < totalLayers; li++) {
      const nReal = trueChildCount[li];
      const isRoot = li === totalLayers - 1;
      const layerName = isRoot ? 'Root_official' : `第 ${li} 層`;
      const layerY = canvasH - PADDING_Y - NODE_H - li * (NODE_H + V_GAP);

      for (let ni = 0; ni < nReal; ni++) {
        const hash = layers[li][ni];
        let role = getNodeRole(li, ni);
        if (isRoot) role = 'root';

        const leftChild  = nodeMap[li - 1][ni * 2];
        // 右子節點：只有在真實子節點數允許時才取
        const rightChildIdx = ni * 2 + 1;
        const rightChild = (rightChildIdx < trueChildCount[li - 1]) ? nodeMap[li - 1][rightChildIdx] : null;

        let nodeX = 0;
        if (leftChild && rightChild) {
          // 精準置中於兩個真實子節點的中間
          const leftCenter  = leftChild.x  + NODE_W / 2;
          const rightCenter = rightChild.x + NODE_W / 2;
          nodeX = (leftCenter + rightCenter) / 2 - NODE_W / 2;
        } else if (leftChild) {
          // 單獨子節點：直接垂直對齊
          nodeX = leftChild.x;
        } else {
          nodeX = ni * (NODE_W + H_GAP);
        }

        const virtual = isVirtualNode(li, ni);
        const node = {
          x: nodeX, y: layerY,
          w: NODE_W, h: NODE_H, hash, role, virtual,
          layerName, layerIdx: li, nodeIdx: ni,
        };
        nodePositions.push(node);
        nodeMap[li][ni] = node;
      }
    }

    // ── 步驟 3：計算所有節點的 X 範圍
    let minX = Infinity, maxX = -Infinity;
    for (const node of nodePositions) {
      if (node.x < minX) minX = node.x;
      if (node.x + node.w > maxX) maxX = node.x + node.w;
    }
    const treeContentW = maxX - minX;

    // ── 步驟 4：整體平移，使 Root 落在畫布幾何正中央
    canvasW = LABEL_W + PADDING_X + treeContentW + PADDING_X;
    const rootNode = nodeMap[totalLayers - 1][0];
    const rootRelCenterX = rootNode ? rootNode.x + NODE_W / 2 : minX + treeContentW / 2;
    const extraShift = treeContentW / 2 - (rootRelCenterX - minX);
    for (const node of nodePositions) {
      node.x = (node.x - minX) + LABEL_W + PADDING_X + extraShift;
    }

    // ── 步驟 5：確保最左節點不超出 LABEL_W 邊界
    let actualMinX = Infinity;
    for (const node of nodePositions) {
      if (node.x < actualMinX) actualMinX = node.x;
    }
    if (actualMinX < LABEL_W + 4) {
      const fixShift = LABEL_W + 4 - actualMinX;
      for (const node of nodePositions) { node.x += fixShift; }
      canvasW += fixShift;
    }

    // ── 步驟 6：確保最右節點不超出畫布右側邊界
    let actualMaxX = -Infinity;
    for (const node of nodePositions) {
      if (node.x + node.w > actualMaxX) actualMaxX = node.x + node.w;
    }
    if (actualMaxX > canvasW - PADDING_X / 2) {
      canvasW = actualMaxX + PADDING_X;
    }
  }

  // ── 對焦到目標節點（將目標葉節點置中於視窗）──
  function focusTarget() {
    const target = nodePositions.find(n => n.role === 'target');
    if (!target) return;
    const wrapW = wrap.clientWidth;
    const wrapH = wrap.clientHeight;
    // 目標節點中心在畫布上的座標（縮放後）
    const targetCX = (target.x + target.w / 2) * scale;
    const targetCY = (target.y + target.h / 2) * scale;
    // 讓目標節點中心對齊容器中心
    canvasLeft = Math.round(wrapW / 2 - targetCX);
    canvasTop  = Math.round(wrapH / 2 - targetCY);
    canvas.style.left = canvasLeft + 'px';
    canvas.style.top  = canvasTop  + 'px';
  }

  function roundRect(ctx, x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h - r);
    ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    ctx.lineTo(x + r, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - r);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.closePath();
  }

  function draw() {
    const dpr = window.devicePixelRatio || 1;
    const displayW = Math.ceil(canvasW * scale);
    const displayH = Math.ceil(canvasH * scale);

    canvas.width  = displayW * dpr;
    canvas.height = displayH * dpr;
    canvas.style.width  = displayW + 'px';
    canvas.style.height = displayH + 'px';
    ctx.setTransform(dpr * scale, 0, 0, dpr * scale, 0, 0);

    ctx.clearRect(0, 0, canvasW, canvasH);

    const layers = treeData.layers;
    const totalLayers = layers.length;
    const colors = getThemeColors();

    // ── 繪製平滑 S 型連接線 ──
    for (let li = 0; li < totalLayers - 1; li++) {
      const childNodes  = nodePositions.filter(n => n.layerIdx === li);
      const parentNodes = nodePositions.filter(n => n.layerIdx === li + 1);

      for (let ci = 0; ci < childNodes.length; ci++) {
        const child  = childNodes[ci];
        const pi     = Math.floor(child.nodeIdx / 2);
        const parent = parentNodes.find(p => p.nodeIdx === pi);
        if (!child || !parent) continue;

        const onPath = isPathEdge(li, ci, li + 1, pi);
        const isVirtEdge = child.virtual || parent.virtual;

        const startX = child.x + child.w / 2;
        const startY = child.y;
        const endX   = parent.x + parent.w / 2;
        const endY   = parent.y + parent.h;
        const midY   = startY - (startY - endY) / 2;

        ctx.save();
        if (isVirtEdge) ctx.setLineDash([4, 3]);
        ctx.beginPath();
        ctx.moveTo(startX, startY);
        ctx.bezierCurveTo(startX, midY, endX, midY, endX, endY);
        ctx.strokeStyle = isVirtEdge ? colors.edgeNormal : (onPath ? colors.edgePath : colors.edgeNormal);
        ctx.lineWidth   = onPath && !isVirtEdge ? 4.0 : 1.2;
        ctx.globalAlpha = isVirtEdge ? 0.2 : (onPath ? 1.0 : 0.3);
        ctx.stroke();
        ctx.restore();
        ctx.globalAlpha = 1.0;
      }
    }

    // ── 繪製高亮重點節點 ──
    for (const node of nodePositions) {
      const { x, y, w, h } = node;

      if (node.virtual) {
        // 虛擬佔位節點：虛線邊框 + 灰底 + 斜體標籤
        const isDark = document.documentElement.classList.contains('dark');
        roundRect(ctx, x, y, w, h, RADIUS);
        ctx.fillStyle = isDark ? '#1a1a1a' : '#f9fafb';
        ctx.fill();
        roundRect(ctx, x, y, w, h, RADIUS);
        ctx.save();
        ctx.setLineDash([4, 3]);
        ctx.strokeStyle = isDark ? '#4b5563' : '#9ca3af';
        ctx.lineWidth = 1.5;
        ctx.stroke();
        ctx.restore();
        ctx.fillStyle = isDark ? '#6b7280' : '#9ca3af';
        ctx.font = 'italic 10px "Noto Sans", sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('虛擬佔位', x + w / 2, y + h / 2);
        continue;
      }

      const c = colors[node.role] || colors.normal;

      if (c.glow) {
        ctx.save();
        ctx.shadowColor = c.glow;
        ctx.shadowBlur  = 20;
        ctx.shadowOffsetX = 0;
        ctx.shadowOffsetY = 0;
        roundRect(ctx, x, y, w, h, RADIUS);
        ctx.fillStyle = c.bg;
        ctx.fill();
        ctx.restore();
      }

      roundRect(ctx, x, y, w, h, RADIUS);
      ctx.fillStyle = c.bg;
      ctx.fill();

      roundRect(ctx, x, y, w, h, RADIUS);
      ctx.strokeStyle = c.border;
      ctx.lineWidth   = node.role !== 'normal' ? 3.0 : 1.5;
      ctx.stroke();

      ctx.fillStyle  = c.text;
      ctx.font       = `${node.role === 'normal' ? 400 : 700} 11px 'Courier New', monospace`;
      ctx.textAlign  = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(shortHash(node.hash), x + w / 2, y + h / 2);
    }

    // ── 繪製層標籤 ──
    ctx.textAlign    = 'right';
    ctx.textBaseline = 'middle';
    ctx.font         = '11px "Noto Sans", sans-serif';
    ctx.fillStyle    = colors.layerText;

    const drawnLayers = new Set();
    for (const node of nodePositions) {
      if (!drawnLayers.has(node.layerIdx)) {
        drawnLayers.add(node.layerIdx);
        // 層標籤固定在 LABEL_W 區域右側，不受整體平移影響
        ctx.fillText(node.layerName, LABEL_W - 8, node.y + node.h / 2);
      }
    }
  }

  // ── 拖曳狀態（用 canvas position:absolute + left/top 實現，無捲軸）──
  let canvasLeft = 0, canvasTop = 0;

  // 避免縮放死循環，設立上下限（最小 0.15，最大 1.2）
  function changeZoom(delta) {
    scale = Math.max(0.15, Math.min(scale + delta, 1.2));
    document.getElementById('zoom-label').textContent = Math.round(scale * 100) + '%';
    draw();
    _centerCanvas();
  }

  function resetZoom() {
    scale = 1.0;
    document.getElementById('zoom-label').textContent = '100%';
    draw();
    _centerCanvas();
  }

  // 將 Canvas 用 left/top 定位到容器正中央（overflow:hidden 模式）
  function _centerCanvas() {
    const scaledW = canvasW * scale;
    const scaledH = canvasH * scale;
    const wrapW   = wrap.clientWidth;
    const wrapH   = wrap.clientHeight;
    canvasLeft = Math.round((wrapW - scaledW) / 2);
    canvasTop  = Math.round((wrapH - scaledH) / 2);
    canvas.style.left = canvasLeft + 'px';
    canvas.style.top  = canvasTop  + 'px';
  }

  // 最適化：計算最適比例，然後置中
  function fitTree() {
    const wrapW = wrap.clientWidth;
    const wrapH = wrap.clientHeight;
    const sx = wrapW / canvasW;
    const sy = wrapH / canvasH;
    scale = Math.max(0.15, Math.min(sx, sy, 1.2));
    document.getElementById('zoom-label').textContent = Math.round(scale * 100) + '%';
    draw();
    _centerCanvas();
  }

  // ── 滾輪縮放（以滑鼠位置為中心縮放）──
  wrap.addEventListener('wheel', e => {
    e.preventDefault();
    const rect    = wrap.getBoundingClientRect();
    // 滑鼠在容器內的位置
    const mouseX  = e.clientX - rect.left;
    const mouseY  = e.clientY - rect.top;
    // 滑鼠在畫布邏輯座標中的位置（縮放前）
    const logicX  = (mouseX - canvasLeft) / scale;
    const logicY  = (mouseY - canvasTop)  / scale;

    const delta   = e.deltaY < 0 ? 0.1 : -0.1;
    const oldScale = scale;
    scale = Math.max(0.15, Math.min(scale + delta, 1.2));

    if (scale === oldScale) return;
    document.getElementById('zoom-label').textContent = Math.round(scale * 100) + '%';
    draw();

    // 縮放後，讓滑鼠指向的邏輯座標保持在同一螢幕位置
    canvasLeft = Math.round(mouseX - logicX * scale);
    canvasTop  = Math.round(mouseY - logicY * scale);
    canvas.style.left = canvasLeft + 'px';
    canvas.style.top  = canvasTop  + 'px';
  }, { passive: false });

  let isDragging = false, dragStartX = 0, dragStartY = 0, canvasStartLeft = 0, canvasStartTop = 0;

  wrap.addEventListener('mousedown', e => {
    isDragging     = true;
    dragStartX     = e.clientX;
    dragStartY     = e.clientY;
    canvasStartLeft = canvasLeft;
    canvasStartTop  = canvasTop;
    wrap.style.cursor = 'grabbing';
    e.preventDefault();
  });
  window.addEventListener('mousemove', e => {
    if (!isDragging) return;
    canvasLeft = canvasStartLeft + (e.clientX - dragStartX);
    canvasTop  = canvasStartTop  + (e.clientY - dragStartY);
    canvas.style.left = canvasLeft + 'px';
    canvas.style.top  = canvasTop  + 'px';
  });
  window.addEventListener('mouseup', () => {
    isDragging = false;
    wrap.style.cursor = 'grab';
  });
  wrap.addEventListener('mouseleave', () => {
    if (isDragging) {
      isDragging = false;
      wrap.style.cursor = 'grab';
    }
  });

  let touchStartX = 0, touchStartY = 0, canvasTouchLeft = 0, canvasTouchTop = 0;
  wrap.addEventListener('touchstart', e => {
    touchStartX    = e.touches[0].clientX;
    touchStartY    = e.touches[0].clientY;
    canvasTouchLeft = canvasLeft;
    canvasTouchTop  = canvasTop;
  }, { passive: true });
  wrap.addEventListener('touchmove', e => {
    canvasLeft = canvasTouchLeft + (e.touches[0].clientX - touchStartX);
    canvasTop  = canvasTouchTop  + (e.touches[0].clientY - touchStartY);
    canvas.style.left = canvasLeft + 'px';
    canvas.style.top  = canvasTop  + 'px';
  }, { passive: true });

  canvas.addEventListener('click', e => {
    const rect  = canvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left) / scale;
    const my = (e.clientY - rect.top)  / scale;

    let hit = null;
    for (const node of nodePositions) {
      if (mx >= node.x && mx <= node.x + node.w &&
          my >= node.y && my <= node.y + node.h) {
        hit = node;
        break;
      }
    }

    if (hit) {
      const roleLabels = {
        target:  '目標葉節點（H_leaf = H(0x00 ‖ m_hex)）',
        sibling: 'Sibling 節點（H_leaf 或 H_node）',
        path:    'Proof 路徑節點（H_node = H(0x01 ‖ L ‖ R)）',
        root:    'Root_official（H_node）',
        normal:  '一般節點（Domain-Separated）',
      };
      if (hit.virtual) {
        document.getElementById('panel-title').textContent = '虛擬佔位節點';
        document.getElementById('panel-hash').textContent  = hit.hash;
        document.getElementById('panel-meta').textContent  =
          `層級：${hit.layerName}　索引：${hit.nodeIdx}\n此節點為奇數層上提（promote）時的視覺補齊佔位，並非實際樹節點`;
      } else {
        document.getElementById('panel-title').textContent = roleLabels[hit.role] || '節點';
        document.getElementById('panel-hash').textContent  = hit.hash;
        document.getElementById('panel-meta').textContent  =
          `層級：${hit.layerName}　索引：${hit.nodeIdx}`;
      }

      const px = Math.min(e.clientX + 16, window.innerWidth  - 440);
      const py = Math.min(e.clientY + 16, window.innerHeight - 120);
      panel.style.left    = px + 'px';
      panel.style.top     = py + 'px';
      panel.style.display = 'block';
    } else {
      panel.style.display = 'none';
    }
  });

  document.addEventListener('click', e => {
    if (!canvas.contains(e.target)) panel.style.display = 'none';
  });

  function init() {
    computeLayout();
    // 初始以 1:1 比例繪製，然後對焦到目標節點
    scale = 1.0;
    document.getElementById('zoom-label').textContent = '100%';
    draw();
    focusTarget();
  }

  // DOMContentLoaded 時初始化；若已載入完成則直接執行
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
  
  // 視窗寬度改變（旋轉手機、調整視窗）時重新對焦目標節點，維持目前縮放。
  // 只看寬度：手機捲動時網址列收合會觸發「只有高度改變」的 resize，
  // 以前每次都 fitTree()，使用者一捲動畫面就被縮到 15%、看不清楚。
  let _lastWrapW = wrap.clientWidth;
  window.addEventListener('resize', () => {
    if (wrap.clientWidth === _lastWrapW) return;
    _lastWrapW = wrap.clientWidth;
    focusTarget();
  });

  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
    if (!localStorage.getItem('theme')) {
      if (e.matches) document.documentElement.classList.add('dark');
      else document.documentElement.classList.remove('dark');
      draw();
    }
  });
  </script>
  {% endif %}
</body>
</html>"""

# ── 路由 ──────────────────────────────────────────────────

@app.route('/')
def dashboard():
    published_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'published'")
    published = published_row is not None and published_row['value'] == '1'

    merkle_root = None
    tally = {}
    votes = []
    valid_count = 0
    tallied_at = None

    if published:
        root_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'merkle_root'")
        merkle_root = root_row['value'] if root_row else ""
        tally_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'tally_json'")
        tally = json.loads(tally_row['value']) if tally_row else {}
        # v2.0 修正：不再選取 vote 欄位，公告板 dashboard 不應逐票展示投票
        # 內容與 m_hex 的對應（規格書 §19.5）。 <3
        # 首頁只列前 50 筆（票數上萬時整頁會非常大）；完整清單見 /api/results
        votes = db.fetchall("SELECT id, m_hex FROM published_votes ORDER BY id LIMIT 50")
        valid_count = db.count("published_votes")
        tallied_at_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'tallied_at'")
        tallied_at = int(tallied_at_row['value']) if tallied_at_row else None

    return render_template_string(
        _DASHBOARD_HTML,
        published=published,
        merkle_root=merkle_root,
        tally=tally,
        votes=votes,
        valid_count=valid_count,
        tallied_at=tallied_at,
    )


@app.route('/verify', methods=['GET'])
def verify_page():
    """
    選票驗證頁面（含視覺化 Merkle Tree）。
    回傳：驗證結果 + 完整 tree_data（供 JS 渲染互動式 Merkle Tree）。
    """
    m_hex = request.args.get('m_hex', '').strip()
    result = None
    tree_data = None

    if m_hex:
        result = _verify_m_hex(m_hex)
        if result.get('valid'):
            tree_data = _build_tree_data(m_hex)

    return render_template_string(
        _VERIFY_HTML,
        m_hex=m_hex,
        result=result,
        tree_data=tree_data,
        ca_cert_url=CA_CERT_URL_FOR_BROWSER,
        viz_max_leaves=VIZ_MAX_LEAVES,
    )


@app.route('/api/admin/reset', methods=['POST'])
def api_admin_reset():
    """
    [POST] 重置公告板狀態（新一輪前使用）。

    背景：admin_tool 的 /api/new_round 原本只重置 TA 與 CA，完全沒有
    清掉 BB 這裡的 published 旗標——/api/publish 一開始就檢查
    bb_state.published=='1'，是的話直接以 ALREADY_PUBLISHED 拒絕新結
    果，導致新一輪投票開票後，BB 永遠停留在上一輪的結果，直到有人手動
    進容器清空資料庫。這裡補上對應的重置端點，清空已公告狀態與選票清
    單，讓下一輪能重新接受公告。

    BB 本身不要求 mTLS 用戶端憑證（要接受一般瀏覽器公開連線），這裡改
    用 Admin Bearer Token 單獨保護這個端點，比照 CA 的 /api/admin/*
    端點模式。 <3
    """
    if not check_admin_token():
        return jsonify(admin_auth_error()), 401

    vote_count = db.count("published_votes")
    db.execute("DELETE FROM published_votes")
    db.execute("DELETE FROM bb_state")
    _invalidate_tree_cache()

    print(f"[BB] 公告板狀態已重置（清除 {vote_count} 筆已公告選票）。")
    return jsonify({"status": "success", "deleted_votes": vote_count}), 200


@app.route('/api/publish', methods=['POST'])
def api_publish():
    """
    [POST] 接收 CC 推送的計票結果（v2.0 Sprint 2：含簽章驗證）
    
    Body: {
        "result_bundle": {
            "root_official": str,
            "tally": dict,
            "valid_m_hex_list": [str],   # v2.0 修正：只給 m_hex 清單，不含 vote 對應 <3
            "merkle_leaf_count": int,
            "tallied_at": int
        },
        "signature": str (Base64),
        "cert_pem": str
    }
    
    驗證流程：
      1. 驗證 CC 憑證是否由 CA 簽發
      2. 驗證 CC 對 result_bundle 的 RSA-PSS 簽章
      3. 檢查是否已公告（防止覆蓋）
      4. 儲存結果
    """
    data = request.get_json()
    if not data or 'result_bundle' not in data or 'signature' not in data or 'cert_pem' not in data:
        return jsonify({
            "status": "error",
            "code": "MISSING_FIELDS",
            "message": "缺少必要欄位（需要 result_bundle, signature, cert_pem）"
        }), 400

    result_bundle = data['result_bundle']
    signature_b64 = data['signature']
    cert_pem = data['cert_pem']

    # 檢查是否已公告（防止覆蓋）
    published_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'published'")
    if published_row and published_row['value'] == '1':
        return jsonify({
            "status": "error",
            "code": "ALREADY_PUBLISHED",
            "message": "結果已公告，不可覆蓋"
        }), 403

    # 步驟 1：驗證 CC 憑證是否由 CA 簽發
    global _ca_cert_pem, _ca_cert
    if not _ca_cert:
        try:
            _ca_cert_pem = load_or_fetch_ca_cert(KEYS_DIR, CA_URL)
            _ca_cert = x509.load_pem_x509_certificate(_ca_cert_pem.encode('utf-8'))
            print("[BB] CA 憑證補載入成功")
        except Exception as ex:
            print(f"[BB] 補載入 CA 憑證失敗：{ex}")
    if not _ca_cert:
        return jsonify({
            "status": "error",
            "code": "CA_CERT_UNAVAILABLE",
            "message": "BB 無法取得 CA 憑證，無法驗證 CC 憑證"
        }), 500

    # v4.0 修正：改用共用的 verify_cert_chain_and_cn()（見
    # shared/key_manager.py）——原本這裡手刻的驗證只檢查簽章鏈與 Subject
    # CN，沒有檢查憑證有效期限，跟其他服務（ta_server 的 release_key、
    # cc_server 對 TA/TPA）的驗證強度不一致；改用共用函式後，順帶也補上
    # 了有效期限檢查，且往後這段邏輯只需要維護一份。 <3
    cc_cert = verify_cert_chain_and_cn(cert_pem, _ca_cert_pem, 'CC')
    if cc_cert is None:
        return jsonify({
            "status": "error",
            "code": "CERT_INVALID",
            "message": "CC 憑證驗證失敗：未由合法 CA 簽發、已過期，或 Subject CN 不是 CC",
        }), 403
    cc_public_key = cc_cert.public_key()
    print(f"[BB] CC 憑證驗證通過（Subject: {cc_cert.subject}）")

    # 步驟 2：驗證 CC 對 result_bundle 的 RSA-PSS 簽章
    try:
        # v2.0 修正：補上 separators=(',', ':') 做 canonical JSON（規格書
        # §18.6），須與 CC 端簽章時的序列化方式完全一致，否則驗章必定失敗。 <3
        bundle_json = json.dumps(result_bundle, sort_keys=True, ensure_ascii=False, separators=(',', ':'))  # <3
        bundle_bytes = bundle_json.encode('utf-8')
        signature = b64_to_bytes(signature_b64)
        
        if not verify_signature(bundle_bytes, signature, cc_public_key):
            return jsonify({
                "status": "error",
                "code": "SIGNATURE_INVALID",
                "message": "CC 簽章驗證失敗"
            }), 403
        
        print(f"[BB] CC 簽章驗證通過（簽章長度：{len(signature)} bytes）")
    except Exception as e:
        return jsonify({
            "status": "error",
            "code": "SIGNATURE_VERIFICATION_ERROR",
            "message": f"簽章驗證過程發生錯誤：{e}"
        }), 500

    # 步驟 3：解析並儲存結果
    # v2.0 修正：改讀 valid_m_hex_list（純 m_hex 清單），不再接受/儲存 vote
    # 與 m_hex 的一一對應，避免任何人從公告資料反推「哪個葉節點是哪一票」。 <3
    root_official      = result_bundle['root_official']
    tally              = result_bundle['tally']
    m_hex_list         = result_bundle.get('valid_m_hex_list', [])
    merkle_leaf_count  = result_bundle.get('merkle_leaf_count')
    tallied_at         = result_bundle.get('tallied_at', int(time.time()))

    # v2.0 修正：新增結構一致性檢查（規格書 §18.5.1 BUNDLE_INCONSISTENT）。
    # 只驗證簽章代表「CC 確實簽了這包資料」，並不代表資料本身內部自洽；
    # 這裡額外核對 merkle_leaf_count 與 m_hex 清單長度、tally 加總是否一致，
    # 防止 CC 端邏輯錯誤或惡意建構出自相矛盾的結果包被 BB 照單全收。 <3
    tally_sum = sum(tally.values()) if isinstance(tally, dict) else -1
    if merkle_leaf_count != len(m_hex_list) or tally_sum != len(m_hex_list):
        return jsonify({
            "status": "error",
            "code": "BUNDLE_INCONSISTENT",
            "message": (
                f"結果包內部不一致：merkle_leaf_count={merkle_leaf_count}, "
                f"len(valid_m_hex_list)={len(m_hex_list)}, sum(tally)={tally_sum}"
            ),
        }), 403  # <3

    # 清空舊資料
    db.execute("DELETE FROM published_votes")

    # 儲存合法選票的 m_hex（含葉節點雜湊），依 CC 送來的洗牌後順序原樣寫入
    for m_hex in m_hex_list:
        leaf_hash = sha256_hex(m_hex.encode('utf-8'))
        db.execute(
            "INSERT INTO published_votes (m_hex, leaf_hash) VALUES (?, ?)",
            (m_hex, leaf_hash),
        )

    # 儲存狀態
    # v2.0 修正：補存 cc_cert_pem，讓選民端 Phase 6 Step 6.2a 可以獨立驗證
    # 「簽章公鑰本身是否合法」，而不是單方面信任 BB 的驗證結果（規格書
    # §6.3 Step 6.1、§18.5.2；先前 BB 只存 cc_signature，沒存 cc_cert_pem）。 <3
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('published', '1')")
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('merkle_root', ?)", (root_official,))
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('tally_json', ?)", (json.dumps(tally),))
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('tallied_at', ?)", (str(tallied_at),))
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('cc_signature', ?)", (signature_b64,))
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('cc_cert_pem', ?)", (cert_pem,))  # <3
    # 原封不動保存 CC 簽章的那串 canonical JSON。以前只存了結果包裡的部分
    # 欄位（少了 deadline、cc_id），任何人都無法重組出被簽章的原文，公開的
    # cc_signature 等於沒人驗得了。瀏覽器直接對這串原文驗章，也不用擔心
    # JS 與 Python 的 JSON 序列化細節（中文、欄位排序）不一致。
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('signed_bundle', ?)", (bundle_json,))
    _invalidate_tree_cache()

    # 日誌使用人類可讀格式
    print(f"[BB] ✅ 結果已驗證並公告（Unix ts：{tallied_at}  →  {ts_to_human(tallied_at)}）")
    print(f"[BB] Root_official = {root_official[:20]}...")
    print(f"[BB] 合法選票數：{len(m_hex_list)}")  # <3
    
    return jsonify({
        "status": "success",
        "message": "結果已驗證並公告",
        "verified": True,
        "tallied_at": tallied_at
    }), 200


@app.route('/api/results', methods=['GET'])
def api_results():
    """[GET] 回傳計票結果與 Merkle Root（Unix timestamp）"""
    published_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'published'")
    if not published_row or published_row['value'] != '1':
        return jsonify({"status": "pending", "message": "尚未公告"}), 200

    root_row      = db.fetchone("SELECT value FROM bb_state WHERE key = 'merkle_root'")
    tally_row     = db.fetchone("SELECT value FROM bb_state WHERE key = 'tally_json'")
    tallied_at_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'tallied_at'")
    sig_row       = db.fetchone("SELECT value FROM bb_state WHERE key = 'cc_signature'")
    cc_cert_row   = db.fetchone("SELECT value FROM bb_state WHERE key = 'cc_cert_pem'")  # <3
    # v2.0 修正：只回傳 m_hex 清單，不再回傳 vote 與 m_hex 的一一對應
    # （規格書 §19.5，避免公開的結果反推出每一張選票對應誰投的內容）。 <3
    votes         = db.fetchall("SELECT m_hex FROM published_votes ORDER BY id")
    m_hex_list    = [v['m_hex'] for v in votes]  # <3
    tallied_at    = int(tallied_at_row['value']) if tallied_at_row else None

    return jsonify({
        "status":            "success",
        "merkle_root":       root_row['value'] if root_row else "",
        "tally":             json.loads(tally_row['value']) if tally_row else {},
        "valid_m_hex_list":  m_hex_list,  # <3 之前是 valid_votes（含 vote），現在只給 m_hex
        "merkle_leaf_count": len(m_hex_list),  # <3
        "cc_signature":      sig_row['value'] if sig_row else "",
        "cc_cert_pem":       cc_cert_row['value'] if cc_cert_row else "",  # <3 讓選民端可獨立驗證簽章公鑰身分鏈
        "tallied_at":        tallied_at,
        "tallied_at_str": ts_to_human(tallied_at) if tallied_at else None,
    }), 200


@app.route('/api/signed_bundle', methods=['GET'])
def api_signed_bundle():
    """[GET] 回傳 CC 簽章的結果包原文、簽章與 CC 憑證，供任何人獨立驗章。

    驗證方式：用 CA 根憑證驗證 cc_cert_pem（CN 必須是 CC），再用其公鑰以
    RSA-PSS（SHA-256、MGF1-SHA-256、salt 長度 = PSS.MAX_LENGTH）驗證
    signature 是否為 signed_bundle 這串 UTF-8 原文的簽章。
    """
    row = db.fetchone("SELECT value FROM bb_state WHERE key = 'signed_bundle'")
    if not row:
        return jsonify({"status": "error", "message": "尚未公告，或這次公告沒有保存簽章原文"}), 404
    sig_row  = db.fetchone("SELECT value FROM bb_state WHERE key = 'cc_signature'")
    cert_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'cc_cert_pem'")
    return jsonify({
        "status":        "success",
        "signed_bundle": row['value'],
        "signature":     sig_row['value'] if sig_row else "",
        "cc_cert_pem":   cert_row['value'] if cert_row else "",
    }), 200


@app.route('/api/merkle_proof/<path:m_hex>', methods=['GET'])
def api_merkle_proof(m_hex: str):
    """
    [GET] 提供指定 m_hex 的 Merkle Proof。
    規範：驗證起點為 H(m)，不使用選票明文。
    """
    result = _verify_m_hex(m_hex)
    if result['valid']:
        return jsonify({
            "status":        "success",
            "m_hex":         m_hex,
            "leaf_hash":     result['leaf_hash'],
            "merkle_proof":  result['proof'],
            "root_official": result['root'],
            # 零信任加密資料
            "sibling_array": [step['sibling'] for step in result['proof']],
        }), 200
    else:
        return jsonify({"status": "error", "message": result['message']}), 404


# ── Config Hot-Reload 端點 ────────────────────────────────────
make_reload_endpoint(app)


# ============================================================
# 內部函式
# ============================================================

# ── Merkle Tree 快取 ─────────────────────────────────────────
# 以前每次驗證都從資料庫讀出全部 m_hex、重建整棵樹，再用 list.index() 逐一
# 找位置；公告後大家同時來驗證時，每個請求都要重做一次。公告內容在下次
# 公告或重置前不會變，改成第一次查詢時建好樹與「m_hex → 位置」對照表，
# 以官方 root 當快取鍵，之後直接查表。只有重建出的 root 等於官方 root 時
# 才會放進快取。
VIZ_MAX_LEAVES = 256
_tree_cache = {"root": None, "tree": None, "index_of": None}
_tree_cache_lock = threading.Lock()


def _invalidate_tree_cache():
    with _tree_cache_lock:
        _tree_cache.update(root=None, tree=None, index_of=None)


def _get_tree(official_root: str):
    """回傳 (MerkleTree, {m_hex: index})；資料重建出的 root 與官方 root 不符時回傳 (None, {})。"""
    with _tree_cache_lock:
        if _tree_cache["root"] == official_root and _tree_cache["tree"] is not None:
            return _tree_cache["tree"], _tree_cache["index_of"]
        votes = db.fetchall("SELECT m_hex FROM published_votes ORDER BY id")
        m_hex_list = [v['m_hex'] for v in votes]
        tree = MerkleTree(m_hex_list)
        if tree.get_root() != official_root:
            return None, {}
        index_of = {m: i for i, m in enumerate(m_hex_list)}
        _tree_cache.update(root=official_root, tree=tree, index_of=index_of)
        return tree, index_of


def _verify_m_hex(m_hex: str) -> dict:
    """驗證 m_hex 是否在 Merkle Tree 中，回傳驗證結果 dict"""
    published_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'published'")
    if not published_row or published_row['value'] != '1':
        return {"valid": False, "message": "結果尚未公告"}

    # v4.0 修正：原本這裡完全沒有讀取 CC 當初簽章公告、寫進 bb_state 的
    # 官方 root，而是每次都從目前的 published_votes 現場重建一棵樹、拿
    # 「剛算出來的 root」去驗證 proof——proof 跟 root 出自同一份即時資料，
    # 邏輯上必然自洽，等於這個檢查對「published_votes 事後被竄改」完全
    # 無感（現場重算的 root 會跟著竄改後的資料一起變，永遠驗證得過）。
    # 前端 /verify 頁面「不信任伺服器」的獨立驗證，用的也是這裡回傳的
    # root，同樣會被連帶騙過。修法：一定要跟 bb_state 裡儲存的官方 root
    # 比對，不符就直接判定資料完整性異常，不能只驗證「proof 對不對得上
    # 現場重算的 root」。 <3
    root_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'merkle_root'")
    official_root = root_row['value'] if root_row else None
    if not official_root:
        return {"valid": False, "message": "找不到官方公告的 Merkle Root"}

    tree, index_of = _get_tree(official_root)
    if tree is None:  # <3 現有選票資料重建出的 root 與官方 root 不符
        return {
            "valid": False,
            "message": "資料完整性異常：現有選票資料與官方公告之 Merkle Root 不符，公告板資料可能遭竄改",
        }

    index = index_of.get(m_hex)
    if index is None:
        return {"valid": False, "message": "找不到此 m_hex，可能選票無效或尚未計入"}
    proof = tree.get_proof(index)

    # 驗證 Merkle Proof（用官方 root，不是現場重算出來的 root）
    is_valid = MerkleTree.verify_proof(m_hex, proof, official_root)  # <3

    if is_valid:
        return {
            "valid":     True,
            "m_hex":     m_hex,
            "leaf_hash": h_leaf(m_hex),
            "proof":     proof,
            "root":      official_root,  # <3
            "index":     index,
            "leaf_count": len(index_of),
        }
    else:
        return {"valid": False, "message": "Merkle Proof 驗證失敗"}


def _build_tree_data(m_hex: str) -> dict:
    """
    建構供前端 JS 渲染的 Merkle Tree 資料結構。
    包含：
      - layers: 每層節點雜湊列表（從葉到根）
      - target_index: 目標葉節點索引
      - proof_path: 每個節點的角色（target/sibling/path/normal）
      - root: Root_official
    """
    root_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'merkle_root'")
    tree, index_of = _get_tree(root_row['value']) if root_row else (None, {})
    # 樹狀圖會把整棵樹的每個節點都送到瀏覽器繪製，票數多時頁面過大、瀏覽器
    # 畫不動，只在票數不多時提供。
    if tree is None or m_hex not in index_of or len(index_of) > VIZ_MAX_LEAVES:
        return None

    index = index_of[m_hex]
    proof = tree.get_proof(index)
    root  = tree.get_root()

    # 建構 proof_path：標記每層每個節點的角色
    #
    # v3.0 修正：原本用 `enumerate(proof)` 假設 proof 陣列第 i 筆就是第 i
    # 層——但 MerkleTree.get_proof() 遇到奇數層、目標節點沒有兄弟被直接
    # 上提時，那一層完全不會產生 proof 項目（見 shared/merkle_tree.py
    # get_proof()），使 proof 陣列長度可能小於實際走過的層數。任何一次
    # 上提發生後，後面所有 proof 項目對應到的真實層數都會被少算一層，
    # 導致視覺化樹狀圖標錯顏色（雖然不影響 MerkleTree.verify_proof 本身
    # 的密碼學正確性，但畫面上高亮的節點是錯的）。
    # 改成完全比照 get_proof() 內部走訪邏輯，自己重新逐層判斷「這一層
    # 目標節點有沒有兄弟」，只有真的有兄弟時才消耗 proof 陣列裡的下一筆、
    # 才畫 sibling；上提的那一層不畫 sibling，但 path 節點仍正確標在
    # 它實際落腳的那一層。 <3
    proof_path = []
    current_index = index

    # 葉節點層（layer 0）：目標節點
    proof_path.append({"layer": 0, "index": current_index, "role": "target"})

    proof_i = 0  # <3 指向 proof 陣列的游標，只有真的有兄弟節點時才前進
    for layer_idx, layer in enumerate(tree.tree[:-1]):  # <3 比照 get_proof()，排除 root 層
        has_sibling = (
            (current_index % 2 == 0 and current_index + 1 < len(layer)) or
            (current_index % 2 == 1)
        )  # <3
        if has_sibling:
            step = proof[proof_i]
            proof_i += 1  # <3
            sibling_index = current_index + 1 if step['position'] == 'right' else current_index - 1
            proof_path.append({"layer": layer_idx, "index": sibling_index, "role": "sibling"})
        # else：此節點在這一層被上提，沒有兄弟，不產生 sibling 標記 <3

        # 下一層的路徑節點（不論是否上提，目標的軌跡都會出現在這裡）
        next_index = current_index // 2
        proof_path.append({"layer": layer_idx + 1, "index": next_index, "role": "path"})
        current_index = next_index

    # Root 節點（最後一層）
    last_layer_idx = len(tree.tree) - 1
    proof_path.append({"layer": last_layer_idx, "index": 0, "role": "root"})

    # 建構 layers（每層節點的雜湊值，補齊奇數層）
    # 同時記錄哪些節點是虛擬佔位（promote 後補齊的視覺用節點）
    layers = []
    virtual_nodes = []
    for layer_idx, layer in enumerate(tree.tree):
        # 若奇數個節點，補齊最後一個供視覺對稱用（虛擬佔位）
        if len(layer) % 2 == 1 and len(layer) > 1:
            layers.append(layer + [layer[-1]])
            virtual_nodes.append({"layer": layer_idx, "index": len(layer)})
        else:
            layers.append(list(layer))

    return {
        "layers":        layers,
        "target_index":  index,
        "proof_path":    proof_path,
        "root":          root,
        "m_hex":         m_hex,
        "leaf_hash":     h_leaf(m_hex),
        "virtual_nodes": virtual_nodes,
    }


if __name__ == '__main__':
    # v4.0 新增：BB 的監聽埠除了 CC 推送結果，還要接受一般瀏覽器（經
    # Caddy）的公開連線——瀏覽器不會持有這套內部 PKI 的用戶端憑證，
    # 所以刻意不要求 CERT_REQUIRED（require_client_cert=False），對
    # CC 身分的驗證繼續由既有的應用層簽章＋Subject CN 核對負責，見
    # shared/tls_utils.py 的說明。
    _ca_cert_path = os.path.join(KEYS_DIR, "ca_cert.pem")
    _ssl_ctx = build_mtls_server_context(
        _tls_cert_path, _tls_key_path, _ca_cert_path, require_client_cert=False,
    )
    app.run(host='0.0.0.0', port=5004, debug=False, ssl_context=_ssl_ctx)
