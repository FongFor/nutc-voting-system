"""
cc_server/app.py  —  計票中心 (CC)

負責收集選票和開票。選民投票時會把加密的數位信封送到這裡，
CC 先用自己的私鑰解開信封取得對稱金鑰，但還不能看到選票內容，
要等截止後向 TA 拿到 SK_TA 才能解密驗證每張選票。

開票完成後會建立 Merkle Tree，把結果推送到公告板（BB），
選民可以用自己的 m_hex 去 BB 驗證選票有沒有被計入。

端點：
  GET  /                        儀表板（信封收集狀況、開票結果）
  GET  /api/public_key          回傳 CC 公鑰
  POST /api/receive_envelope    接收數位信封（截止後拒絕）
  POST /api/tally               觸發開票流程
  GET  /api/results             查詢計票結果
  GET  /api/config              查看目前設定
  POST /api/config/reload       重新載入 config.json
"""

import os
import sys
import time
import json
import secrets
import hashlib
import datetime
import threading
import sqlite3  # <3 新增：用於捕捉 token_hash UNIQUE 約束衝突，做原子化去重

# 確保 shared/ 可被 import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string, redirect
import requests as http_requests

from shared.key_manager import (
    load_or_generate_keypair,
    load_or_request_certificate,
    load_or_fetch_ca_cert,
    verify_cert_chain_and_cn,  # <3 v4.0：共用的「驗憑證鏈 + 核對 CN」函式
)
from shared.tls_utils import load_or_request_tls_certificate, build_mtls_server_context, mtls_client_kwargs  # <3 v4.0：mTLS
from shared.crypto_utils import open_envelope_layer1, open_envelope_layer2, sign_data
from shared.merkle_tree import MerkleTree
from shared.format_utils import int_to_hex, ts_to_human, bytes_to_b64
from shared.db_utils import Database
from shared.ui_style import UI_HEAD, THEME_TOGGLE
from shared.config_loader import make_reload_endpoint, get_service_registration_token
from shared.admin_auth import is_internal_ip, check_admin_token, admin_auth_error  # <3 /api/tally 存取控制
# v2.0 修正：release_key 改用專用格式簽章（見 _do_tally），不再需要 create_auth_packet <3
from cryptography.hazmat.primitives import serialization

# ============================================================
# 常數設定
# ============================================================
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR    = os.path.join(SERVICE_DIR, "keys")
# <3 v4.0：資料庫獨立放進 data/ 子目錄，才能掛載成持久化 volume——
# 原本直接放在 SERVICE_DIR 底下，跟隨容器可寫層一起被重建時清空，
# envelopes/valid_votes（已送達尚未開票的選票）沒了會直接遺失選票，
# 任何一次重新部署都可能連帶造成這個後果。
DATA_DIR    = os.path.join(SERVICE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH     = os.path.join(DATA_DIR, "cc.db")
CC_ID       = "CC"
CC_HOSTNAME = os.environ.get("CC_HOSTNAME", "cc")  # <3 v4.0：填入 TLS 憑證的 SAN
CA_URL      = os.environ.get("CA_URL",  "https://localhost:5001")
TA_URL      = os.environ.get("TA_URL",  "https://localhost:5002")
BB_URL      = os.environ.get("BB_URL",  "https://localhost:5004")
TPA_URL     = os.environ.get("TPA_URL", "https://localhost:5000")

# 截止時間與選舉狀態快取（每次請求時向 TA 重新查詢）
_DEADLINE: int = int(os.environ.get("VOTE_DEADLINE", "0"))
_ELECTION_STATE: str = 'standby'  # 安全預設值：啟動前凍結所有投票業務

def _get_deadline() -> int:
    """
    取得投票截止時間（Unix timestamp）。
    優先順序：環境變數 VOTE_DEADLINE > TA /api/deadline > 0（不限制）
    """
    global _DEADLINE
    if _DEADLINE > 0:
        return _DEADLINE
    try:
        resp = http_requests.get(f"{TA_URL}/api/deadline", timeout=5, **_CC_MTLS)
        data = resp.json()
        if data.get("status") == "success":
            _DEADLINE = int(data["deadline"])
            print(f"[CC] 從 TA 取得截止時間：{_DEADLINE}  →  {data.get('deadline_str', '')}")
            return _DEADLINE
    except Exception as e:
        print(f"[CC] 無法從 TA 取得截止時間（{e}），截止時間強制執行暫停。")
    return 0

# ============================================================
# 資料庫初始化
# ============================================================
db = Database(DB_PATH)
db.execute("""
    CREATE TABLE IF NOT EXISTS envelopes (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        c_data      TEXT NOT NULL,
        iv          TEXT NOT NULL,
        k           TEXT NOT NULL,
        received_at INTEGER NOT NULL,
        status      TEXT NOT NULL DEFAULT 'pending'
    )
""")
db.execute("""
    CREATE TABLE IF NOT EXISTS valid_votes (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        vote        TEXT NOT NULL,
        m_hex       TEXT NOT NULL UNIQUE,
        leaf_hash   TEXT,
        shuffle_seq INTEGER,
        verified_at INTEGER NOT NULL
    )
""")
# m_hex 需要唯一索引才能擋重複選票（見 _do_tally 的 IntegrityError 處理）；
# 對於在此欄位改動前就已建立的舊資料庫，用獨立的 CREATE UNIQUE INDEX 補上。 <3
try:
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_valid_votes_m_hex ON valid_votes (m_hex)")
except Exception:
    pass  # <3 舊資料庫內已有重複 m_hex 資料時，索引建立會失敗，此為已知遷移限制
db.execute("""
    CREATE TABLE IF NOT EXISTS tally_state (
        key         TEXT PRIMARY KEY,
        value       TEXT NOT NULL
    )
""")
# CC 是單一程序，啟動時殘留的 'running' 一定是上次開票中途當掉留下的，
# 不清掉的話之後的開票請求會永遠被判定為「進行中」。
db.execute("DELETE FROM tally_state WHERE key IN ('running', 'progress')")
db.execute("""
    CREATE TABLE IF NOT EXISTS used_token_hashes (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        token_hash  TEXT UNIQUE NOT NULL,
        recorded_at INTEGER NOT NULL
    )
""")
# 為舊有 envelopes / valid_votes 表新增 v2.0 欄位（若不存在） <3
for _col_sql in [
    "ALTER TABLE envelopes ADD COLUMN tag        TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE envelopes ADD COLUMN aad        TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE envelopes ADD COLUMN token_hash TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE valid_votes ADD COLUMN shuffle_seq INTEGER",  # <3
]:
    try:
        db.execute(_col_sql)
    except Exception:
        pass  # 欄位已存在

# ============================================================
# 金鑰初始化（啟動時執行）
# ============================================================
print(f"[CC] 初始化金鑰...")
(
    _private_key, _public_key, _e, _n, _d,
    _private_key_pem, _public_key_pem
) = load_or_generate_keypair(KEYS_DIR)

try:
    _ca_cert_pem = load_or_fetch_ca_cert(KEYS_DIR, CA_URL)
except Exception as ex:
    print(f"[CC] 警告：無法取得 CA 憑證（{ex}）")
    _ca_cert_pem = None

try:
    # v2.0 修正：附上一次性 SERVICE_REGISTRATION_TOKEN，避免任何人單靠
    # entity_id 字串就能向 CA 換發合法服務憑證。 <3
    _cert_pem = load_or_request_certificate(
        KEYS_DIR, CC_ID, _public_key_pem, CA_URL,
        registration_token=get_service_registration_token(),
    )  # <3
except Exception as ex:
    print(f"[CC] 警告：無法取得憑證（{ex}）")
    _cert_pem = ""

# v4.0 新增：另外申請一把獨立的 TLS 專用憑證，跟上面的應用層身分憑證
# 完全分開，供本服務的 HTTPS 監聽埠與對外呼叫（CA/TA/BB/TPA）使用。
try:
    _tls_cert_path, _tls_key_path = load_or_request_tls_certificate(
        KEYS_DIR, CC_ID, CC_HOSTNAME, CA_URL,
        registration_token=get_service_registration_token(),
    )
except Exception as ex:
    print(f"[CC] 警告：無法取得 TLS 憑證（{ex}）")
    _tls_cert_path = _tls_key_path = None

# 供本檔案所有對外呼叫共用的 mTLS 參數（cert= 我方憑證、verify= CA 根
# 憑證），直接以 **_CC_MTLS 展開進 http_requests.get/post(...)。
_CC_MTLS = mtls_client_kwargs(_tls_cert_path, _tls_key_path, os.path.join(KEYS_DIR, "ca_cert.pem"))

print(f"[CC] 初始化完成。")

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


# ── Deadline Middleware ────────────────────────────────────────
def _check_deadline():
    """
    選舉狀態 + 截止時間強制執行 Middleware。
    每次都向 TA 重新查詢，避免多 worker 或重啟後快取失效的問題。
    回傳 None 表示允許繼續；回傳 Response 表示應立即拒絕。
    """
    global _DEADLINE, _ELECTION_STATE
    election_state = _ELECTION_STATE
    deadline = _DEADLINE
    try:
        resp = http_requests.get(f"{TA_URL}/api/deadline", timeout=5, **_CC_MTLS)
        data = resp.json()
        if data.get("status") == "success":
            election_state = data.get("election_state", "standby")
            deadline = int(data["deadline"])
            _DEADLINE = deadline
            _ELECTION_STATE = election_state
    except Exception:
        pass  # 若 TA 不可達，回退到快取值

    if election_state == 'standby':
        return jsonify({
            "status":  "error",
            "code":    "ELECTION_NOT_STARTED",
            "message": "選舉尚未啟動，所有投票業務目前凍結中",
        }), 403

    if deadline <= 0:
        return None

    now = int(time.time())
    if now > deadline:
        remaining_over = now - deadline
        print(f"[CC] Deadline Middleware 拒絕請求：已超時 {remaining_over} 秒（Unix ts：{now} > {deadline}）")
        return jsonify({
            "status":       "error",
            "code":         "DEADLINE_EXCEEDED",
            "message":      f"投票已截止，無法接收新選票（已超時 {remaining_over} 秒）",
            "server_time":  now,
            "deadline":     deadline,
            "server_time_str": ts_to_human(now),
            "deadline_str":    ts_to_human(deadline),
        }), 403
    return None


# ── HTML 模板 ──────────────────────────────────────────────
_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <title>計票中心｜NUTC 線上投票</title>""" + UI_HEAD + """
  <meta http-equiv="refresh" content="15">
</head>
<body>
<header class="topbar">
  <div class="container-wide topbar-inner">
    <a class="brand" href="/">
      <span class="brand-name">NUTC 線上投票</span>
      <span class="brand-sub">計票中心（CC）</span>
    </a>
    <div class="topbar-actions">
      {% if election_state == 'standby' %}<span class="badge badge-warn">等待啟動選舉</span>
      {% elif deadline_ts and is_expired %}<span class="badge badge-err">投票已截止</span>
      {% elif deadline_ts %}<span class="badge badge-ok">截止 {{ deadline_str }}</span>
      {% else %}<span class="badge badge-ok">運作中</span>{% endif %}
      """ + THEME_TOGGLE + """
    </div>
  </div>
</header>

<main>
  <div class="container-wide stack-lg">
    <div class="stack-sm">
      <h1>計票中心（CC）</h1>
      <p class="lead">接收加密選票，截止後向時間授權中心取得私鑰開票，並簽章公告結果。</p>
    </div>

    <div class="grid grid-4">
      <div class="stat"><div class="stat-label">收到信封</div><div class="stat-value">{{ envelope_count }}</div></div>
      <div class="stat"><div class="stat-label">合法選票</div><div class="stat-value">{{ valid_count }}</div></div>
      <div class="stat"><div class="stat-label">開票狀態</div>
        <div class="stat-value" style="font-size:1.15rem">{% if tally_done %}<span class="text-ok">已完成</span>{% else %}<span class="muted">待開票</span>{% endif %}</div>
      </div>
      <div class="stat"><div class="stat-label">Merkle Root</div>
        <div class="stat-value mono" style="font-size:0.95rem">{% if merkle_root %}{{ merkle_root[:20] }}…{% else %}<span class="muted">尚未產生</span>{% endif %}</div>
      </div>
    </div>

    {% if not tally_done %}
    <form method="POST" action="/ui/tally">
      <button type="submit" class="btn btn-primary">開票（向 TA 請求開票私鑰）</button>
    </form>
    {% endif %}

    {% if tally_done and tally_results %}
    <section class="card stack" aria-labelledby="tallyTitle">
      <h2 id="tallyTitle" class="section-title">計票結果</h2>
      {% for candidate, count in tally_results | dictsort(by='value', reverse=true) %}
      {% set pct = (count / valid_count * 100) if valid_count > 0 else 0 %}
      <div class="stack-sm">
        <div class="row-between"><span class="strong">{{ candidate }}</span><span><span class="strong">{{ count }}</span> 票 <span class="small muted">{{ "%.1f"|format(pct) }}%</span></span></div>
        <div class="bar"><span style="width: {{ pct }}%"></span></div>
      </div>
      {% endfor %}
      {% if merkle_root %}
      <div class="stack-sm"><p class="small muted">官方 Merkle Root</p><code class="hash">{{ merkle_root }}</code></div>
      {% endif %}
    </section>
    {% endif %}

    <section class="card stack" aria-labelledby="statTitle">
      <h2 id="statTitle" class="section-title">選票驗證統計</h2>
      {# 刻意不逐張列出「候選人 + m_hex」：m_hex 印在選民的投票回執上，列出對應
         關係等於讓看得到這頁、又知道某人 m_hex 的人查出他投給誰；按收件順序
         排列也會抵銷批次打亂與洗牌的效果。各候選人得票數見上方計票結果。 #}
      <div class="grid grid-4">
        {% for key, label in [('verified', '合法'), ('invalid', '無效'), ('m_duplicate', '重複'), ('pending', '待開票')] %}
        <div class="stat"><div class="stat-label">{{ label }}</div><div class="stat-value">{{ envelope_status_counts.get(key, 0) }}</div></div>
        {% endfor %}
      </div>
    </section>

    <section class="card card-flush" aria-labelledby="envTitle">
      <div class="card-head">
        <h2 id="envTitle" class="section-title">最近收到的加密信封</h2>
        <span class="small muted">共 {{ envelope_count }} 封{% if envelope_count > envelopes|length %}，顯示最新 {{ envelopes|length }} 封{% endif %}・每 15 秒自動更新</span>
      </div>
      {% if envelopes %}
      <div class="table-wrap">
        <table class="table table-stack">
          <thead><tr><th class="num">#</th><th>密文（前 20 字元）</th><th>狀態</th><th>收到時間</th></tr></thead>
          <tbody>
            {% for e in envelopes %}
            <tr>
              <td class="num muted hide-sm" data-label="#">{{ loop.index }}</td>
              <td class="mono small" data-label="密文">{{ e.c_data[:20] }}…</td>
              <td data-label="狀態">
                {% if e.status == 'verified' %}<span class="badge badge-ok">已驗證</span>
                {% elif e.status == 'invalid' %}<span class="badge badge-err">無效</span>
                {% elif e.status == 'm_duplicate' %}<span class="badge badge-err">重複</span>
                {% else %}<span class="badge">待驗證</span>{% endif %}
              </td>
              <td class="small muted nowrap" data-label="收到時間">{{ e.received_at | ts_to_str }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% else %}
      <div class="card-body muted">尚未收到任何加密信封。</div>
      {% endif %}
    </section>
  </div>
</main>
</body>
</html>"""
# ── 路由 ──────────────────────────────────────────────────

@app.route('/')
def dashboard():
    envelopes  = db.fetchall("SELECT id, c_data, status, received_at FROM envelopes ORDER BY id DESC LIMIT 50")  # 首頁只列最新 50 封
    envelope_status_counts = {
        r['status']: r['n'] for r in db.fetchall("SELECT status, COUNT(*) AS n FROM envelopes GROUP BY status")
    }
    envelope_count = db.count("envelopes")
    valid_count    = db.count("valid_votes")

    # 讀取開票狀態
    tally_row    = db.fetchone("SELECT value FROM tally_state WHERE key = 'done'")
    tally_done   = tally_row is not None and tally_row['value'] == '1'
    root_row     = db.fetchone("SELECT value FROM tally_state WHERE key = 'merkle_root'")
    merkle_root  = root_row['value'] if root_row else None
    tally_json_row = db.fetchone("SELECT value FROM tally_state WHERE key = 'tally_json'")
    tally_results  = json.loads(tally_json_row['value']) if tally_json_row else {}

    deadline = _get_deadline()
    now = int(time.time())
    is_expired = deadline > 0 and now > deadline
    deadline_str_local = (
        ts_to_human(deadline)
        if deadline > 0 else None
    )
    # 查詢選舉狀態（供 UI 顯示）
    election_state = _ELECTION_STATE
    try:
        resp = http_requests.get(f"{TA_URL}/api/deadline", timeout=3, **_CC_MTLS)
        data = resp.json()
        if data.get("status") == "success":
            election_state = data.get("election_state", "standby")
    except Exception:
        pass

    return render_template_string(
        _DASHBOARD_HTML,
        envelopes=envelopes,
        envelope_status_counts=envelope_status_counts,
        envelope_count=envelope_count,
        valid_count=valid_count,
        tally_done=tally_done,
        merkle_root=merkle_root,
        tally_results=tally_results,
        deadline_ts=deadline if deadline > 0 else None,
        deadline_str=deadline_str_local,
        is_expired=is_expired,
        election_state=election_state,
    )


@app.route('/ui/tally', methods=['POST'])
def ui_tally():
    """
    Web UI 觸發開票按鈕。
    v2.0 修正：補上內部 IP 白名單檢查（規格書 §18.4.4），瀏覽器表單提交
    無法附加 Bearer Token，因此僅套用 IP 白名單這一層。 <3
    """
    if not is_internal_ip(request.remote_addr):
        return jsonify(admin_auth_error()), 403  # <3
    if _get_state('done') != '1' and _claim_tally():
        db.execute("DELETE FROM tally_state WHERE key IN ('last_result', 'progress')")
        threading.Thread(target=_tally_job, daemon=True).start()
    return redirect('/')


@app.route('/api/public_key', methods=['GET'])
def api_public_key():
    """[GET] 回傳 CC 公鑰 PEM 與憑證。
    v3.0 修正：補上 cert_pem，讓呼叫端（選民）能對這把公鑰做憑證鏈驗證，
    不再只能盲目信任裸公鑰。 <3
    """
    return jsonify({
        "status":         "success",
        "public_key_pem": _public_key_pem,
        "cert_pem":       _cert_pem,  # <3
    }), 200


@app.route('/api/receive_envelope', methods=['POST'])
def api_receive_envelope():
    """
    [POST] 接收數位信封（Phase 3 Step 3.9-3.10）。
    截止時間後回傳 HTTP 403。
    Body: {"c_data": "...", "iv": "...", "tag": "...", "aad": "...", "c_key": "...", "token_hash": "..."}
    驗證 token_hash 未重複使用，解開外層取 k，暫存至 DB。
    """
    # ── Deadline Middleware ──────────────────────────────────
    deadline_resp = _check_deadline()
    if deadline_resp is not None:
        return deadline_resp

    data = request.get_json()
    if not data or not all(k in data for k in ('c_data', 'iv', 'c_key')):
        return jsonify({"status": "error", "message": "缺少信封欄位"}), 400

    now = int(time.time())

    # ── b. token_hash 為必要欄位（Phase 3 Step 3.10b）
    # v2.0 修正：之前 token_hash 缺漏時（例如 voter_client 送空字串）會被
    # `if token_hash:` 判為 falsy 而整段跳過去重檢查，等於一人一票防線
    # 對所有信封都失效。現在強制要求非空。 <3
    token_hash = data.get('token_hash', '')
    if not token_hash:
        return jsonify({
            "status":  "error",
            "code":    "TOKEN_HASH_REQUIRED",
            "message": "缺少 token_hash，無法驗證一人一票",
        }), 403  # <3

    try:
        pending = open_envelope_layer1(data, _private_key)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    # v2.0 修正：去重原本是「先 SELECT 查是否存在、再 INSERT」，兩步之間
    # 有 TOCTOU 競態視窗，併發請求可能讓同一 token_hash 通過兩次。現在改
    # 成直接 INSERT，靠 used_token_hashes.token_hash 的 UNIQUE 約束在資料庫
    # 層級原子化擋下重複，用 IntegrityError 判斷是否搶佔成功。 <3
    try:
        db.execute(
            "INSERT INTO used_token_hashes (token_hash, recorded_at) VALUES (?, ?)",
            (token_hash, now),
        )
    except sqlite3.IntegrityError:
        return jsonify({
            "status":  "error",
            "code":    "TOKEN_HASH_REUSED",
            "message": "此 Token 已用於提交信封，不可重複使用",
        }), 403  # <3

    db.execute(
        "INSERT INTO envelopes (c_data, iv, tag, aad, k, token_hash, received_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            pending['c_data'], pending['iv'],
            pending.get('tag', ''), pending.get('aad', ''),
            pending['k'], token_hash, now, 'pending',
        ),
    )
    print(f"[CC] 收到數位信封（Unix ts：{now}  →  {ts_to_human(now)}）")

    # v4.0 新增：對「收到信封」這件事本身簽一張收據（receipt），選民端可
    # 選擇驗證。這條端點刻意不驗證選民身分（匿名投票的核心設計——CC 不能
    # 知道是誰送的），所以收據不能綁 sender_id/receiver_id，改綁
    # envelope_hash：對這次收到的信封欄位（c_data/iv/tag/aad/c_key/
    # token_hash）算 canonical JSON 的 SHA-256。選民自己本來就知道這些欄
    # 位（是自己送出去的），可以在本地重算同一個雜湊比對，藉此確認「這張
    # 收據對應的就是我剛剛送出的這份信封」，而不是被套用到別次提交、或被
    # 攻擊者偽造的「已接收」假訊息。沒有這張收據時（VERIFY_CC_RECEIPT=
    # false，見 voter_client），選民只能假設 HTTPS 傳輸沒被動手腳；有了
    # 收據，選民可以在當下就偵測「回應是否真的來自 CC、對應的是不是這份
    # 信封」，補上跟 Voter↔TPA 那組雙向認證同等級的保障。 <3
    envelope_hash = hashlib.sha256(
        json.dumps(
            {
                'c_data':     data.get('c_data'),
                'iv':         data.get('iv'),
                'tag':        data.get('tag', ''),
                'aad':        data.get('aad', ''),
                'c_key':      data.get('c_key'),
                'token_hash': token_hash,
            },
            sort_keys=True, ensure_ascii=False, separators=(',', ':'),
        ).encode('utf-8')
    ).hexdigest()
    receipt_payload = {
        "sender_id":      CC_ID,
        "envelope_hash":  envelope_hash,
        "received_at":    now,
    }
    receipt_signature = b""
    if _cert_pem and _private_key:
        receipt_payload_bytes = json.dumps(
            receipt_payload, sort_keys=True, ensure_ascii=False, separators=(',', ':')
        ).encode('utf-8')
        receipt_signature = sign_data(receipt_payload_bytes, _private_key)

    return jsonify({
        "status":  "success",
        "message": "信封已接收",
        "receipt": {
            "payload":   receipt_payload,
            "signature": bytes_to_b64(receipt_signature) if receipt_signature else "",
        },
        "cc_cert_pem": _cert_pem,
    }), 200


@app.route('/api/tally', methods=['POST'])
def api_tally():
    """
    [POST] 觸發開票（Phase 5）。
    1. 向 TA 請求 SK_TA
    2. 向 TPA 取得公鑰大整數 (e, n)
    3. 解密驗證所有暫存信封
    4. 建構 Merkle Tree
    5. 推送結果至 BB

    存取控制（v2.0 修正，規格書 §18.4.4）：僅限內部 IP + Admin Bearer Token。
    先前此端點任何人都能呼叫觸發開票。 <3
    """
    if not is_internal_ip(request.remote_addr) or not check_admin_token():
        return jsonify(admin_auth_error()), 403  # <3
    if not _claim_tally():
        return jsonify({"status": "running", "message": "開票正在進行中"}), 409
    try:
        result = _run_tally_and_record()
    finally:
        _release_tally()
    if result.get('status') == 'success':
        return jsonify(result), 200
    else:
        return jsonify(result), 400


@app.route('/api/tally/start', methods=['POST'])
def api_tally_start():
    """
    [POST] 在背景開始開票，立即回傳 202，進度用 /api/tally/status 查詢。

    同步的 /api/tally 要等整個開票（解密每一張票、建 Merkle Tree、推送 BB）
    做完才回應，票數一多就會超過呼叫端（Admin）的逾時時間——CC 其實還在
    繼續開票，但 Admin 畫面顯示錯誤，容易讓人誤以為開票失敗。Admin 改呼叫
    這支，再輪詢進度。存取控制同 /api/tally。
    """
    if not is_internal_ip(request.remote_addr) or not check_admin_token():
        return jsonify(admin_auth_error()), 403
    if _get_state('done') == '1':
        return jsonify({"status": "already_done", "message": "已完成開票"}), 200
    if not _claim_tally():
        return jsonify({"status": "running", "message": "開票正在進行中"}), 202
    db.execute("DELETE FROM tally_state WHERE key IN ('last_result', 'progress')")
    threading.Thread(target=_tally_job, daemon=True).start()
    return jsonify({"status": "started", "message": "已開始開票"}), 202


@app.route('/api/tally/status', methods=['GET'])
def api_tally_status():
    """[GET] 查詢開票狀態：idle / running / done / error，附進度與結果。"""
    if not is_internal_ip(request.remote_addr) or not check_admin_token():
        return jsonify(admin_auth_error()), 403
    # 順序很重要：先看 'running'，再讀結果。背景執行緒是「先寫 last_result、
    # 再釋放 running」，所以一旦看到 running 已經不在，結果一定已經寫好；
    # 反過來先讀結果的話，執行緒剛好在兩次讀取之間完成時，會回報「已完成」
    # 卻沒有結果。
    running  = _get_state('running')
    progress = _get_state('progress')
    last     = _get_state('last_result')
    if running:
        state = 'running'
    elif _get_state('done') == '1':
        state = 'done'
    elif last:
        state = 'error'
    else:
        state = 'idle'
    return jsonify({
        "status":   "success",
        "state":    state,
        "progress": json.loads(progress) if progress else None,
        "result":   json.loads(last) if last else None,
    }), 200


@app.route('/api/admin/reset_tally', methods=['POST'])
def api_admin_reset_tally():
    """
    [POST] 重置本輪計票狀態（新一輪前使用）。

    背景：admin_tool 的 /api/new_round 原本只重置 TA（回 standby）與 CA
    （清空選民名冊），完全沒有清掉 CC 這裡的開票狀態——_do_tally() 一開
    始就檢查 tally_state.done=='1'，是的話直接回傳 already_done 拒絕重
    跑，導致新一輪投票結束後永遠無法再次開票，直到有人手動進容器清空
    資料庫。這裡補上對應的重置端點，清空本輪所有選票/去重/開票狀態，
    讓下一輪能重新從零開始。

    存取控制比照 /api/tally：僅限內部 IP + Admin Bearer Token。 <3
    """
    if not is_internal_ip(request.remote_addr) or not check_admin_token():
        return jsonify(admin_auth_error()), 403

    envelope_count = db.count("envelopes")
    db.execute("DELETE FROM envelopes")
    db.execute("DELETE FROM valid_votes")
    db.execute("DELETE FROM used_token_hashes")
    db.execute("DELETE FROM tally_state")

    print(f"[CC] 本輪計票狀態已重置（清除 {envelope_count} 筆信封記錄）。")
    return jsonify({"status": "success", "deleted_envelopes": envelope_count}), 200


@app.route('/api/results', methods=['GET'])
def api_results():
    """[GET] 回傳計票結果與 Merkle Root"""
    tally_row = db.fetchone("SELECT value FROM tally_state WHERE key = 'done'")
    if not tally_row or tally_row['value'] != '1':
        return jsonify({"status": "pending", "message": "尚未開票"}), 200

    root_row = db.fetchone("SELECT value FROM tally_state WHERE key = 'merkle_root'")
    tally_json_row = db.fetchone("SELECT value FROM tally_state WHERE key = 'tally_json'")
    # v2.0 修正：
    #  1. 排序改用 shuffle_seq，跟簽章推送給 BB 的 root_official 用同一份
    #     順序重建 Merkle Tree，否則這個公開端點自己給的資料會跟官方結果對不上。
    #  2. 不再回傳 vote 與 m_hex 的一一對應（valid_votes），只給 m_hex 清單，
    #     跟 result_bundle 對 BB 的隱私原則一致（規格書 §19.5）。 <3
    valid_votes = db.fetchall("SELECT vote, m_hex FROM valid_votes ORDER BY shuffle_seq")
    m_hex_list  = [v['m_hex'] for v in valid_votes]  # <3

    return jsonify({
        "status":            "success",
        "merkle_root":       root_row['value'] if root_row else "",
        "tally":             json.loads(tally_json_row['value']) if tally_json_row else {},
        "valid_m_hex_list":  m_hex_list,  # <3 之前是 valid_votes（含 vote），現在只給 m_hex
        "merkle_leaf_count": len(m_hex_list),  # <3
        "tpa_e":             _get_state('tpa_e'),
        "tpa_n":             _get_state('tpa_n'),
    }), 200


@app.route('/api/merkle_proof/<int:index>', methods=['GET'])
def api_merkle_proof(index: int):
    """[GET] 取得指定葉節點的 Merkle Proof"""
    # v2.0 修正：改用 shuffle_seq 排序，與 _do_tally 建構並簽章的
    # root_official 使用同一份洗牌後順序，proof 才驗證得過。 <3
    valid_votes = db.fetchall("SELECT m_hex FROM valid_votes ORDER BY shuffle_seq")
    if not valid_votes:
        return jsonify({"status": "error", "message": "尚無合法選票"}), 404
    if index < 0 or index >= len(valid_votes):
        return jsonify({"status": "error", "message": "索引超出範圍"}), 400

    m_hex_list = [v['m_hex'] for v in valid_votes]
    tree = MerkleTree(m_hex_list)
    proof = tree.get_proof(index)
    root  = tree.get_root()

    return jsonify({
        "status":        "success",
        "index":         index,
        "m_hex":         m_hex_list[index],
        "merkle_proof":  proof,
        "root_official": root,
    }), 200


# ── Config Hot-Reload 端點 ────────────────────────────────────
make_reload_endpoint(app)


# ============================================================
# 內部函式
# ============================================================

def _get_state(key: str):
    row = db.fetchone("SELECT value FROM tally_state WHERE key = ?", (key,))
    return row['value'] if row else None


def _set_state(key: str, value: str):
    db.execute(
        "INSERT OR REPLACE INTO tally_state (key, value) VALUES (?, ?)",
        (key, value),
    )


# ── 開票互斥鎖 ────────────────────────────────────────────────
# 原本只靠 _do_tally() 開頭檢查 done=='1'，兩個開票請求同時進來時都會
# 通過檢查、一起開票。現在用 tally_state 的 PRIMARY KEY 做原子搶佔：
# INSERT 'running' 成功的才能開票，其他請求直接回「開票進行中」。
def _claim_tally() -> bool:
    try:
        db.execute("INSERT INTO tally_state (key, value) VALUES ('running', ?)", (str(int(time.time())),))
        return True
    except sqlite3.IntegrityError:
        return False


def _release_tally():
    db.execute("DELETE FROM tally_state WHERE key = 'running'")


def _run_tally_and_record() -> dict:
    """執行開票並把結果存進 tally_state，供 /api/tally/status 查詢。
    呼叫前必須已經 _claim_tally()。"""
    try:
        result = _do_tally()
    except Exception as e:
        result = {"status": "error", "message": f"開票過程發生未預期錯誤：{e}"}
    _set_state('last_result', json.dumps(result, ensure_ascii=False))
    return result


def _tally_job():
    """背景開票執行緒（/api/tally/start、/ui/tally）。"""
    try:
        _run_tally_and_record()
    finally:
        _release_tally()


def _do_tally() -> dict:
    """執行開票流程（Phase 5，v2.0 Sprint 2：含認證封包）"""
    # 檢查是否已開票
    if _get_state('done') == '1':
        return {"status": "already_done", "message": "已完成開票"}

    # 步驟 1：向 TA 請求 SK_TA
    # v2.0 修正：改用規格書 §18.3.3 定義的 release_key 專用格式（頂層
    # payload/signature/cert_pem，payload 含 requester_id/timestamp/nonce/
    # purpose），不再套用通用 Auth_Packet 格式（那個格式沒有 purpose 欄位，
    # 且 cert_pem 是包在 payload 內，與 TA 端現在的驗證邏輯對不上）。 <3
    try:
        if _cert_pem and _private_key:
            release_payload = {
                "requester_id": CC_ID,
                "timestamp":    int(time.time()),
                "nonce":        secrets.token_hex(16),
                "purpose":      "tally",
            }
            release_payload_bytes = json.dumps(
                release_payload, sort_keys=True, ensure_ascii=False, separators=(',', ':')
            ).encode('utf-8')  # <3 canonical JSON
            release_signature = sign_data(release_payload_bytes, _private_key)
            request_payload = {
                "payload":   release_payload,
                "signature": bytes_to_b64(release_signature),
                "cert_pem":  _cert_pem,
            }  # <3
            print(f"[CC] 向 TA 請求 SK_TA（nonce: {release_payload['nonce'][:16]}...）")
        else:
            # 向後兼容：若無憑證，則不附帶認證封包
            request_payload = {}
            print(f"[CC] 警告：無憑證，向 TA 請求 SK_TA（無認證封包）")

        resp = http_requests.post(f"{TA_URL}/api/release_key", json=request_payload, timeout=10, **_CC_MTLS)
        sk_ta_data = resp.json()
        
        if sk_ta_data.get('status') != 'released':
            error_code = sk_ta_data.get('code', 'UNKNOWN')
            error_msg = sk_ta_data.get('message', '未知錯誤')
            print(f"[CC] TA 拒絕釋放私鑰（{error_code}）：{error_msg}")
            return {
                "status": "error",
                "code": error_code,
                "message": f"TA 拒絕釋放私鑰：{error_msg}"
            }
        
        print(f"[CC] ✅ 已從 TA 取得 SK_TA")
    except Exception as e:
        return {"status": "error", "message": f"無法連接 TA：{e}"}

    # 步驟 2：向 TPA 取得公鑰大整數 (e, n)
    # v4.0 修正：原本直接信任回應裡的裸 e/n 欄位，完全沒有驗證來源——這把
    # e/n 是開票時驗證每張選票盲簽章合法性的關鍵依據，跟緊接在下面對 TA
    # 的交叉驗證形成明顯落差，也跟選民瀏覽器端已經在做的憑證鏈驗證邏輯
    # 不一致。改成先驗證 cert_pem 的 CA 簽章鏈與 Subject CN，再從「已驗證
    # 的憑證」本身取出 e/n，不再信任回應裡分開提供、可能跟 cert_pem 講不
    # 同故事的裸 e/n 欄位。 <3
    try:
        resp = http_requests.get(f"{TPA_URL}/api/public_key", timeout=10, **_CC_MTLS)
        tpa_data = resp.json()
        tpa_cert_pem = tpa_data.get('cert_pem', '')
    except Exception as e:
        return {"status": "error", "message": f"無法取得 TPA 公鑰：{e}"}

    tpa_cert_obj = verify_cert_chain_and_cn(tpa_cert_pem, _ca_cert_pem, 'TPA')  # <3
    if tpa_cert_obj is None:
        return {"status": "error", "code": "TPA_CERT_INVALID",
                "message": "無法驗證 TPA 憑證，拒絕使用本次取得的公鑰"}  # <3

    tpa_public_numbers = tpa_cert_obj.public_key().public_numbers()  # <3
    tpa_e = tpa_public_numbers.e
    tpa_n = tpa_public_numbers.n
    _set_state('tpa_e', int_to_hex(tpa_e))
    _set_state('tpa_n', int_to_hex(tpa_n))

    # 步驟 2.5：交叉驗證 TA 釋放的私鑰，是否真的對應其 CA 認證過的公鑰
    # v3.0 修正：原本收到 /api/release_key 回應後直接載入使用，完全沒有
    # 驗證這把私鑰是否真的屬於 TA——如果 CC 連到 TA_URL 這條路徑上被人
    # 動了手腳（例如 Docker 內部網路裡插入一個假冒的 TA），CC 會照單全
    # 收一把來路不明的私鑰，雖然這把假私鑰解不開真正用「真 TA 公鑰」加
    # 密的選票內容（RSA-OAEP 解密會直接失敗），但足以讓全部選票被誤判
    # 為非法、整場開票直接歸零，等同一次「讓選舉作廢」的攻擊。
    # 修法不是另外跑一次即時雙向握手，而是重複利用 Phase 1 已經建立好
    # 的信任：直接向 TA 要它自己 CA 簽發的公鑰憑證，驗證憑證鏈、核對
    # Subject CN 真的是 "TA"，再拿憑證裡的公鑰模數，跟這次釋放的私鑰
    # 反推出的模數比對是否一致——一致才代表這把私鑰在數學上不可能是
    # 別人偽造的（要偽造就等於要破解 RSA）。 <3
    try:
        ta_pubkey_resp = http_requests.get(f"{TA_URL}/api/public_key", timeout=10, **_CC_MTLS)
        ta_pubkey_data = ta_pubkey_resp.json()
        ta_cert_pem = ta_pubkey_data.get('cert_pem', '')
    except Exception as e:
        return {"status": "error", "message": f"無法取得 TA 憑證以進行交叉驗證：{e}"}  # <3

    ta_cert_obj = verify_cert_chain_and_cn(ta_cert_pem, _ca_cert_pem, 'TA')  # <3
    if ta_cert_obj is None:
        return {"status": "error", "code": "TA_CERT_INVALID",
                "message": "無法驗證 TA 憑證，拒絕使用本次釋放的私鑰"}  # <3

    certified_ta_n = ta_cert_obj.public_key().public_numbers().n  # <3

    # 步驟 3：載入 TA 私鑰
    ta_private_key = serialization.load_pem_private_key(
        sk_ta_data['private_key_pem'].encode('utf-8'),
        password=None,
    )
    released_n = ta_private_key.private_numbers().public_numbers.n  # <3

    if released_n != certified_ta_n:
        # <3 私鑰的模數跟已認證公鑰的模數對不上——這把私鑰不是真的 TA 的，
        # 不管是誰給的、透過什麼管道給的，一律拒絕使用，不進行任何解密。
        print("[CC] 嚴重警告：TA 釋放的私鑰與其 CA 認證公鑰不匹配，可能遭偽冒攻擊！")
        return {"status": "error", "code": "TA_KEY_MISMATCH",
                "message": "TA 釋放的私鑰與其認證公鑰不匹配，拒絕使用（可能遭偽冒攻擊）"}  # <3

    # 步驟 4：解密驗證所有暫存信封
    # 走到這裡代表本輪還沒開票完成（done != '1'，且已取得開票鎖）。valid_votes
    # 若有資料，一定是上次開票中途失敗留下的：全部清掉、信封退回 pending
    # 重新驗證。這樣 valid_votes 只會有「這次」驗證通過的票，寫入後才能逐筆
    # 比對（見下方讀回比對）。信封本身才是資料來源，重新驗證不會有損失。
    with db.transaction() as conn:
        conn.execute("DELETE FROM valid_votes")
        conn.execute("UPDATE envelopes SET status = 'pending' WHERE status IN ('verified', 'invalid', 'm_duplicate')")

    pending_envelopes = db.fetchall(
        "SELECT id, c_data, iv, tag, aad, k FROM envelopes WHERE status = 'pending'"
    )
    now = int(time.time())
    total = len(pending_envelopes)
    _set_state('progress', json.dumps({"processed": 0, "total": total}))

    # 解密（CPU 密集）與寫入分開：先全部解密完，再在同一個交易裡一次寫完。
    # 原本每張票各做 2 次獨立交易（INSERT valid_votes + UPDATE envelopes），
    # 每次都要等 commit 落盤，票數上千時光是資料庫就要好幾分鐘。整批寫入
    # 也讓開票變成全有或全無：中途出錯不會留下寫了一半的結果，可以重跑。
    outcomes = []  # (envelope id, 解密結果或 None, 錯誤訊息)
    for i, env in enumerate(pending_envelopes, 1):
        pending = {
            'c_data': env['c_data'],
            'iv':     env['iv'],
            'tag':    env.get('tag', ''),
            'aad':    env.get('aad', ''),
            'k':      env['k'],
        }
        try:
            outcomes.append((env['id'], open_envelope_layer2(pending, ta_private_key, tpa_e, tpa_n), None))
        except Exception as exc:
            outcomes.append((env['id'], None, str(exc)))
        if i % 100 == 0 or i == total:
            _set_state('progress', json.dumps({"processed": i, "total": total}))

    # 這次驗證通過的選票，留在記憶體裡作為計票與簽章的唯一依據
    verified = []          # [{"id", "vote", "m_hex"}]，依寫入順序（= id 遞增）
    invalid_reasons = {}   # 錯誤訊息 → 張數
    duplicate_count = 0
    with db.transaction() as conn:
        for env_id, result, error in outcomes:
            if result is None:
                conn.execute("UPDATE envelopes SET status = 'invalid' WHERE id = ?", (env_id,))
                invalid_reasons[error] = invalid_reasons.get(error, 0) + 1
                continue

            # v2.0 修正：原本沒有做 m_hex（選票流水號雜湊）去重，重放同一張
            # 已簽章選票的最後一道防線是空的。現在靠 valid_votes.m_hex 的
            # UNIQUE 索引在資料庫層原子化擋下重複，用 IntegrityError 判斷。 <3
            try:
                cur = conn.execute(
                    "INSERT INTO valid_votes (vote, m_hex, verified_at) VALUES (?, ?, ?)",
                    (result['vote'], result['m_hex'], now),
                )
            except sqlite3.IntegrityError:
                conn.execute("UPDATE envelopes SET status = 'm_duplicate' WHERE id = ?", (env_id,))
                duplicate_count += 1
                continue  # <3

            conn.execute("UPDATE envelopes SET status = 'verified' WHERE id = ?", (env_id,))
            verified.append({"id": cur.lastrowid, "vote": result['vote'], "m_hex": result['m_hex']})
    valid_count = len(verified)

    # 日誌只記統計數字。以前每張合法票都印一行「選票合法：<候選人>」，順序就是
    # CC 收到信封的順序——voter_client 的批次打亂與開票後的洗牌，都是為了切斷
    # 「提交順序 ↔ 選票內容」的關聯，逐張依序記錄候選人等於把這層保護寫進日誌。
    print(f"[CC] 解密驗證完成：共 {total} 封，合法 {valid_count}，無效 {sum(invalid_reasons.values())}，重複 {duplicate_count}")
    for reason, count in sorted(invalid_reasons.items(), key=lambda kv: -kv[1]):
        print(f"[CC]   無效原因：{reason} × {count}")

    # 寫入後立刻讀回，逐筆比對資料庫與這次驗證的結果。
    # 以前計票、洗牌、建 Merkle Tree 都是「重新從資料庫讀 valid_votes」，只要
    # 有人能改 CC 的資料庫檔案，在寫入與讀取之間塞一筆沒經過驗證的票，就會
    # 被計入並由 CC 正式簽章。現在計票與簽章只用記憶體裡的 verified；這裡的
    # 比對用來偵測竄改——不一致就中止開票，不簽章、不公告。
    stored = db.fetchall("SELECT id, vote, m_hex FROM valid_votes ORDER BY id")
    if [(r['id'], r['vote'], r['m_hex']) for r in stored] != [(v['id'], v['vote'], v['m_hex']) for v in verified]:
        print(f"[CC] 嚴重警告：valid_votes 與本次驗證結果不一致（資料庫 {len(stored)} 筆、驗證通過 {valid_count} 筆），已中止開票")
        return {
            "status":  "error",
            "code":    "VALID_VOTES_MISMATCH",
            "message": "資料庫中的有效選票與本次驗證結果不一致，可能遭竄改，已中止開票（未簽章、未公告）",
        }

    # 步驟 5：Secure Shuffle + 建構 Merkle Tree
    # 將合法選票以密碼學安全隨機順序洗牌，斷絕「提交順序 → 選民」關聯
    # Fisher-Yates shuffle（使用 secrets CSPRNG）——對象是記憶體裡驗證通過的清單，
    # 不重新讀資料庫（理由見上方讀回比對）
    valid_votes = list(verified)
    for i in range(len(valid_votes) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        valid_votes[i], valid_votes[j] = valid_votes[j], valid_votes[i]

    # v2.0 修正：洗牌結果原本只存在這次執行的記憶體裡，算完 root 就丟了，
    # valid_votes 表沒有記錄洗牌後的順序。之後 /api/results、
    # /api/merkle_proof/<index> 又是用未洗牌的 id 順序重建 Merkle Tree，
    # 算出來的 root 會跟這裡簽章、推送給 BB 的 root_official 對不上，
    # 選民拿 CC 給的 proof 去驗證會失敗。現在把洗牌後的順序寫回 shuffle_seq。 <3
    db.executemany(
        "UPDATE valid_votes SET shuffle_seq = ? WHERE id = ?",
        [(seq, v['id']) for seq, v in enumerate(valid_votes)],
    )  # <3 一次交易寫完，不再逐筆 commit

    m_hex_list = [v['m_hex'] for v in valid_votes]

    if m_hex_list:
        tree = MerkleTree(m_hex_list)
        merkle_root = tree.get_root()
        print(f"[CC] 已對 {len(m_hex_list)} 張合法選票進行 secure shuffle")
    else:
        merkle_root = ""

    # 計票
    tally = {}
    for v in valid_votes:
        tally[v['vote']] = tally.get(v['vote'], 0) + 1

    _set_state('done', '1')
    _set_state('merkle_root', merkle_root)
    _set_state('tally_json', json.dumps(tally))
    # 儲存開票時間（Unix timestamp）
    _set_state('tallied_at', str(now))

    print(f"[CC] 開票完成（Unix ts：{now}  →  {ts_to_human(now)}）。合法選票：{valid_count}，Root_official：{merkle_root[:20]}...")

    # 步驟 6：對開票結果簽章並推送至 BB (v2.0 Sprint 2)
    bb_published = True
    bb_publish_warning = None
    try:
        # v2.0 修正：規格書 §19.5 明確要求推送給 BB 的結果只能含
        # valid_m_hex_list（純 m_hex 清單），不可含 vote 與 m_hex 的
        # 一一對應，否則任何人都能從公告結果反推「哪一張葉節點對應哪一
        # 票」。個別選票內容只保留在 tally 的候選人加總裡，不逐票公開。 <3
        # v2.0 修正：補上 deadline、cc_id 兩個規格書 §18.5.1/§20.4 要求的
        # 欄位，供 BB 做結構一致性檢查（BUNDLE_INCONSISTENT）與稽核追溯。 <3
        result_bundle = {
            "root_official":     merkle_root,
            "tally":             tally,
            "valid_m_hex_list":  m_hex_list,   # <3 只給 m_hex，不含 vote
            "merkle_leaf_count": len(m_hex_list),  # <3
            "deadline":          _get_deadline(),  # <3
            "cc_id":             CC_ID,  # <3
            "tallied_at":        now,
        }

        # 對結果包進行 RSA-PSS 簽章
        # v2.0 修正：補上 separators=(',', ':') 做 canonical JSON（規格書
        # §18.6）。先前缺少此參數，CC/BB 雙方雖能自洽驗章，但外部稽核工具
        # 照規格重建 canonical JSON 後會因序列化結果不同而驗章失敗。 <3
        bundle_json = json.dumps(result_bundle, sort_keys=True, ensure_ascii=False, separators=(',', ':'))  # <3
        bundle_bytes = bundle_json.encode('utf-8')
        signature = sign_data(bundle_bytes, _private_key)
        
        # 構造完整的推送包（含簽章和憑證）
        bb_payload = {
            "result_bundle":    result_bundle,
            "signature":        bytes_to_b64(signature),
            "cert_pem":         _cert_pem,
        }
        
        resp = http_requests.post(f"{BB_URL}/api/publish", json=bb_payload, timeout=10, **_CC_MTLS)
        if resp.status_code == 200:
            print(f"[CC] 結果已簽章並推送至 BB（簽章長度：{len(signature)} bytes）")
        else:
            bb_published = False
            bb_publish_warning = f"BB 拒絕結果（HTTP {resp.status_code}）：{resp.text}"
            print(f"[CC] 警告：{bb_publish_warning}")
    except Exception as e:
        bb_published = False
        bb_publish_warning = f"無法連接 BB：{e}"
        print(f"[CC] 警告：{bb_publish_warning}")

    # v4.0 新增：CC 對 BB 沒有做任何身分／回應驗證——BB_URL 目前是內部
    # docker DNS 名稱，一旦這條路徑被攻擊者攔截（未來服務各自上網後風險更
    # 高），攻擊者可以攔下這個 POST、回一個假的 HTTP 200，讓 CC 誤以為結果
    # 已公告，但真正的 BB 從未收到。這裡不用要求 BB 額外簽章回應（那需要
    # BB 也持有金鑰、且改動 BB 的 API），改用成本低很多的「送出後立刻讀
    # 回」：直接呼叫 BB 自己的公開 GET 端點，拿它現在實際存的
    # merkle_root/tally/valid_m_hex_list 跟這次送出去的內容逐項比對——這幾
    # 個值都是 CC 自己算出來、自己簽過章的，不需要 BB 簽任何東西，只要
    # 「BB 現在存的東西跟我剛剛送的一模一樣」就能抓到「送丟了 / 被送到假
    # 的地方」這個情況，而不是只看 HTTP 200 就相信。 <3
    if bb_published:
        try:
            verify_resp = http_requests.get(f"{BB_URL}/api/results", timeout=10, **_CC_MTLS)
            verify_data = verify_resp.json()
            if (
                verify_data.get('merkle_root') != merkle_root
                or verify_data.get('tally') != tally
                or verify_data.get('valid_m_hex_list') != m_hex_list
            ):
                bb_published = False
                bb_publish_warning = (
                    "BB read-back 驗證失敗：BB 目前公告的內容與 CC 剛剛送出的不一致，"
                    "結果可能被送到錯誤的目的地或在傳輸途中被竄改"
                )
                print(f"[CC] 警告：{bb_publish_warning}")
            else:
                print("[CC] BB read-back 驗證通過，確認結果已正確公告")
        except Exception as e:
            bb_published = False
            bb_publish_warning = f"BB read-back 驗證時發生錯誤：{e}"
            print(f"[CC] 警告：{bb_publish_warning}")

    return {
        "status":              "success",
        "valid_count":         valid_count,
        "tally":               tally,
        "merkle_root":         merkle_root,
        # Unix timestamp（後端標準）
        "tallied_at":          now,
        # v4.0 新增：開票本身（本地計票、Merkle Tree、簽章）成功與否，跟
        # 「結果是否真的送達並被 BB 正確公告」是兩件事，不要混在同一個
        # status 欄位裡（否則會動到 /api/tally 既有的成功/400 判斷邏輯）。
        # 呼叫端（Admin dashboard 等）應額外檢查 bb_published，True 才代表
        # 選民真的能去 BB 查到這次的結果。 <3
        "bb_published":        bb_published,
        "bb_publish_warning":  bb_publish_warning,
    }


if __name__ == '__main__':
    # v4.0 新增：CC 只會被 Voter（提交信封）與 Admin（觸發開票）連線，
    # 兩者都持有本套 PKI 核發的 TLS 用戶端憑證，要求對方出示合法 mTLS
    # 憑證不會擋到任何合法流量。
    _ca_cert_path = os.path.join(KEYS_DIR, "ca_cert.pem")
    _ssl_ctx = build_mtls_server_context(
        _tls_cert_path, _tls_key_path, _ca_cert_path, require_client_cert=True,
    )
    app.run(host='0.0.0.0', port=5003, debug=False, ssl_context=_ssl_ctx)
