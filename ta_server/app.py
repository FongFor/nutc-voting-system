"""
ta_server/app.py  —  時間授權中心 (TA)

負責管理投票的時間窗口。啟動時會生成 RSA 金鑰對並向 CA 申請憑證，
同時根據設定計算出投票截止時間。截止前 SK_TA 會一直鎖著，
等到時間到了，CC 才能來拿金鑰開票。

前端有個倒數計時頁面，可以即時看到還剩多少時間。

端點：
  GET  /                  倒數計時儀表板
  GET  /api/public_key    回傳 TA 公鑰
  GET  /api/deadline      查詢截止時間（回傳 Unix timestamp）
  POST /api/release_key   釋放 SK_TA（截止後才會放行）
  GET  /api/config        查看目前設定
  POST /api/config/reload 重新載入 config.json
"""

import os
import sys
import time
import base64

# 確保 shared/ 可被 import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string

from shared.key_manager import (
    load_or_generate_keypair,
    load_or_request_certificate,
    load_or_fetch_ca_cert,
    verify_cert_chain_and_cn,  # <3 v4.0：共用的「驗憑證鏈 + 核對 CN」函式
)
from shared.tls_utils import load_or_request_tls_certificate, build_mtls_server_context  # <3 v4.0：mTLS
from shared.format_utils import int_to_hex, ts_to_human
from shared.db_utils import Database
from shared.ui_style import UI_HEAD, THEME_TOGGLE
from shared.config_loader import make_reload_endpoint, get_vote_duration, get_delta_t, get_service_registration_token
from shared.admin_auth import check_admin_token, admin_auth_error  # <3 v4.0：保護 start_election/reset_election
from shared.crypto_utils import verify_signature  # <3 v4.0：release_key 簽章驗證改用共用函式
import json  # <3 用於 release_key 請求的 canonical JSON 驗簽

# ============================================================
# 常數設定
# ============================================================
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR    = os.path.join(SERVICE_DIR, "keys")
# <3 v4.0：資料庫獨立放進 data/ 子目錄，才能掛載成持久化 volume——
# 原本直接放在 SERVICE_DIR 底下，跟隨容器可寫層一起被重建時清空，
# 選舉狀態（election_state：是否 running、截止時間）沒了等於選舉被迫
# 中止，任何一次重新部署都可能連帶造成這個後果。
DATA_DIR    = os.path.join(SERVICE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH     = os.path.join(DATA_DIR, "ta.db")
TA_ID       = "TA"
TA_HOSTNAME = os.environ.get("TA_HOSTNAME", "ta")  # <3 v4.0：填入 TLS 憑證的 SAN
CA_URL      = os.environ.get("CA_URL", "https://localhost:5001")
DELTA_T     = int(os.environ.get("DELTA_T", str(get_delta_t())))  # <3 release_key 請求時間戳檢查用

# 選舉狀態由資料庫管理：standby（待命）→ running（進行中）
# 截止時間在管理員手動啟動選舉後才計算，啟動前不倒數

# ============================================================
# 資料庫初始化
# ============================================================
db = Database(DB_PATH)
db.execute("""
    CREATE TABLE IF NOT EXISTS key_release_log (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        requested_at INTEGER NOT NULL,
        requester_id TEXT,
        status       TEXT NOT NULL,
        reason       TEXT
    )
""")
db.execute("""
    CREATE TABLE IF NOT EXISTS used_nonces (
        nonce TEXT PRIMARY KEY,
        used_at INTEGER NOT NULL
    )
""")
db.execute("""
    CREATE TABLE IF NOT EXISTS election_state (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
""")
if db.fetchone("SELECT value FROM election_state WHERE key = 'state'") is None:
    db.execute("INSERT INTO election_state (key, value) VALUES ('state', 'standby')")


def _get_election_state() -> str:
    row = db.fetchone("SELECT value FROM election_state WHERE key = 'state'")
    return row['value'] if row else 'standby'


def _get_deadline_ts() -> int:
    row = db.fetchone("SELECT value FROM election_state WHERE key = 'deadline'")
    return int(row['value']) if row else 0


# ============================================================
# 金鑰初始化（啟動時執行）
# ============================================================
print(f"[TA] 初始化金鑰...")
(
    _private_key, _public_key, _e, _n, _d,
    _private_key_pem, _public_key_pem
) = load_or_generate_keypair(KEYS_DIR)

try:
    _ca_cert_pem = load_or_fetch_ca_cert(KEYS_DIR, CA_URL)
except Exception as ex:
    print(f"[TA] 警告：無法取得 CA 憑證（{ex}）")
    _ca_cert_pem = None

try:
    # v2.0 修正：附上一次性 SERVICE_REGISTRATION_TOKEN，避免任何人單靠
    # entity_id 字串就能向 CA 換發合法服務憑證。 <3
    _cert_pem = load_or_request_certificate(
        KEYS_DIR, TA_ID, _public_key_pem, CA_URL,
        registration_token=get_service_registration_token(),
    )  # <3
except Exception as ex:
    print(f"[TA] 警告：無法取得憑證（{ex}）")
    _cert_pem = ""

# v4.0 新增：另外申請一把獨立的 TLS 專用憑證（見 shared/tls_utils.py），
# 跟上面的應用層身分憑證完全分開，供本服務的 HTTPS 監聽埠使用。
try:
    _tls_cert_path, _tls_key_path = load_or_request_tls_certificate(
        KEYS_DIR, TA_ID, TA_HOSTNAME, CA_URL,
        registration_token=get_service_registration_token(),
    )
except Exception as ex:
    print(f"[TA] 警告：無法取得 TLS 憑證（{ex}）")
    _tls_cert_path = _tls_key_path = None

# 日誌使用人類可讀格式（ts_to_human 確保時區正確）
print(f"[TA] 初始化完成。選舉狀態：{_get_election_state()}")

# ============================================================
# Flask App
# ============================================================
app = Flask(__name__)

# ── HTML 模板 ──────────────────────────────────────────────
_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <title>時間授權中心｜NUTC 線上投票</title>""" + UI_HEAD + """
</head>
<body>
<header class="topbar">
  <div class="container-wide topbar-inner">
    <a class="brand" href="/">
      <span class="brand-name">NUTC 線上投票</span>
      <span class="brand-sub">時間授權中心（TA）</span>
    </a>
    <div class="topbar-actions">
      {% if election_state == 'standby' %}<span class="badge badge-warn">待命中</span>{% elif is_expired %}<span class="badge badge-err">投票已截止</span>{% else %}<span class="badge badge-ok">投票進行中</span>{% endif %}
      """ + THEME_TOGGLE + """
    </div>
  </div>
</header>

<main>
  <div class="container-wide stack-lg">
    <div class="stack-sm">
      <h1>時間授權中心（TA）</h1>
      <p class="lead">保管開票私鑰（SK_TA），投票截止後才會釋放給計票中心。</p>
    </div>

    <section class="card stack text-center" aria-live="polite">
      {% if election_state == 'standby' %}
      <p class="eyebrow">選舉尚未啟動</p>
      <p class="stat-value">等待管理員啟動選舉</p>
      <p class="small muted">所有投票業務目前暫停。</p>
      {% elif is_expired %}
      <p class="eyebrow">投票已截止</p>
      <p class="stat-value">00:00:00</p>
      <p class="small muted">開票私鑰已解鎖，可釋放給計票中心（CC）開票。</p>
      {% else %}
      <p class="eyebrow">距離投票截止</p>
      <p class="stat-value mono" style="font-size:2.4rem" id="countdown">
        <span id="cd-hours">--</span>:<span id="cd-minutes">--</span>:<span id="cd-seconds">--</span>
      </p>
      <p class="small muted">截止時間 {{ deadline_str }}</p>
      {% endif %}
    </section>

    <div class="grid grid-2">
      <div class="stat"><div class="stat-label">開票私鑰（SK_TA）</div>
        <div class="stat-value" style="font-size:1.15rem">
          {% if election_state == 'standby' %}<span class="muted">待命中</span>{% elif is_expired %}<span class="text-ok">可釋放</span>{% else %}<span class="text-warn">鎖定中</span>{% endif %}
        </div>
      </div>
      <div class="stat"><div class="stat-label">釋放請求次數</div><div class="stat-value">{{ release_count }}</div></div>
    </div>

    <section class="card card-flush" aria-labelledby="relTitle">
      <div class="card-head"><h2 id="relTitle" class="section-title">金鑰釋放紀錄</h2><span class="small muted">最新 {{ release_logs|length }} 筆</span></div>
      {% if release_logs %}
      <div class="table-wrap">
        <table class="table table-stack">
          <thead><tr><th class="num">#</th><th>結果</th><th>原因</th><th>時間</th></tr></thead>
          <tbody>
            {% for log in release_logs %}
            <tr>
              <td class="num muted hide-sm" data-label="#">{{ loop.index }}</td>
              <td data-label="結果">{% if log.status == 'released' %}<span class="badge badge-ok">已釋放</span>{% else %}<span class="badge badge-err">拒絕</span>{% endif %}</td>
              <td class="small" data-label="原因">{{ log.reason or '—' }}</td>
              <td class="small muted nowrap" data-label="時間">{{ log.requested_at | ts_to_str }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% else %}
      <div class="card-body muted">尚無釋放紀錄。</div>
      {% endif %}
    </section>
  </div>
</main>
{% if election_state == 'running' and not is_expired %}
<script>
  const deadline = {{ deadline_ts }} * 1000;
  function update() {
    const diff = Math.max(0, deadline - Date.now());
    if (diff === 0) { location.reload(); return; }
    const h = Math.floor(diff / 3600000), m = Math.floor((diff % 3600000) / 60000), s = Math.floor((diff % 60000) / 1000);
    document.getElementById('cd-hours').textContent   = String(h).padStart(2, '0');
    document.getElementById('cd-minutes').textContent = String(m).padStart(2, '0');
    document.getElementById('cd-seconds').textContent = String(s).padStart(2, '0');
  }
  setInterval(update, 1000);
  update();
</script>
{% endif %}
</body>
</html>"""
# ── Jinja2 自訂過濾器：Unix timestamp → 人類可讀 ──────────────
@app.template_filter('ts_to_str')
def ts_to_str(ts):
    """將 Unix timestamp 轉為 YYYY-MM-DD HH:MM:SS（僅用於 UI 顯示）
    使用 ts_to_human() 確保時區正確（預設 UTC+8，可由 DISPLAY_TIMEZONE_OFFSET 環境變數覆蓋）"""
    return ts_to_human(ts)


# ── 路由 ──────────────────────────────────────────────────

@app.route('/')
def dashboard():
    now = int(time.time())
    election_state = _get_election_state()
    deadline = _get_deadline_ts()
    is_expired = election_state == 'running' and deadline > 0 and now >= deadline
    release_logs = db.fetchall(
        "SELECT id, status, reason, requested_at FROM key_release_log ORDER BY id DESC LIMIT 20"
    )
    release_count = db.count("key_release_log")
    return render_template_string(
        _DASHBOARD_HTML,
        election_state=election_state,
        is_expired=is_expired,
        deadline_str=ts_to_human(deadline) if deadline > 0 else None,
        deadline_ts=deadline,
        release_logs=release_logs,
        release_count=release_count,
    )


@app.route('/api/public_key', methods=['GET'])
def api_public_key():
    """[GET] 回傳 TA 公鑰 PEM 與憑證。
    v3.0 修正：補上 cert_pem，讓呼叫端（選民、CC）能對這把公鑰做憑證鏈
    驗證，不再只能盲目信任裸公鑰——原本這裡沒有 cert_pem，就算呼叫端
    想驗證也無材料可驗。 <3
    """
    return jsonify({
        "status":         "success",
        "public_key_pem": _public_key_pem,
        "cert_pem":       _cert_pem,  # <3
    }), 200


@app.route('/api/deadline', methods=['GET'])
def api_deadline():
    """
    [GET] 回傳截止時間資訊（含選舉狀態）。
    election_state: 'standby' | 'running'
    standby 時 deadline = 0，下游服務應以 ELECTION_NOT_STARTED 拒絕所有投票業務。
    """
    now = int(time.time())
    election_state = _get_election_state()
    deadline = _get_deadline_ts()
    is_expired = election_state == 'running' and deadline > 0 and now >= deadline
    remaining = max(0, deadline - now) if deadline > 0 else None
    return jsonify({
        "status":            "success",
        "election_state":    election_state,
        "deadline":          deadline,
        "server_time":       now,
        "remaining_seconds": remaining,
        "is_expired":        is_expired,
        "deadline_str":      ts_to_human(deadline) if deadline > 0 else None,
        "server_time_str":   ts_to_human(now),
    }), 200


@app.route('/api/release_key', methods=['POST'])
def api_release_key():
    """
    [POST] 釋放 SK_TA（v2.0 修正：欄位結構對齊規格書 §18.3.3）

    Body: {
        "payload": {
            "requester_id": "CC",
            "timestamp":    <Unix ts>,
            "nonce":        "<32 hex chars>",
            "purpose":      "tally"
        },
        "signature": "<base64 Sig_CC(canonical_json(payload))>",
        "cert_pem":  "-----BEGIN CERTIFICATE-----..."
    }

    驗證流程：
      1. 檢查是否已截止
      2. 驗證 cert_pem 由 CA 簽發、且 Subject CN 為 "CC"
      3. 驗證 payload 簽章、時間戳（ΔT）、nonce（必要且未使用過）、purpose
      4. 釋放 SK_TA

    回傳：{"status": "released", "private_key_pem": ..., "d_hex": ..., "n_hex": ..., "released_at": <Unix ts>}
    """
    now = int(time.time())
    data = request.get_json() or {}

    # 步驟 1：檢查選舉狀態與截止時間
    election_state = _get_election_state()
    deadline = _get_deadline_ts()

    if election_state == 'standby':
        db.execute(
            "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
            (now, None, 'rejected', '選舉尚未啟動（standby）'),
        )
        return jsonify({
            "status":  "rejected",
            "code":    "ELECTION_NOT_STARTED",
            "message": "選舉尚未啟動，無法釋放私鑰",
        }), 403

    if now < deadline:
        remaining = deadline - now
        db.execute(
            "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
            (now, None, 'rejected', f'投票尚未截止（還有 {remaining} 秒）'),
        )
        return jsonify({
            "status":            "rejected",
            "code":              "NOT_YET_DEADLINE",
            "message":           f"投票尚未截止，還有 {remaining} 秒",
            "remaining_seconds": remaining,
            "deadline":          deadline,
            "server_time":       now,
        }), 403

    # v2.0 修正：欄位結構改為規格書 §18.3.3 頂層 payload/signature/cert_pem，
    # 不再套用通用 Auth_Packet（sender_id/receiver_id、cert_pem 包在 payload
    # 內）格式 —— release_key 請求本來就沒有 receiver_id，cert_pem 也不屬於
    # payload 的一部分，硬套通用格式反而跟規格書不符。 <3
    payload       = data.get('payload')
    signature_b64 = data.get('signature')
    cert_pem      = data.get('cert_pem')

    if not payload or not signature_b64 or not cert_pem:
        db.execute(
            "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
            (now, (payload or {}).get('requester_id'), 'rejected', '缺少 payload/signature/cert_pem'),
        )
        return jsonify({
            "status":  "error",
            "code":    "MISSING_FIELDS",
            "message": "需要 payload、signature、cert_pem 三個欄位",
        }), 400  # <3

    requester_id = payload.get('requester_id', '')

    # 步驟 2：cert_pem 須由 CA 簽發
    if not _ca_cert_pem:
        db.execute(
            "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
            (now, requester_id, 'rejected', 'TA 無 CA 憑證，無法驗證'),
        )
        return jsonify({
            "status": "error",
            "code": "CA_CERT_UNAVAILABLE",
            "message": "TA 無法取得 CA 憑證，無法驗證請求方身分"
        }), 500

    # v4.0 修正：改用共用的 verify_cert_chain_and_cn()（見
    # shared/key_manager.py）——原本這裡跟 cc_server/bb_server/voter_client
    # 各自手刻一份幾乎相同的「驗簽章鏈 + 核對 Subject CN」邏輯，改成呼叫
    # 同一份共用實作，並順便補上原本沒做的憑證有效期限檢查。 <3
    _requester_cert = verify_cert_chain_and_cn(cert_pem, _ca_cert_pem, 'CC')
    if _requester_cert is None:
        db.execute(
            "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
            (now, requester_id, 'rejected', 'cert_pem 未由合法 CA 簽發、已過期，或 Subject CN 不是 CC'),
        )
        return jsonify({"status": "error", "code": "CERT_INVALID",
                        "message": "cert_pem 未由合法 CA 簽發、已過期，或 Subject CN 不是 CC"}), 403  # <3

    _requester_pub = _requester_cert.public_key()

    # v2.0 修正：只驗證憑證身分還不夠 —— 還要求 payload 自報的 requester_id
    # 與憑證身分一致，把身分主張綁回 PKI 身分鏈。 <3
    if requester_id != 'CC':
        db.execute(
            "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
            (now, requester_id, 'rejected', f'請求方非 CC（requester_id={requester_id}）'),
        )
        return jsonify({
            "status": "error",
            "code": "UNAUTHORIZED_REQUESTER",
            "message": f"僅允許 CC 請求 SK_TA（實際請求方：{requester_id}）"
        }), 403

    # 步驟 3：purpose 必須為 "tally"（規格書 §18.3.3，防止把其他用途的簽章封包拿來重放）
    if payload.get('purpose') != 'tally':
        db.execute(
            "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
            (now, requester_id, 'rejected', f"purpose 不符：{payload.get('purpose')}"),
        )
        return jsonify({"status": "error", "code": "PURPOSE_INVALID",
                        "message": "purpose 必須為 'tally'"}), 403  # <3

    # 步驟 4：時間戳（雙向 ΔT）
    timestamp = payload.get('timestamp', 0)
    time_diff = abs(now - timestamp)
    if time_diff > DELTA_T:
        db.execute(
            "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
            (now, requester_id, 'rejected', f'時間誤差超過容許範圍：{time_diff} 秒'),
        )
        return jsonify({"status": "error", "code": "TIMESTAMP_OUT_OF_RANGE",
                        "message": f"時間誤差超過容許範圍：{time_diff} 秒 > {DELTA_T} 秒"}), 403  # <3

    # 步驟 5：nonce 必須存在且未使用過
    # v2.0 修正：先前用 `if nonce:` 做真值判斷，nonce 為空字串時會整段跳過
    # 防重放檢查；現在缺少 nonce 直接視為錯誤拒絕。 <3
    nonce = payload.get('nonce', '')
    if not nonce:
        db.execute(
            "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
            (now, requester_id, 'rejected', 'nonce 缺漏'),
        )
        return jsonify({"status": "error", "code": "NONCE_MISSING",
                        "message": "缺少 nonce，無法防重放"}), 403  # <3

    existing = db.fetchone("SELECT nonce FROM used_nonces WHERE nonce = ?", (nonce,))
    if existing:
        db.execute(
            "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
            (now, requester_id, 'rejected', 'NONCE_REPLAY'),
        )
        return jsonify({
            "status": "error",
            "code": "NONCE_REPLAY",
            "message": "nonce 已使用過（重放攻擊）"
        }), 403

    # 步驟 6：驗證簽章（canonical JSON，規格書 §18.6）
    # v4.0 修正：改呼叫共用的 shared.crypto_utils.verify_signature()，不再
    # 手刻一份 PSS padding 參數——原本這裡用 PSS.MAX_LENGTH，跟
    # auth_component.py 的 verify_auth_component() 用 PSS.AUTO 不一致，
    # 雖然目前所有簽章端都固定用 MAX_LENGTH 簽章、兩種驗證寫法剛好都算
    # 得過，但重複維護五份幾乎相同的「建 PSS padding 物件」邏輯，容易在
    # 未來改動時悄悄產生真正的不相容。 <3
    payload_bytes = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if _requester_pub is None or not verify_signature(payload_bytes, base64.b64decode(signature_b64), _requester_pub):
        db.execute(
            "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
            (now, requester_id, 'rejected', '簽章驗證失敗'),
        )
        return jsonify({"status": "error", "code": "SIGNATURE_INVALID",
                        "message": "release_key 請求簽章驗證失敗"}), 403  # <3

    # 記錄 nonce（防重放）
    db.execute("INSERT INTO used_nonces (nonce, used_at) VALUES (?, ?)", (nonce, now))
    print(f"[TA] release_key 請求驗證通過（請求方：{requester_id}）")

    # 步驟 7：釋放 SK_TA
    db.execute(
        "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
        (now, requester_id, 'released', None),
    )
    print(f"[TA] ✅ SK_TA 已釋放給 {requester_id}（Unix ts：{now}  →  {ts_to_human(now)}）")

    return jsonify({
        "status":          "released",
        "private_key_pem": _private_key_pem,
        "d_hex":           int_to_hex(_d),
        "n_hex":           int_to_hex(_n),
        "released_at":     now,
    }), 200


@app.route('/api/start_election', methods=['POST'])
def api_start_election():
    """
    [POST] 手動啟動選舉（管理員操作）。
    讀取 config.json 的 timing.vote_duration_seconds，計算截止時間，
    將選舉狀態從 standby 切換至 running。
    已啟動後再次呼叫回傳 409。

    v4.0 修正：原本這個端點完全沒有身分檢查，只靠 mTLS 擋「有沒有合法憑
    證」，沒擋「這個合法憑證是不是真的有權限做這件事」——這套 PKI 核發過
    憑證的任何實體（TPA、CC、BB、甚至選民端服務）都能呼叫這個端點提早
    開始投票，跟旁邊 /api/release_key 嚴格要求 Subject CN 必須是 CC 的
    作法不一致。改成要求 Admin Bearer Token，比照 CA 的 /api/admin/* 與
    CC 的 /api/tally 既有作法。 <3
    """
    if not check_admin_token():
        return jsonify(admin_auth_error()), 401  # <3

    current_state = _get_election_state()
    if current_state == 'running':
        deadline = _get_deadline_ts()
        return jsonify({
            "status":       "error",
            "code":         "ALREADY_STARTED",
            "message":      "選舉已啟動，無法重複啟動",
            "deadline":     deadline,
            "deadline_str": ts_to_human(deadline),
        }), 409

    duration = get_vote_duration()
    now = int(time.time())
    deadline = now + duration

    db.execute("INSERT OR REPLACE INTO election_state (key, value) VALUES ('state', 'running')")
    db.execute("INSERT OR REPLACE INTO election_state (key, value) VALUES ('deadline', ?)", (str(deadline),))

    print(f"[TA] ✅ 選舉已啟動！持續 {duration} 秒，截止時間：{deadline}  →  {ts_to_human(deadline)}")

    return jsonify({
        "status":           "success",
        "message":          f"選舉已啟動，投票持續 {duration} 秒",
        "deadline":         deadline,
        "deadline_str":     ts_to_human(deadline),
        "duration_seconds": duration,
        "started_at":       now,
    }), 200


@app.route('/api/admin/reset_election', methods=['POST'])
def api_admin_reset_election():
    """[POST] 重置選舉狀態至 standby（新一輪前使用）。清除截止時間與 nonce 記錄。

    v4.0 修正：同 /api/start_election，原本無任何身分檢查，任何持有這套
    PKI 合法憑證的實體都能呼叫，清空進行中選舉的截止時間與 nonce 記錄，
    等同一次可重複發動的服務中斷攻擊。改成要求 Admin Bearer Token。 <3
    """
    if not check_admin_token():
        return jsonify(admin_auth_error()), 401  # <3

    db.execute("INSERT OR REPLACE INTO election_state (key, value) VALUES ('state', 'standby')")
    db.execute("DELETE FROM election_state WHERE key = 'deadline'")
    db.execute("DELETE FROM used_nonces")
    print("[TA] 選舉狀態已重置至 standby。")
    return jsonify({"status": "success", "message": "選舉狀態已重置至 standby"}), 200


# ── Config Hot-Reload 端點 ────────────────────────────────────
make_reload_endpoint(app)


if __name__ == '__main__':
    # v4.0 新增：TA 只會被 TPA（查公鑰）與 CC（釋放金鑰）連線，兩者都是
    # 已經跑過自己的 CA 憑證 bootstrap 流程的內部服務，要求對方出示合法
    # mTLS 憑證不會擋到任何合法流量。
    _ca_cert_path = os.path.join(KEYS_DIR, "ca_cert.pem")
    _ssl_ctx = build_mtls_server_context(
        _tls_cert_path, _tls_key_path, _ca_cert_path, require_client_cert=True,
    )
    app.run(host='0.0.0.0', port=5002, debug=False, ssl_context=_ssl_ctx)
