"""
tpa_server/app.py  —  第三方認證機構 (TPA)

處理選民的身分驗證和盲簽章。選民投票前必須先通過這裡的雙向認證，
確認身分合法後才能拿到盲簽章，整個過程不會知道選民投給誰。

有幾個安全機制：
- 每個認證封包都有 nonce (si)，用過就作廢，防止重放攻擊
- 記錄已投票的選民，同一個人不能投兩次
- 截止時間到了之後，認證和盲簽章請求都會被拒絕（HTTP 403）

端點：
  GET  /                  監控儀表板
  GET  /api/public_key    回傳 TPA 公鑰（含 e, n 大整數）
  POST /api/auth          驗證選民身分，回傳 TPA 認證回應
  POST /api/blind_sign    對盲化選票做盲簽章
  GET  /api/config        查看目前設定
  POST /api/config/reload 重新載入 config.json
"""

import os
import sys
import json
import time
import datetime

# 確保 shared/ 可被 import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string

from shared.key_manager import (
    load_or_generate_keypair,
    load_or_request_certificate,
    load_or_fetch_ca_cert,
    verify_cert_with_ca,
    get_public_key_from_cert,
)
from shared.auth_component import create_auth_packet, verify_auth_component
from shared.crypto_utils_test import blind_sign
from shared.format_utils import int_to_hex, hex_to_int, ts_to_human
from shared.db_utils import Database
from shared.config_loader import make_reload_endpoint, get_delta_t

# ============================================================
# 常數設定
# ============================================================
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR    = os.path.join(SERVICE_DIR, "keys")
DB_PATH     = os.path.join(SERVICE_DIR, "tpa.db")
TPA_ID      = "TPA"
CA_URL      = os.environ.get("CA_URL", "http://localhost:5001")
TA_URL      = os.environ.get("TA_URL", "http://localhost:5002")
DELTA_T     = int(os.environ.get("DELTA_T", str(get_delta_t())))

# 截止時間：優先從環境變數讀取，否則啟動時從 TA 取得
_DEADLINE: int = int(os.environ.get("VOTE_DEADLINE", "0"))

def _get_deadline() -> int:
    """
    取得投票截止時間（Unix timestamp）。
    優先順序：環境變數 VOTE_DEADLINE > TA /api/deadline > 0（不限制）
    """
    global _DEADLINE
    if _DEADLINE > 0:
        return _DEADLINE
    try:
        import requests as _req
        resp = _req.get(f"{TA_URL}/api/deadline", timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            _DEADLINE = int(data["deadline"])
            print(f"[TPA] 從 TA 取得截止時間：{_DEADLINE}  →  {data.get('deadline_str', '')}")
            return _DEADLINE
    except Exception as e:
        print(f"[TPA] 無法從 TA 取得截止時間（{e}），截止時間強制執行暫停。")
    return 0

# ============================================================
# 資料庫初始化
# ============================================================
db = Database(DB_PATH)
db.execute("""
    CREATE TABLE IF NOT EXISTS used_nonces (
        si          TEXT PRIMARY KEY,
        sender_id   TEXT NOT NULL,
        used_at     INTEGER NOT NULL
    )
""")
db.execute("""
    CREATE TABLE IF NOT EXISTS voted_users (
        sender_id   TEXT PRIMARY KEY,
        voted_at    INTEGER NOT NULL
    )
""")
db.execute("""
    CREATE TABLE IF NOT EXISTS auth_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id   TEXT NOT NULL,
        si          TEXT NOT NULL,
        status      TEXT NOT NULL,
        reason      TEXT,
        processed_at INTEGER NOT NULL
    )
""")

# ============================================================
# 金鑰初始化（啟動時執行）
# ============================================================
print(f"[TPA] 初始化金鑰...")
(
    _private_key, _public_key, _e, _n, _d,
    _private_key_pem, _public_key_pem
) = load_or_generate_keypair(KEYS_DIR)

# 取得 CA 根憑證
try:
    _ca_cert_pem = load_or_fetch_ca_cert(KEYS_DIR, CA_URL)
except Exception as ex:
    print(f"[TPA] 警告：無法取得 CA 憑證（{ex}），部分驗證功能將降級。")
    _ca_cert_pem = None

# 向 CA 申請憑證
try:
    _cert_pem = load_or_request_certificate(KEYS_DIR, TPA_ID, _public_key_pem, CA_URL)
except Exception as ex:
    print(f"[TPA] 警告：無法取得憑證（{ex}），認證回應功能將受限。")
    _cert_pem = ""

print(f"[TPA] 初始化完成。e={hex(_e)[:20]}...")

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
    截止時間強制執行 Middleware。
    若當前時間 > deadline，回傳 HTTP 403（Forbidden）。
    回傳 None 表示允許繼續；回傳 Response 表示應立即拒絕。
    """
    deadline = _get_deadline()
    if deadline <= 0:
        return None   # 未設定截止時間，允許通過

    now = int(time.time())
    if now > deadline:
        remaining_over = now - deadline
        print(f"[TPA] Deadline Middleware 拒絕請求：已超時 {remaining_over} 秒（Unix ts：{now} > {deadline}）")
        return jsonify({
            "status":       "error",
            "code":         "DEADLINE_EXCEEDED",
            "message":      f"投票已截止，無法處理此請求（已超時 {remaining_over} 秒）",
            # Unix timestamp（後端標準）
            "server_time":  now,
            "deadline":     deadline,
            # 人類可讀（僅供 UI/日誌）
            "server_time_str": ts_to_human(now),
            "deadline_str":    ts_to_human(deadline),
        }), 403
    return None


# ── HTML 模板 ──────────────────────────────────────────────
_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TPA 第三方機構</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <meta http-equiv="refresh" content="10">
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">
  <div class="max-w-5xl mx-auto px-4 py-10">

    <!-- Header -->
    <div class="flex items-center gap-4 mb-8">
      <div class="w-12 h-12 rounded-xl bg-blue-600 flex items-center justify-center text-2xl">🏛️</div>
      <div>
        <h1 class="text-2xl font-bold text-white">第三方機構 (TPA)</h1>
        <p class="text-gray-400 text-sm">NUTC Voting System · Trusted Third Party Authority</p>
      </div>
      <div class="ml-auto flex flex-col items-end gap-1">
        <span class="px-3 py-1 rounded-full bg-green-900 text-green-300 text-xs font-semibold">● 運作中</span>
        {% if deadline_ts %}
        <span class="px-3 py-1 rounded-full text-xs font-semibold
          {% if is_expired %}bg-red-900 text-red-300{% else %}bg-amber-900 text-amber-300{% endif %}">
          {% if is_expired %}🔒 投票已截止{% else %}截止：{{ deadline_str }}{% endif %}
        </span>
        {% endif %}
      </div>
    </div>

    <!-- Stats -->
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
      <div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
        <p class="text-gray-400 text-xs mb-1">已處理認證</p>
        <p class="text-3xl font-bold text-blue-400">{{ total_auth }}</p>
      </div>
      <div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
        <p class="text-gray-400 text-xs mb-1">認證成功</p>
        <p class="text-3xl font-bold text-green-400">{{ success_auth }}</p>
      </div>
      <div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
        <p class="text-gray-400 text-xs mb-1">已投票選民</p>
        <p class="text-3xl font-bold text-yellow-400">{{ voted_count }}</p>
      </div>
      <div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
        <p class="text-gray-400 text-xs mb-1">拒絕請求</p>
        <p class="text-3xl font-bold text-red-400">{{ rejected_auth }}</p>
      </div>
    </div>

    <!-- Auth Log Table -->
    <div class="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden mb-6">
      <div class="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
        <h2 class="font-semibold text-gray-200">認證記錄（最新 20 筆）</h2>
        <span class="text-xs text-gray-500">每 10 秒自動更新</span>
      </div>
      {% if logs %}
      <table class="w-full text-sm">
        <thead class="bg-gray-800 text-gray-400 text-xs uppercase">
          <tr>
            <th class="px-6 py-3 text-left">#</th>
            <th class="px-6 py-3 text-left">選民 ID</th>
            <th class="px-6 py-3 text-left">Nonce (si)</th>
            <th class="px-6 py-3 text-left">狀態</th>
            <th class="px-6 py-3 text-left">原因</th>
            <th class="px-6 py-3 text-left">時間（人類可讀）</th>
            <th class="px-6 py-3 text-left">Unix ts</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-800">
          {% for log in logs %}
          <tr class="hover:bg-gray-800/50 transition">
            <td class="px-6 py-3 text-gray-500">{{ log.id }}</td>
            <td class="px-6 py-3 font-mono text-blue-300">{{ log.sender_id }}</td>
            <td class="px-6 py-3 font-mono text-gray-400 text-xs">{{ log.si[:16] }}...</td>
            <td class="px-6 py-3">
              {% if log.status == 'success' %}
              <span class="px-2 py-0.5 rounded-full bg-green-900 text-green-300 text-xs">成功</span>
              {% else %}
              <span class="px-2 py-0.5 rounded-full bg-red-900 text-red-300 text-xs">✗ 拒絕</span>
              {% endif %}
            </td>
            <td class="px-6 py-3 text-gray-400 text-xs">{{ log.reason or '—' }}</td>
            <!-- UI 顯示：人類可讀格式 -->
            <td class="px-6 py-3 text-gray-300 text-xs font-mono">{{ log.processed_at | ts_to_str }}</td>
            <td class="px-6 py-3 text-gray-500 text-xs">{{ log.processed_at }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <div class="px-6 py-10 text-center text-gray-500">尚無認證記錄</div>
      {% endif %}
    </div>

    <!-- Voted Users -->
    <div class="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-800">
        <h2 class="font-semibold text-gray-200">已投票選民</h2>
      </div>
      {% if voted_users %}
      <table class="w-full text-sm">
        <thead class="bg-gray-800 text-gray-400 text-xs uppercase">
          <tr>
            <th class="px-6 py-3 text-left">選民 ID</th>
            <th class="px-6 py-3 text-left">投票時間（人類可讀）</th>
            <th class="px-6 py-3 text-left">Unix ts</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-800">
          {% for v in voted_users %}
          <tr class="hover:bg-gray-800/50 transition">
            <td class="px-6 py-3 font-mono text-yellow-300">{{ v.sender_id }}</td>
            <!-- UI 顯示：人類可讀格式 -->
            <td class="px-6 py-3 text-gray-300 font-mono text-xs">{{ v.voted_at | ts_to_str }}</td>
            <td class="px-6 py-3 text-gray-500 text-xs">{{ v.voted_at }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <div class="px-6 py-10 text-center text-gray-500">尚無已投票選民</div>
      {% endif %}
    </div>

  </div>
</body>
</html>"""


# ── 路由 ──────────────────────────────────────────────────

@app.route('/')
def dashboard():
    logs = db.fetchall(
        "SELECT id, sender_id, si, status, reason, processed_at FROM auth_log ORDER BY id DESC LIMIT 20"
    )
    voted_users = db.fetchall("SELECT sender_id, voted_at FROM voted_users ORDER BY voted_at DESC")
    total_auth    = db.count("auth_log")
    success_auth  = db.count("auth_log", "status = 'success'")
    rejected_auth = db.count("auth_log", "status = 'rejected'")
    voted_count   = db.count("voted_users")

    deadline = _get_deadline()
    now = int(time.time())
    is_expired = deadline > 0 and now > deadline
    deadline_str_local = (
        ts_to_human(deadline)
        if deadline > 0 else None
    )

    return render_template_string(
        _DASHBOARD_HTML,
        logs=logs,
        voted_users=voted_users,
        total_auth=total_auth,
        success_auth=success_auth,
        rejected_auth=rejected_auth,
        voted_count=voted_count,
        deadline_ts=deadline if deadline > 0 else None,
        deadline_str=deadline_str_local,
        is_expired=is_expired,
    )


@app.route('/api/public_key', methods=['GET'])
def api_public_key():
    """[GET] 回傳 TPA 公鑰 PEM 與大整數 (e, n)，供 Voter 盲化使用。"""
    return jsonify({
        "status":         "success",
        "public_key_pem": _public_key_pem,
        "e":              int_to_hex(_e),
        "n":              int_to_hex(_n),
    }), 200


@app.route('/api/auth', methods=['POST'])
def api_auth():
    """
    [POST] 驗證 Voter 認證封包，回傳 TPA 認證回應。（Phase 2）
    截止時間後回傳 HTTP 403。
    Body: {
        "auth_packet": { payload: {...}, signature: "..." },
        "voter_cert_pem": "-----BEGIN CERTIFICATE-----..."
    }
    防重放：檢查 si 是否已使用。
    防重複投票：檢查 sender_id 是否已投票。
    升級認證：使用 verify_auth_component（含 CA 憑證鏈驗證）。
    """
    # ── Deadline Middleware ──────────────────────────────────
    deadline_resp = _check_deadline()
    if deadline_resp is not None:
        return deadline_resp

    data = request.get_json()
    if not data or 'auth_packet' not in data or 'voter_cert_pem' not in data:
        return jsonify({"status": "error", "message": "缺少 auth_packet 或 voter_cert_pem"}), 400

    packet       = data['auth_packet']
    voter_cert_pem = data['voter_cert_pem']
    payload      = packet.get('payload', {})
    sender_id    = payload.get('sender_id', '')
    si           = payload.get('si', '')
    timestamp    = payload.get('timestamp', 0)
    now          = int(time.time())

    def _log(status, reason=None):
        db.execute(
            "INSERT INTO auth_log (sender_id, si, status, reason, processed_at) VALUES (?, ?, ?, ?, ?)",
            (sender_id, si, status, reason, now),
        )

    # ── 防重放：檢查 si ──────────────────────────────────
    if db.exists("SELECT 1 FROM used_nonces WHERE si = ?", (si,)):
        _log('rejected', '重放攻擊：si 已使用')
        return jsonify({"status": "error", "message": "重放攻擊：nonce 已使用"}), 403

    # ── 防重複投票：檢查 sender_id ───────────────────────
    if db.exists("SELECT 1 FROM voted_users WHERE sender_id = ?", (sender_id,)):
        _log('rejected', f'重複投票：{sender_id} 已投票')
        return jsonify({"status": "error", "message": f"{sender_id} 已投票，不可重複投票"}), 403

    # ── 升級認證：verify_auth_component ─────────────────
    import base64
    try:
        signature_bytes = base64.b64decode(packet['signature'])

        # 若有 CA 憑證，先驗證 Voter 憑證合法性
        if _ca_cert_pem:
            if not verify_cert_with_ca(voter_cert_pem, _ca_cert_pem):
                _log('rejected', 'Voter 憑證 CA 驗證失敗')
                return jsonify({"status": "error", "message": "Voter 憑證 CA 驗證失敗"}), 403

        verify_auth_component(
            expected_receiver_id=TPA_ID,
            sender_id=sender_id,
            packet_receiver_id=payload.get('receiver_id', ''),
            packet_timestamp=timestamp,
            packet_cert_pem=voter_cert_pem,
            packet_signature=signature_bytes,
            packet_si=si,
            ca_public_key=None,   # CA 公鑰驗證已在上方完成
            delta_t=DELTA_T,
        )
    except Exception as exc:
        _log('rejected', str(exc))
        return jsonify({"status": "error", "message": f"認證失敗：{exc}"}), 403

    # ── 記錄 si（防重放）────────────────────────────────
    db.execute(
        "INSERT INTO used_nonces (si, sender_id, used_at) VALUES (?, ?, ?)",
        (si, sender_id, now),
    )

    # ── 標記已投票（防重複投票）─────────────────────────
    db.execute(
        "INSERT INTO voted_users (sender_id, voted_at) VALUES (?, ?)",
        (sender_id, now),
    )

    _log('success')
    # 日誌使用人類可讀格式
    print(f"[TPA] 認證成功：{sender_id}（Unix ts：{now}  →  {ts_to_human(now)}）")

    # ── 生成 TPA 認證回應封包 ────────────────────────────
    response_packet = create_auth_packet(TPA_ID, sender_id, _private_key, _cert_pem)

    return jsonify({
        "status":          "success",
        "response_packet": response_packet,
        "tpa_cert_pem":    _cert_pem,
    }), 200


@app.route('/api/blind_sign', methods=['POST'])
def api_blind_sign():
    """
    [POST] 對盲化選票執行盲簽章。（Phase 3）
    截止時間後回傳 HTTP 403。
    Body: {"m_prime_hex": "0x..."}
    回傳: {"S_hex": "0x..."}
    注意：此端點應在 /api/auth 成功後才呼叫（由 voter_client 控制流程）。
    """
    # ── Deadline Middleware ──────────────────────────────────
    deadline_resp = _check_deadline()
    if deadline_resp is not None:
        return deadline_resp

    data = request.get_json()
    if not data or 'm_prime_hex' not in data:
        return jsonify({"status": "error", "message": "缺少 m_prime_hex"}), 400

    try:
        m_prime = hex_to_int(data['m_prime_hex'])
        S = blind_sign(m_prime, _d, _n)
        return jsonify({"status": "success", "S_hex": int_to_hex(S)}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Config Hot-Reload 端點 ────────────────────────────────────
make_reload_endpoint(app)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
