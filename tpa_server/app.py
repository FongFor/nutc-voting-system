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
import secrets
import base64
import datetime

from cryptography import x509  # <3 新增：驗證 Voter 憑證的 CA 簽章鏈需要載入憑證物件
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.asymmetric import padding as _asym_padding

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
from shared.blind_signature import blind_sign
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
db.execute("""
    CREATE TABLE IF NOT EXISTS blind_sign_log (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        blinded_m_hex   TEXT NOT NULL,
        signed_b_m_hex  TEXT NOT NULL,
        created_at      INTEGER NOT NULL
    )
""")
db.execute("""
    CREATE TABLE IF NOT EXISTS issued_tokens (
        token_id    TEXT PRIMARY KEY,
        voter_id    TEXT NOT NULL,
        issued_at   INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL,
        used        INTEGER NOT NULL DEFAULT 0
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
    選舉狀態 + 截止時間強制執行 Middleware。
    每次都向 TA 重新查詢，避免快取失效問題。
    回傳 None 表示允許繼續；回傳 Response 表示應立即拒絕。
    """
    global _DEADLINE, _ELECTION_STATE
    import requests as _req
    election_state = _ELECTION_STATE
    deadline = _DEADLINE
    try:
        resp = _req.get(f"{TA_URL}/api/deadline", timeout=5)
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
            "message": "選舉尚未啟動，請等待管理員開始選舉",
        }), 403

    if deadline <= 0:
        return None

    now = int(time.time())
    if now > deadline:
        remaining_over = now - deadline
        print(f"[TPA] Deadline Middleware 拒絕請求：已超時 {remaining_over} 秒（Unix ts：{now} > {deadline}）")
        return jsonify({
            "status":       "error",
            "code":         "DEADLINE_EXCEEDED",
            "message":      f"投票已截止，無法處理此請求（已超時 {remaining_over} 秒）",
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TPA 盲簽章授權中心</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            msblue: '#0078D4',
            msblueHover: '#0060A8',
            deepblack: '#050505',
            cardblack: '#111111'
          }
        }
      }
    }
  </script>
  <link href="https://fonts.googleapis.com/css2?family=Noto+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Noto Sans', sans-serif; }
    /* 隱藏捲軸但保留功能 */
    pre::-webkit-scrollbar { height: 8px; }
    pre::-webkit-scrollbar-track { background: transparent; }
    pre::-webkit-scrollbar-thumb { background: rgba(156, 163, 175, 0.5); border-radius: 4px; }
  </style>
  <script>
    if (localStorage.getItem('theme') === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    function toggleTheme() {
      if (document.documentElement.classList.contains('dark')) {
        document.documentElement.classList.remove('dark');
        localStorage.setItem('theme', 'light');
      } else {
        document.documentElement.classList.add('dark');
        localStorage.setItem('theme', 'dark');
      }
    }
  </script>
  <meta http-equiv="refresh" content="15">
</head>
<body class="bg-gray-50 dark:bg-deepblack text-gray-800 dark:text-gray-100 min-h-screen transition-colors duration-300">
  <div class="max-w-5xl mx-auto px-4 py-10">

    <div class="flex items-center gap-4 mb-8">
      <div class="w-12 h-12 rounded-xl bg-white/70 dark:bg-cardblack/80 backdrop-blur-md shadow-sm flex items-center justify-center border border-gray-200 dark:border-gray-800">
        <svg class="w-6 h-6 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
      </div>
      <div>
        <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">第三方授權中心 (TPA)</h1>
        <p class="text-gray-500 dark:text-gray-400 text-sm">NUTC Voting System · Third-Party Authenticator</p>
      </div>
      
      <div class="ml-auto flex items-center gap-3">
        <span class="px-3 py-1.5 rounded-full text-xs font-medium border bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border-green-200 dark:border-green-800/50 backdrop-blur-sm flex items-center shadow-sm">
          <span class="inline-block w-1.5 h-1.5 rounded-full bg-green-500 mr-1.5 shadow-[0_0_4px_#22c55e]"></span> 運作中
        </span>
        
        <button onclick="toggleTheme()" class="p-2 rounded-lg bg-white/70 dark:bg-cardblack/80 border border-gray-200 dark:border-gray-800 shadow-sm hover:bg-gray-100 dark:hover:bg-gray-900 transition-colors text-gray-600 dark:text-gray-300 focus:outline-none focus:ring-2 focus:ring-msblue/50">
          <svg class="w-4 h-4 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
          <svg class="w-4 h-4 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
        </button>
      </div>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-3 gap-5 mb-8">
      <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-5 flex flex-col justify-center transition-all hover:shadow-lg">
        <p class="text-gray-500 dark:text-gray-400 text-xs font-medium uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <svg class="w-3.5 h-3.5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"></path></svg>
          已核發盲簽章
        </p>
        <p class="text-3xl font-semibold text-gray-900 dark:text-white">{{ sign_count }}</p>
      </div>
      <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-5 flex flex-col justify-center transition-all hover:shadow-lg">
        <p class="text-gray-500 dark:text-gray-400 text-xs font-medium uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <svg class="w-3.5 h-3.5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
          金鑰演算法
        </p>
        <p class="text-lg font-medium text-gray-800 dark:text-gray-200">RSA-FDH <span class="text-gray-400 dark:text-gray-600 font-light mx-1">/</span> 2048-bit</p>
      </div>
      <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-5 flex flex-col justify-center transition-all hover:shadow-lg">
        <p class="text-gray-500 dark:text-gray-400 text-xs font-medium uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <svg class="w-3.5 h-3.5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
          簽章狀態
        </p>
        {% if election_state == 'standby' %}
        <p class="text-lg font-medium text-amber-600 dark:text-amber-500 flex items-center gap-1">
          ⏸ 等待管理員啟動選舉
        </p>
        {% else %}
        <p class="text-lg font-medium text-green-600 dark:text-green-500 flex items-center gap-1">
          開放請求中
        </p>
        {% endif %}
      </div>
    </div>

    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-100 dark:border-gray-800/60 bg-gray-50/50 dark:bg-[#0a0a0a]/50 flex items-center justify-between">
        <h2 class="font-medium text-gray-800 dark:text-gray-200 text-sm">盲簽章核發記錄</h2>
        <span class="text-[10px] text-gray-500 dark:text-gray-500 flex items-center gap-1.5">
          <span class="relative flex h-1.5 w-1.5">
            <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-msblue opacity-40"></span>
            <span class="relative inline-flex rounded-full h-1.5 w-1.5 bg-msblue"></span>
          </span>
          自動更新
        </span>
      </div>
      {% if logs %}
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead class="bg-gray-50 dark:bg-[#0a0a0a] text-gray-500 dark:text-gray-400 text-xs uppercase tracking-wider">
            <tr>
              <th class="px-6 py-3.5 text-left font-medium">#</th>
              <th class="px-6 py-3.5 text-left font-medium">盲化訊息 (前 20)</th>
              <th class="px-6 py-3.5 text-left font-medium">盲簽章結果 (前 20)</th>
              <th class="px-6 py-3.5 text-left font-medium">核發時間</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100 dark:divide-gray-800">
            {% for log in logs %}
            <tr class="hover:bg-gray-50 dark:hover:bg-[#1a1a1a] transition-colors">
              <td class="px-6 py-4 text-gray-400 dark:text-gray-600 text-xs">{{ log.id }}</td>
              <td class="px-6 py-4 font-mono font-medium text-gray-600 dark:text-gray-400 text-[11px]">{{ log.blinded_m_hex[:20] }}...</td>
              <td class="px-6 py-4 font-mono font-medium text-msblue dark:text-[#3399FF] text-[11px]">{{ log.signed_b_m_hex[:20] }}...</td>
              <td class="px-6 py-4">
                <p class="text-gray-600 dark:text-gray-400 text-[11px] font-mono">{{ log.created_at | ts_to_str }}</p>
                <p class="text-gray-400 dark:text-gray-600 text-[10px]">{{ log.created_at }}</p>
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% else %}
      <div class="px-6 py-12 text-center text-gray-500 dark:text-gray-500">
        <svg class="w-10 h-10 mx-auto text-gray-300 dark:text-gray-700 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
        <p class="text-sm">尚未核發任何盲簽章</p>
      </div>
      {% endif %}
    </div>

    <div class="mt-6 bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-6">
      <div class="flex justify-between items-center mb-4">
        <h2 class="font-medium text-gray-800 dark:text-gray-200 flex items-center gap-2 text-sm">
          <svg class="w-4 h-4 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path></svg>
          公鑰（PEM 格式預覽）
        </h2>
        <span class="text-[11px] text-gray-400 dark:text-gray-500 border border-gray-200 dark:border-gray-700 px-2 py-0.5 rounded-md">公開資訊</span>
      </div>
      <div class="bg-gray-50 dark:bg-[#050505] rounded-lg p-5 border border-gray-100 dark:border-gray-800/80 shadow-inner">
        <pre class="text-[11px] leading-relaxed text-gray-600 dark:text-gray-400 font-mono overflow-x-auto whitespace-pre-wrap break-all">{{ pk_pem }}</pre>
      </div>
    </div>

  </div>
</body>
</html>"""
# ── 路由 ──────────────────────────────────────────────────

@app.route('/')
def dashboard():
    # 盲簽章記錄（供儀表板表格顯示）
    logs = db.fetchall(
        "SELECT id, blinded_m_hex, signed_b_m_hex, created_at FROM blind_sign_log ORDER BY id DESC LIMIT 20"
    )
    sign_count    = db.count("blind_sign_log")

    voted_users   = db.fetchall("SELECT sender_id, voted_at FROM voted_users ORDER BY voted_at DESC")
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
    election_state = _ELECTION_STATE

    return render_template_string(
        _DASHBOARD_HTML,
        logs=logs,
        sign_count=sign_count,
        pk_pem=_public_key_pem,
        voted_users=voted_users,
        total_auth=total_auth,
        success_auth=success_auth,
        rejected_auth=rejected_auth,
        voted_count=voted_count,
        deadline_ts=deadline if deadline > 0 else None,
        deadline_str=deadline_str_local,
        is_expired=is_expired,
        election_state=election_state,
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
        # v2.0 修正：補上 code 欄位，統一符合規格書 §18 通用錯誤格式。 <3
        return jsonify({"status": "error", "code": "MISSING_FIELDS",
                        "message": "缺少 auth_packet 或 voter_cert_pem"}), 400  # <3

    packet       = data['auth_packet']
    voter_cert_pem = data['voter_cert_pem']
    payload      = packet.get('payload', {})
    sender_id    = payload.get('sender_id', '')
    # v2.0：欄位名改為 nonce，向後兼容讀取舊名 si
    si           = payload.get('nonce', payload.get('si', ''))
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
        # v2.0 修正：補上 code 欄位（§2.5 錯誤碼表）。 <3
        return jsonify({"status": "error", "code": "NONCE_REPLAY",
                        "message": "重放攻擊：nonce 已使用"}), 403  # <3

    # ── 防重複投票：檢查 sender_id ───────────────────────
    if db.exists("SELECT 1 FROM voted_users WHERE sender_id = ?", (sender_id,)):
        _log('rejected', f'重複投票：{sender_id} 已投票')
        return jsonify({"status": "error", "code": "ALREADY_VOTED",
                        "message": f"{sender_id} 已投票，不可重複投票"}), 403  # <3

    # ── 升級認證：verify_auth_component ─────────────────
    import base64
    try:
        signature_bytes = base64.b64decode(packet['signature'])

        # Fail-secure：沒有 CA 憑證就無法驗證 Voter 身分，一律拒絕而非放行 <3
        if not _ca_cert_pem:
            _log('rejected', 'TPA 無 CA 憑證，無法驗證請求方身分')
            return jsonify({
                "status": "error",
                "code": "CA_CERT_UNAVAILABLE",
                "message": "TPA 無法取得 CA 憑證，無法驗證請求方身分"
            }), 500  # <3

        if not verify_cert_with_ca(voter_cert_pem, _ca_cert_pem):
            _log('rejected', 'Voter 憑證 CA 驗證失敗')
            return jsonify({"status": "error", "code": "CERT_INVALID",
                            "message": "Voter 憑證 CA 驗證失敗"}), 403  # <3

        _ca_cert_obj = x509.load_pem_x509_certificate(_ca_cert_pem.encode('utf-8'))  # <3
        _ca_pub = _ca_cert_obj.public_key()  # <3

        verify_auth_component(
            expected_receiver_id=TPA_ID,
            sender_id=sender_id,
            packet_receiver_id=payload.get('receiver_id', ''),
            packet_timestamp=timestamp,
            packet_cert_pem=voter_cert_pem,
            packet_signature=signature_bytes,
            packet_nonce=si,      # v2.0：packet_si → packet_nonce
            ca_public_key=_ca_pub,  # <3 之前固定傳 None，CA 簽章鏈驗證形同虛設，現在確實傳入 CA 公鑰
            delta_t=DELTA_T,
        )
    except Exception as exc:
        _log('rejected', str(exc))
        # v2.0 修正：verify_auth_component 拋出的例外訊息裡通常已經帶有明確
        # 的失敗原因，這裡對照規格書 §2.5 錯誤碼表做字串比對分類，統一補上
        # code 欄位，而不是一律回傳沒有 code 的通用訊息。 <3
        _error_msg = str(exc)
        if "CERT_INVALID" in _error_msg:
            _code = "CERT_INVALID"
        elif "接收方 ID 不符" in _error_msg:
            _code = "RECEIVER_ID_MISMATCH"
        elif "時間誤差超過" in _error_msg:
            _code = "TIMESTAMP_OUT_OF_RANGE"
        elif "nonce_echo 不符" in _error_msg:
            _code = "NONCE_ECHO_MISMATCH"
        else:
            _code = "SIGNATURE_INVALID"  # <3
        return jsonify({"status": "error", "code": _code,
                        "message": f"認證失敗：{exc}"}), 403  # <3

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
    print(f"[TPA] 認證成功：{sender_id}（Unix ts：{now}  →  {ts_to_human(now)}）")

    # ── 生成 TPA 認證回應封包 ────────────────────────────
    response_packet = create_auth_packet(TPA_ID, sender_id, _private_key, _cert_pem)

    # ── 簽發 Voting Token（Phase 2 Step 2.3） ────────────
    deadline = _get_deadline()
    token_lifetime = 600  # 10 分鐘
    expires_at = min(deadline, now + token_lifetime) if deadline > 0 else now + token_lifetime

    token_id = secrets.token_hex(32)
    token_payload = {
        "token_id":   token_id,
        "voter_id":   sender_id,
        "issued_at":  now,
        "expires_at": expires_at,
        "nonce_bind": si,
    }
    # v2.0 修正：補上 separators=(',', ':') 做 canonical JSON（規格書 §18.6）。
    # 先前缺少此參數，TPA 自簽自驗雖能自洽，但外部稽核工具照規格重建
    # canonical JSON 後會因序列化結果不同而驗章失敗。 <3
    token_payload_bytes = json.dumps(token_payload, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')  # <3
    token_sig = _private_key.sign(
        token_payload_bytes,
        _asym_padding.PSS(
            mgf=_asym_padding.MGF1(_hashes.SHA256()),
            salt_length=_asym_padding.PSS.MAX_LENGTH,
        ),
        _hashes.SHA256(),
    )
    voting_token = {
        "payload":   token_payload,
        "signature": base64.b64encode(token_sig).decode('utf-8'),
    }

    db.execute(
        "INSERT INTO issued_tokens (token_id, voter_id, issued_at, expires_at, used) VALUES (?, ?, ?, ?, 0)",
        (token_id, sender_id, now, expires_at),
    )
    print(f"[TPA] 已簽發 Voting Token：{token_id[:16]}...（expires: {ts_to_human(expires_at)}）")

    return jsonify({
        "status":          "success",
        "response_packet": response_packet,
        "tpa_cert_pem":    _cert_pem,
        "voting_token":    voting_token,
    }), 200


@app.route('/api/blind_sign', methods=['POST'])
def api_blind_sign():
    """
    [POST] 對盲化選票執行盲簽章。（Phase 3 Step 3.5-3.6）
    截止時間後回傳 HTTP 403。
    Body: {"m_prime_hex": "0x...", "voting_token": {...}}
    回傳: {"S_hex": "0x..."}
    Token 驗證：簽章有效 + 未過期 + 未使用，用後標記為 used。
    """
    # ── Deadline Middleware ──────────────────────────────────
    deadline_resp = _check_deadline()
    if deadline_resp is not None:
        return deadline_resp

    data = request.get_json()
    if not data or 'm_prime_hex' not in data:
        return jsonify({"status": "error", "message": "缺少 m_prime_hex"}), 400

    now = int(time.time())

    # ── Voting Token 驗證 ────────────────────────────────────
    # v2.0 修正：Token 之前是可選的（缺 Token 只印警告照樣簽），等於任何人
    # 都能跳過 Phase 2 身分驗證直接拿到盲簽章。現在強制要求 Token。 <3
    voting_token = data.get('voting_token')
    if not voting_token:
        return jsonify({"status": "error", "code": "TOKEN_REQUIRED",
                        "message": "缺少 Voting Token，必須先完成 Phase 2 身分驗證取得授權"}), 403  # <3

    token_payload = voting_token.get('payload', {})
    token_sig_b64 = voting_token.get('signature', '')
    token_id      = token_payload.get('token_id', '')

    # b. 驗證 Token 簽章
    try:
        # v2.0 修正：與簽發端一致，補上 canonical JSON 的 separators。 <3
        token_payload_bytes = json.dumps(token_payload, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')  # <3
        token_sig = base64.b64decode(token_sig_b64)
        _public_key.verify(
            token_sig,
            token_payload_bytes,
            _asym_padding.PSS(
                mgf=_asym_padding.MGF1(_hashes.SHA256()),
                salt_length=_asym_padding.PSS.MAX_LENGTH,
            ),
            _hashes.SHA256(),
        )
    except Exception:
        return jsonify({"status": "error", "code": "TOKEN_SIGNATURE_INVALID",
                        "message": "Voting Token 簽章驗證失敗"}), 403

    # c. 驗證 Token 是否過期
    if now > token_payload.get('expires_at', 0):
        return jsonify({"status": "error", "code": "TOKEN_EXPIRED",
                        "message": "Voting Token 已過期"}), 403

    # d+e. 驗證 Token 未使用，並以「原子條件更新」標記已使用
    # v2.0 修正：原本是先 SELECT 查 used 再另外 UPDATE，兩步之間存在 TOCTOU
    # 競態，併發請求可能讓同一 Token 被消耗兩次。現在改成單一原子 UPDATE ...
    # WHERE used = 0，用 rowcount 判斷是否搶佔成功。 <3
    row = db.fetchone(
        "SELECT used FROM issued_tokens WHERE token_id = ?", (token_id,)
    )
    if not row:
        return jsonify({"status": "error", "code": "TOKEN_NOT_FOUND",
                        "message": "Token 不存在（可能由非本 TPA 簽發）"}), 403

    claimed = db.execute(
        "UPDATE issued_tokens SET used = 1 WHERE token_id = ? AND used = 0", (token_id,)
    )  # <3 rowcount==0 代表已被搶先使用（即使剛剛的 SELECT 顯示未使用）
    if claimed == 0:
        return jsonify({"status": "error", "code": "TOKEN_ALREADY_USED",
                        "message": "Voting Token 已使用"}), 403  # <3

    print(f"[TPA] Token 已消耗：{token_id[:16]}...")

    try:
        m_prime = hex_to_int(data['m_prime_hex'])
        S = blind_sign(m_prime, _d, _n)
        S_hex = int_to_hex(S)
        db.execute(
            "INSERT INTO blind_sign_log (blinded_m_hex, signed_b_m_hex, created_at) VALUES (?, ?, ?)",
            (data['m_prime_hex'], S_hex, now),
        )
        return jsonify({"status": "success", "S_hex": S_hex}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Config Hot-Reload 端點 ────────────────────────────────────
make_reload_endpoint(app)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
