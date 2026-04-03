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

# 確保 shared/ 可被 import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string

from shared.key_manager import (
    load_or_generate_keypair,
    load_or_request_certificate,
    load_or_fetch_ca_cert,
)
from shared.format_utils import int_to_hex, ts_to_human
from shared.db_utils import Database
from shared.config_loader import make_reload_endpoint, get_vote_duration

# ============================================================
# 常數設定
# ============================================================
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR    = os.path.join(SERVICE_DIR, "keys")
DB_PATH     = os.path.join(SERVICE_DIR, "ta.db")
TA_ID       = "TA"
CA_URL      = os.environ.get("CA_URL", "http://localhost:5001")

# 投票截止時間：從環境變數讀取（Unix timestamp），預設為啟動後 N 秒（由 config.json 決定）
_default_deadline = int(time.time()) + int(os.environ.get("VOTE_DURATION_SECONDS", str(get_vote_duration())))
DEADLINE = int(os.environ.get("VOTE_DEADLINE", str(_default_deadline)))

# ============================================================
# 資料庫初始化
# ============================================================
db = Database(DB_PATH)
db.execute("""
    CREATE TABLE IF NOT EXISTS key_release_log (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        requested_at INTEGER NOT NULL,
        status       TEXT NOT NULL,
        reason       TEXT
    )
""")

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
    _cert_pem = load_or_request_certificate(KEYS_DIR, TA_ID, _public_key_pem, CA_URL)
except Exception as ex:
    print(f"[TA] 警告：無法取得憑證（{ex}）")
    _cert_pem = ""

# 日誌使用人類可讀格式（ts_to_human 確保時區正確）
print(f"[TA] 初始化完成。投票截止時間（Unix）：{DEADLINE}  →  {ts_to_human(DEADLINE)}")

# ============================================================
# Flask App
# ============================================================
app = Flask(__name__)

# ── HTML 模板 ──────────────────────────────────────────────
_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TA 時間授權中心</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">
  <div class="max-w-3xl mx-auto px-4 py-10">

    <!-- Header -->
    <div class="flex items-center gap-4 mb-8">
      <div class="w-12 h-12 rounded-xl bg-amber-600 flex items-center justify-center text-2xl">⏱️</div>
      <div>
        <h1 class="text-2xl font-bold text-white">時間授權中心 (TA)</h1>
        <p class="text-gray-400 text-sm">NUTC Voting System · Time Authority</p>
      </div>
      <span id="status-badge" class="ml-auto px-3 py-1 rounded-full text-xs font-semibold
        {% if is_expired %}bg-red-900 text-red-300{% else %}bg-green-900 text-green-300{% endif %}">
        {% if is_expired %}● 投票已截止{% else %}● 投票進行中{% endif %}
      </span>
    </div>

    <!-- Countdown Card -->
    <div class="bg-gray-900 rounded-2xl border border-gray-800 p-8 mb-6 text-center">
      {% if is_expired %}
      <p class="text-red-400 text-lg font-semibold mb-2">投票已截止</p>
      <p class="text-gray-400 text-sm">SK_TA 已可釋放給計票中心（CC）</p>
      <div class="mt-6 grid grid-cols-4 gap-3">
        <div class="bg-gray-800 rounded-xl p-4"><p class="text-3xl font-bold text-red-400">00</p><p class="text-xs text-gray-500 mt-1">時</p></div>
        <div class="bg-gray-800 rounded-xl p-4"><p class="text-3xl font-bold text-red-400">00</p><p class="text-xs text-gray-500 mt-1">分</p></div>
        <div class="bg-gray-800 rounded-xl p-4"><p class="text-3xl font-bold text-red-400">00</p><p class="text-xs text-gray-500 mt-1">秒</p></div>
        <div class="bg-gray-800 rounded-xl p-4"><p class="text-3xl font-bold text-red-400">00</p><p class="text-xs text-gray-500 mt-1">毫秒</p></div>
      </div>
      {% else %}
      <p class="text-amber-400 text-lg font-semibold mb-2">距離投票截止</p>
      <!-- UI 顯示：人類可讀格式（YYYY-MM-DD HH:MM:SS），由後端 ts_to_human() 轉換 -->
      <p class="text-gray-400 text-sm mb-1">截止時間：<span class="text-amber-300 font-mono">{{ deadline_str }}</span></p>
      <p class="text-gray-600 text-xs mb-6">Unix timestamp：{{ deadline_ts }}</p>
      <div class="grid grid-cols-4 gap-3" id="countdown">
        <div class="bg-gray-800 rounded-xl p-4">
          <p class="text-3xl font-bold text-amber-400" id="cd-hours">--</p>
          <p class="text-xs text-gray-500 mt-1">時</p>
        </div>
        <div class="bg-gray-800 rounded-xl p-4">
          <p class="text-3xl font-bold text-amber-400" id="cd-minutes">--</p>
          <p class="text-xs text-gray-500 mt-1">分</p>
        </div>
        <div class="bg-gray-800 rounded-xl p-4">
          <p class="text-3xl font-bold text-amber-400" id="cd-seconds">--</p>
          <p class="text-xs text-gray-500 mt-1">秒</p>
        </div>
        <div class="bg-gray-800 rounded-xl p-4">
          <p class="text-3xl font-bold text-amber-400" id="cd-ms">--</p>
          <p class="text-xs text-gray-500 mt-1">毫秒</p>
        </div>
      </div>
      {% endif %}
    </div>

    <!-- Key Status -->
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
      <div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
        <p class="text-gray-400 text-xs mb-1">SK_TA 狀態</p>
        <p class="text-lg font-bold {% if is_expired %}text-red-400{% else %}text-green-400{% endif %}">
          {% if is_expired %}可釋放{% else %}鎖定中{% endif %}
        </p>
      </div>
      <div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
        <p class="text-gray-400 text-xs mb-1">釋放請求次數</p>
        <p class="text-3xl font-bold text-amber-400">{{ release_count }}</p>
      </div>
    </div>

    <!-- Release Log -->
    <div class="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-800">
        <h2 class="font-semibold text-gray-200">金鑰釋放記錄</h2>
      </div>
      {% if release_logs %}
      <table class="w-full text-sm">
        <thead class="bg-gray-800 text-gray-400 text-xs uppercase">
          <tr>
            <th class="px-6 py-3 text-left">#</th>
            <th class="px-6 py-3 text-left">狀態</th>
            <th class="px-6 py-3 text-left">原因</th>
            <th class="px-6 py-3 text-left">時間（人類可讀）</th>
            <th class="px-6 py-3 text-left">Unix ts</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-800">
          {% for log in release_logs %}
          <tr class="hover:bg-gray-800/50 transition">
            <td class="px-6 py-3 text-gray-500">{{ log.id }}</td>
            <td class="px-6 py-3">
              {% if log.status == 'released' %}
              <span class="px-2 py-0.5 rounded-full bg-green-900 text-green-300 text-xs">✓ 已釋放</span>
              {% else %}
              <span class="px-2 py-0.5 rounded-full bg-red-900 text-red-300 text-xs">拒絕</span>
              {% endif %}
            </td>
            <td class="px-6 py-3 text-gray-400 text-xs">{{ log.reason or '—' }}</td>
            <!-- UI 顯示：人類可讀格式（ts_to_str 過濾器使用 ts_to_human，時區正確） -->
            <td class="px-6 py-3 text-gray-300 text-xs font-mono">{{ log.requested_at | ts_to_str }}</td>
            <td class="px-6 py-3 text-gray-500 text-xs">{{ log.requested_at }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <div class="px-6 py-10 text-center text-gray-500">尚無釋放記錄</div>
      {% endif %}
    </div>

  </div>

  {% if not is_expired %}
  <script>
    // 後端傳入 Unix timestamp（整數秒），前端轉毫秒做倒數
    const deadline = {{ deadline_ts }} * 1000;
    function update() {
      const now = Date.now();
      const diff = Math.max(0, deadline - now);
      if (diff === 0) { location.reload(); return; }
      const h  = Math.floor(diff / 3600000);
      const m  = Math.floor((diff % 3600000) / 60000);
      const s  = Math.floor((diff % 60000) / 1000);
      const ms = Math.floor((diff % 1000) / 10);
      document.getElementById('cd-hours').textContent   = String(h).padStart(2,'0');
      document.getElementById('cd-minutes').textContent = String(m).padStart(2,'0');
      document.getElementById('cd-seconds').textContent = String(s).padStart(2,'0');
      document.getElementById('cd-ms').textContent      = String(ms).padStart(2,'0');
    }
    setInterval(update, 50);
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
    is_expired = now >= DEADLINE
    release_logs = db.fetchall(
        "SELECT id, status, reason, requested_at FROM key_release_log ORDER BY id DESC LIMIT 20"
    )
    release_count = db.count("key_release_log")
    return render_template_string(
        _DASHBOARD_HTML,
        is_expired=is_expired,
        deadline_str=ts_to_human(DEADLINE),  # 人類可讀（時區正確）
        deadline_ts=DEADLINE,                # Unix timestamp（傳給 JS 倒數）
        release_logs=release_logs,
        release_count=release_count,
    )


@app.route('/api/public_key', methods=['GET'])
def api_public_key():
    """[GET] 回傳 TA 公鑰 PEM"""
    return jsonify({
        "status":         "success",
        "public_key_pem": _public_key_pem,
    }), 200


@app.route('/api/deadline', methods=['GET'])
def api_deadline():
    """
    [GET] 回傳截止時間資訊。
    後端/API 一律回傳 Unix timestamp；
    deadline_str / server_time_str 僅供 UI/日誌顯示用。
    """
    now = int(time.time())
    remaining = max(0, DEADLINE - now)
    return jsonify({
        "status":            "success",
        # ── Unix timestamp（後端標準）──
        "deadline":          DEADLINE,
        "server_time":       now,
        "remaining_seconds": remaining,
        "is_expired":        now >= DEADLINE,
        # ── 人類可讀（僅供 UI/日誌，時區正確）──
        "deadline_str":      ts_to_human(DEADLINE),
        "server_time_str":   ts_to_human(now),
    }), 200


@app.route('/api/release_key', methods=['POST'])
def api_release_key():
    """
    [POST] 釋放 SK_TA（僅在截止後允許）。
    回傳：{"status": "released", "private_key_pem": ..., "d_hex": ..., "n_hex": ..., "released_at": <Unix ts>}
    """
    now = int(time.time())

    if now < DEADLINE:
        remaining = DEADLINE - now
        db.execute(
            "INSERT INTO key_release_log (requested_at, status, reason) VALUES (?, ?, ?)",
            (now, 'rejected', f'投票尚未截止（還有 {remaining} 秒）'),
        )
        return jsonify({
            "status":            "rejected",
            "message":           f"投票尚未截止，還有 {remaining} 秒",
            "remaining_seconds": remaining,
            # Unix timestamp（後端標準）
            "deadline":          DEADLINE,
            "server_time":       now,
        }), 403

    db.execute(
        "INSERT INTO key_release_log (requested_at, status, reason) VALUES (?, ?, ?)",
        (now, 'released', None),
    )
    # 日誌使用人類可讀格式（時區正確）
    print(f"[TA] SK_TA 已釋放（Unix ts：{now}  →  {ts_to_human(now)}）")

    return jsonify({
        "status":          "released",
        "private_key_pem": _private_key_pem,
        "d_hex":           int_to_hex(_d),
        "n_hex":           int_to_hex(_n),
        # Unix timestamp（後端標準）
        "released_at":     now,
    }), 200


# ── Config Hot-Reload 端點 ────────────────────────────────────
make_reload_endpoint(app)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)
