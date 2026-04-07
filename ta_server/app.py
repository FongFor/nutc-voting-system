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
  <link href="https://fonts.googleapis.com/css2?family=Noto+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Noto Sans', sans-serif; }
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
</head>
<body class="bg-gray-50 dark:bg-deepblack text-gray-800 dark:text-gray-100 min-h-screen transition-colors duration-300">
  <div class="max-w-4xl mx-auto px-4 py-10">

    <div class="flex items-center gap-4 mb-8">
      <div class="w-12 h-12 rounded-xl bg-white/70 dark:bg-cardblack/80 backdrop-blur-md shadow-sm flex items-center justify-center border border-gray-200 dark:border-gray-800">
        <svg class="w-6 h-6 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
      </div>
      <div>
        <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">時間授權中心 (TA)</h1>
        <p class="text-gray-500 dark:text-gray-400 text-sm">NUTC Voting System · Time Authority</p>
      </div>
      
      <div class="ml-auto flex items-center gap-3">
        <span id="status-badge" class="px-3 py-1.5 rounded-full text-[11px] font-medium border backdrop-blur-sm shadow-sm flex items-center
          {% if is_expired %}bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800/50{% else %}bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border-green-200 dark:border-green-800/50{% endif %}">
          <span class="inline-block w-1.5 h-1.5 rounded-full mr-1.5 {% if is_expired %}bg-red-500 shadow-[0_0_4px_#ef4444]{% else %}bg-green-500 shadow-[0_0_4px_#22c55e]{% endif %}"></span>
          {% if is_expired %}投票已截止{% else %}投票進行中{% endif %}
        </span>
        
        <button onclick="toggleTheme()" class="p-2 rounded-lg bg-white/70 dark:bg-cardblack/80 border border-gray-200 dark:border-gray-800 shadow-sm hover:bg-gray-100 dark:hover:bg-gray-900 transition-colors text-gray-600 dark:text-gray-300 focus:outline-none focus:ring-2 focus:ring-msblue/50">
          <svg class="w-4 h-4 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
          <svg class="w-4 h-4 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
        </button>
      </div>
    </div>

    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-2xl border border-gray-200 dark:border-gray-800 shadow-md p-8 mb-8 text-center relative overflow-hidden">
      {% if is_expired %}
      <div class="absolute top-0 left-0 w-full h-1 bg-red-500"></div>
      <div class="w-16 h-16 bg-red-50 dark:bg-red-900/20 rounded-full flex items-center justify-center mx-auto mb-4 border border-red-100 dark:border-red-900/50">
        <svg class="w-8 h-8 text-red-500 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
      </div>
      <p class="text-red-600 dark:text-red-400 text-xl font-semibold mb-2">投票已截止</p>
      <p class="text-gray-500 dark:text-gray-400 text-sm">SK_TA 私鑰已解鎖，可釋放給計票中心（CC）進行開票</p>
      
      <div class="mt-8 flex justify-center gap-4 sm:gap-6">
        <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-xl p-5 w-24 border border-gray-200 dark:border-gray-800 shadow-sm"><p class="text-4xl font-light font-mono text-red-500 dark:text-red-400">00</p><p class="text-[11px] text-gray-500 mt-2 uppercase tracking-wider">時</p></div>
        <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-xl p-5 w-24 border border-gray-200 dark:border-gray-800 shadow-sm"><p class="text-4xl font-light font-mono text-red-500 dark:text-red-400">00</p><p class="text-[11px] text-gray-500 mt-2 uppercase tracking-wider">分</p></div>
        <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-xl p-5 w-24 border border-gray-200 dark:border-gray-800 shadow-sm"><p class="text-4xl font-light font-mono text-red-500 dark:text-red-400">00</p><p class="text-[11px] text-gray-500 mt-2 uppercase tracking-wider">秒</p></div>
        <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-xl p-5 w-24 border border-gray-200 dark:border-gray-800 shadow-sm"><p class="text-4xl font-light font-mono text-red-500 dark:text-red-400">00</p><p class="text-[11px] text-gray-500 mt-2 uppercase tracking-wider">毫秒</p></div>
      </div>
      {% else %}
      <div class="absolute top-0 left-0 w-full h-1 bg-msblue"></div>
      <p class="text-gray-800 dark:text-gray-200 text-lg font-medium mb-3 flex items-center justify-center gap-2">
        <svg class="w-5 h-5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        距離投票截止
      </p>
      <div class="inline-flex items-center gap-3 bg-gray-50 dark:bg-[#0a0a0a] px-4 py-2 rounded-lg border border-gray-200 dark:border-gray-800/80 mb-2">
        <p class="text-gray-500 dark:text-gray-400 text-[13px]">截止時間</p>
        <div class="w-px h-3 bg-gray-300 dark:bg-gray-700"></div>
        <p class="text-msblue dark:text-[#3399FF] font-mono text-sm font-medium">{{ deadline_str }}</p>
      </div>
      <p class="text-gray-400 dark:text-gray-600 text-[11px] mb-8 font-mono">Unix ts: {{ deadline_ts }}</p>
      
      <div class="flex justify-center gap-3 sm:gap-6" id="countdown">
        <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-xl p-4 sm:p-5 w-20 sm:w-24 border border-gray-200 dark:border-gray-800 shadow-sm flex flex-col justify-center transition-all">
          <p class="text-3xl sm:text-4xl font-light font-mono text-msblue dark:text-[#3399FF]" id="cd-hours">--</p>
          <p class="text-[10px] sm:text-[11px] text-gray-500 mt-2 uppercase tracking-wider font-medium">時</p>
        </div>
        <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-xl p-4 sm:p-5 w-20 sm:w-24 border border-gray-200 dark:border-gray-800 shadow-sm flex flex-col justify-center transition-all">
          <p class="text-3xl sm:text-4xl font-light font-mono text-msblue dark:text-[#3399FF]" id="cd-minutes">--</p>
          <p class="text-[10px] sm:text-[11px] text-gray-500 mt-2 uppercase tracking-wider font-medium">分</p>
        </div>
        <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-xl p-4 sm:p-5 w-20 sm:w-24 border border-gray-200 dark:border-gray-800 shadow-sm flex flex-col justify-center transition-all">
          <p class="text-3xl sm:text-4xl font-light font-mono text-msblue dark:text-[#3399FF]" id="cd-seconds">--</p>
          <p class="text-[10px] sm:text-[11px] text-gray-500 mt-2 uppercase tracking-wider font-medium">秒</p>
        </div>
        <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-xl p-4 sm:p-5 w-20 sm:w-24 border border-gray-200 dark:border-gray-800 shadow-sm flex flex-col justify-center transition-all">
          <p class="text-3xl sm:text-4xl font-light font-mono text-gray-400 dark:text-gray-500" id="cd-ms">--</p>
          <p class="text-[10px] sm:text-[11px] text-gray-500 mt-2 uppercase tracking-wider font-medium">毫秒</p>
        </div>
      </div>
      {% endif %}
    </div>

    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
      
      <div class="md:col-span-1 space-y-6">
        <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-sm p-5 flex flex-col justify-center">
          <p class="text-gray-500 dark:text-gray-400 text-xs font-medium uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <svg class="w-3.5 h-3.5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path></svg>
            SK_TA 狀態
          </p>
          {% if is_expired %}
          <div class="flex items-center gap-2 text-red-600 dark:text-red-400">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"></path></svg>
            <span class="text-lg font-semibold">可釋放</span>
          </div>
          {% else %}
          <div class="flex items-center gap-2 text-green-600 dark:text-green-500">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
            <span class="text-lg font-semibold">鎖定中</span>
          </div>
          {% endif %}
        </div>
        
        <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-sm p-5 flex flex-col justify-center">
          <p class="text-gray-500 dark:text-gray-400 text-xs font-medium uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <svg class="w-3.5 h-3.5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 5l7 7-7 7M5 5l7 7-7 7"></path></svg>
            釋放請求次數
          </p>
          <p class="text-3xl font-semibold text-gray-900 dark:text-white">{{ release_count }}</p>
        </div>
      </div>

      <div class="md:col-span-2 bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md overflow-hidden flex flex-col">
        <div class="px-5 py-4 border-b border-gray-100 dark:border-gray-800/60 bg-gray-50/50 dark:bg-[#0a0a0a]/50 flex items-center justify-between">
          <h2 class="font-medium text-gray-800 dark:text-gray-200 text-sm flex items-center gap-2">
            <svg class="w-4 h-4 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
            金鑰釋放記錄
          </h2>
        </div>
        {% if release_logs %}
        <div class="overflow-x-auto flex-1">
          <table class="w-full text-sm">
            <thead class="bg-gray-50 dark:bg-[#0a0a0a] text-gray-500 dark:text-gray-500 text-[11px] uppercase tracking-wider">
              <tr>
                <th class="px-5 py-3 text-left font-medium">#</th>
                <th class="px-5 py-3 text-left font-medium">狀態</th>
                <th class="px-5 py-3 text-left font-medium">原因</th>
                <th class="px-5 py-3 text-left font-medium">時間</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-800/60">
              {% for log in release_logs %}
              <tr class="hover:bg-gray-50 dark:hover:bg-[#1a1a1a] transition-colors">
                <td class="px-5 py-3.5 text-gray-400 dark:text-gray-600 text-[11px]">{{ log.id }}</td>
                <td class="px-5 py-3.5">
                  {% if log.status == 'released' %}
                  <span class="px-2 py-0.5 rounded text-[10px] font-medium bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800 flex inline-flex items-center gap-1"><svg class="w-2.5 h-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>已釋放</span>
                  {% else %}
                  <span class="px-2 py-0.5 rounded text-[10px] font-medium bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800">拒絕</span>
                  {% endif %}
                </td>
                <td class="px-5 py-3.5 text-gray-600 dark:text-gray-400 text-xs">{{ log.reason or '—' }}</td>
                <td class="px-5 py-3.5">
                  <p class="text-gray-600 dark:text-gray-400 text-[11px] font-mono">{{ log.requested_at | ts_to_str }}</p>
                  <p class="text-gray-400 dark:text-gray-600 text-[10px]">{{ log.requested_at }}</p>
                </td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
        {% else %}
        <div class="px-5 py-12 text-center text-gray-500 dark:text-gray-600 flex-1 flex flex-col justify-center">
          <svg class="w-10 h-10 mx-auto text-gray-300 dark:text-gray-700 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
          <p class="text-sm">尚無釋放記錄</p>
        </div>
        {% endif %}
      </div>
      
    </div>

  </div>

  {% if not is_expired %}
  <script>
    // 保持後端傳入 Unix timestamp (秒) 並轉換的原始邏輯 100% 不變
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
