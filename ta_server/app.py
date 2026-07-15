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
)
from shared.format_utils import int_to_hex, ts_to_human
from shared.db_utils import Database
from shared.config_loader import make_reload_endpoint, get_vote_duration
from shared.auth_component import verify_auth_component
from cryptography import x509

# ============================================================
# 常數設定
# ============================================================
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR    = os.path.join(SERVICE_DIR, "keys")
DB_PATH     = os.path.join(SERVICE_DIR, "ta.db")
TA_ID       = "TA"
CA_URL      = os.environ.get("CA_URL", "http://localhost:5001")

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
    _cert_pem = load_or_request_certificate(KEYS_DIR, TA_ID, _public_key_pem, CA_URL)
except Exception as ex:
    print(f"[TA] 警告：無法取得憑證（{ex}）")
    _cert_pem = ""

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
          {% if election_state == 'standby' %}bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800/50{% elif is_expired %}bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800/50{% else %}bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border-green-200 dark:border-green-800/50{% endif %}">
          <span class="inline-block w-1.5 h-1.5 rounded-full mr-1.5 {% if election_state == 'standby' %}bg-amber-400 shadow-[0_0_4px_#f59e0b]{% elif is_expired %}bg-red-500 shadow-[0_0_4px_#ef4444]{% else %}bg-green-500 shadow-[0_0_4px_#22c55e]{% endif %}"></span>
          {% if election_state == 'standby' %}待命中{% elif is_expired %}投票已截止{% else %}投票進行中{% endif %}
        </span>
        
        <button onclick="toggleTheme()" class="p-2 rounded-lg bg-white/70 dark:bg-cardblack/80 border border-gray-200 dark:border-gray-800 shadow-sm hover:bg-gray-100 dark:hover:bg-gray-900 transition-colors text-gray-600 dark:text-gray-300 focus:outline-none focus:ring-2 focus:ring-msblue/50">
          <svg class="w-4 h-4 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
          <svg class="w-4 h-4 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
        </button>
      </div>
    </div>

    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-2xl border border-gray-200 dark:border-gray-800 shadow-md p-8 mb-8 text-center relative overflow-hidden">
      {% if election_state == 'standby' %}
      <div class="absolute top-0 left-0 w-full h-1 bg-amber-400"></div>
      <div class="w-16 h-16 bg-amber-50 dark:bg-amber-900/20 rounded-full flex items-center justify-center mx-auto mb-4 border border-amber-100 dark:border-amber-900/50">
        <svg class="w-8 h-8 text-amber-500 dark:text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
      </div>
      <p class="text-amber-600 dark:text-amber-400 text-xl font-semibold mb-2">⏸ 等待管理員啟動選舉</p>
      <p class="text-gray-500 dark:text-gray-400 text-sm">選舉尚未啟動，所有投票業務目前凍結中</p>
      <div class="mt-8 flex justify-center gap-4 sm:gap-6">
        <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-xl p-5 w-24 border border-gray-200 dark:border-gray-800 shadow-sm"><p class="text-4xl font-light font-mono text-amber-400 dark:text-amber-500">--</p><p class="text-[11px] text-gray-500 mt-2 uppercase tracking-wider">時</p></div>
        <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-xl p-5 w-24 border border-gray-200 dark:border-gray-800 shadow-sm"><p class="text-4xl font-light font-mono text-amber-400 dark:text-amber-500">--</p><p class="text-[11px] text-gray-500 mt-2 uppercase tracking-wider">分</p></div>
        <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-xl p-5 w-24 border border-gray-200 dark:border-gray-800 shadow-sm"><p class="text-4xl font-light font-mono text-amber-400 dark:text-amber-500">--</p><p class="text-[11px] text-gray-500 mt-2 uppercase tracking-wider">秒</p></div>
        <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-xl p-5 w-24 border border-gray-200 dark:border-gray-800 shadow-sm"><p class="text-4xl font-light font-mono text-amber-400 dark:text-amber-500">--</p><p class="text-[11px] text-gray-500 mt-2 uppercase tracking-wider">毫秒</p></div>
      </div>
      {% elif is_expired %}
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
          {% if election_state == 'standby' %}
          <div class="flex items-center gap-2 text-amber-600 dark:text-amber-400">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
            <span class="text-lg font-semibold">待命中</span>
          </div>
          {% elif is_expired %}
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

  {% if election_state == 'running' and not is_expired %}
  <script>
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
    """[GET] 回傳 TA 公鑰 PEM"""
    return jsonify({
        "status":         "success",
        "public_key_pem": _public_key_pem,
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
    [POST] 釋放 SK_TA（v2.0 Sprint 2：需驗證請求方身分）
    
    Body: {
        "auth": {
            "sender_id": "CC",
            "receiver_id": "TA",
            "timestamp": <Unix ts>,
            "nonce": <hex>,
            "cert_pem": <PEM>,
            "signature": <hex>
        }
    }
    
    驗證流程：
      1. 檢查是否已截止
      2. 驗證認證封包（憑證、簽章、時間戳、nonce）
      3. 檢查請求方是否為 CC
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

    # 步驟 2：驗證認證封包（v2.0 Sprint 2）
    auth_packet = data.get('auth')
    if not auth_packet:
        db.execute(
            "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
            (now, 'UNKNOWN', 'rejected', '缺少認證封包'),
        )
        return jsonify({
            "status":  "error",
            "code":    "AUTH_REQUIRED",
            "message": "需要認證封包（必須提供 auth 欄位）",
        }), 403

    # auth_packet 結構：{"payload": {...}, "signature": "base64..."}
    auth_payload = auth_packet.get('payload', {})

    # 驗證認證封包
    if not _ca_cert_pem:
        db.execute(
            "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
            (now, auth_payload.get('sender_id'), 'rejected', 'TA 無 CA 憑證，無法驗證'),
        )
        return jsonify({
            "status": "error",
            "code": "CA_CERT_UNAVAILABLE",
            "message": "TA 無法取得 CA 憑證，無法驗證請求方身分"
        }), 500

    try:
        _ca_pub = None
        if _ca_cert_pem:
            try:
                _ca_cert_obj = x509.load_pem_x509_certificate(_ca_cert_pem.encode('utf-8'))
                _ca_pub = _ca_cert_obj.public_key()
            except Exception:
                pass

        verify_auth_component(
            expected_receiver_id=TA_ID,
            sender_id=auth_payload.get('sender_id'),
            packet_receiver_id=auth_payload.get('receiver_id'),
            packet_timestamp=auth_payload.get('timestamp'),
            packet_cert_pem=auth_payload.get('cert_pem'),
            packet_signature=base64.b64decode(auth_packet.get('signature', '')),
            packet_nonce=auth_payload.get('nonce'),
            ca_public_key=_ca_pub,
        )
        sender_id = auth_payload.get('sender_id', 'UNKNOWN')
        print(f"[TA] 認證封包驗證通過（請求方：{sender_id}）")
    except Exception as e:
        error_msg = str(e)
        db.execute(
            "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
            (now, auth_payload.get('sender_id'), 'rejected', f'認證失敗：{error_msg}'),
        )

        # 判斷錯誤類型並回傳對應的錯誤代碼
        if "CERT_INVALID" in error_msg:
            code = "CERT_INVALID"
        elif "SIGNATURE_INVALID" in error_msg:
            code = "SIGNATURE_INVALID"
        elif "TIMESTAMP_OUT_OF_RANGE" in error_msg:
            code = "TIMESTAMP_OUT_OF_RANGE"
        elif "RECEIVER_ID_MISMATCH" in error_msg:
            code = "RECEIVER_ID_MISMATCH"
        elif "NONCE_REPLAY" in error_msg:
            code = "NONCE_REPLAY"
        else:
            code = "AUTH_FAILED"

        return jsonify({
            "status": "error",
            "code": code,
            "message": f"認證封包驗證失敗：{error_msg}"
        }), 403

    # 步驟 3：檢查請求方是否為 CC
    sender_id = auth_payload.get('sender_id', '')
    if sender_id != 'CC':
        db.execute(
            "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
            (now, sender_id, 'rejected', f'請求方非 CC（實際：{sender_id}）'),
        )
        return jsonify({
            "status": "error",
            "code": "UNAUTHORIZED_REQUESTER",
            "message": f"僅允許 CC 請求 SK_TA（實際請求方：{sender_id}）"
        }), 403

    # 步驟 4：檢查 nonce 是否已使用（防重放攻擊）
    nonce = auth_payload.get('nonce', '')
    if nonce:
        existing = db.fetchone("SELECT nonce FROM used_nonces WHERE nonce = ?", (nonce,))
        if existing:
            db.execute(
                "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
                (now, sender_id, 'rejected', 'NONCE_REPLAY'),
            )
            return jsonify({
                "status": "error",
                "code": "NONCE_REPLAY",
                "message": "nonce 已使用過（重放攻擊）"
            }), 403
        
        # 記錄 nonce
        db.execute("INSERT INTO used_nonces (nonce, used_at) VALUES (?, ?)", (nonce, now))

    # 步驟 5：釋放 SK_TA
    db.execute(
        "INSERT INTO key_release_log (requested_at, requester_id, status, reason) VALUES (?, ?, ?, ?)",
        (now, sender_id, 'released', None),
    )
    print(f"[TA] ✅ SK_TA 已釋放給 {sender_id}（Unix ts：{now}  →  {ts_to_human(now)}）")

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
    """
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
    """[POST] 重置選舉狀態至 standby（新一輪前使用）。清除截止時間與 nonce 記錄。"""
    db.execute("INSERT OR REPLACE INTO election_state (key, value) VALUES ('state', 'standby')")
    db.execute("DELETE FROM election_state WHERE key = 'deadline'")
    db.execute("DELETE FROM used_nonces")
    print("[TA] 選舉狀態已重置至 standby。")
    return jsonify({"status": "success", "message": "選舉狀態已重置至 standby"}), 200


# ── Config Hot-Reload 端點 ────────────────────────────────────
make_reload_endpoint(app)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)
