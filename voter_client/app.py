"""
voter_client/app.py  —  選民端

選民用來投票的 Web 介面。啟動時會自動處理金鑰和憑證，
不需要手動設定什麼。

投票流程：
  1. 選民選好候選人後按送出
  2. 先跟 TPA 做雙向身分認證
  3. 把選票雜湊值盲化後送給 TPA 簽章（TPA 不知道你投給誰）
  4. 去盲化後驗證簽章，打包成數位信封送到 CC
  5. 投票完成，頁面會顯示 m_hex，記下來之後可以去 BB 驗證

截止時間到了之後，頁面的倒數計時會變紅，送出按鈕會被禁用。

端點：
  GET  /               投票頁面
  POST /vote           執行投票流程
  GET  /status         查看投票記錄
  GET  /api/vote_status 查詢投票狀態（JSON）
"""

import os
import sys
import json
import time
import datetime

# 確保 shared/ 可被 import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session
import requests as http_requests

from shared.key_manager import (
    load_or_generate_keypair,
    load_or_request_certificate,
    load_or_fetch_ca_cert,
    verify_cert_with_ca,
)
from shared.auth_component import create_auth_packet, verify_auth_component
from shared.crypto_utils import encapsulate_vote
from shared.blind_signature import (
    generate_blinding_factor,
    blind_message,
    unblind_signature,
    verify_blind_signature,
)
from shared.format_utils import int_to_hex, hex_to_int, sha256_hex, ts_to_human
from shared.db_utils import Database
from shared.config_loader import get_candidates as cfg_get_candidates, make_reload_endpoint

# ============================================================
# 常數設定
# ============================================================
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR    = os.path.join(SERVICE_DIR, "keys")
DB_PATH     = os.path.join(SERVICE_DIR, "voter.db")

VOTER_ID    = os.environ.get("VOTER_ID", "VOTER_001")
CA_URL      = os.environ.get("CA_URL",  "http://localhost:5001")
TPA_URL     = os.environ.get("TPA_URL", "http://localhost:5000")
TA_URL      = os.environ.get("TA_URL",  "http://localhost:5002")
CC_URL      = os.environ.get("CC_URL",  "http://localhost:5003")
BB_URL      = os.environ.get("BB_URL",  "http://localhost:5004")

# 候選人清單：優先環境變數，否則從 config.json 讀取（hot-reload）
def _get_candidates():
    env_val = os.environ.get("CANDIDATES")
    if env_val:
        return [c.strip() for c in env_val.split(",") if c.strip()]
    return cfg_get_candidates()

# ============================================================
# 資料庫初始化
# ============================================================
db = Database(DB_PATH)
db.execute("""
    CREATE TABLE IF NOT EXISTS vote_record (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        voter_id    TEXT NOT NULL,
        sn          TEXT NOT NULL,
        vote        TEXT NOT NULL,
        m_hex       TEXT NOT NULL,
        s_prime_hex TEXT NOT NULL,
        voted_at    INTEGER NOT NULL,
        status      TEXT NOT NULL DEFAULT 'submitted'
    )
""")
db.execute("""
    CREATE TABLE IF NOT EXISTS vote_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        step        TEXT NOT NULL,
        message     TEXT NOT NULL,
        status      TEXT NOT NULL,
        logged_at   INTEGER NOT NULL
    )
""")

# ============================================================
# 金鑰初始化（啟動時執行）
# ============================================================
print(f"[Voter:{VOTER_ID}] 初始化金鑰...")
(
    _private_key, _public_key, _e, _n, _d,
    _private_key_pem, _public_key_pem
) = load_or_generate_keypair(KEYS_DIR)

try:
    _ca_cert_pem = load_or_fetch_ca_cert(KEYS_DIR, CA_URL)
except Exception as ex:
    print(f"[Voter] 警告：無法取得 CA 憑證（{ex}）")
    _ca_cert_pem = None

try:
    _cert_pem = load_or_request_certificate(KEYS_DIR, VOTER_ID, _public_key_pem, CA_URL)
except Exception as ex:
    print(f"[Voter] 警告：無法取得憑證（{ex}）")
    _cert_pem = ""

print(f"[Voter:{VOTER_ID}] 初始化完成。")

# ============================================================
# Flask App
# ============================================================
app = Flask(__name__)
app.secret_key = os.urandom(24)


# ── Jinja2 自訂過濾器：Unix timestamp → 人類可讀 ──────────────
@app.template_filter('ts_to_str')
def ts_to_str(ts):
    """將 Unix timestamp 轉為 YYYY-MM-DD HH:MM:SS（僅用於 UI 顯示）"""
    try:
        return datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)


# ── HTML 模板 ──────────────────────────────────────────────
_VOTE_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>投票系統 - {{ voter_id }}</title>
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
    
    /* 自訂單選框樣式 */
    .candidate-radio:checked + div {
      border-color: #0078D4;
      background-color: rgba(0, 120, 212, 0.05);
    }
    .dark .candidate-radio:checked + div {
      background-color: rgba(51, 153, 255, 0.1);
      border-color: #3399FF;
    }
    .candidate-radio:checked + div .radio-inner-circle {
      background-color: #0078D4;
      transform: scale(1);
    }
    .dark .candidate-radio:checked + div .radio-inner-circle {
      background-color: #3399FF;
    }
    .candidate-radio:checked + div .candidate-name {
      color: #0078D4;
      font-weight: 600;
    }
    .dark .candidate-radio:checked + div .candidate-name {
      color: #3399FF;
    }
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
  <div class="max-w-2xl mx-auto px-4 py-10">

    <div class="flex items-center gap-4 mb-8">
      <div class="w-12 h-12 rounded-xl bg-white/70 dark:bg-cardblack/80 backdrop-blur-md shadow-sm flex items-center justify-center border border-gray-200 dark:border-gray-800">
        <svg class="w-6 h-6 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
      </div>
      <div>
        <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">電子投票系統</h1>
        <p class="text-gray-500 dark:text-gray-400 text-sm">NUTC Voting System · 選民：<span class="font-mono">{{ voter_id }}</span></p>
      </div>
      
      <div class="ml-auto flex items-center gap-3">
        {% if already_voted %}
        <span class="px-3 py-1.5 rounded-full bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800/50 backdrop-blur-sm text-xs font-medium flex items-center shadow-sm">
          <svg class="w-3.5 h-3.5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg> 已投票
        </span>
        {% else %}
        <span class="px-3 py-1.5 rounded-full bg-msblue/10 dark:bg-msblue/20 text-msblue dark:text-[#3399FF] border border-msblue/20 dark:border-msblue/30 backdrop-blur-sm text-xs font-medium flex items-center shadow-sm">
          <span class="inline-block w-1.5 h-1.5 rounded-full bg-msblue mr-1.5"></span> 尚未投票
        </span>
        {% endif %}
        
        <button onclick="toggleTheme()" class="p-2 rounded-lg bg-white/70 dark:bg-cardblack/80 border border-gray-200 dark:border-gray-800 shadow-sm hover:bg-gray-100 dark:hover:bg-gray-900 transition-colors text-gray-600 dark:text-gray-300 focus:outline-none focus:ring-2 focus:ring-msblue/50">
          <svg class="w-4 h-4 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
          <svg class="w-4 h-4 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
        </button>
      </div>
    </div>

    <div id="deadline-banner" class="mb-6 hidden transition-all duration-500">
      <div id="deadline-active"
        class="bg-amber-50/80 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-800/50 backdrop-blur-md rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between shadow-sm hidden">
        <div class="mb-3 sm:mb-0">
          <p class="text-amber-800 dark:text-amber-400 font-medium text-sm flex items-center gap-1.5">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
            投票截止倒數
          </p>
          <p class="text-gray-600 dark:text-gray-400 text-[11px] mt-1">截止時間：<span id="deadline-str" class="font-mono text-amber-700 dark:text-amber-300"></span></p>
          <p class="text-gray-500 dark:text-gray-500 text-[10px]">Unix timestamp：<span id="deadline-ts-display" class="font-mono"></span></p>
        </div>
        <div class="text-left sm:text-right">
          <p id="countdown-display" class="text-2xl font-bold font-mono text-amber-600 dark:text-amber-500 tracking-wider">--:--:--</p>
          <p class="text-[10px] text-amber-700/70 dark:text-amber-500/70 uppercase tracking-widest mt-0.5">剩餘時間</p>
        </div>
      </div>
      
      <div id="deadline-expired"
        class="bg-red-50/80 dark:bg-red-900/10 border border-red-200 dark:border-red-900/50 backdrop-blur-md rounded-xl p-5 shadow-sm hidden">
        <div class="flex items-start gap-3">
          <svg class="w-5 h-5 text-red-600 dark:text-red-500 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
          <div>
            <p class="text-red-800 dark:text-red-400 font-semibold text-sm">投票已截止</p>
            <p class="text-red-600/80 dark:text-red-400/80 text-xs mt-1">截止時間已過，無法再提交選票。</p>
          </div>
        </div>
      </div>
    </div>

    {% if flash_msg %}
    <div class="mb-6 p-4 rounded-xl shadow-sm flex items-start gap-3 {% if flash_type == 'error' %}bg-red-50/80 dark:bg-red-900/10 border border-red-200 dark:border-red-900/50 text-red-800 dark:text-red-300{% else %}bg-green-50/80 dark:bg-green-900/10 border border-green-200 dark:border-green-900/50 text-green-800 dark:text-green-300{% endif %}">
      {% if flash_type == 'error' %}
      <svg class="w-5 h-5 shrink-0 text-red-600 dark:text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
      {% else %}
      <svg class="w-5 h-5 shrink-0 text-green-600 dark:text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
      {% endif %}
      <span class="text-sm pt-0.5">{{ flash_msg }}</span>
    </div>
    {% endif %}

    {% if already_voted %}
    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-2xl border border-gray-200 dark:border-gray-800 shadow-md p-8 mb-6 relative overflow-hidden">
      <div class="absolute top-0 left-0 w-full h-1.5 bg-green-500"></div>
      
      <div class="flex flex-col items-center text-center mb-8 mt-2">
        <div class="w-16 h-16 bg-green-50 dark:bg-green-900/20 rounded-full flex items-center justify-center mb-4 border border-green-100 dark:border-green-800/50 shadow-sm">
          <svg class="w-8 h-8 text-green-500 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
        </div>
        <h2 class="text-xl font-semibold text-gray-900 dark:text-white mb-2">投票完成！</h2>
        <p class="text-gray-500 dark:text-gray-400 text-sm">您的選票已成功提交並加密傳送至計票中心。</p>
      </div>
      
      <div class="space-y-4 mb-8">
        <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-xl p-4 border border-gray-100 dark:border-gray-800/80 shadow-inner">
          <p class="text-[11px] text-gray-500 dark:text-gray-500 uppercase tracking-wider mb-1 font-medium">投票內容</p>
          <p class="font-mono text-msblue dark:text-[#3399FF] font-semibold text-lg">{{ vote_record.vote }}</p>
        </div>
        
        <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-xl p-4 border border-gray-100 dark:border-gray-800/80 shadow-inner">
          <p class="text-[11px] text-gray-500 dark:text-gray-500 uppercase tracking-wider mb-1 font-medium">投票時間</p>
          <p class="font-mono text-sm text-gray-800 dark:text-gray-200">{{ vote_record.voted_at | ts_to_str }}</p>
        </div>
        
        <div class="bg-blue-50/50 dark:bg-blue-900/5 rounded-xl p-4 border border-blue-100 dark:border-blue-900/30 relative overflow-hidden">
          <div class="absolute left-0 top-0 w-1 h-full bg-msblue"></div>
          <p class="text-[11px] text-msblue dark:text-[#3399FF] uppercase tracking-wider mb-1.5 font-semibold">選票包雜湊值 m_hex (用於獨立驗證)</p>
          <p class="font-mono text-[11px] text-gray-700 dark:text-gray-300 break-all">{{ vote_record.m_hex }}</p>
        </div>
      </div>
      
      <div class="flex flex-col sm:flex-row gap-3">
        <a href="/status" class="flex-1 py-3 bg-white dark:bg-cardblack border border-gray-300 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-900 rounded-xl text-sm font-medium text-gray-700 dark:text-gray-200 text-center transition shadow-sm flex items-center justify-center gap-2">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
          查看詳細狀態
        </a>
        <a href="{{ bb_url }}/verify?m_hex={{ vote_record.m_hex }}" target="_blank"
          class="flex-1 py-3 bg-msblue hover:bg-msblueHover rounded-xl text-sm font-medium text-white text-center transition shadow-md flex items-center justify-center gap-2">
          前往 BB 驗證 <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
        </a>
      </div>
    </div>

    {% else %}
    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-2xl border border-gray-200 dark:border-gray-800 shadow-md p-6 sm:p-8 mb-6">
      <h2 class="font-medium text-gray-900 dark:text-white mb-6 text-base sm:text-lg flex items-center gap-2">
        <svg class="w-5 h-5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>
        請選擇您支持的候選人
      </h2>
      
      <form method="POST" action="/vote" id="voteForm">
        <div class="space-y-3 mb-8">
          {% for candidate in candidates %}
          <label class="block relative cursor-pointer group">
            <input type="radio" name="candidate" value="{{ candidate }}" required class="candidate-radio peer sr-only">
            <div class="flex items-center p-4 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-[#1a1a1a] hover:bg-gray-50 dark:hover:bg-[#222] transition-all duration-200 shadow-sm">
              <div class="w-5 h-5 rounded-full border-2 border-gray-300 dark:border-gray-600 mr-4 flex flex-shrink-0 items-center justify-center bg-white dark:bg-gray-800">
                <div class="radio-inner-circle w-2.5 h-2.5 rounded-full bg-transparent transform scale-0 transition-transform duration-200"></div>
              </div>
              <span class="candidate-name font-mono text-gray-700 dark:text-gray-300 text-sm sm:text-base transition-colors duration-200">{{ candidate }}</span>
            </div>
          </label>
          {% endfor %}
        </div>
        
        <button type="submit" id="submitBtn"
          class="w-full py-3.5 bg-msblue hover:bg-msblueHover rounded-xl text-white font-medium transition shadow-md text-sm flex justify-center items-center gap-2 disabled:opacity-60 disabled:cursor-not-allowed disabled:hover:bg-msblue">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"></path></svg>
          提交加密選票
        </button>
        <p id="deadline-block-msg" class="mt-4 text-center text-red-600 dark:text-red-400 text-sm font-medium hidden flex justify-center items-center gap-1">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
          投票已截止，無法提交選票。
        </p>
      </form>
    </div>

    <div class="bg-white/50 dark:bg-cardblack/50 backdrop-blur-md rounded-xl border border-gray-200 dark:border-gray-800 p-5 shadow-sm">
      <h3 class="font-medium text-gray-800 dark:text-gray-200 mb-4 text-sm flex items-center gap-2">
        <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        零信任安全投票流程
      </h3>
      <div class="space-y-3 text-[13px] text-gray-600 dark:text-gray-400">
        <div class="flex items-start gap-2.5">
          <span class="flex items-center justify-center w-5 h-5 rounded-full bg-msblue/10 dark:bg-msblue/20 text-msblue dark:text-[#3399FF] text-[10px] font-bold shrink-0 mt-0.5">1</span>
          <span>雙向身分認證（Voter ↔ TPA），包含 X.509 CA 憑證鏈驗證確保身分合法。</span>
        </div>
        <div class="flex items-start gap-2.5">
          <span class="flex items-center justify-center w-5 h-5 rounded-full bg-msblue/10 dark:bg-msblue/20 text-msblue dark:text-[#3399FF] text-[10px] font-bold shrink-0 mt-0.5">2</span>
          <span>盲簽章 (Blind Signature)：選票雜湊值盲化後送 TPA 簽章，發行方無法得知投票內容，保障絕對隱私。</span>
        </div>
        <div class="flex items-start gap-2.5">
          <span class="flex items-center justify-center w-5 h-5 rounded-full bg-msblue/10 dark:bg-msblue/20 text-msblue dark:text-[#3399FF] text-[10px] font-bold shrink-0 mt-0.5">3</span>
          <span class="break-all">封裝數位信封：C_Data = E_k(E_PK_TA(...), S', m)，C_Key = E_PK_CC(k)。</span>
        </div>
        <div class="flex items-start gap-2.5">
          <span class="flex items-center justify-center w-5 h-5 rounded-full bg-msblue/10 dark:bg-msblue/20 text-msblue dark:text-[#3399FF] text-[10px] font-bold shrink-0 mt-0.5">4</span>
          <span>信封加密傳送至計票中心（CC），等待時間授權中心 (TA) 截止後釋放私鑰進行開票。</span>
        </div>
      </div>
    </div>
    {% endif %}

  </div>

  <script>
    // ── 截止時間強制執行（前端）────────────────────────────────
    // 1. 從 TA /api/deadline 取得 Unix timestamp
    // 2. JS 倒數計時器（每 50ms 更新）
    // 3. 截止後：禁用按鈕、顯示截止提示
    // 4. fetch 攔截：提交前再次檢查 Date.now() > deadline * 1000

    let deadlineTs = 0;  // Unix timestamp（秒）

    async function fetchDeadline() {
      try {
        const resp = await fetch('{{ ta_url }}/api/deadline');
        const data = await resp.json();
        if (data.status === 'success') {
          deadlineTs = data.deadline;  // Unix timestamp（後端標準）
          // UI 顯示：人類可讀格式（YYYY-MM-DD HH:MM:SS）
          const deadlineDate = new Date(deadlineTs * 1000);
          const pad = n => String(n).padStart(2, '0');
          const humanStr = `${deadlineDate.getFullYear()}-${pad(deadlineDate.getMonth()+1)}-${pad(deadlineDate.getDate())} ${pad(deadlineDate.getHours())}:${pad(deadlineDate.getMinutes())}:${pad(deadlineDate.getSeconds())}`;
          const strEl = document.getElementById('deadline-str');
          const tsEl  = document.getElementById('deadline-ts-display');
          if (strEl) strEl.textContent = humanStr;
          if (tsEl)  tsEl.textContent  = deadlineTs;
          document.getElementById('deadline-banner')?.classList.remove('hidden');
          document.getElementById('deadline-active')?.classList.remove('hidden');
          startCountdown();
        }
      } catch (e) {
        console.warn('[Voter] 無法取得截止時間：', e);
      }
    }

    function startCountdown() {
      const countdownEl = document.getElementById('countdown-display');
      const submitBtn   = document.getElementById('submitBtn');
      const blockMsg    = document.getElementById('deadline-block-msg');
      const activeEl    = document.getElementById('deadline-active');
      const expiredEl   = document.getElementById('deadline-expired');

      function update() {
        if (!deadlineTs) return;
        const now  = Math.floor(Date.now() / 1000);  // 轉為秒，與後端 Unix ts 一致
        const diff = deadlineTs - now;

        if (diff <= 0) {
          // ── 截止：禁用按鈕、顯示截止提示 ──
          if (countdownEl) countdownEl.textContent = '00:00:00';
          if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg> 投票已截止';
          }
          if (blockMsg)   blockMsg.classList.remove('hidden');
          if (activeEl)   activeEl.classList.add('hidden');
          if (expiredEl)  expiredEl.classList.remove('hidden');
          return;  // 停止更新
        }

        // ── 倒數顯示（人類可讀格式）──
        const h  = Math.floor(diff / 3600);
        const m  = Math.floor((diff % 3600) / 60);
        const s  = diff % 60;
        const pad = n => String(n).padStart(2, '0');
        if (countdownEl) countdownEl.textContent = `${pad(h)}:${pad(m)}:${pad(s)}`;

        // 剩餘 60 秒以內：倒數變紅色警示
        if (diff <= 60 && countdownEl) {
          countdownEl.classList.remove('text-amber-600', 'dark:text-amber-500');
          countdownEl.classList.add('text-red-600', 'dark:text-red-500');
        }

        setTimeout(update, 500);
      }
      update();
    }

    // ── fetch 攔截：提交前再次檢查截止時間 ──────────────────────
    document.getElementById('voteForm')?.addEventListener('submit', function(e) {
      // 若已取得截止時間，且當前時間已超過截止時間，阻止提交
      if (deadlineTs > 0) {
        const nowSec = Math.floor(Date.now() / 1000);
        if (nowSec > deadlineTs) {
          e.preventDefault();
          const blockMsg = document.getElementById('deadline-block-msg');
          if (blockMsg) blockMsg.classList.remove('hidden');
          const submitBtn = document.getElementById('submitBtn');
          if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg> 投票已截止';
          }
          console.warn('[Voter] fetch 攔截：截止時間已過，阻止提交（nowSec=' + nowSec + ' > deadlineTs=' + deadlineTs + '）');
          return;
        }
      }
      // 正常提交：顯示處理中
      const btn = document.getElementById('submitBtn');
      if (btn) {
        btn.innerHTML = '<svg class="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg> 處理中...';
        btn.disabled = true;
      }
    });

    // 頁面載入時取得截止時間
    fetchDeadline();
  </script>
</body>
</html>"""

_STATUS_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>投票狀態 - {{ voter_id }}</title>
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
  <div class="max-w-3xl mx-auto px-4 py-10">

    <div class="flex items-center justify-between mb-8">
      <div class="flex items-center gap-4">
        <a href="/" class="p-2 -ml-2 rounded-lg text-gray-500 dark:text-gray-400 hover:text-msblue hover:bg-msblue/10 dark:hover:text-white transition-colors" title="返回投票頁">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path></svg>
        </a>
        <div class="w-10 h-10 rounded-xl bg-white/70 dark:bg-cardblack/80 shadow-sm flex items-center justify-center border border-gray-200 dark:border-gray-800">
          <svg class="w-5 h-5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path></svg>
        </div>
        <div>
          <h1 class="text-xl font-semibold text-gray-900 dark:text-white">投票狀態</h1>
          <p class="text-gray-500 dark:text-gray-400 text-xs mt-0.5">選民：<span class="font-mono">{{ voter_id }}</span></p>
        </div>
      </div>
      
      <button onclick="toggleTheme()" class="p-2 rounded-lg bg-white/70 dark:bg-cardblack/80 border border-gray-200 dark:border-gray-800 shadow-sm hover:bg-gray-100 dark:hover:bg-gray-900 transition-colors text-gray-600 dark:text-gray-300 focus:outline-none focus:ring-2 focus:ring-msblue/50">
        <svg class="w-4 h-4 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
        <svg class="w-4 h-4 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
      </button>
    </div>

    {% if vote_record %}
    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-2xl border border-gray-200 dark:border-gray-800 shadow-md p-6 sm:p-8 mb-6">
      <h2 class="font-medium text-gray-800 dark:text-gray-200 mb-6 text-sm flex items-center gap-2 uppercase tracking-wider">
        <svg class="w-4 h-4 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
        加密記錄檔案
      </h2>
      
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm mb-6">
        <div class="bg-gray-50 dark:bg-[#0a0a0a] rounded-xl p-4 border border-gray-100 dark:border-gray-800/80 shadow-inner">
          <p class="text-gray-500 dark:text-gray-500 text-[11px] uppercase tracking-wider mb-1 font-medium">選民 ID</p>
          <p class="font-mono text-gray-800 dark:text-gray-200">{{ vote_record.voter_id }}</p>
        </div>
        <div class="bg-gray-50 dark:bg-[#0a0a0a] rounded-xl p-4 border border-gray-100 dark:border-gray-800/80 shadow-inner">
          <p class="text-gray-500 dark:text-gray-500 text-[11px] uppercase tracking-wider mb-1 font-medium">隨機序號 (SN)</p>
          <p class="font-mono text-gray-800 dark:text-gray-300 text-xs">{{ vote_record.sn }}</p>
        </div>
        <div class="bg-gray-50 dark:bg-[#0a0a0a] rounded-xl p-4 border border-gray-100 dark:border-gray-800/80 shadow-inner">
          <p class="text-gray-500 dark:text-gray-500 text-[11px] uppercase tracking-wider mb-1 font-medium">投票內容</p>
          <p class="font-mono text-msblue dark:text-[#3399FF] font-semibold text-base">{{ vote_record.vote }}</p>
        </div>
        <div class="bg-gray-50 dark:bg-[#0a0a0a] rounded-xl p-4 border border-gray-100 dark:border-gray-800/80 shadow-inner">
          <p class="text-gray-500 dark:text-gray-500 text-[11px] uppercase tracking-wider mb-1 font-medium">投票時間</p>
          <p class="text-gray-800 dark:text-gray-200 font-mono text-[13px]">{{ vote_record.voted_at | ts_to_str }}</p>
          <p class="text-gray-400 dark:text-gray-600 text-[10px] mt-1 font-mono">ts: {{ vote_record.voted_at }}</p>
        </div>
      </div>
      
      <div class="space-y-4 pt-4 border-t border-gray-100 dark:border-gray-800">
        <div>
          <p class="text-gray-500 dark:text-gray-500 text-[11px] uppercase tracking-wider mb-1 font-medium flex items-center gap-1.5">
            <span class="w-1.5 h-1.5 rounded-full bg-msblue"></span> m_hex（選票包雜湊值，用於 Merkle Proof 驗證）
          </p>
          <p class="font-mono text-[11px] sm:text-xs text-gray-700 dark:text-gray-400 break-all bg-gray-50 dark:bg-[#0a0a0a] p-3 rounded-lg border border-gray-100 dark:border-gray-800/80 shadow-inner">{{ vote_record.m_hex }}</p>
        </div>
        <div>
          <p class="text-gray-500 dark:text-gray-500 text-[11px] uppercase tracking-wider mb-1 font-medium flex items-center gap-1.5">
            <span class="w-1.5 h-1.5 rounded-full bg-purple-500"></span> S'_hex（TPA 盲簽章截斷預覽）
          </p>
          <p class="font-mono text-[11px] text-gray-500 dark:text-gray-500 break-all bg-gray-50 dark:bg-[#0a0a0a] p-3 rounded-lg border border-gray-100 dark:border-gray-800/80 shadow-inner">{{ vote_record.s_prime_hex[:80] }}...</p>
        </div>
      </div>
    </div>

    <div class="flex gap-3 mb-8">
      <a href="{{ bb_url }}/verify?m_hex={{ vote_record.m_hex }}" target="_blank"
        class="w-full py-3.5 bg-msblue hover:bg-msblueHover rounded-xl text-white font-medium transition shadow-md text-sm flex justify-center items-center gap-2">
        前往公告板 (BB) 驗證 Merkle Proof <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
      </a>
    </div>
    {% else %}
    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-2xl border border-gray-200 dark:border-gray-800 shadow-md p-16 text-center">
      <div class="w-16 h-16 bg-gray-50 dark:bg-[#1a1a1a] rounded-full flex items-center justify-center mx-auto mb-4 border border-gray-100 dark:border-gray-800">
        <svg class="w-8 h-8 text-gray-400 dark:text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
      </div>
      <p class="text-gray-600 dark:text-gray-400 font-medium mb-4">您尚未完成投票。</p>
      <a href="/" class="inline-flex px-6 py-2.5 bg-msblue hover:bg-msblueHover rounded-lg text-sm font-medium text-white transition shadow-sm">
        前往投票頁面
      </a>
    </div>
    {% endif %}

    {% if logs %}
    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-100 dark:border-gray-800/60 bg-gray-50/50 dark:bg-[#0a0a0a]/50 flex items-center justify-between">
        <h2 class="font-medium text-gray-800 dark:text-gray-200 text-sm flex items-center gap-2">
          <svg class="w-4 h-4 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"></path></svg>
          底層加密流程記錄
        </h2>
      </div>
      <div class="divide-y divide-gray-100 dark:divide-gray-800/60">
        {% for log in logs %}
        <div class="px-6 py-4 flex items-start gap-4 hover:bg-gray-50 dark:hover:bg-[#1a1a1a] transition-colors">
          <span class="mt-0.5 shrink-0">
            {% if log.status == 'ok' %}
            <svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
            {% else %}
            <svg class="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
            {% endif %}
          </span>
          <div class="flex-1 min-w-0">
            <p class="text-[11px] text-gray-500 dark:text-gray-400 font-medium mb-0.5">{{ log.step }}</p>
            <p class="text-sm text-gray-800 dark:text-gray-300 font-mono leading-relaxed truncate">{{ log.message }}</p>
          </div>
          <div class="text-right shrink-0">
            <p class="text-[11px] text-gray-600 dark:text-gray-400 font-mono">{{ log.logged_at | ts_to_str }}</p>
            <p class="text-[10px] text-gray-400 dark:text-gray-600 font-mono mt-0.5">ts: {{ log.logged_at }}</p>
          </div>
        </div>
        {% endfor %}
      </div>
    </div>
    {% endif %}

  </div>
</body>
</html>"""
# ── 路由 ──────────────────────────────────────────────────

@app.route('/')
def index():
    vote_record = db.fetchone(
        "SELECT * FROM vote_record WHERE voter_id = ? ORDER BY id DESC LIMIT 1",
        (VOTER_ID,)
    )
    already_voted = vote_record is not None

    flash_msg  = session.pop('flash_msg', None)
    flash_type = session.pop('flash_type', 'info')

    # 每次請求都讀最新候選人清單（hot-reload）
    candidates = _get_candidates()

    return render_template_string(
        _VOTE_HTML,
        voter_id=VOTER_ID,
        candidates=candidates,
        already_voted=already_voted,
        vote_record=vote_record,
        flash_msg=flash_msg,
        flash_type=flash_type,
        bb_url=BB_URL,
        ta_url=TA_URL,
    )


@app.route('/vote', methods=['POST'])
def vote():
    """執行完整投票流程（Phase 2 + 3）"""
    # 檢查是否已投票
    existing = db.fetchone(
        "SELECT id FROM vote_record WHERE voter_id = ?", (VOTER_ID,)
    )
    if existing:
        session['flash_msg']  = "您已投票，不可重複投票。"
        session['flash_type'] = 'error'
        return redirect('/')

    candidate = request.form.get('candidate', '').strip()
    candidates = _get_candidates()
    if not candidate or candidate not in candidates:
        session['flash_msg']  = "請選擇有效的候選人。"
        session['flash_type'] = 'error'
        return redirect('/')

    now = int(time.time())
    sn  = f"SN{now}{VOTER_ID[-3:]}"   # 唯一序號

    def _log(step, message, status='ok'):
        db.execute(
            "INSERT INTO vote_log (step, message, status, logged_at) VALUES (?, ?, ?, ?)",
            (step, message, status, now),
        )

    try:
        # ── Step 1：取得 TPA 公鑰 ────────────────────────
        resp = http_requests.get(f"{TPA_URL}/api/public_key", timeout=10)
        tpa_data = resp.json()
        tpa_e = hex_to_int(tpa_data['e'])
        tpa_n = hex_to_int(tpa_data['n'])
        tpa_pub_pem = tpa_data['public_key_pem']
        _log("Phase 2 - 取得 TPA 公鑰", f"e={tpa_data['e'][:20]}...")

        # ── Step 2：取得 CC 公鑰 ─────────────────────────
        resp = http_requests.get(f"{CC_URL}/api/public_key", timeout=10)
        cc_pub_pem = resp.json()['public_key_pem']
        _log("Phase 2 - 取得 CC 公鑰", "CC 公鑰已取得")

        # ── Step 3：取得 TA 公鑰 ─────────────────────────
        resp = http_requests.get(f"{TA_URL}/api/public_key", timeout=10)
        ta_pub_pem = resp.json()['public_key_pem']
        _log("Phase 2 - 取得 TA 公鑰", "TA 公鑰已取得")

        # ── Step 4：Phase 2 雙向認證 ─────────────────────
        auth_packet = create_auth_packet(VOTER_ID, "TPA", _private_key, _cert_pem)
        resp = http_requests.post(
            f"{TPA_URL}/api/auth",
            json={"auth_packet": auth_packet, "voter_cert_pem": _cert_pem},
            timeout=10,
        )
        auth_result = resp.json()
        if auth_result.get('status') != 'success':
            # 截止時間錯誤特別處理
            if auth_result.get('code') == 'DEADLINE_EXCEEDED':
                raise Exception(f"投票已截止（TPA 拒絕）：{auth_result.get('message', '')}")
            raise Exception(f"TPA 認證失敗：{auth_result.get('message', '')}")
        _log("Phase 2 - TPA 認證", "TPA 認證成功")

        # 驗證 TPA 回應封包（雙向認證）
        import base64
        response_packet = auth_result['response_packet']
        tpa_cert_pem    = auth_result['tpa_cert_pem']

        # 若有 CA 憑證，驗證 TPA 憑證合法性
        if _ca_cert_pem and tpa_cert_pem:
            if not verify_cert_with_ca(tpa_cert_pem, _ca_cert_pem):
                raise Exception("TPA 憑證 CA 驗證失敗")

        rp = response_packet
        sig_bytes = base64.b64decode(rp['signature'])
        verify_auth_component(
            expected_receiver_id=VOTER_ID,
            sender_id=rp['payload']['sender_id'],
            packet_receiver_id=rp['payload']['receiver_id'],
            packet_timestamp=rp['payload']['timestamp'],
            packet_cert_pem=tpa_cert_pem,
            packet_signature=sig_bytes,
            packet_si=rp['payload']['si'],
            ca_public_key=None,
            delta_t=300,
        )
        _log("Phase 2 - 驗證 TPA 回應", "雙向認證完成")

        # ── Step 5：計算選票雜湊值 m ─────────────────────
        inner_hash = sha256_hex(f"{VOTER_ID}|{sn}|{candidate}".encode('utf-8'))
        outer_hash = sha256_hex(f"{inner_hash}|{candidate}".encode('utf-8'))
        m_hex = hex(int(outer_hash, 16))
        _log("Phase 3 - 計算 m", f"m={m_hex[:20]}...")

        # ── Step 6：盲化選票 ─────────────────────────────
        m_int = hex_to_int(m_hex)
        r = generate_blinding_factor(tpa_n)
        m_prime = blind_message(m_int, r, tpa_e, tpa_n)
        m_prime_hex = int_to_hex(m_prime)
        _log("Phase 3 - 盲化選票", f"m'={m_prime_hex[:20]}...")

        # ── Step 7：TPA 盲簽章 ───────────────────────────
        resp = http_requests.post(
            f"{TPA_URL}/api/blind_sign",
            json={"m_prime_hex": m_prime_hex},
            timeout=10,
        )
        sign_result = resp.json()
        if sign_result.get('status') != 'success':
            if sign_result.get('code') == 'DEADLINE_EXCEEDED':
                raise Exception(f"投票已截止（TPA 拒絕盲簽章）：{sign_result.get('message', '')}")
            raise Exception(f"盲簽章失敗：{sign_result.get('message', '')}")
        S_hex = sign_result['S_hex']
        _log("Phase 3 - TPA 盲簽章", f"S={S_hex[:20]}...")

        # ── Step 8：去盲化，取得 S' ──────────────────────
        S_int = hex_to_int(S_hex)
        r_inv = pow(r, -1, tpa_n)
        S_prime_int = (S_int * r_inv) % tpa_n
        S_prime_hex = int_to_hex(S_prime_int)

        if not verify_blind_signature(S_prime_int, tpa_e, tpa_n, m_int):
            raise Exception("盲簽章數學驗證失敗")
        _log("Phase 3 - 去盲化 + 驗證", f"S'={S_prime_hex[:20]}... 驗證通過")

        # ── Step 9：封裝數位信封 ─────────────────────────
        envelope = encapsulate_vote(
            voter_id=VOTER_ID,
            sn=sn,
            vote_content=candidate,
            s_prime_hex=S_prime_hex,
            m_hex=m_hex,
            cc_public_key_pem=cc_pub_pem,
            ta_public_key_pem=ta_pub_pem,
        )
        _log("Phase 3 - 封裝數位信封", "信封已封裝")

        # ── Step 10：傳送信封至 CC ───────────────────────
        resp = http_requests.post(
            f"{CC_URL}/api/receive_envelope",
            json=envelope,
            timeout=10,
        )
        cc_result = resp.json()
        if cc_result.get('status') != 'success':
            if cc_result.get('code') == 'DEADLINE_EXCEEDED':
                raise Exception(f"投票已截止（CC 拒絕信封）：{cc_result.get('message', '')}")
            raise Exception(f"CC 接收失敗：{cc_result.get('message', '')}")
        _log("Phase 3 - 傳送至 CC", "信封已送達 CC")

        # ── 儲存投票記錄（Unix timestamp）────────────────
        db.execute(
            "INSERT INTO vote_record (voter_id, sn, vote, m_hex, s_prime_hex, voted_at, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (VOTER_ID, sn, candidate, m_hex, S_prime_hex, now, 'submitted'),
        )
        # 日誌使用人類可讀格式
        print(f"[Voter:{VOTER_ID}] 投票成功（Unix ts：{now}  →  {ts_to_human(now)}）")

        session['flash_msg']  = f"投票成功！您的選票已加密傳送至計票中心。請保存您的 m_hex 以便日後驗證。"
        session['flash_type'] = 'success'
        return redirect('/')

    except Exception as exc:
        _log("投票流程錯誤", str(exc), status='error')
        session['flash_msg']  = f"投票失敗：{exc}"
        session['flash_type'] = 'error'
        return redirect('/')


@app.route('/status')
def status():
    vote_record = db.fetchone(
        "SELECT * FROM vote_record WHERE voter_id = ? ORDER BY id DESC LIMIT 1",
        (VOTER_ID,)
    )
    logs = db.fetchall(
        "SELECT step, message, status, logged_at FROM vote_log ORDER BY id DESC LIMIT 30"
    )
    return render_template_string(
        _STATUS_HTML,
        voter_id=VOTER_ID,
        vote_record=vote_record,
        logs=logs,
        bb_url=BB_URL,
    )


@app.route('/api/vote_status', methods=['GET'])
def api_vote_status():
    """[GET] 回傳投票狀態 JSON（Unix timestamp）"""
    vote_record = db.fetchone(
        "SELECT voter_id, sn, vote, m_hex, voted_at, status FROM vote_record WHERE voter_id = ? ORDER BY id DESC LIMIT 1",
        (VOTER_ID,)
    )
    if vote_record:
        return jsonify({
            "status":      "voted",
            "voter_id":    vote_record['voter_id'],
            "vote":        vote_record['vote'],
            "m_hex":       vote_record['m_hex'],
            # Unix timestamp（後端標準）
            "voted_at":    vote_record['voted_at'],
            # 人類可讀（僅供 UI/日誌）
            "voted_at_str": ts_to_human(vote_record['voted_at']),
        }), 200
    else:
        return jsonify({"status": "not_voted", "voter_id": VOTER_ID}), 200


# ── Config Hot-Reload 端點 ────────────────────────────────────
make_reload_endpoint(app)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=False)
