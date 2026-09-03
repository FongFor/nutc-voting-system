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
import sys
import time
import hashlib
import secrets
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string
import requests as http_requests

from shared.db_utils import Database
from shared.config_loader import get_admin_api_token  # <3 呼叫 CA/CC 的 Admin 端點需要帶 Bearer Token

# ============================================================
# 常數設定
# ============================================================
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR    = os.path.join(SERVICE_DIR, "data")
DB_PATH     = os.path.join(DATA_DIR, "admin.db")

CA_URL    = os.environ.get("CA_URL",    "http://localhost:5001")
TA_URL    = os.environ.get("TA_URL",    "http://localhost:5002")
CC_URL    = os.environ.get("CC_URL",    "http://localhost:5003")


def _admin_headers() -> dict:
    """呼叫 CA /api/admin/* 或 CC /api/tally 時附上的 Admin Bearer Token 標頭。 <3"""
    return {"Authorization": f"Bearer {get_admin_api_token()}"}
BB_URL    = os.environ.get("BB_URL",    "http://localhost:5004")
VOTER_URL = os.environ.get("VOTER_URL", "http://localhost:5005")

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
    )
    resp.raise_for_status()
    return resp.json()


# ============================================================
# Flask App
# ============================================================
app = Flask(__name__)

# ── HTML 模板 ──────────────────────────────────────────────
_BASE_CSS = """
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
  .mono { font-family: 'Courier New', Courier, monospace; }
  .otp-blur { filter: blur(4px); transition: filter 0.2s; cursor: pointer; }
  .otp-blur:hover { filter: none; }
  @media print {
    .no-print { display: none !important; }
    body { background: white !important; color: black !important; }
    .print-card { border: 1px solid #ccc !important; break-inside: avoid; }
  }
</style>
<script>
  if (localStorage.getItem('theme') === 'dark' ||
      (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    document.documentElement.classList.add('dark');
  }
  function toggleTheme() {
    document.documentElement.classList.toggle('dark');
    localStorage.setItem('theme', document.documentElement.classList.contains('dark') ? 'dark' : 'light');
  }
</script>
"""

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>admin</title>
  """ + _BASE_CSS + """
</head>
<body class="bg-gray-50 dark:bg-deepblack text-gray-800 dark:text-gray-100 min-h-screen transition-colors duration-300">
<div class="max-w-6xl mx-auto px-4 py-10">

  <!-- 頁首 -->
  <div class="flex items-center gap-4 mb-8">
    <div class="w-12 h-12 rounded-xl bg-white/70 dark:bg-cardblack/80 backdrop-blur-md shadow-sm flex items-center justify-center border border-gray-200 dark:border-gray-800">
      <svg class="w-6 h-6 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
          d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
      </svg>
    </div>
    <div>
      <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">Admin</h1>
    </div>
    <div class="ml-auto flex items-center gap-3">
      <a href="/api/export" target="_blank"
        class="no-print px-4 py-2 rounded-lg bg-green-600 hover:bg-green-700 text-sm text-white shadow-sm flex items-center gap-2 transition">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
        </svg>
        匯出
      </a>
      <a href="/print" target="_blank"
        class="no-print px-4 py-2 rounded-lg bg-white/70 dark:bg-cardblack/80 border border-gray-200 dark:border-gray-800 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-900 shadow-sm flex items-center gap-2 transition">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z"/>
        </svg>
        列印
      </a>
      <button onclick="toggleTheme()" class="p-2 rounded-lg bg-white/70 dark:bg-cardblack/80 border border-gray-200 dark:border-gray-800 shadow-sm hover:bg-gray-100 dark:hover:bg-gray-900 transition text-gray-600 dark:text-gray-300">
        <svg class="w-4 h-4 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/></svg>
        <svg class="w-4 h-4 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
      </button>
    </div>
  </div>



  <!-- 統計卡片 -->
  <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-4">
      <p class="text-gray-500 dark:text-gray-400 text-xs font-medium uppercase tracking-wider mb-1">名冊總數</p>
      <p class="text-3xl font-semibold text-gray-900 dark:text-white">{{ stats.total }}</p>
    </div>
    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-4">
      <p class="text-gray-500 dark:text-gray-400 text-xs font-medium uppercase tracking-wider mb-1">待領取</p>
      <p class="text-3xl font-semibold text-amber-500">{{ stats.pending }}</p>
    </div>
    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-4">
      <p class="text-gray-500 dark:text-gray-400 text-xs font-medium uppercase tracking-wider mb-1">已完成認證</p>
      <p class="text-3xl font-semibold text-green-500">{{ stats.registered }}</p>
    </div>
    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-4">
      <p class="text-gray-500 dark:text-gray-400 text-xs font-medium uppercase tracking-wider mb-1">已派發 OTP</p>
      <p class="text-3xl font-semibold text-msblue">{{ stats.distributed }}</p>
    </div>
  </div>

  <!-- 選舉控制 -->
  <div class="mb-8 bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-6">
    <h2 class="font-medium text-gray-800 dark:text-gray-200 mb-4 text-sm uppercase tracking-wider flex items-center gap-2">
      <svg class="w-4 h-4 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
      </svg>選舉控制
    </h2>
    <div class="flex flex-wrap items-center gap-4">
      <div class="flex items-center gap-2">
        {% if election_state == 'standby' %}
        <span class="w-2.5 h-2.5 rounded-full bg-amber-400 shrink-0"></span>
        <span class="text-amber-700 dark:text-amber-400 font-medium text-sm">待命</span>
        {% else %}
        <span class="w-2.5 h-2.5 rounded-full bg-green-500 shrink-0 shadow-[0_0_6px_#22c55e]"></span>
        <span class="text-green-700 dark:text-green-400 font-medium text-sm">進行中</span>
        {% if election_deadline_str %}
        <span class="text-gray-500 dark:text-gray-400 text-xs ml-1">（截止：{{ election_deadline_str }}）</span>
        {% endif %}
        {% endif %}
      </div>
      <div class="ml-auto flex gap-3">
        {% if election_state == 'standby' %}
        <button onclick="newRound()"
          class="px-4 py-2.5 bg-white dark:bg-cardblack hover:bg-red-50 dark:hover:bg-red-900/20 border border-gray-300 dark:border-gray-700 hover:border-red-300 dark:hover:border-red-700 rounded-lg text-red-600 dark:text-red-400 font-medium text-sm transition shadow-sm flex items-center gap-2">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
          </svg>
          重設名單
        </button>
        <button onclick="startElection()"
          class="px-5 py-2.5 bg-msblue hover:bg-msblueHover rounded-lg text-white font-medium text-sm transition shadow-md flex items-center gap-2 focus:outline-none focus:ring-2 focus:ring-msblue/50">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
          啟動
        </button>
        {% else %}
        <button onclick="newRound()"
          class="ml-auto px-5 py-2.5 bg-red-600 hover:bg-red-700 rounded-lg text-white font-medium text-sm transition shadow-md flex items-center gap-2 focus:outline-none focus:ring-2 focus:ring-red-500/50">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
          </svg>
          結束本輪 · 重置新一輪
        </button>
        {% endif %}
      </div>
    </div>
    <div id="electionMsg" class="mt-3 text-sm hidden"></div>
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">

    <!-- 新增單一 -->
    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-6">
      <h2 class="font-medium text-gray-800 dark:text-gray-200 mb-4 text-sm uppercase tracking-wider flex items-center gap-2">
        <svg class="w-4 h-4 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/>
        </svg>新增
      </h2>
      <div class="space-y-3">
        <input type="text" id="singleVoterId" placeholder="學號 / VOTER_ID"
          class="w-full px-4 py-2.5 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-[#1a1a1a] text-sm text-gray-800 dark:text-gray-200 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-msblue/50 focus:border-msblue transition font-mono">
        <button onclick="addSingleVoter()"
          class="w-full py-2.5 bg-msblue hover:bg-msblueHover rounded-lg text-white font-medium text-sm transition shadow-md flex items-center justify-center gap-2">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
          </svg>
          生成 OTP 並註冊至 CA
        </button>
      </div>
      <div id="singleMsg" class="mt-3 text-sm hidden"></div>
    </div>

    <!-- 批次新增 -->
    <div class="lg:col-span-2 bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-6">
      <h2 class="font-medium text-gray-800 dark:text-gray-200 mb-4 text-sm uppercase tracking-wider flex items-center gap-2">
        <svg class="w-4 h-4 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h7"/>
        </svg>批次匯入
      </h2>
      <p class="text-xs text-gray-500 dark:text-gray-400 mb-3">每行輸入一個學號，或以逗號分隔。</p>
      <textarea id="batchIds" rows="5" placeholder="VOTER_001&#10;VOTER_002&#10;VOTER_003"
        class="w-full px-4 py-3 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-[#1a1a1a] text-sm text-gray-800 dark:text-gray-200 placeholder-gray-400 font-mono focus:outline-none focus:ring-2 focus:ring-msblue/50 focus:border-msblue transition resize-none"></textarea>
      <button onclick="addBatch()"
        class="mt-3 w-full py-2.5 bg-white dark:bg-cardblack hover:bg-gray-50 dark:hover:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-700 dark:text-gray-300 font-medium text-sm transition shadow-sm flex items-center justify-center gap-2">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/>
        </svg>
        批次生成 OTP 並全部註冊至 CA
      </button>
      <div id="batchMsg" class="mt-3 text-sm hidden"></div>
    </div>
  </div>

  <!-- 選民名冊表格 -->
  <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md overflow-hidden">
    <div class="px-6 py-4 border-b border-gray-100 dark:border-gray-800/60 bg-gray-50/50 dark:bg-[#0a0a0a]/50 flex items-center justify-between">
      <h2 class="font-medium text-gray-800 dark:text-gray-200 flex items-center gap-2 text-sm">
        <svg class="w-4 h-4 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
        </svg>
        選民名冊
      </h2>
      <span class="text-xs text-gray-400 dark:text-gray-500">OTP 欄位懸停以顯示明文</span>
    </div>
    {% if voters %}
    <div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead class="bg-gray-50 dark:bg-[#0a0a0a] text-gray-500 dark:text-gray-400 text-xs uppercase tracking-wider">
          <tr>
            <th class="px-5 py-3.5 text-left font-medium">#</th>
            <th class="px-5 py-3.5 text-left font-medium">選民 ID</th>
            <th class="px-5 py-3.5 text-left font-medium">OTP（懸停顯示）</th>
            <th class="px-5 py-3.5 text-left font-medium">CA 狀態</th>
            <th class="px-5 py-3.5 text-left font-medium">建立時間</th>
            <th class="px-5 py-3.5 text-left font-medium">派發</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100 dark:divide-gray-800">
          {% for v in voters %}
          <tr class="hover:bg-gray-50 dark:hover:bg-[#1a1a1a] transition-colors">
            <td class="px-5 py-4 text-gray-400 text-xs">{{ v.id }}</td>
            <td class="px-5 py-4 font-mono font-medium text-msblue dark:text-[#3399FF]">{{ v.voter_id }}</td>
            <td class="px-5 py-4">
              <span class="otp-blur font-mono text-xs text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded" title="懸停顯示">{{ v.otp }}</span>
            </td>
            <td class="px-5 py-4">
              {% if v.ca_status == 'registered' %}
              <span class="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800/50">
                <span class="w-1.5 h-1.5 rounded-full bg-green-500"></span> 已完成認證
              </span>
              {% else %}
              <span class="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-800/50">
                <span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span> 待領取
              </span>
              {% endif %}
            </td>
            <td class="px-5 py-4 text-gray-500 dark:text-gray-400 text-xs font-mono">{{ v.created_at_str }}</td>
            <td class="px-5 py-4">
              {% if v.distributed %}
              <span class="text-xs text-green-600 dark:text-green-400 font-medium">已派發</span>
              {% else %}
              <button onclick="markDistributed({{ v.id }})"
                class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-700 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition">
                標記已派發
              </button>
              {% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% else %}
    <div class="px-6 py-16 text-center">
      <svg class="w-12 h-12 mx-auto text-gray-300 dark:text-gray-700 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
      </svg>
      <p class="text-gray-500 dark:text-gray-500">尚未新增任何選民，請在上方表單輸入學號。</p>
    </div>
    {% endif %}
  </div>

</div>

<script>
async function newRound() {
  if (!confirm('確定要重置為新一輪投票？\\n\\n此操作將：\\n1. 重置選舉狀態（TA → standby）\\n2. 清除 CA 選民名冊（選民需重新憑 OTP 登記）\\n3. 清除本地 OTP 名冊\\n\\n選民再次造訪投票頁時會自動偵測到重置，導向重新身分綁定。\\n請確認本輪計票與公告已完成。')) return;
  const msg = document.getElementById('electionMsg');
  showMsg(msg, '重置中，請稍候...', 'info');
  try {
    const resp = await fetch('/api/new_round', { method: 'POST', headers: {'Content-Type': 'application/json'} });
    const data = await resp.json();
    if (data.status === 'success') {
      const r = data.results || {};
      const taOk  = r.ta  && r.ta.status  === 'success';
      const caOk  = r.ca  && r.ca.status  === 'success';
      showMsg(msg, `[成功] 新一輪重置完成！TA:${taOk?'[成功]':'[失敗]'}  CA:${caOk?'[成功]':'[失敗]'}  Admin名冊:[成功]\n請重新新增選民名冊後再啟動選舉。選民造訪投票頁時將自動導向重新身分綁定。`, 'success');
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
  el.classList.remove('hidden');
  const styles = {
    success: 'text-green-700 dark:text-green-400 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800/50',
    error:   'text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/50',
    warn:    'text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800/50',
    info:    'text-blue-700 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800/50',
  };
  el.className = `mt-3 text-sm p-3 rounded-lg ${styles[type] || styles.info}`;
  el.textContent = text;
}
</script>
</body>
</html>"""

_PRINT_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <title>選民 OTP 密碼表（列印版）</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Noto+Sans:wght@400;500;600;700&display=swap');
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Noto Sans', sans-serif; background: #f8f9fa; color: #1a1a1a; padding: 20px; }
    .no-print { margin-bottom: 20px; }
    h1 { font-size: 1.4rem; font-weight: 700; margin-bottom: 4px; }
    .subtitle { color: #666; font-size: 0.8rem; margin-bottom: 20px; }
    .warning-box {
      border: 2px solid #dc2626; border-radius: 8px; padding: 12px 16px;
      margin-bottom: 24px; background: #fef2f2; color: #7f1d1d;
      font-size: 0.8rem; line-height: 1.5;
    }
    .cards { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
    .card {
      border: 1.5px solid #d1d5db; border-radius: 10px; padding: 16px 20px;
      background: white; page-break-inside: avoid;
    }
    .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
    .card-label { font-size: 0.65rem; text-transform: uppercase; letter-spacing: .06em; color: #6b7280; font-weight: 600; }
    .voter-id { font-family: 'Courier New', monospace; font-size: 1rem; font-weight: 700; color: #0078D4; }
    .otp-label { font-size: 0.65rem; text-transform: uppercase; letter-spacing: .06em; color: #6b7280; font-weight: 600; margin-bottom: 4px; }
    .otp-value { font-family: 'Courier New', monospace; font-size: 0.95rem; font-weight: 600; color: #1a1a1a; letter-spacing: .04em; word-break: break-all; }
    .otp-hash { font-family: 'Courier New', monospace; font-size: 0.6rem; color: #9ca3af; word-break: break-all; margin-top: 6px; }
    .footer { font-size: 0.65rem; color: #9ca3af; margin-top: 6px; }
    .status-badge { font-size: 0.6rem; padding: 2px 8px; border-radius: 20px; font-weight: 600; }
    .status-pending    { background: #fffbeb; color: #92400e; border: 1px solid #fde68a; }
    .status-registered { background: #f0fdf4; color: #166534; border: 1px solid #bbf7d0; }
    @media print {
      body { background: white; padding: 10px; }
      .no-print { display: none !important; }
    }
  </style>
</head>
<body>

<div class="no-print">
  <button onclick="window.print()"
    style="padding:10px 24px;background:#0078D4;color:white;border:none;border-radius:8px;font-size:0.9rem;cursor:pointer;font-weight:600;">
    列印 / 儲存 PDF
  </button>
  <a href="/" style="margin-left:12px;color:#0078D4;font-size:0.9rem;">← 返回管理介面</a>
</div>

<h1>NUTC 投票系統 — 選民 OTP 密碼表</h1>
<p class="subtitle">列印日期：{{ now_str }} · 本文件屬機密，請安全保管</p>

  <div class="warning-box">
    <strong>[警告] 安全提醒：</strong>
    本密碼表為選民進行身分認證的唯一憑據，請以實體信件或加密管道派發，嚴禁以明文電子郵件或通訊軟體傳遞。
    每位選民應在收到後立即使用，並請求信封銷毀。本表中的 OTP <strong>僅可使用一次</strong>，
    使用後系統自動失效。
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
      {% if v.ca_status == 'registered' %}已完成{% else %}未領取{% endif %}
    </span>
  </div>
  <div class="otp-label">一次性密碼 / OTP（請妥善保管）</div>
  <div class="otp-value">{{ v.otp }}</div>
  <div class="otp-hash">H(OTP) = {{ v.otp_hash[:32] }}...</div>
  <div class="footer">生成時間：{{ v.created_at_str }}  ·  NUTC Voting System v2.0</div>
</div>
{% endfor %}
</div>

</body>
</html>"""

# ── 路由 ──────────────────────────────────────────────────────

@app.route('/')
def dashboard():
    voters = db.fetchall(
        "SELECT id, voter_id, otp, otp_hash, ca_status, created_at, distributed FROM voter_roster ORDER BY id DESC"
    )
    for v in voters:
        v['created_at_str'] = _ts_fmt(v['created_at'])

    total      = len(voters)
    pending    = sum(1 for v in voters if v['ca_status'] == 'pending')
    registered = sum(1 for v in voters if v['ca_status'] == 'registered')
    distributed = sum(1 for v in voters if v['distributed'])

    # 從 CA 同步選民認證狀態（把 CA 端已完成的 registered 狀態寫回本地）
    try:
        ca_resp = http_requests.get(f"{CA_URL}/api/admin/voter_registry", headers=_admin_headers(), timeout=3)  # <3
        ca_data = ca_resp.json()
        if ca_data.get("status") == "success":
            for row in ca_data.get("voters", []):
                if row.get("status") == "registered":
                    db.execute(
                        "UPDATE voter_roster SET ca_status = 'registered' WHERE voter_id = ? AND ca_status != 'registered'",
                        (row["voter_id"],),
                    )
    except Exception:
        pass

    # 查詢選舉狀態（供 UI 顯示）
    election_state = 'standby'
    election_deadline_str = None
    try:
        resp = http_requests.get(f"{TA_URL}/api/deadline", timeout=3)
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


@app.route('/api/add_voter', methods=['POST'])
def api_add_voter():
    """新增單一選民：本地端生成 OTP，只送 H(OTP) 至 CA（零知識）。"""
    data = request.get_json()
    if not data or not data.get('voter_id', '').strip():
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
    if not data or 'voter_ids' not in data:
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
    """新一輪重置：TA 回到 standby + CA 清除名冊 + Admin 清除本地名冊。"""
    results = {}

    # 1. 重置 TA 選舉狀態
    try:
        resp = http_requests.post(f"{TA_URL}/api/admin/reset_election", json={}, timeout=10)
        results['ta'] = resp.json()
    except Exception as e:
        results['ta'] = {"status": "error", "message": str(e)}

    # 2. 清除 CA 選民名冊
    try:
        resp = http_requests.post(f"{CA_URL}/api/admin/reset_voter_registry", json={}, headers=_admin_headers(), timeout=10)  # <3
        results['ca'] = resp.json()
    except Exception as e:
        results['ca'] = {"status": "error", "message": str(e)}

    # 3. 清除本地名冊
    row = db.fetchone("SELECT COUNT(*) as cnt FROM voter_roster")
    count = row['cnt'] if row else 0
    db.execute("DELETE FROM voter_roster")
    results['admin'] = {"status": "success", "deleted": count}

    print(f"[Admin] 新一輪重置完成。本地刪除 {count} 筆。TA: {results['ta']}  CA: {results['ca']}")
    return jsonify({"status": "success", "results": results}), 200


@app.route('/api/start_election', methods=['POST'])
def api_start_election():
    """向 TA 發送啟動選舉指令（管理員操作）。"""
    try:
        resp = http_requests.post(f"{TA_URL}/api/start_election", json={}, timeout=10)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"status": "error", "message": f"無法連接 TA：{e}"}), 502


@app.route('/api/election_status', methods=['GET'])
def api_election_status():
    """查詢選舉狀態（從 TA 取得）。"""
    try:
        resp = http_requests.get(f"{TA_URL}/api/deadline", timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"status": "error", "message": f"無法連接 TA：{e}"}), 502


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
        r = http_requests.get(f"{TA_URL}/api/deadline", timeout=5)
        export["sections"]["election_state"] = r.json()
    except Exception as e:
        export["sections"]["election_state"] = {"error": str(e)}

    # 3. CA 選民名冊狀態
    try:
        r = http_requests.get(f"{CA_URL}/api/admin/voter_registry", headers=_admin_headers(), timeout=5)  # <3
        export["sections"]["ca_voter_registry"] = r.json().get("voters", [])
    except Exception as e:
        export["sections"]["ca_voter_registry"] = {"error": str(e)}

    # 4. BB 公告結果
    try:
        r = http_requests.get(f"{BB_URL}/api/results", timeout=5)
        export["sections"]["published_results"] = r.json()
    except Exception as e:
        export["sections"]["published_results"] = {"error": str(e)}

    # 5. 選民投票回執
    try:
        r = http_requests.get(f"{VOTER_URL}/api/all_receipts", timeout=5)
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
    app.run(host='0.0.0.0', port=5010, debug=False)
