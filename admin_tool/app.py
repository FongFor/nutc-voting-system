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
import io
import sys
import json
import time
import hashlib
import secrets
import datetime
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string
import requests as http_requests
import qrcode
import qrcode.image.svg  # <3 v4.0：純向量、不需要 Pillow，QR 內容完全本地生成，不經過任何第三方服務

from shared.db_utils import Database
from shared.config_loader import get_admin_api_token, get_service_registration_token  # <3 呼叫 CA/CC 的 Admin 端點需要帶 Bearer Token
from shared.key_manager import load_or_fetch_ca_cert  # <3 v4.0：mTLS
from shared.tls_utils import load_or_request_tls_certificate, build_mtls_server_context, mtls_client_kwargs  # <3 v4.0：mTLS

# ============================================================
# 常數設定
# ============================================================
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR    = os.path.join(SERVICE_DIR, "data")
DB_PATH     = os.path.join(DATA_DIR, "admin.db")
KEYS_DIR    = os.path.join(SERVICE_DIR, "keys")  # <3 v4.0：admin_tool 沒有應用層身分憑證，只快取 CA 根憑證＋TLS 專用金鑰對
os.makedirs(KEYS_DIR, exist_ok=True)
ADMIN_HOSTNAME = os.environ.get("ADMIN_HOSTNAME", "admin")  # <3 v4.0：填入 TLS 憑證的 SAN

CA_URL    = os.environ.get("CA_URL",    "https://localhost:5001")
TA_URL    = os.environ.get("TA_URL",    "https://localhost:5002")
CC_URL    = os.environ.get("CC_URL",    "https://localhost:5003")
TPA_URL   = os.environ.get("TPA_URL",   "https://localhost:5000")  # <3 v4.0：new_round 需重置 TPA 的 issued_tokens


def _admin_headers() -> dict:
    """呼叫 CA /api/admin/* 或 CC /api/tally 時附上的 Admin Bearer Token 標頭。 <3"""
    return {"Authorization": f"Bearer {get_admin_api_token()}"}
BB_URL    = os.environ.get("BB_URL",    "https://localhost:5004")
VOTER_URL = os.environ.get("VOTER_URL", "https://localhost:5005")

# <3 v4.0 新增：選民實際用瀏覽器連上的公開網域（跟 Caddyfile 用同一個
# SITE_ADDRESS），QR code 要靠這個組出「掃了就能直接開啟投票網站」的網址。
SITE_ADDRESS = os.environ.get("SITE_ADDRESS", "localhost:5005")


def _build_register_qr_svg(voter_id: str, otp: str) -> str:
    """產生「掃描後自動開啟投票網站並帶入學號/OTP」的 QR code（inline SVG）。

    刻意把 voter_id/otp 放在網址的 fragment（# 後面），而不是一般的
    ?query= 參數：fragment 天生不會被送到伺服器，Caddy／Flask 的 access
    log 完全看不到裡面的明文 OTP，只存在掃碼裝置自己的網址列。就算之後
    這個網址被看到，OTP 本身在 CA 完成一次註冊後就永久失效，不能重複
    使用。QR 圖檔完全在本機用 qrcode 套件生成（純向量 SVG），不會呼叫
    任何第三方 QR 產生服務，OTP 明文不會離開這台伺服器。 <3
    """
    frag = urllib.parse.urlencode({"vid": voter_id, "otp": otp})
    url = f"https://{SITE_ADDRESS}/register#{frag}"
    img = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage, box_size=6)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode('utf-8')

# v4.0 新增：先快取 CA 根憑證，才有材料驗證 CA 與其他實體的 TLS 憑證，
# 再向 CA 申請本服務專用的 TLS 憑證（admin_tool 沒有應用層身分憑證，這是
# 它唯一持有的一把金鑰對）。
try:
    load_or_fetch_ca_cert(KEYS_DIR, CA_URL)
except Exception as ex:
    print(f"[Admin] 警告：無法取得 CA 憑證（{ex}）")

try:
    _TLS_CERT_PATH, _TLS_KEY_PATH = load_or_request_tls_certificate(
        KEYS_DIR, "ADMIN", ADMIN_HOSTNAME, CA_URL,
        registration_token=get_service_registration_token(),
    )
except Exception as ex:
    print(f"[Admin] 警告：無法取得 TLS 憑證（{ex}）")
    _TLS_CERT_PATH = _TLS_KEY_PATH = None

# 供本檔案所有對外呼叫共用的 mTLS 參數。
_ADMIN_MTLS = mtls_client_kwargs(_TLS_CERT_PATH, _TLS_KEY_PATH, os.path.join(KEYS_DIR, "ca_cert.pem"))

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
        **_ADMIN_MTLS,
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
  .qr-thumb svg { width: 100%; height: 100%; display: block; }
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
        <button onclick="triggerTally()"
          class="ml-auto px-5 py-2.5 bg-msblue hover:bg-msblueHover rounded-lg text-white font-medium text-sm transition shadow-md flex items-center gap-2 focus:outline-none focus:ring-2 focus:ring-msblue/50">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5M7.188 2.239l.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656l-2.12 2.122"/>
          </svg>
          觸發開票
        </button>
        <button onclick="newRound()"
          class="px-5 py-2.5 bg-red-600 hover:bg-red-700 rounded-lg text-white font-medium text-sm transition shadow-md flex items-center gap-2 focus:outline-none focus:ring-2 focus:ring-red-500/50">
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
            <th class="px-5 py-3.5 text-left font-medium">QR（現場掃碼登記）</th>
            <th class="px-5 py-3.5 text-left font-medium">CA 狀態</th>
            <th class="px-5 py-3.5 text-left font-medium">建立時間</th>
            <th class="px-5 py-3.5 text-left font-medium">派發</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100 dark:divide-gray-800">
          {% for v in voters %}
          <tr class="hover:bg-gray-50 dark:hover:bg-[#1a1a1a] transition-colors">
            <td class="px-5 py-4 text-gray-400 text-xs">{{ loop.index }}</td>
            <td class="px-5 py-4 font-mono font-medium text-msblue dark:text-[#3399FF]">{{ v.voter_id }}</td>
            <td class="px-5 py-4">
              <span class="otp-blur font-mono text-xs text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded" title="懸停顯示">{{ v.otp }}</span>
            </td>
            <td class="px-5 py-4">
              {% if v.qr_svg %}
              <div class="qr-thumb w-12 h-12 p-1 bg-white rounded cursor-pointer hover:ring-2 hover:ring-msblue transition"
                data-voter-id="{{ v.voter_id }}" onclick="openQrModal(this)" title="點擊放大，供選民掃描">{{ v.qr_svg | safe }}</div>
              {% else %}
              <span class="text-xs text-gray-400">—</span>
              {% endif %}
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

<!-- QR 放大彈窗，方便現場選民掃描 -->
<div id="qrModal" class="hidden fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onclick="closeQrModal()">
  <div class="bg-white dark:bg-cardblack rounded-2xl p-6 max-w-xs w-full text-center" onclick="event.stopPropagation()">
    <p id="qrModalVoterId" class="font-mono text-sm text-gray-600 dark:text-gray-300 mb-3"></p>
    <div id="qrModalContent" class="mx-auto bg-white p-2 rounded-lg" style="width:240px;height:240px"></div>
    <p class="text-xs text-gray-400 mt-3">請選民用手機相機或掃碼 App 掃描，將自動開啟投票頁並帶入學號與 OTP</p>
    <button onclick="closeQrModal()"
      class="mt-4 text-xs px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 transition">關閉</button>
  </div>
</div>

<script>
function openQrModal(el) {
  document.getElementById('qrModalContent').innerHTML = el.innerHTML;
  document.getElementById('qrModalVoterId').textContent = el.dataset.voterId;
  document.getElementById('qrModal').classList.remove('hidden');
}

function closeQrModal() {
  document.getElementById('qrModal').classList.add('hidden');
}

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

async function triggerTally() {
  if (!confirm('確定要觸發開票？\\n\\nCC 只有在投票確實已截止時才會真的執行開票，若尚未截止會被拒絕，可放心先試。')) return;
  const msg = document.getElementById('electionMsg');
  showMsg(msg, '正在向 CC 發送開票指令（可能需要幾秒到數十秒）...', 'info');
  try {
    const resp = await fetch('/api/trigger_tally', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({}),
    });
    const data = await resp.json();
    if (data.status === 'success') {
      const bbOk = data.bb_published ? '[成功]' : `[警告：${data.bb_publish_warning || '未確認公告成功'}]`;
      showMsg(msg, `[成功] 開票完成！合法選票：${data.valid_count}，Merkle Root：${(data.merkle_root||'').slice(0,20)}...，BB 公告：${bbOk}`, 'success');
    } else if (data.status === 'already_done') {
      showMsg(msg, '[資訊] 本輪已完成開票，無需重複觸發', 'warn');
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
        # <3 v4.0：只有還沒完成 CA 註冊的選民，QR 裡的 OTP 才還能用；
        # 已註冊的話 OTP 已經永久失效，秀出一個掃了也沒用的 QR 沒有意義。
        v['qr_svg'] = _build_register_qr_svg(v['voter_id'], v['otp']) if v['ca_status'] != 'registered' else None

    total      = len(voters)
    pending    = sum(1 for v in voters if v['ca_status'] == 'pending')
    registered = sum(1 for v in voters if v['ca_status'] == 'registered')
    distributed = sum(1 for v in voters if v['distributed'])

    # 從 CA 同步選民認證狀態（把 CA 端已完成的 registered 狀態寫回本地）
    try:
        ca_resp = http_requests.get(f"{CA_URL}/api/admin/voter_registry", headers=_admin_headers(), timeout=3, **_ADMIN_MTLS)  # <3
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
        resp = http_requests.get(f"{TA_URL}/api/deadline", timeout=3, **_ADMIN_MTLS)
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
    # v3.0 修正：`data.get('voter_id', '')` 遇到明確傳 `"voter_id": null`
    # 時會拿到 None（預設值只在完全沒有這個 key 時才生效），對 None 呼叫
    # .strip() 會丟 AttributeError 變成沒處理過的 500。改用 `or ''`。 <3
    if not data or not (data.get('voter_id') or '').strip():  # <3
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
    # v4.0 修正：原本用 `'voter_ids' not in data` 只擋得住「完全沒帶這個
    # 欄位」，若明確傳 `"voter_ids": null`，這個 key 存在、檢查會放行，
    # 下面 `for v in data['voter_ids']` 對 None 做迭代直接丟未攔截的
    # TypeError、變成沒處理過的 500——跟 /api/add_voter 先前修過的同一種
    # null-crash bug，這裡漏補。改用 `not data.get('voter_ids')` 同時擋
    # 「缺欄位」「欄位是 null」「欄位是空陣列」三種情況。 <3
    if not data or not data.get('voter_ids'):
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
    """新一輪重置：TA 回到 standby + TPA 清除發票紀錄 + CA 清除名冊 +
    CC 清除開票狀態 + BB 清除公告狀態 + Admin 清除本地名冊。

    v4.0 修正：原本這裡完全沒有重置 CC/BB，導致上一輪開票/公告過一次
    後，CC 的 tally_state.done 與 BB 的 bb_state.published 會一直卡在
    「已完成」，新一輪投票結束後 CC 直接拒絕重新開票、BB 也會拒絕接受
    新結果並繼續顯示上一輪的舊資料——實測發現的真實 bug，過去只能手動
    docker exec 進容器清資料庫繞過，這裡補上正式的重置端點呼叫。 <3

    v4.0 再修正：TPA 也完全沒被重置過。TPA 的 issued_tokens 表記錄每位
    選民「這一輪」是否已消耗過 Voting Token（used=1），/api/auth 用它來
    擋重複投票。這張表如果沒清，任何上一輪真正投過票的選民，到了新一輪
    重新認證時一樣會被判定 ALREADY_VOTED、直接卡在 TPA 認證這關——實測
    發現：選民端明明還沒投這一輪，卻顯示已投票／認證失敗，根源就在這裡
    而不是選民端。補上 TPA 的重置呼叫（步驟 2，緊接在 TA 之後）。 <3
    """
    results = {}

    # 1. 重置 TA 選舉狀態
    # v4.0 修正：TA 這兩個端點現在要求 Admin Bearer Token（見
    # ta_server/app.py），補上 headers=_admin_headers()，否則會被 401 擋下。 <3
    try:
        resp = http_requests.post(f"{TA_URL}/api/admin/reset_election", json={}, headers=_admin_headers(), timeout=10, **_ADMIN_MTLS)  # <3
        results['ta'] = resp.json()
    except Exception as e:
        results['ta'] = {"status": "error", "message": str(e)}

    # 2. 清除 TPA 發票／認證紀錄（<3 新增，修正新一輪一開始就被判定已投票的問題）
    try:
        resp = http_requests.post(f"{TPA_URL}/api/admin/reset", json={}, headers=_admin_headers(), timeout=10, **_ADMIN_MTLS)
        results['tpa'] = resp.json()
    except Exception as e:
        results['tpa'] = {"status": "error", "message": str(e)}

    # 3. 清除 CA 選民名冊
    try:
        resp = http_requests.post(f"{CA_URL}/api/admin/reset_voter_registry", json={}, headers=_admin_headers(), timeout=10, **_ADMIN_MTLS)  # <3
        results['ca'] = resp.json()
    except Exception as e:
        results['ca'] = {"status": "error", "message": str(e)}

    # 4. 清除 CC 開票狀態（<3 新增，修正無法重新開票的問題）
    try:
        resp = http_requests.post(f"{CC_URL}/api/admin/reset_tally", json={}, headers=_admin_headers(), timeout=10, **_ADMIN_MTLS)
        results['cc'] = resp.json()
    except Exception as e:
        results['cc'] = {"status": "error", "message": str(e)}

    # 5. 清除 BB 公告狀態（<3 新增，修正 BB 停留在上一輪結果的問題）
    try:
        resp = http_requests.post(f"{BB_URL}/api/admin/reset", json={}, headers=_admin_headers(), timeout=10, **_ADMIN_MTLS)
        results['bb'] = resp.json()
    except Exception as e:
        results['bb'] = {"status": "error", "message": str(e)}

    # 6. 清除本地名冊
    row = db.fetchone("SELECT COUNT(*) as cnt FROM voter_roster")
    count = row['cnt'] if row else 0
    db.execute("DELETE FROM voter_roster")
    results['admin'] = {"status": "success", "deleted": count}

    print(f"[Admin] 新一輪重置完成。本地刪除 {count} 筆。TA: {results['ta']}  TPA: {results['tpa']}  CA: {results['ca']}  CC: {results['cc']}  BB: {results['bb']}")
    return jsonify({"status": "success", "results": results}), 200


@app.route('/api/start_election', methods=['POST'])
def api_start_election():
    """向 TA 發送啟動選舉指令（管理員操作）。"""
    try:
        resp = http_requests.post(f"{TA_URL}/api/start_election", json={}, headers=_admin_headers(), timeout=10, **_ADMIN_MTLS)  # <3
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"status": "error", "message": f"無法連接 TA：{e}"}), 502


@app.route('/api/election_status', methods=['GET'])
def api_election_status():
    """查詢選舉狀態（從 TA 取得）。"""
    try:
        resp = http_requests.get(f"{TA_URL}/api/deadline", timeout=5, **_ADMIN_MTLS)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"status": "error", "message": f"無法連接 TA：{e}"}), 502


@app.route('/api/trigger_tally', methods=['POST'])
def api_trigger_tally():
    """
    [POST] 向 CC 觸發開票（v4.0 補上）。

    問題：CC 整個 Flask app（含網頁儀表板本身的「觸發開票」按鈕）都被
    mTLS CERT_REQUIRED 保護，不持有這套 PKI 用戶端憑證的瀏覽器連 TLS
    handshake 都過不了——包含管理員自己的瀏覽器。CC_URL 這個常數原本就
    定義在本檔案，但從未真的被用來呼叫 CC，等於管理員完全沒有合法路徑
    能觸發開票，只能 docker exec 進 CC 容器內部呼叫，明顯不是預期行為。

    修法：比照本檔案呼叫 CA/TA 的既有模式，用 Admin 自己已經持有的
    mTLS 用戶端憑證（_ADMIN_MTLS）代為呼叫 CC/api/tally，讓瀏覽器不需要
    持有內部 PKI 憑證，一樣能透過 Admin 這個中介觸發開票。 <3
    """
    try:
        resp = http_requests.post(f"{CC_URL}/api/tally", json={}, headers=_admin_headers(), timeout=120, **_ADMIN_MTLS)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"status": "error", "message": f"無法連接 CC：{e}"}), 502


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
        r = http_requests.get(f"{TA_URL}/api/deadline", timeout=5, **_ADMIN_MTLS)
        export["sections"]["election_state"] = r.json()
    except Exception as e:
        export["sections"]["election_state"] = {"error": str(e)}

    # 3. CA 選民名冊狀態
    try:
        r = http_requests.get(f"{CA_URL}/api/admin/voter_registry", headers=_admin_headers(), timeout=5, **_ADMIN_MTLS)  # <3
        export["sections"]["ca_voter_registry"] = r.json().get("voters", [])
    except Exception as e:
        export["sections"]["ca_voter_registry"] = {"error": str(e)}

    # 4. BB 公告結果
    try:
        r = http_requests.get(f"{BB_URL}/api/results", timeout=5, **_ADMIN_MTLS)
        export["sections"]["published_results"] = r.json()
    except Exception as e:
        export["sections"]["published_results"] = {"error": str(e)}

    # 5. 選民投票回執
    try:
        r = http_requests.get(f"{VOTER_URL}/api/all_receipts", timeout=5, **_ADMIN_MTLS)
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
    # v4.0 修正：Admin 的實際使用情境是系統維運人員直接用瀏覽器操作
    # 儀表板（新增選民、啟動/重置選舉），不是服務對服務的機器呼叫——
    # 目前系統裡也沒有任何東西會主動連進 Admin 並出示用戶端憑證。強制
    # CERT_REQUIRED 只會逼操作者把用戶端憑證匯入瀏覽器才能打開頁面，
    # 增加操作摩擦卻沒有對應的安全效益，所以跟 BB/Voter 一樣改成
    # require_client_cert=False——Admin 本來就不對外開放（沒有 Caddy
    # 代理、沒有對外 port），這一層防護交給網路層存取控制，不依賴傳輸層
    # 用戶端憑證。
    _ca_cert_path = os.path.join(KEYS_DIR, "ca_cert.pem")
    _ssl_ctx = build_mtls_server_context(
        _TLS_CERT_PATH, _TLS_KEY_PATH, _ca_cert_path, require_client_cert=False,
    )
    app.run(host='0.0.0.0', port=5010, debug=False, ssl_context=_ssl_ctx)
