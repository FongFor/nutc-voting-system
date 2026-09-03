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
import datetime
import sqlite3  # <3 新增：用於捕捉 token_hash UNIQUE 約束衝突，做原子化去重

# 確保 shared/ 可被 import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string, redirect
import requests as http_requests

from shared.key_manager import (
    load_or_generate_keypair,
    load_or_request_certificate,
    load_or_fetch_ca_cert,
)
from shared.crypto_utils import open_envelope_layer1, open_envelope_layer2, sign_data
from shared.merkle_tree import MerkleTree
from shared.format_utils import int_to_hex, hex_to_int, ts_to_human, bytes_to_b64
from shared.db_utils import Database
from shared.config_loader import make_reload_endpoint, get_service_registration_token
from shared.admin_auth import is_internal_ip, check_admin_token, admin_auth_error  # <3 /api/tally 存取控制
# v2.0 修正：release_key 改用專用格式簽章（見 _do_tally），不再需要 create_auth_packet <3
from cryptography.hazmat.primitives import serialization

# ============================================================
# 常數設定
# ============================================================
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR    = os.path.join(SERVICE_DIR, "keys")
DB_PATH     = os.path.join(SERVICE_DIR, "cc.db")
CC_ID       = "CC"
CA_URL      = os.environ.get("CA_URL",  "http://localhost:5001")
TA_URL      = os.environ.get("TA_URL",  "http://localhost:5002")
BB_URL      = os.environ.get("BB_URL",  "http://localhost:5004")
TPA_URL     = os.environ.get("TPA_URL", "http://localhost:5000")

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
        resp = http_requests.get(f"{TA_URL}/api/deadline", timeout=5)
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
        resp = http_requests.get(f"{TA_URL}/api/deadline", timeout=5)
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CC 計票中心</title>
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
  <meta http-equiv="refresh" content="15">
</head>
<body class="bg-gray-50 dark:bg-deepblack text-gray-800 dark:text-gray-100 min-h-screen transition-colors duration-300">
  <div class="max-w-5xl mx-auto px-4 py-10">

    <div class="flex items-center gap-4 mb-8">
      <div class="w-12 h-12 rounded-xl bg-white/70 dark:bg-cardblack/80 backdrop-blur-md shadow-sm flex items-center justify-center border border-gray-200 dark:border-gray-800">
        <svg class="w-6 h-6 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"></path></svg>
      </div>
      <div>
        <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">計票中心 (CC)</h1>
        <p class="text-gray-500 dark:text-gray-400 text-sm">NUTC Voting System · Count Center</p>
      </div>
      
      <div class="ml-auto flex items-center gap-3">
        <div class="flex flex-col items-end gap-1.5">
          {% if election_state == 'standby' %}
          <span class="px-3 py-1 rounded-full text-[11px] font-medium border bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800/50 backdrop-blur-sm flex items-center shadow-sm">
            <span class="inline-block w-1.5 h-1.5 rounded-full bg-amber-400 mr-1.5"></span>⏸ 等待管理員啟動選舉
          </span>
          {% else %}
          <span class="px-3 py-1 rounded-full text-[11px] font-medium border bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border-green-200 dark:border-green-800/50 backdrop-blur-sm flex items-center shadow-sm">
            <span class="inline-block w-1.5 h-1.5 rounded-full bg-green-500 mr-1.5 shadow-[0_0_4px_#22c55e]"></span>運作中
          </span>
          {% if deadline_ts %}
          <span class="px-3 py-1 rounded-full text-[11px] font-medium border backdrop-blur-sm shadow-sm flex items-center
            {% if is_expired %}bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800/50{% else %}bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800/50{% endif %}">
            {% if is_expired %}
              <svg class="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
              投票已截止
            {% else %}
              <svg class="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
              截止：{{ deadline_str }}
            {% endif %}
          </span>
          {% endif %}
          {% endif %}
        </div>

        <div class="h-8 w-px bg-gray-200 dark:bg-gray-700 mx-1"></div>

        <button onclick="toggleTheme()" class="p-2 rounded-lg bg-white/70 dark:bg-cardblack/80 border border-gray-200 dark:border-gray-800 shadow-sm hover:bg-gray-100 dark:hover:bg-gray-900 transition-colors text-gray-600 dark:text-gray-300 focus:outline-none focus:ring-2 focus:ring-msblue/50">
          <svg class="w-4 h-4 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
          <svg class="w-4 h-4 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
        </button>
      </div>
    </div>

    <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
      <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-sm p-5 flex flex-col justify-center">
        <p class="text-gray-500 dark:text-gray-400 text-xs font-medium uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <svg class="w-3.5 h-3.5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
          收到信封
        </p>
        <p class="text-3xl font-semibold text-gray-900 dark:text-white">{{ envelope_count }}</p>
      </div>
      <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-sm p-5 flex flex-col justify-center">
        <p class="text-gray-500 dark:text-gray-400 text-xs font-medium uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <svg class="w-3.5 h-3.5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
          合法選票
        </p>
        <p class="text-3xl font-semibold text-gray-900 dark:text-white">{{ valid_count }}</p>
      </div>
      <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-sm p-5 flex flex-col justify-center">
        <p class="text-gray-500 dark:text-gray-400 text-xs font-medium uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <svg class="w-3.5 h-3.5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path></svg>
          開票狀態
        </p>
        <p class="text-sm font-semibold flex items-center gap-1 {% if tally_done %}text-green-600 dark:text-green-400{% else %}text-amber-600 dark:text-amber-500{% endif %}">
          {% if tally_done %}
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
            已完成
          {% else %}
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
            待開票
          {% endif %}
        </p>
      </div>
      <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-sm p-5 flex flex-col justify-center">
        <p class="text-gray-500 dark:text-gray-400 text-xs font-medium uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <svg class="w-3.5 h-3.5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4"></path></svg>
          Merkle Root
        </p>
        <p class="text-xs font-mono text-gray-700 dark:text-gray-300 break-all bg-gray-50 dark:bg-[#0a0a0a] rounded px-2 py-1 border border-gray-100 dark:border-gray-800">
          {% if merkle_root %}{{ merkle_root[:20] }}...{% else %}<span class="text-gray-400">尚未產生</span>{% endif %}
        </p>
      </div>
    </div>

    {% if not tally_done %}
    <div class="mb-6">
      <form method="POST" action="/ui/tally">
        <button type="submit"
          class="w-full py-3.5 rounded-xl bg-msblue hover:bg-msblueHover text-white font-medium shadow-md transition-all text-sm flex items-center justify-center gap-2 focus:outline-none focus:ring-2 focus:ring-msblue/50 focus:ring-offset-2 dark:focus:ring-offset-[#050505]">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5M7.188 2.239l.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656l-2.12 2.122"></path></svg>
          觸發開票（向 TA 請求 SK_TA）
        </button>
      </form>
    </div>
    {% endif %}

    {% if tally_done and tally_results %}
    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-msblue/30 dark:border-msblue/40 shadow-md p-6 mb-8">
      <h2 class="font-medium text-gray-800 dark:text-gray-200 mb-5 text-sm uppercase tracking-wider flex items-center gap-2">
        <svg class="w-4 h-4 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path></svg>
        計票結果
      </h2>
      <div class="space-y-4">
        {% for candidate, count in tally_results.items() %}
        <div>
          <div class="flex justify-between text-sm mb-1.5">
            <span class="font-mono text-gray-700 dark:text-gray-300 font-medium">{{ candidate }}</span>
            <span class="text-gray-900 dark:text-white font-semibold">{{ count }} 票</span>
          </div>
          <div class="w-full bg-gray-100 dark:bg-[#1a1a1a] rounded-full h-2 overflow-hidden">
            <div class="bg-msblue h-2 rounded-full transition-all duration-500" style="width: {{ (count / valid_count * 100) | int }}%"></div>
          </div>
        </div>
        {% endfor %}
      </div>
      {% if merkle_root %}
      <div class="mt-6 pt-5 border-t border-gray-100 dark:border-gray-800">
        <p class="text-[11px] text-gray-500 dark:text-gray-400 mb-1">Root_official</p>
        <p class="font-mono text-[11px] sm:text-xs text-gray-800 dark:text-gray-300 break-all bg-gray-50 dark:bg-[#0a0a0a] p-3 rounded-lg border border-gray-200 dark:border-gray-800/80 shadow-inner">{{ merkle_root }}</p>
      </div>
      {% endif %}
    </div>
    {% endif %}

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      
      <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md overflow-hidden flex flex-col">
        <div class="px-5 py-4 border-b border-gray-100 dark:border-gray-800/60 bg-gray-50/50 dark:bg-[#0a0a0a]/50">
          <h2 class="font-medium text-gray-800 dark:text-gray-200 text-sm flex items-center gap-2">
            <svg class="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
            合法選票記錄
          </h2>
        </div>
        {% if valid_votes %}
        <div class="overflow-x-auto flex-1">
          <table class="w-full text-sm">
            <thead class="bg-gray-50 dark:bg-[#0a0a0a] text-gray-500 dark:text-gray-500 text-[11px] uppercase tracking-wider">
              <tr>
                <th class="px-5 py-3 text-left font-medium">#</th>
                <th class="px-5 py-3 text-left font-medium">內容</th>
                <th class="px-5 py-3 text-left font-medium">m_hex (前 20)</th>
                <th class="px-5 py-3 text-left font-medium">驗證時間</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-800/60">
              {% for v in valid_votes %}
              <tr class="hover:bg-gray-50 dark:hover:bg-[#1a1a1a] transition-colors">
                <td class="px-5 py-3.5 text-gray-400 dark:text-gray-600 text-[11px]">{{ v.id }}</td>
                <td class="px-5 py-3.5 font-mono text-gray-800 dark:text-gray-300 font-medium text-xs">{{ v.vote }}</td>
                <td class="px-5 py-3.5 font-mono text-gray-500 dark:text-gray-500 text-[11px]">{{ v.m_hex[:20] }}...</td>
                <td class="px-5 py-3.5">
                  <p class="text-gray-600 dark:text-gray-400 text-[11px] font-mono">{{ v.verified_at | ts_to_str }}</p>
                  <p class="text-gray-400 dark:text-gray-600 text-[10px]">{{ v.verified_at }}</p>
                </td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
        {% else %}
        <div class="px-5 py-16 text-center text-gray-500 dark:text-gray-600 flex-1 flex flex-col justify-center">
          <svg class="w-10 h-10 mx-auto text-gray-300 dark:text-gray-700 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
          <p class="text-sm">尚無合法選票</p>
          <p class="text-xs mt-1 text-gray-400">（需先觸發開票）</p>
        </div>
        {% endif %}
      </div>

      <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md overflow-hidden flex flex-col">
        <div class="px-5 py-4 border-b border-gray-100 dark:border-gray-800/60 bg-gray-50/50 dark:bg-[#0a0a0a]/50 flex items-center justify-between">
          <h2 class="font-medium text-gray-800 dark:text-gray-200 text-sm flex items-center gap-2">
            <svg class="w-4 h-4 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
            收到的數位信封
          </h2>
          <span class="text-[10px] text-gray-500 dark:text-gray-500 flex items-center gap-1.5">
            <span class="relative flex h-1.5 w-1.5">
              <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-msblue opacity-40"></span>
              <span class="relative inline-flex rounded-full h-1.5 w-1.5 bg-msblue"></span>
            </span>
            自動更新
          </span>
        </div>
        {% if envelopes %}
        <div class="overflow-x-auto flex-1">
          <table class="w-full text-sm">
            <thead class="bg-gray-50 dark:bg-[#0a0a0a] text-gray-500 dark:text-gray-500 text-[11px] uppercase tracking-wider">
              <tr>
                <th class="px-5 py-3 text-left font-medium">#</th>
                <th class="px-5 py-3 text-left font-medium">C_Data (前 20)</th>
                <th class="px-5 py-3 text-left font-medium">狀態</th>
                <th class="px-5 py-3 text-left font-medium">收到時間</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-800/60">
              {% for e in envelopes %}
              <tr class="hover:bg-gray-50 dark:hover:bg-[#1a1a1a] transition-colors">
                <td class="px-5 py-3.5 text-gray-400 dark:text-gray-600 text-[11px]">{{ e.id }}</td>
                <td class="px-5 py-3.5 font-mono text-gray-500 dark:text-gray-500 text-[11px]">{{ e.c_data[:20] }}...</td>
                <td class="px-5 py-3.5">
                  {% if e.status == 'verified' %}
                  <span class="px-2 py-0.5 rounded text-[10px] font-medium bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800 whitespace-nowrap">已驗證</span>
                  {% elif e.status == 'invalid' %}
                  <span class="px-2 py-0.5 rounded text-[10px] font-medium bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800 whitespace-nowrap">無效</span>
                  {% else %}
                  <span class="px-2 py-0.5 rounded text-[10px] font-medium bg-yellow-50 dark:bg-amber-900/30 text-yellow-700 dark:text-amber-400 border border-yellow-200 dark:border-amber-800 whitespace-nowrap">待驗證</span>
                  {% endif %}
                </td>
                <td class="px-5 py-3.5">
                  <p class="text-gray-600 dark:text-gray-400 text-[11px] font-mono">{{ e.received_at | ts_to_str }}</p>
                  <p class="text-gray-400 dark:text-gray-600 text-[10px]">{{ e.received_at }}</p>
                </td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
        {% else %}
        <div class="px-5 py-16 text-center text-gray-500 dark:text-gray-600 flex-1 flex flex-col justify-center">
          <svg class="w-10 h-10 mx-auto text-gray-300 dark:text-gray-700 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
          <p class="text-sm">尚未收到任何數位信封</p>
        </div>
        {% endif %}
      </div>
      
    </div>

  </div>
</body>
</html>"""
# ── 路由 ──────────────────────────────────────────────────

@app.route('/')
def dashboard():
    envelopes  = db.fetchall("SELECT id, c_data, status, received_at FROM envelopes ORDER BY id DESC")
    valid_votes = db.fetchall("SELECT id, vote, m_hex, verified_at FROM valid_votes ORDER BY id")
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
        resp = http_requests.get(f"{TA_URL}/api/deadline", timeout=3)
        data = resp.json()
        if data.get("status") == "success":
            election_state = data.get("election_state", "standby")
    except Exception:
        pass

    return render_template_string(
        _DASHBOARD_HTML,
        envelopes=envelopes,
        valid_votes=valid_votes,
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
    _do_tally()
    return redirect('/')


@app.route('/api/public_key', methods=['GET'])
def api_public_key():
    """[GET] 回傳 CC 公鑰 PEM"""
    return jsonify({
        "status":         "success",
        "public_key_pem": _public_key_pem,
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
    return jsonify({"status": "success", "message": "信封已接收"}), 200


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
    result = _do_tally()
    if result.get('status') == 'success':
        return jsonify(result), 200
    else:
        return jsonify(result), 400


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

        resp = http_requests.post(f"{TA_URL}/api/release_key", json=request_payload, timeout=10)
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
    try:
        resp = http_requests.get(f"{TPA_URL}/api/public_key", timeout=10)
        tpa_data = resp.json()
        tpa_e = hex_to_int(tpa_data['e'])
        tpa_n = hex_to_int(tpa_data['n'])
        _set_state('tpa_e', tpa_data['e'])
        _set_state('tpa_n', tpa_data['n'])
    except Exception as e:
        return {"status": "error", "message": f"無法取得 TPA 公鑰：{e}"}

    # 步驟 3：載入 TA 私鑰
    ta_private_key = serialization.load_pem_private_key(
        sk_ta_data['private_key_pem'].encode('utf-8'),
        password=None,
    )

    # 步驟 4：解密驗證所有暫存信封
    pending_envelopes = db.fetchall(
        "SELECT id, c_data, iv, tag, aad, k FROM envelopes WHERE status = 'pending'"
    )
    now = int(time.time())
    valid_count = 0

    for env in pending_envelopes:
        pending = {
            'c_data': env['c_data'],
            'iv':     env['iv'],
            'tag':    env.get('tag', ''),
            'aad':    env.get('aad', ''),
            'k':      env['k'],
        }
        try:
            result = open_envelope_layer2(pending, ta_private_key, tpa_e, tpa_n)

            # v2.0 修正：原本沒有做 m_hex（選票流水號雜湊）去重，重放同一張
            # 已簽章選票的最後一道防線是空的。現在靠 valid_votes.m_hex 的
            # UNIQUE 索引在資料庫層原子化擋下重複，用 IntegrityError 判斷。 <3
            try:
                db.execute(
                    "INSERT INTO valid_votes (vote, m_hex, verified_at) VALUES (?, ?, ?)",
                    (result['vote'], result['m_hex'], now),
                )
            except sqlite3.IntegrityError:
                db.execute(
                    "UPDATE envelopes SET status = 'm_duplicate' WHERE id = ?",
                    (env['id'],),
                )
                print(f"[CC] 選票重複（m_hex 已存在，視為非法）：{result['m_hex'][:16]}...")
                continue  # <3

            db.execute(
                "UPDATE envelopes SET status = 'verified' WHERE id = ?",
                (env['id'],),
            )
            valid_count += 1
            # 日誌使用人類可讀格式
            print(f"[CC] 選票合法：{result['vote']}（Unix ts：{now}  →  {ts_to_human(now)}）")
        except Exception as exc:
            db.execute(
                "UPDATE envelopes SET status = 'invalid' WHERE id = ?",
                (env['id'],),
            )
            print(f"[CC] 選票無效：{exc}")

    # 步驟 5：Secure Shuffle + 建構 Merkle Tree
    # 將合法選票以密碼學安全隨機順序洗牌，斷絕「提交順序 → 選民」關聯
    valid_votes_raw = db.fetchall("SELECT id, vote, m_hex FROM valid_votes ORDER BY id")

    # Fisher-Yates shuffle（使用 secrets CSPRNG）
    valid_votes = list(valid_votes_raw)
    for i in range(len(valid_votes) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        valid_votes[i], valid_votes[j] = valid_votes[j], valid_votes[i]

    # v2.0 修正：洗牌結果原本只存在這次執行的記憶體裡，算完 root 就丟了，
    # valid_votes 表沒有記錄洗牌後的順序。之後 /api/results、
    # /api/merkle_proof/<index> 又是用未洗牌的 id 順序重建 Merkle Tree，
    # 算出來的 root 會跟這裡簽章、推送給 BB 的 root_official 對不上，
    # 選民拿 CC 給的 proof 去驗證會失敗。現在把洗牌後的順序寫回 shuffle_seq。 <3
    for seq, v in enumerate(valid_votes):
        db.execute("UPDATE valid_votes SET shuffle_seq = ? WHERE id = ?", (seq, v['id']))  # <3

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
        
        resp = http_requests.post(f"{BB_URL}/api/publish", json=bb_payload, timeout=10)
        if resp.status_code == 200:
            print(f"[CC] 結果已簽章並推送至 BB（簽章長度：{len(signature)} bytes）")
        else:
            print(f"[CC] 警告：BB 拒絕結果（HTTP {resp.status_code}）：{resp.text}")
    except Exception as e:
        print(f"[CC] 警告：無法推送至 BB（{e}）")

    return {
        "status":       "success",
        "valid_count":  valid_count,
        "tally":        tally,
        "merkle_root":  merkle_root,
        # Unix timestamp（後端標準）
        "tallied_at":   now,
    }


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=False)
