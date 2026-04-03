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
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">
  <div class="max-w-2xl mx-auto px-4 py-10">

    <!-- Header -->
    <div class="flex items-center gap-4 mb-8">
      <div class="w-12 h-12 rounded-xl bg-rose-600 flex items-center justify-center text-2xl">🗳️</div>
      <div>
        <h1 class="text-2xl font-bold text-white">電子投票系統</h1>
        <p class="text-gray-400 text-sm">NUTC Voting System · 選民：{{ voter_id }}</p>
      </div>
      {% if already_voted %}
      <span class="ml-auto px-3 py-1 rounded-full bg-green-900 text-green-300 text-xs font-semibold">✓ 已投票</span>
      {% else %}
      <span class="ml-auto px-3 py-1 rounded-full bg-blue-900 text-blue-300 text-xs font-semibold">● 尚未投票</span>
      {% endif %}
    </div>

    <!-- Deadline Countdown Banner -->
    <div id="deadline-banner" class="mb-6 hidden">
      <div id="deadline-active"
        class="bg-amber-900/30 border border-amber-700 rounded-xl p-4 flex items-center justify-between hidden">
        <div>
          <p class="text-amber-300 font-semibold text-sm">⏱ 投票截止倒數</p>
          <!-- UI 顯示：人類可讀格式（由 JS 填入） -->
          <p class="text-gray-400 text-xs mt-0.5">截止時間：<span id="deadline-str" class="font-mono text-amber-200"></span></p>
          <p class="text-gray-600 text-xs">Unix timestamp：<span id="deadline-ts-display"></span></p>
        </div>
        <div class="text-right">
          <p id="countdown-display" class="text-2xl font-bold font-mono text-amber-400">--:--:--</p>
          <p class="text-xs text-gray-500">剩餘時間</p>
        </div>
      </div>
      <div id="deadline-expired"
        class="bg-red-900/40 border border-red-700 rounded-xl p-4 hidden">
        <p class="text-red-300 font-bold">投票已截止</p>
        <p class="text-gray-400 text-sm mt-1">截止時間已過，無法再提交選票。</p>
      </div>
    </div>

    {% if flash_msg %}
    <div class="mb-6 p-4 rounded-xl {% if flash_type == 'error' %}bg-red-900/40 border border-red-700 text-red-300{% else %}bg-green-900/40 border border-green-700 text-green-300{% endif %}">
      {{ flash_msg }}
    </div>
    {% endif %}

    {% if already_voted %}
    <!-- Already Voted -->
    <div class="bg-gray-900 rounded-2xl border border-gray-800 p-8 text-center mb-6">
      <div class="text-5xl mb-4">✅</div>
      <h2 class="text-xl font-semibold text-green-400 mb-2">投票完成！</h2>
      <p class="text-gray-400 text-sm mb-6">您的選票已成功提交並加密傳送至計票中心。</p>
      <div class="bg-gray-800 rounded-xl p-4 text-left mb-4">
        <p class="text-xs text-gray-400 mb-1">投票內容</p>
        <p class="font-mono text-rose-300 font-semibold">{{ vote_record.vote }}</p>
      </div>
      <div class="bg-gray-800 rounded-xl p-4 text-left mb-2">
        <p class="text-xs text-gray-400 mb-1">投票時間（人類可讀）</p>
        <p class="font-mono text-xs text-gray-300">{{ vote_record.voted_at | ts_to_str }}</p>
      </div>
      <div class="bg-gray-800 rounded-xl p-4 text-left mb-6">
        <p class="text-xs text-gray-400 mb-1">選票包雜湊值 m_hex（請妥善保存，用於驗證）</p>
        <p class="font-mono text-xs text-indigo-300 break-all">{{ vote_record.m_hex }}</p>
      </div>
      <div class="flex gap-3">
        <a href="/status" class="flex-1 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm font-semibold text-center transition">
          查看詳細狀態
        </a>
        <a href="{{ bb_url }}/verify?m_hex={{ vote_record.m_hex }}" target="_blank"
          class="flex-1 py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-sm font-semibold text-center transition">
          前往 BB 驗證 →
        </a>
      </div>
    </div>

    {% else %}
    <!-- Vote Form -->
    <div class="bg-gray-900 rounded-2xl border border-gray-800 p-8 mb-6">
      <h2 class="font-semibold text-gray-200 mb-6 text-lg">請選擇您支持的候選人</h2>
      <form method="POST" action="/vote" id="voteForm">
        <div class="space-y-3 mb-8">
          {% for candidate in candidates %}
          <label class="flex items-center gap-4 p-4 rounded-xl border border-gray-700 hover:border-rose-500 hover:bg-gray-800/50 cursor-pointer transition group">
            <input type="radio" name="candidate" value="{{ candidate }}" required
              class="w-4 h-4 accent-rose-500">
            <span class="font-mono text-gray-200 group-hover:text-white transition">{{ candidate }}</span>
          </label>
          {% endfor %}
        </div>
        <button type="submit" id="submitBtn"
          class="w-full py-3 bg-rose-600 hover:bg-rose-500 rounded-xl text-white font-semibold transition text-sm disabled:opacity-50 disabled:cursor-not-allowed disabled:bg-gray-700">
          提交選票
        </button>
        <p id="deadline-block-msg" class="mt-3 text-center text-red-400 text-sm hidden">
          投票已截止，無法提交選票。
        </p>
      </form>
    </div>

    <!-- Flow Info -->
    <div class="bg-gray-900 rounded-xl border border-gray-800 p-5">
      <h3 class="font-semibold text-gray-300 mb-3 text-sm">投票流程說明</h3>
      <div class="space-y-2 text-xs text-gray-400">
        <div class="flex items-start gap-2">
          <span class="text-blue-400 mt-0.5">①</span>
          <span>雙向身分認證（Voter ↔ TPA），含 CA 憑證鏈驗證</span>
        </div>
        <div class="flex items-start gap-2">
          <span class="text-blue-400 mt-0.5">②</span>
          <span>盲簽章：選票雜湊值盲化後送 TPA 簽章，保護投票隱私</span>
        </div>
        <div class="flex items-start gap-2">
          <span class="text-blue-400 mt-0.5">③</span>
          <span>數位信封：C_Data = E_k(E_PK_TA(...), S', m)，C_Key = E_PK_CC(k)</span>
        </div>
        <div class="flex items-start gap-2">
          <span class="text-blue-400 mt-0.5">④</span>
          <span>信封傳送至計票中心（CC），等待截止後開票</span>
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
            submitBtn.textContent = '投票已截止';
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
          countdownEl.classList.remove('text-amber-400');
          countdownEl.classList.add('text-red-400');
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
            submitBtn.textContent = '投票已截止';
          }
          console.warn('[Voter] fetch 攔截：截止時間已過，阻止提交（nowSec=' + nowSec + ' > deadlineTs=' + deadlineTs + '）');
          return;
        }
      }
      // 正常提交：顯示處理中
      const btn = document.getElementById('submitBtn');
      if (btn) {
        btn.textContent = '⏳ 處理中...';
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
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">
  <div class="max-w-3xl mx-auto px-4 py-10">

    <div class="flex items-center gap-3 mb-8">
      <a href="/" class="text-gray-400 hover:text-white text-sm">← 返回投票頁</a>
    </div>

    <div class="flex items-center gap-4 mb-8">
      <div class="w-12 h-12 rounded-xl bg-rose-600 flex items-center justify-center text-2xl">📊</div>
      <div>
        <h1 class="text-2xl font-bold text-white">投票狀態</h1>
        <p class="text-gray-400 text-sm">選民：{{ voter_id }}</p>
      </div>
    </div>

    {% if vote_record %}
    <!-- Vote Record -->
    <div class="bg-gray-900 rounded-xl border border-gray-800 p-6 mb-6">
      <h2 class="font-semibold text-gray-200 mb-4">投票記錄</h2>
      <div class="grid grid-cols-2 gap-4 text-sm">
        <div>
          <p class="text-gray-400 text-xs mb-1">選民 ID</p>
          <p class="font-mono text-rose-300">{{ vote_record.voter_id }}</p>
        </div>
        <div>
          <p class="text-gray-400 text-xs mb-1">序號 (SN)</p>
          <p class="font-mono text-gray-300">{{ vote_record.sn }}</p>
        </div>
        <div>
          <p class="text-gray-400 text-xs mb-1">投票內容</p>
          <p class="font-mono text-rose-300 font-semibold">{{ vote_record.vote }}</p>
        </div>
        <div>
          <p class="text-gray-400 text-xs mb-1">投票時間（人類可讀）</p>
          <!-- UI 顯示：人類可讀格式 -->
          <p class="text-gray-300 font-mono text-xs">{{ vote_record.voted_at | ts_to_str }}</p>
          <p class="text-gray-600 text-xs mt-0.5">Unix ts：{{ vote_record.voted_at }}</p>
        </div>
      </div>
      <div class="mt-4 pt-4 border-t border-gray-800">
        <p class="text-gray-400 text-xs mb-1">m_hex（選票包雜湊值，用於 Merkle Proof 驗證）</p>
        <p class="font-mono text-xs text-indigo-300 break-all">{{ vote_record.m_hex }}</p>
      </div>
      <div class="mt-3">
        <p class="text-gray-400 text-xs mb-1">S'_hex（TPA 盲簽章，前 40 字元）</p>
        <p class="font-mono text-xs text-gray-400 break-all">{{ vote_record.s_prime_hex[:40] }}...</p>
      </div>
    </div>

    <!-- Verify Button -->
    <div class="flex gap-3">
      <a href="{{ bb_url }}/verify?m_hex={{ vote_record.m_hex }}" target="_blank"
        class="flex-1 py-3 bg-indigo-600 hover:bg-indigo-500 rounded-xl text-sm font-semibold text-center transition">
        前往 BB 驗證 Merkle Proof →
      </a>
    </div>
    {% else %}
    <div class="bg-gray-900 rounded-xl border border-gray-800 p-10 text-center">
      <p class="text-gray-500">尚未投票</p>
      <a href="/" class="mt-4 inline-block px-6 py-2 bg-rose-600 hover:bg-rose-500 rounded-lg text-sm font-semibold transition">
        前往投票
      </a>
    </div>
    {% endif %}

    <!-- Vote Log -->
    {% if logs %}
    <div class="mt-6 bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-800">
        <h2 class="font-semibold text-gray-200">投票流程記錄</h2>
      </div>
      <div class="divide-y divide-gray-800">
        {% for log in logs %}
        <div class="px-6 py-3 flex items-start gap-3">
          <span class="{% if log.status == 'ok' %}text-green-400{% else %}text-red-400{% endif %} text-sm mt-0.5">
            {% if log.status == 'ok' %}✓{% else %}✗{% endif %}
          </span>
          <div class="flex-1 min-w-0">
            <p class="text-xs text-gray-400">{{ log.step }}</p>
            <p class="text-sm text-gray-200 truncate">{{ log.message }}</p>
          </div>
          <!-- UI 顯示：人類可讀格式 -->
          <div class="text-right shrink-0">
            <p class="text-xs text-gray-300 font-mono">{{ log.logged_at | ts_to_str }}</p>
            <p class="text-xs text-gray-600">{{ log.logged_at }}</p>
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
