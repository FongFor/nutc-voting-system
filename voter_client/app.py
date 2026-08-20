"""
voter_client/app.py  —  選民端

所有密碼學運算在選民瀏覽器本地完成（Web Crypto API + BigInt）：
  - RSA-2048 金鑰對生成
  - PoP 持有權簽章（RSA-PSS-SHA256）
  - TPA 認證封包（JSON sort + RSA-PSS）
  - FDH 盲化因子（MGF1-SHA256 BigInt）
  - 盲化 / 去盲化 / 驗證
  - 數位信封封裝（AES-256-GCM + RSA-OAEP）

私鑰（SK_Voter）與憑證儲存於 IndexedDB

Flask 伺服器只做：
  1. 提供 HTML 頁面與 /voter-crypto.js
  2. 代理請求至 CA / TPA / CC / TA / BB
  3. 接收並儲存投票回執（m_hex、SN）
"""

import os
import sys
import time
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string
import requests as http_requests

from shared.db_utils import Database
from shared.config_loader import get_candidates as cfg_get_candidates, make_reload_endpoint
from shared.format_utils import ts_to_human

# ============================================================
# 常數設定
# ============================================================
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR    = os.path.join(SERVICE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH     = os.path.join(DATA_DIR, "voter.db")

VOTER_ID = os.environ.get("VOTER_ID", "")   # 僅作表單預設值，不強制
CA_URL   = os.environ.get("CA_URL",  "http://localhost:5001")
TPA_URL  = os.environ.get("TPA_URL", "http://localhost:5000")
TA_URL   = os.environ.get("TA_URL",  "http://localhost:5002")
CC_URL   = os.environ.get("CC_URL",  "http://localhost:5003")
BB_URL   = os.environ.get("BB_URL",  "http://localhost:5004")

def _get_candidates():
    env_val = os.environ.get("CANDIDATES")
    if env_val:
        return [c.strip() for c in env_val.split(",") if c.strip()]
    return cfg_get_candidates()

# ============================================================
# 資料庫初始化（只保留回執記錄，crypto 在 browser 端）
# ============================================================
db = Database(DB_PATH)
db.execute("""
    CREATE TABLE IF NOT EXISTS vote_record (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        voter_id    TEXT NOT NULL,
        sn          TEXT NOT NULL UNIQUE,
        vote        TEXT NOT NULL,
        m_hex       TEXT NOT NULL,
        s_prime_hex TEXT NOT NULL,
        voted_at    INTEGER NOT NULL
    )
""")

# ============================================================
# Flask App
# ============================================================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))

# ── 代理工具 ──────────────────────────────────────────────────

def _proxy(method, url, data=None, params=None):
    try:
        if method == "GET":
            r = http_requests.get(url, params=params, timeout=10)
        else:
            r = http_requests.post(url, json=data, timeout=15)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"status": "error", "message": f"代理錯誤：{e}"}), 502

# ── API 代理路由 ────────────────────────────────────────────

@app.route('/api/proxy/ca/issue_cert', methods=['POST'])
def proxy_ca_issue_cert():
    return _proxy("POST", f"{CA_URL}/api/issue_cert", request.get_json())

@app.route('/api/proxy/ca/voter_status', methods=['GET'])
def proxy_ca_voter_status():
    voter_id = request.args.get('voter_id', '')
    return _proxy("GET", f"{CA_URL}/api/voter_status", params={'voter_id': voter_id})

@app.route('/api/proxy/tpa/public_key', methods=['GET'])
def proxy_tpa_pk():
    return _proxy("GET", f"{TPA_URL}/api/public_key")

@app.route('/api/proxy/tpa/auth', methods=['POST'])
def proxy_tpa_auth():
    return _proxy("POST", f"{TPA_URL}/api/auth", request.get_json())

@app.route('/api/proxy/tpa/blind_sign', methods=['POST'])
def proxy_tpa_blind_sign():
    return _proxy("POST", f"{TPA_URL}/api/blind_sign", request.get_json())

@app.route('/api/proxy/cc/public_key', methods=['GET'])
def proxy_cc_pk():
    return _proxy("GET", f"{CC_URL}/api/public_key")

@app.route('/api/proxy/cc/receive_envelope', methods=['POST'])
def proxy_cc_envelope():
    return _proxy("POST", f"{CC_URL}/api/receive_envelope", request.get_json())

@app.route('/api/proxy/ta/public_key', methods=['GET'])
def proxy_ta_pk():
    return _proxy("GET", f"{TA_URL}/api/public_key")

@app.route('/api/proxy/ta/deadline', methods=['GET'])
def proxy_ta_deadline():
    return _proxy("GET", f"{TA_URL}/api/deadline")

@app.route('/api/proxy/bb/results', methods=['GET'])
def proxy_bb_results():
    return _proxy("GET", f"{BB_URL}/api/results")

# ── 業務 API ──────────────────────────────────────────────────

@app.route('/api/candidates', methods=['GET'])
def api_candidates():
    return jsonify({"status": "success", "candidates": _get_candidates()}), 200

@app.route('/api/all_receipts', methods=['GET'])
def api_all_receipts():
    """回傳本輪所有投票回執（供 Admin 匯出使用）。"""
    rows = db.fetchall(
        "SELECT voter_id, sn, vote, m_hex, voted_at FROM vote_record ORDER BY voted_at"
    )
    for r in rows:
        r['voted_at_str'] = ts_to_human(r['voted_at'])
    return jsonify({"status": "success", "receipts": rows, "count": len(rows)}), 200

@app.route('/api/vote_status', methods=['GET'])
def api_vote_status():
    voter_id = request.args.get('voter_id', '')
    if not voter_id:
        return jsonify({"status": "not_voted"}), 200
    rec = db.fetchone(
        "SELECT voter_id, sn, vote, m_hex, voted_at FROM vote_record WHERE voter_id = ? ORDER BY id DESC LIMIT 1",
        (voter_id,)
    )
    if rec:
        return jsonify({"status": "voted", **rec, "voted_at_str": ts_to_human(rec['voted_at'])}), 200
    return jsonify({"status": "not_voted", "voter_id": voter_id}), 200

@app.route('/api/save_vote_receipt', methods=['POST'])
def api_save_vote_receipt():
    """瀏覽器完成投票流程後，上傳回執儲存於 DB 供查詢。"""
    d = request.get_json() or {}
    required = ['voter_id', 'sn', 'vote', 'm_hex', 's_prime_hex']
    if not all(k in d for k in required):
        return jsonify({"status": "error", "message": "缺少必要欄位"}), 400
    now = int(time.time())
    try:
        db.execute(
            "INSERT OR IGNORE INTO vote_record (voter_id, sn, vote, m_hex, s_prime_hex, voted_at) VALUES (?,?,?,?,?,?)",
            (d['voter_id'], d['sn'], d['vote'], d['m_hex'], d['s_prime_hex'], now),
        )
        print(f"[Voter:{d['voter_id']}] 投票回執已儲存  sn={d['sn']}  m={d['m_hex'][:16]}...")
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "success"}), 200

# ── 共用 JS（瀏覽器端密碼學工具集） ─────────────────────────────

_CRYPTO_JS = r"""
/* =====================================================================
   voter-crypto.js  —  瀏覽器端密碼學工具集
   - Web Crypto API：RSA-2048 keygen / RSA-PSS sign / RSA-OAEP encrypt / AES-GCM
   - BigInt：modpow, modinv, FDH (MGF1-SHA256), 盲化 / 去盲化
   - IndexedDB：keypair + cert 本地持久化
   ===================================================================== */

/* ---------- IndexedDB helpers ---------- */
function _idb(mode) {
  return new Promise((res, rej) => {
    const req = indexedDB.open('voter-crypto', 1);
    req.onupgradeneeded = e => e.target.result.createObjectStore('kv');
    req.onsuccess = e => res([e.target.result, mode]);
    req.onerror  = () => rej(req.error);
  });
}
async function idbSave(entries) {
  const [db] = await _idb('readwrite');
  return new Promise((res, rej) => {
    const tx = db.transaction('kv', 'readwrite');
    const s  = tx.objectStore('kv');
    for (const [k, v] of Object.entries(entries)) s.put(v, k);
    tx.oncomplete = res;
    tx.onerror    = () => rej(tx.error);
  });
}
async function idbLoad(key) {
  const [db] = await _idb('readonly');
  return new Promise((res, rej) => {
    const tx = db.transaction('kv', 'readonly');
    const r  = tx.objectStore('kv').get(key);
    r.onsuccess = () => res(r.result ?? null);
    r.onerror   = () => rej(r.error);
  });
}
async function idbHasCert() {
  return !!(await idbLoad('certPem'));
}

/* ---------- PEM / DER / Bytes ---------- */
function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  const str  = atob(b64);
  return Uint8Array.from(str, c => c.charCodeAt(0)).buffer;
}
function derToPem(der, type) {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(der)));
  return `-----BEGIN ${type}-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END ${type}-----`;
}
function hexToBytes(hex) {
  const h = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  const padded = h.length % 2 ? '0' + h : h;
  return new Uint8Array(padded.match(/.{2}/g).map(b => parseInt(b, 16)));
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBigInt(hex) {
  return BigInt(hex.startsWith('0x') || hex.startsWith('0X') ? hex : '0x' + hex);
}
function b64encode(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

/* ---------- SHA-256 ---------- */
async function sha256Bytes(input) {
  const data = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}
async function sha256Hex(input) {
  return bytesToHex(await sha256Bytes(input));
}

/* ---------- RSA keypair ---------- */
async function generateRSAKeypair() {
  return crypto.subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify']
  );
}
async function exportPublicKeyPEM(publicKey) {
  return derToPem(await crypto.subtle.exportKey('spki', publicKey), 'PUBLIC KEY');
}

/* ---------- RSA-PSS 簽章 (saltLength=32 = hLen) ---------- */
async function rsaPssSign(privateKey, data) {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const sig   = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, privateKey, bytes);
  return b64encode(new Uint8Array(sig));
}

/* ---------- RSA-OAEP 加密 ---------- */
async function rsaOaepEncrypt(publicKeyPEM, plaintext) {
  const key  = await crypto.subtle.importKey('spki', pemToDer(publicKeyPEM), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const data = plaintext instanceof Uint8Array ? plaintext : new TextEncoder().encode(plaintext);
  return b64encode(new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, data)));
}

/* ---------- AES-256-GCM 加密 ---------- */
async function aesGcmEncrypt(plaintext, aadStr) {
  const k    = crypto.getRandomValues(new Uint8Array(32));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const aad  = new TextEncoder().encode(aadStr);
  const pt   = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
  const sk   = await crypto.subtle.importKey('raw', k, 'AES-GCM', true, ['encrypt']);
  const ct   = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, sk, pt));
  return {
    k,
    iv:     b64encode(iv),
    c_data: b64encode(ct.slice(0, -16)),
    tag:    b64encode(ct.slice(-16)),
    aad:    b64encode(aad),
  };
}

/* ---------- BigInt 工具 ---------- */
function modpow(base, exp, mod) {
  let r = 1n; base %= mod;
  for (; exp > 0n; exp >>= 1n) {
    if (exp & 1n) r = r * base % mod;
    base = base * base % mod;
  }
  return r;
}
function modinv(a, m) {
  let [r0, r1, s0, s1] = [a, m, 1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  return ((s0 % m) + m) % m;
}

/* ---------- FDH (MGF1-SHA256)  ---------- */
async function fdh(mBytes, nBits) {
  const target = Math.ceil(nBits / 8);
  const parts  = [];
  let len = 0;
  for (let i = 0; len < target; i++) {
    const ctr = new Uint8Array(4);
    new DataView(ctr.buffer).setUint32(0, i, false);
    const h = await sha256Bytes(new Uint8Array([...mBytes, ...ctr]));
    parts.push(h); len += 32;
  }
  const mask = new Uint8Array(parts.flat ? parts.flatMap(a => [...a]) : [].concat(...parts.map(a => [...a]))).slice(0, target);
  const excess = 8 * target - nBits + 1;
  if (excess > 0) mask[0] &= (0xFF >> excess);
  return hexToBigInt(bytesToHex(mask));
}

/* ---------- 盲化 / 去盲化 ---------- */
function generateBlindingFactor(n) {
  const bytes = new Uint8Array(Math.ceil(n.toString(16).length / 2) + 4);
  let r;
  do {
    crypto.getRandomValues(bytes);
    r = hexToBigInt(bytesToHex(bytes)) % n;
  } while (r <= 1n);
  return r;
}
function blindMessage(mu, r, e, n)   { return (mu * modpow(r, e, n)) % n; }
function unblindSignature(S, r, n)   { return (S  * modinv(r, n))   % n; }

/* ---------- 認證封包（格式須與 Python shared/auth_component.py 一致） ---------- */
async function createAuthPacket(senderId, receiverId, privateKey, certPem, nonceEcho) {
  const nonce   = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
  const ts      = Math.floor(Date.now() / 1000);
  const payload = { cert_pem: certPem, nonce, receiver_id: receiverId, sender_id: senderId, timestamp: ts };
  if (nonceEcho) payload.nonce_echo = nonceEcho;
  /* sort_keys=True + separators=(',',':') — 與 Python _serialize_payload 完全一致 */
  const sorted  = Object.fromEntries(Object.keys(payload).sort().map(k => [k, payload[k]]));
  const jsonStr = JSON.stringify(sorted);          // compact，無空格，自然排序後已一致
  const sig     = await rsaPssSign(privateKey, jsonStr);
  return { payload, signature: sig };
}
"""

@app.route('/voter-crypto.js')
def serve_crypto_js():
    return _CRYPTO_JS, 200, {'Content-Type': 'application/javascript; charset=utf-8'}

# ── HTML 模板 ──────────────────────────────────────────────────

_BASE_STYLE = """
<script src="https://cdn.tailwindcss.com"></script>
<script>
  tailwind.config = { darkMode: 'class', theme: { extend: { colors: { msblue:'#0078D4', msblueHover:'#0060A8', deepblack:'#050505', cardblack:'#111111' } } } };
  if (localStorage.getItem('theme')==='dark'||(!('theme' in localStorage)&&window.matchMedia('(prefers-color-scheme: dark)').matches)) document.documentElement.classList.add('dark');
  function toggleTheme() { document.documentElement.classList.toggle('dark'); localStorage.setItem('theme', document.documentElement.classList.contains('dark')?'dark':'light'); }
</script>
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>body{font-family:'Noto Sans',sans-serif;}</style>
<script src="/voter-crypto.js"></script>
"""

# ─────────────────────────────────────────
# 1. 身分綁定頁
# ─────────────────────────────────────────
_REGISTER_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>選民身分綁定</title>""" + _BASE_STYLE + """
</head>
<body class="bg-gray-50 dark:bg-deepblack text-gray-800 dark:text-gray-100 min-h-screen flex items-center justify-center p-4">
<div class="w-full max-w-md">

  <div class="flex items-center gap-3 mb-8">
    <div class="w-10 h-10 rounded-xl bg-white/70 dark:bg-cardblack border border-gray-200 dark:border-gray-800 flex items-center justify-center shadow-sm">
      <svg class="w-5 h-5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
    </div>
    <div>
      <h1 class="text-xl font-semibold text-gray-900 dark:text-white">身分綁定 — Phase 0</h1>
      <p class="text-xs text-gray-500">金鑰在您的瀏覽器本地生成，私鑰永不上傳</p>
    </div>
    <button onclick="toggleTheme()" class="ml-auto p-2 rounded-lg bg-white/70 dark:bg-cardblack border border-gray-200 dark:border-gray-800 text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-900">
      <svg class="w-4 h-4 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/></svg>
      <svg class="w-4 h-4 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
    </button>
  </div>

  <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-2xl border border-gray-200 dark:border-gray-800 shadow-md p-7">
    <div class="space-y-5">
      <div>
        <label class="block text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">學號 / Voter ID</label>
        <input id="voterId" type="text" value="{{ default_voter_id }}" placeholder="請輸入您的學號"
          class="w-full px-4 py-3 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-[#1a1a1a] text-sm font-mono text-gray-800 dark:text-gray-200 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-msblue/50 focus:border-msblue transition" spellcheck="false">
      </div>
      <div>
        <label class="block text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">一次性密碼 (OTP)</label>
        <input id="otp" type="text" placeholder="請輸入教務處信件中的 OTP"
          class="w-full px-4 py-3 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-[#1a1a1a] text-sm font-mono text-gray-800 dark:text-gray-200 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-msblue/50 focus:border-msblue transition" spellcheck="false" autocomplete="off">
      </div>
      <button id="regBtn" onclick="doRegister()"
        class="w-full py-3.5 bg-msblue hover:bg-msblueHover rounded-xl text-white font-medium text-sm transition shadow-md flex justify-center items-center gap-2">
        <svg id="regIcon" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
        <span id="regText">生成金鑰 · 建立 PoP · 申請憑證</span>
      </button>
    </div>
    <div id="regStatus" class="mt-4 text-sm hidden p-3 rounded-lg"></div>
  </div>

  <!-- 步驟說明 -->
  <div class="mt-5 bg-white/50 dark:bg-cardblack/50 rounded-xl border border-gray-200 dark:border-gray-800 p-4 text-xs text-gray-500 dark:text-gray-400 space-y-1.5">
    <p class="font-semibold text-gray-700 dark:text-gray-300 mb-2">瀏覽器本地執行步驟：</p>
    <p>① 在您的瀏覽器生成 RSA-2048 金鑰對（私鑰永不離開此裝置）</p>
    <p>② 用私鑰對 <code class="font-mono bg-gray-100 dark:bg-gray-800 px-1 rounded">REGISTER|學號|時間戳</code> 簽章（PoP 持有權證明）</p>
    <p>③ 將公鑰 + OTP + PoP 送至 CA，驗證通過後取得憑證</p>
    <p>④ 憑證與金鑰對儲存於 IndexedDB（僅此瀏覽器可存取）</p>
  </div>
</div>

<script>
// 若為新一輪自動導向，顯示提示
(function() {
  const reason = new URLSearchParams(location.search).get('reason');
  if (reason === 'new_round') {
    const el = document.getElementById('regStatus');
    el.classList.remove('hidden');
    el.className = 'mt-4 text-sm p-3 rounded-lg text-blue-700 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800/50';
    el.textContent = 'ℹ 系統已進入新一輪投票，請重新輸入學號與新的 OTP 完成身分綁定。';
  }
})();

async function doRegister() {
  const voterId = document.getElementById('voterId').value.trim();
  const otp     = document.getElementById('otp').value.trim();
  const btn     = document.getElementById('regBtn');
  const icon    = document.getElementById('regIcon');
  const text    = document.getElementById('regText');
  const status  = document.getElementById('regStatus');

  if (!voterId) { showStatus(status, '請輸入學號', 'error'); return; }
  if (!otp)     { showStatus(status, '請輸入 OTP', 'error'); return; }

  btn.disabled = true;
  icon.outerHTML = '<svg id="regIcon" class="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>';

  try {
    showStatus(status, '① 生成 RSA-2048 金鑰對...', 'info');
    const keypair = await generateRSAKeypair();
    const pubPEM  = await exportPublicKeyPEM(keypair.publicKey);
    const privJwk = await crypto.subtle.exportKey('jwk', keypair.privateKey);

    showStatus(status, '② 建立 PoP 持有權簽章...', 'info');
    const ts       = Math.floor(Date.now() / 1000);
    const challenge = `REGISTER|${voterId}|${ts}`;
    const popSig   = await rsaPssSign(keypair.privateKey, challenge);

    showStatus(status, '③ 向 CA 申請憑證...', 'info');
    const resp = await fetch('/api/proxy/ca/issue_cert', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ entity_id: voterId, public_key: pubPEM, otp, timestamp: ts, pop_signature: popSig }),
    });
    const data = await resp.json();
    if (data.status !== 'success') {
      const codeMap = {
        ENTITY_NOT_REGISTERED: '此學號尚未在教務處名冊中登記，請聯繫教務處。',
        ALREADY_REGISTERED:    '此學號已完成過身分綁定。',
        OTP_INVALID:           'OTP 不正確，請確認信件內容。',
        TIMESTAMP_OUT_OF_RANGE:'裝置時間偏差過大，請校正後重試。',
        POP_INVALID:           'PoP 驗證失敗，請重新整理頁面後再試。',
      };
      throw new Error(codeMap[data.code] || data.message || data.code);
    }

    showStatus(status, '④ 儲存憑證至 IndexedDB...', 'info');
    await idbSave({ privJwk, pubPEM, certPem: data.certificate, voterId });

    showStatus(status, `✓ 身分綁定成功！憑證已安全儲存於本裝置。`, 'success');
    document.getElementById('regText').textContent = '✓ 完成，跳轉至投票頁...';
    setTimeout(() => location.href = '/', 1500);

  } catch (e) {
    showStatus(status, `✗ ${e.message}`, 'error');
    document.getElementById('regBtn').disabled = false;
    document.getElementById('regText').textContent = '生成金鑰 · 建立 PoP · 申請憑證';
  }
}

function showStatus(el, msg, type) {
  el.classList.remove('hidden');
  const cls = { success:'text-green-700 dark:text-green-400 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800/50',
                error:  'text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/50',
                info:   'text-blue-700 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800/50' };
  el.className = `mt-4 text-sm p-3 rounded-lg ${cls[type]}`;
  el.textContent = msg;
}
</script>
</body>
</html>"""

# ─────────────────────────────────────────
# 2. 投票頁
# ─────────────────────────────────────────
_VOTE_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>電子投票系統</title>""" + _BASE_STYLE + """
</head>
<body class="bg-gray-50 dark:bg-deepblack text-gray-800 dark:text-gray-100 min-h-screen transition-colors duration-300">
<div class="max-w-2xl mx-auto px-4 py-10">

  <!-- 頁首 -->
  <div class="flex items-center gap-3 mb-8">
    <div class="w-10 h-10 rounded-xl bg-white/70 dark:bg-cardblack border border-gray-200 dark:border-gray-800 flex items-center justify-center shadow-sm">
      <svg class="w-5 h-5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
    </div>
    <div>
      <h1 class="text-xl font-semibold text-gray-900 dark:text-white">電子投票系統</h1>
      <p class="text-xs text-gray-500 dark:text-gray-400">選民：<span id="voterIdDisplay" class="font-mono">載入中...</span></p>
    </div>
    <div class="ml-auto flex gap-2">
      <a href="/status" class="text-xs px-3 py-1.5 rounded-lg bg-white/70 dark:bg-cardblack border border-gray-200 dark:border-gray-800 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-900 transition">投票記錄</a>
      <button onclick="doLogout()" class="text-xs px-3 py-1.5 rounded-lg bg-white/70 dark:bg-cardblack border border-gray-200 dark:border-gray-800 text-gray-500 hover:bg-red-50 dark:hover:bg-red-900/20 hover:text-red-600 dark:hover:text-red-400 transition">重新身分綁定</button>
      <button onclick="toggleTheme()" class="p-2 rounded-lg bg-white/70 dark:bg-cardblack border border-gray-200 dark:border-gray-800 text-gray-500">
        <svg class="w-4 h-4 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/></svg>
        <svg class="w-4 h-4 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
      </button>
    </div>
  </div>

  <!-- 截止時間 -->
  <div id="deadlineCard" class="mb-6 hidden bg-white/70 dark:bg-cardblack/80 rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-4 text-sm text-center text-gray-600 dark:text-gray-400">
    截止：<span id="deadlineStr" class="font-mono font-medium text-msblue"></span>
  </div>

  <!-- 已投票提示 -->
  <div id="votedBanner" class="hidden mb-6 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800/50 rounded-xl p-5 text-center">
    <p class="text-green-700 dark:text-green-400 font-semibold mb-1">您已完成投票</p>
    <p class="text-xs text-gray-500 dark:text-gray-400">m_hex：<span id="votedMhex" class="font-mono break-all"></span></p>
    <a href="/status" class="mt-3 inline-block text-xs text-msblue hover:underline">查看完整回執 →</a>
  </div>

  <!-- 投票表單 -->
  <div id="voteForm" class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-2xl border border-gray-200 dark:border-gray-800 shadow-md p-7">
    <h2 class="font-semibold text-gray-800 dark:text-gray-200 mb-5 text-sm uppercase tracking-wider">請選擇候選人</h2>
    <div id="candidateList" class="space-y-3 mb-6">
      <p class="text-gray-400 text-sm">載入候選人中...</p>
    </div>
    <button id="voteBtn" onclick="doVote()" disabled
      class="w-full py-3.5 bg-msblue hover:bg-msblueHover disabled:opacity-50 disabled:cursor-not-allowed rounded-xl text-white font-medium text-sm transition shadow-md flex justify-center items-center gap-2">
      <svg id="voteIcon" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
      <span id="voteText">確認投票</span>
    </button>
    <!-- 進度步驟 -->
    <div id="voteProgress" class="mt-4 space-y-1.5 hidden text-xs font-mono text-gray-500 dark:text-gray-400"></div>
  </div>

  <!-- 成功提示 -->
  <div id="successCard" class="hidden mt-6 bg-green-50 dark:bg-green-900/10 border border-green-200 dark:border-green-800/50 rounded-xl p-6">
    <p class="text-green-700 dark:text-green-400 font-semibold text-base mb-3">投票成功</p>
    <p class="text-xs text-gray-500 mb-1">請保存您的 m_hex 以便日後在 BB 驗證：</p>
    <code id="successMhex" class="block bg-gray-100 dark:bg-gray-800/60 rounded-lg p-3 text-xs font-mono break-all text-gray-700 dark:text-gray-300 mt-2"></code>
    <a href="/status" class="mt-4 inline-block text-xs text-msblue hover:underline">查看完整回執 →</a>
  </div>

  <!-- 錯誤提示 -->
  <div id="errorCard" class="hidden mt-4 bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800/50 rounded-xl p-4 text-sm text-red-700 dark:text-red-400"></div>
</div>

<script>
let _selectedCandidate = null;
let _privateKey = null, _certPem = null, _voterId = null;

async function init() {
  // 1. 確認身分綁定
  const certPem = await idbLoad('certPem');
  if (!certPem) { location.href = '/register'; return; }
  _certPem  = certPem;
  _voterId  = await idbLoad('voterId');
  const jwk = await idbLoad('privJwk');
  _privateKey = await crypto.subtle.importKey('jwk', jwk, { name:'RSA-PSS', hash:'SHA-256' }, false, ['sign']);
  document.getElementById('voterIdDisplay').textContent = _voterId || '—';

  // 1.5 自動偵測新一輪重置（CA 名冊已清除 → 自動清除舊憑證並導向重新綁定）
  try {
    const caResp = await fetch(`/api/proxy/ca/voter_status?voter_id=${encodeURIComponent(_voterId)}`);
    const caData = await caResp.json();
    if (caData.registered === false) {
      await new Promise(res => {
        const req = indexedDB.deleteDatabase('voter-crypto');
        req.onsuccess = res; req.onerror = res;
      });
      location.href = '/register?reason=new_round';
      return;
    }
  } catch(_) {}

  // 2. 確認未重複投票
  const statusResp = await fetch(`/api/vote_status?voter_id=${encodeURIComponent(_voterId)}`);
  const statusData = await statusResp.json();
  if (statusData.status === 'voted') {
    document.getElementById('votedBanner').classList.remove('hidden');
    document.getElementById('votedMhex').textContent = statusData.m_hex;
    document.getElementById('voteForm').classList.add('hidden');
    return;
  }

  // 3. 載入截止時間
  try {
    const deadResp = await fetch('/api/proxy/ta/deadline');
    const dead = await deadResp.json();
    if (dead.status === 'success' && dead.deadline_str) {
      document.getElementById('deadlineCard').classList.remove('hidden');
      document.getElementById('deadlineStr').textContent = dead.deadline_str;
    }
  } catch(_) {}

  // 4. 載入候選人
  try {
    const candResp = await fetch('/api/candidates');
    const candData = await candResp.json();
    const list = document.getElementById('candidateList');
    list.innerHTML = '';
    if (!candData.candidates || candData.candidates.length === 0) {
      list.innerHTML = '<p class="text-amber-500 text-sm">⚠ 目前無候選人，請聯繫管理員確認 config.json。</p>';
      return;
    }
    candData.candidates.forEach(c => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.setAttribute('data-candidate', c);
      btn.onclick = () => selectCandidate(c);
      btn.className = 'w-full text-left px-5 py-3.5 rounded-xl border-2 border-gray-200 dark:border-gray-700 hover:border-msblue hover:bg-blue-50/50 dark:hover:bg-blue-900/10 transition font-medium text-gray-800 dark:text-gray-200 text-sm';
      btn.id = `cand-${c}`;
      btn.textContent = c;
      list.appendChild(btn);
    });
  } catch(e) {
    document.getElementById('candidateList').innerHTML =
      `<p class="text-red-500 text-sm">✗ 候選人載入失敗：${e.message}<br>請確認選民端服務是否正常運作。</p>`;
  }
}

function selectCandidate(c) {
  _selectedCandidate = c;
  document.querySelectorAll('[data-candidate]').forEach(el => {
    el.classList.toggle('border-msblue', el.getAttribute('data-candidate') === c);
    el.classList.toggle('bg-blue-50/50', el.getAttribute('data-candidate') === c);
    el.classList.toggle('dark:bg-blue-900/10', el.getAttribute('data-candidate') === c);
  });
  document.getElementById('voteBtn').disabled = false;
}

function addStep(msg, ok) {
  const div = document.getElementById('voteProgress');
  div.classList.remove('hidden');
  const p = document.createElement('p');
  p.textContent = (ok === true ? '✓ ' : ok === false ? '✗ ' : '⋯ ') + msg;
  p.className = ok === true ? 'text-green-600 dark:text-green-400' : ok === false ? 'text-red-500' : 'text-blue-500';
  div.appendChild(p);
  div.scrollTop = div.scrollHeight;
}

async function doVote() {
  if (!_selectedCandidate) return;
  const btn = document.getElementById('voteBtn');
  btn.disabled = true;
  document.getElementById('voteText').textContent = '處理中...';
  document.getElementById('voteProgress').innerHTML = '';
  document.getElementById('voteProgress').classList.remove('hidden');
  document.getElementById('errorCard').classList.add('hidden');
  document.getElementById('successCard').classList.add('hidden');

  try {
    const candidate = _selectedCandidate;

    // Step 1: 取得公鑰
    addStep('取得 TPA / CC / TA 公鑰...');
    const [tpaR, ccR, taR] = await Promise.all([
      fetch('/api/proxy/tpa/public_key').then(r=>r.json()),
      fetch('/api/proxy/cc/public_key').then(r=>r.json()),
      fetch('/api/proxy/ta/public_key').then(r=>r.json()),
    ]);
    if (tpaR.status !== 'success') throw new Error('無法取得 TPA 公鑰：' + (tpaR.message || ''));
    const tpa_e = hexToBigInt(tpaR.e), tpa_n = hexToBigInt(tpaR.n);
    const cc_pub_pem = ccR.public_key_pem, ta_pub_pem = taR.public_key_pem;
    addStep('公鑰取得完成', true);

    // Step 2: TPA 身分認證
    addStep('向 TPA 進行雙向認證...');
    const authPkt = await createAuthPacket(_voterId, 'TPA', _privateKey, _certPem);
    const authResp = await fetch('/api/proxy/tpa/auth', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ auth_packet: authPkt, voter_cert_pem: _certPem }),
    });
    const authData = await authResp.json();
    if (authData.status !== 'success') throw new Error('TPA 認證失敗：' + (authData.message || authData.code || ''));
    // v2.0 修正：之前這裡拿到 authData.voting_token 後從未使用，導致 Phase 3
    // 盲簽章請求沒有帶 Token，Phase 2 的身分驗證與 Phase 3 的取簽完全脫鉤。 <3
    const votingToken = authData.voting_token;
    if (!votingToken) throw new Error('TPA 未核發 Voting Token，無法繼續投票流程');  // <3
    addStep('TPA 認證成功', true);

    // Step 3: 計算選票雜湊 m（FDH 預處理）
    addStep('計算選票雜湊值...');
    const sn         = 'SN' + Date.now() + (_voterId.slice(-3) || '000');
    const innerHash  = await sha256Hex(_voterId + '|' + sn + '|' + candidate);
    const outerHash  = await sha256Hex(innerHash + '|' + candidate);
    const m_hex      = outerHash;                   // 64-char hex，不含 0x
    const m_bytes    = hexToBytes(m_hex);            // 32 bytes
    addStep(`m = ${m_hex.slice(0,16)}...`, true);

    // Step 4: FDH + 盲化
    addStep('FDH 擴展 + 盲化選票...');
    const nBits   = tpa_n.toString(2).length;
    const mu      = await fdh(m_bytes, nBits);
    const r       = generateBlindingFactor(tpa_n);
    const m_prime = blindMessage(mu, r, tpa_e, tpa_n);
    const m_prime_hex = '0x' + m_prime.toString(16);
    addStep('盲化完成', true);

    // Step 5: TPA 盲簽章
    addStep('向 TPA 請求盲簽章...');
    const signResp = await fetch('/api/proxy/tpa/blind_sign', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ m_prime_hex, voting_token: votingToken }),  // <3 附上 Phase 2 取得的 Voting Token
    });
    const signData = await signResp.json();
    if (signData.status !== 'success') throw new Error('盲簽章失敗：' + (signData.message || signData.code || ''));
    const S_int   = hexToBigInt(signData.S_hex);
    addStep('盲簽章取得', true);

    // Step 6: 去盲化 + 驗證
    addStep('去盲化 + 本地數學驗證...');
    const S_prime   = unblindSignature(S_int, r, tpa_n);
    const mu_check  = await fdh(m_bytes, nBits);
    if (modpow(S_prime, tpa_e, tpa_n) !== mu_check) throw new Error('盲簽章本地驗證失敗');
    const s_prime_hex = '0x' + S_prime.toString(16);
    addStep('盲簽章驗證通過', true);

    // Step 7: 封裝數位信封
    addStep('封裝 AES-GCM + RSA-OAEP 數位信封...');
    const inner_enc_b64 = await rsaOaepEncrypt(ta_pub_pem, innerHash + '|' + candidate);
    const aes_pt        = inner_enc_b64 + '|' + s_prime_hex + '|' + m_hex;
    const aad_str       = 'voting-system-v2|' + _voterId + '|' + sn;
    const { k, iv, c_data, tag, aad } = await aesGcmEncrypt(aes_pt, aad_str);
    const c_key  = await rsaOaepEncrypt(cc_pub_pem, k);
    // v2.0 修正：之前 token_hash 寫死空字串，CC 端的一人一票去重機制對所有
    // 選票永遠不會生效。規格書 §3.4：token_hash = H(Token.payload.token_id)。 <3
    const token_hash = await sha256Hex(votingToken.payload.token_id);  // <3
    const envelope = { c_data, iv, tag, aad, c_key, token_hash };
    addStep('信封封裝完成', true);

    // Step 8: 傳送至 CC
    addStep('傳送數位信封至計票中心...');
    const ccResp = await fetch('/api/proxy/cc/receive_envelope', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(envelope),
    });
    const ccData = await ccResp.json();
    if (ccData.status !== 'success') throw new Error('CC 拒絕信封：' + (ccData.message || ccData.code || ''));
    addStep('CC 已接收信封', true);

    // Step 9: 上傳回執
    await fetch('/api/save_vote_receipt', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ voter_id: _voterId, sn, vote: candidate, m_hex, s_prime_hex }),
    });

    document.getElementById('successCard').classList.remove('hidden');
    document.getElementById('successMhex').textContent = m_hex;
    document.getElementById('voteForm').classList.add('opacity-50', 'pointer-events-none');

  } catch(e) {
    addStep(e.message, false);
    const errCard = document.getElementById('errorCard');
    errCard.textContent = e.message;
    errCard.classList.remove('hidden');
    btn.disabled = false;
    document.getElementById('voteText').textContent = '確認投票';
  }
}

async function doLogout() {
  if (!confirm('確定要清除本裝置的身分綁定？\\n清除後需重新輸入學號和 OTP 才能投票。')) return;
  await new Promise((res, rej) => {
    const req = indexedDB.deleteDatabase('voter-crypto');
    req.onsuccess = res;
    req.onerror   = () => rej(req.error);
  });
  location.href = '/register';
}

init().catch(e => {
  document.body.innerHTML = `<div class="p-8 text-red-600">初始化錯誤：${e.message}</div>`;
});
</script>
</body>
</html>"""

# ─────────────────────────────────────────
# 3. 狀態 / 回執頁
# ─────────────────────────────────────────
_STATUS_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>投票回執</title>""" + _BASE_STYLE + """
</head>
<body class="bg-gray-50 dark:bg-deepblack text-gray-800 dark:text-gray-100 min-h-screen p-6">
<div class="max-w-xl mx-auto">
  <div class="flex items-center gap-3 mb-8">
    <a href="/" class="text-xs text-msblue hover:underline">← 返回</a>
    <h1 class="text-xl font-semibold text-gray-900 dark:text-white">投票回執</h1>
    <button onclick="toggleTheme()" class="ml-auto p-2 rounded-lg bg-white/70 dark:bg-cardblack border border-gray-200 dark:border-gray-800 text-gray-500">
      <svg class="w-4 h-4 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/></svg>
      <svg class="w-4 h-4 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
    </button>
  </div>

  {% if record %}
  <div class="bg-white/70 dark:bg-cardblack/80 rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-6 space-y-4">
    <div class="flex items-center gap-2 mb-2">
      <span class="px-2.5 py-1 rounded-full text-xs font-medium bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800/50">已投票</span>
      <span class="text-xs text-gray-400">{{ record.voted_at | ts_to_str }}</span>
    </div>
    {% for label, val in [('選民 ID', record.voter_id), ('SN', record.sn), ('投票對象', record.vote)] %}
    <div>
      <p class="text-xs text-gray-400 uppercase tracking-wider mb-1">{{ label }}</p>
      <p class="font-mono text-sm text-gray-800 dark:text-gray-200">{{ val }}</p>
    </div>
    {% endfor %}
    <div>
      <p class="text-xs text-gray-400 uppercase tracking-wider mb-1">m_hex（可至 BB 驗證）</p>
      <code class="block bg-gray-50 dark:bg-[#050505] rounded-lg p-3 text-xs font-mono break-all text-gray-700 dark:text-gray-300 border border-gray-100 dark:border-gray-800/80">{{ record.m_hex }}</code>
    </div>
  </div>
  {% else %}
  <div class="text-center py-16 text-gray-400">
    <p>尚未找到投票記錄。</p>
    <a href="/" class="mt-3 inline-block text-sm text-msblue hover:underline">前往投票</a>
  </div>
  {% endif %}
</div>
</body>
</html>"""

# ── 路由 ─────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template_string(_VOTE_HTML)

@app.route('/register')
def register_page():
    return render_template_string(_REGISTER_HTML, default_voter_id=VOTER_ID)

@app.route('/status')
def status():
    voter_id = request.args.get('voter_id', '')
    record   = None
    if voter_id:
        record = db.fetchone(
            "SELECT voter_id, sn, vote, m_hex, voted_at FROM vote_record WHERE voter_id = ? ORDER BY id DESC LIMIT 1",
            (voter_id,)
        )
    else:
        record = db.fetchone("SELECT voter_id, sn, vote, m_hex, voted_at FROM vote_record ORDER BY id DESC LIMIT 1")

    app.jinja_env.filters['ts_to_str'] = lambda ts: datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S') if ts else ''
    return render_template_string(_STATUS_HTML, record=record)

make_reload_endpoint(app)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=False)
