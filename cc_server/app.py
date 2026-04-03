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
import datetime

# 確保 shared/ 可被 import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string, redirect
import requests as http_requests

from shared.key_manager import (
    load_or_generate_keypair,
    load_or_request_certificate,
    load_or_fetch_ca_cert,
)
from shared.crypto_utils import open_envelope_layer1, open_envelope_layer2
from shared.merkle_tree import MerkleTree
from shared.format_utils import int_to_hex, hex_to_int, ts_to_human
from shared.db_utils import Database
from shared.config_loader import make_reload_endpoint
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

# 截止時間：優先從環境變數讀取，否則從 TA 取得
_DEADLINE: int = int(os.environ.get("VOTE_DEADLINE", "0"))

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
        m_hex       TEXT NOT NULL,
        leaf_hash   TEXT,
        verified_at INTEGER NOT NULL
    )
""")
db.execute("""
    CREATE TABLE IF NOT EXISTS tally_state (
        key         TEXT PRIMARY KEY,
        value       TEXT NOT NULL
    )
""")

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
    _cert_pem = load_or_request_certificate(KEYS_DIR, CC_ID, _public_key_pem, CA_URL)
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
    截止時間強制執行 Middleware。
    若當前時間 > deadline，回傳 HTTP 403（Forbidden）。
    回傳 None 表示允許繼續；回傳 Response 表示應立即拒絕。
    """
    deadline = _get_deadline()
    if deadline <= 0:
        return None   # 未設定截止時間，允許通過

    now = int(time.time())
    if now > deadline:
        remaining_over = now - deadline
        print(f"[CC] Deadline Middleware 拒絕請求：已超時 {remaining_over} 秒（Unix ts：{now} > {deadline}）")
        return jsonify({
            "status":       "error",
            "code":         "DEADLINE_EXCEEDED",
            "message":      f"投票已截止，無法接收新選票（已超時 {remaining_over} 秒）",
            # Unix timestamp（後端標準）
            "server_time":  now,
            "deadline":     deadline,
            # 人類可讀（僅供 UI/日誌）
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
  <meta http-equiv="refresh" content="15">
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">
  <div class="max-w-5xl mx-auto px-4 py-10">

    <!-- Header -->
    <div class="flex items-center gap-4 mb-8">
      <div class="w-12 h-12 rounded-xl bg-emerald-600 flex items-center justify-center text-2xl">🗳️</div>
      <div>
        <h1 class="text-2xl font-bold text-white">計票中心 (CC)</h1>
        <p class="text-gray-400 text-sm">NUTC Voting System · Count Center</p>
      </div>
      <div class="ml-auto flex flex-col items-end gap-1">
        <span class="px-3 py-1 rounded-full bg-green-900 text-green-300 text-xs font-semibold">● 運作中</span>
        {% if deadline_ts %}
        <span class="px-3 py-1 rounded-full text-xs font-semibold
          {% if is_expired %}bg-red-900 text-red-300{% else %}bg-amber-900 text-amber-300{% endif %}">
          {% if is_expired %}投票已截止{% else %} 截止：{{ deadline_str }}{% endif %}
        </span>
        {% endif %}
      </div>
    </div>

    <!-- Stats -->
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
      <div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
        <p class="text-gray-400 text-xs mb-1">收到信封</p>
        <p class="text-3xl font-bold text-emerald-400">{{ envelope_count }}</p>
      </div>
      <div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
        <p class="text-gray-400 text-xs mb-1">合法選票</p>
        <p class="text-3xl font-bold text-green-400">{{ valid_count }}</p>
      </div>
      <div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
        <p class="text-gray-400 text-xs mb-1">開票狀態</p>
        <p class="text-sm font-bold {% if tally_done %}text-green-400{% else %}text-yellow-400{% endif %}">
          {% if tally_done %}✓ 已完成{% else %} 待開票{% endif %}
        </p>
      </div>
      <div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
        <p class="text-gray-400 text-xs mb-1">Merkle Root</p>
        <p class="text-xs font-mono text-emerald-300 break-all">
          {% if merkle_root %}{{ merkle_root[:20] }}...{% else %}—{% endif %}
        </p>
      </div>
    </div>

    <!-- Tally Button -->
    {% if not tally_done %}
    <div class="mb-6">
      <form method="POST" action="/ui/tally">
        <button type="submit"
          class="w-full py-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold transition text-sm">
          觸發開票（向 TA 請求 SK_TA）
        </button>
      </form>
    </div>
    {% endif %}

    <!-- Tally Results -->
    {% if tally_done and tally_results %}
    <div class="bg-gray-900 rounded-xl border border-gray-800 p-6 mb-6">
      <h2 class="font-semibold text-gray-200 mb-4">計票結果</h2>
      <div class="space-y-3">
        {% for candidate, count in tally_results.items() %}
        <div>
          <div class="flex justify-between text-sm mb-1">
            <span class="font-mono text-emerald-300">{{ candidate }}</span>
            <span class="text-gray-300 font-bold">{{ count }} 票</span>
          </div>
          <div class="w-full bg-gray-800 rounded-full h-2">
            <div class="bg-emerald-500 h-2 rounded-full" style="width: {{ (count / valid_count * 100) | int }}%"></div>
          </div>
        </div>
        {% endfor %}
      </div>
      {% if merkle_root %}
      <div class="mt-4 pt-4 border-t border-gray-800">
        <p class="text-xs text-gray-400">Root_official</p>
        <p class="font-mono text-xs text-emerald-300 break-all mt-1">{{ merkle_root }}</p>
      </div>
      {% endif %}
    </div>
    {% endif %}

    <!-- Valid Votes Table -->
    <div class="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden mb-6">
      <div class="px-6 py-4 border-b border-gray-800">
        <h2 class="font-semibold text-gray-200">合法選票記錄</h2>
      </div>
      {% if valid_votes %}
      <table class="w-full text-sm">
        <thead class="bg-gray-800 text-gray-400 text-xs uppercase">
          <tr>
            <th class="px-6 py-3 text-left">#</th>
            <th class="px-6 py-3 text-left">投票內容</th>
            <th class="px-6 py-3 text-left">m_hex（前 20 字元）</th>
            <th class="px-6 py-3 text-left">驗證時間</th>
            <th class="px-6 py-3 text-left">Unix ts</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-800">
          {% for v in valid_votes %}
          <tr class="hover:bg-gray-800/50 transition">
            <td class="px-6 py-3 text-gray-500">{{ v.id }}</td>
            <td class="px-6 py-3 font-mono text-emerald-300">{{ v.vote }}</td>
            <td class="px-6 py-3 font-mono text-gray-400 text-xs">{{ v.m_hex[:20] }}...</td>
            <!-- UI 顯示：人類可讀格式 -->
            <td class="px-6 py-3 text-gray-300 text-xs font-mono">{{ v.verified_at | ts_to_str }}</td>
            <td class="px-6 py-3 text-gray-500 text-xs">{{ v.verified_at }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <div class="px-6 py-10 text-center text-gray-500">尚無合法選票（需先觸發開票）</div>
      {% endif %}
    </div>

    <!-- Envelopes Table -->
    <div class="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
        <h2 class="font-semibold text-gray-200">收到的數位信封</h2>
        <span class="text-xs text-gray-500">每 15 秒自動更新</span>
      </div>
      {% if envelopes %}
      <table class="w-full text-sm">
        <thead class="bg-gray-800 text-gray-400 text-xs uppercase">
          <tr>
            <th class="px-6 py-3 text-left">#</th>
            <th class="px-6 py-3 text-left">C_Data（前 20 字元）</th>
            <th class="px-6 py-3 text-left">狀態</th>
            <th class="px-6 py-3 text-left">收到時間（人類可讀）</th>
            <th class="px-6 py-3 text-left">Unix ts</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-800">
          {% for e in envelopes %}
          <tr class="hover:bg-gray-800/50 transition">
            <td class="px-6 py-3 text-gray-500">{{ e.id }}</td>
            <td class="px-6 py-3 font-mono text-gray-400 text-xs">{{ e.c_data[:20] }}...</td>
            <td class="px-6 py-3">
              {% if e.status == 'verified' %}
              <span class="px-2 py-0.5 rounded-full bg-green-900 text-green-300 text-xs">已驗證</span>
              {% elif e.status == 'invalid' %}
              <span class="px-2 py-0.5 rounded-full bg-red-900 text-red-300 text-xs">✗ 無效</span>
              {% else %}
              <span class="px-2 py-0.5 rounded-full bg-yellow-900 text-yellow-300 text-xs">待驗證</span>
              {% endif %}
            </td>
            <!-- UI 顯示：人類可讀格式 -->
            <td class="px-6 py-3 text-gray-300 text-xs font-mono">{{ e.received_at | ts_to_str }}</td>
            <td class="px-6 py-3 text-gray-500 text-xs">{{ e.received_at }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <div class="px-6 py-10 text-center text-gray-500">尚未收到任何數位信封</div>
      {% endif %}
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
    )


@app.route('/ui/tally', methods=['POST'])
def ui_tally():
    """Web UI 觸發開票按鈕"""
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
    [POST] 接收數位信封（Phase 3）。
    截止時間後回傳 HTTP 403。
    Body: {"c_data": "...", "iv": "...", "c_key": "..."}
    用 SK_CC 解密 C_Key 取得 k，暫存至 DB。
    """
    # ── Deadline Middleware ──────────────────────────────────
    deadline_resp = _check_deadline()
    if deadline_resp is not None:
        return deadline_resp

    data = request.get_json()
    if not data or not all(k in data for k in ('c_data', 'iv', 'c_key')):
        return jsonify({"status": "error", "message": "缺少信封欄位"}), 400

    try:
        pending = open_envelope_layer1(data, _private_key)
        now = int(time.time())
        db.execute(
            "INSERT INTO envelopes (c_data, iv, k, received_at, status) VALUES (?, ?, ?, ?, ?)",
            (pending['c_data'], pending['iv'], pending['k'], now, 'pending'),
        )
        # 日誌使用人類可讀格式
        print(f"[CC] 收到數位信封（Unix ts：{now}  →  {ts_to_human(now)}）")
        return jsonify({"status": "success", "message": "信封已接收"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/tally', methods=['POST'])
def api_tally():
    """
    [POST] 觸發開票（Phase 5）。
    1. 向 TA 請求 SK_TA
    2. 向 TPA 取得公鑰大整數 (e, n)
    3. 解密驗證所有暫存信封
    4. 建構 Merkle Tree
    5. 推送結果至 BB
    """
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
    valid_votes = db.fetchall("SELECT vote, m_hex FROM valid_votes ORDER BY id")

    return jsonify({
        "status":        "success",
        "merkle_root":   root_row['value'] if root_row else "",
        "tally":         json.loads(tally_json_row['value']) if tally_json_row else {},
        "valid_votes":   valid_votes,
        "tpa_e":         _get_state('tpa_e'),
        "tpa_n":         _get_state('tpa_n'),
    }), 200


@app.route('/api/merkle_proof/<int:index>', methods=['GET'])
def api_merkle_proof(index: int):
    """[GET] 取得指定葉節點的 Merkle Proof"""
    valid_votes = db.fetchall("SELECT m_hex FROM valid_votes ORDER BY id")
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
    """執行開票流程（Phase 5）"""
    # 檢查是否已開票
    if _get_state('done') == '1':
        return {"status": "already_done", "message": "已完成開票"}

    # 步驟 1：向 TA 請求 SK_TA
    try:
        resp = http_requests.post(f"{TA_URL}/api/release_key", timeout=10)
        sk_ta_data = resp.json()
        if sk_ta_data.get('status') != 'released':
            return {"status": "error", "message": f"TA 拒絕釋放私鑰：{sk_ta_data.get('message', '')}"}
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
        "SELECT id, c_data, iv, k FROM envelopes WHERE status = 'pending'"
    )
    now = int(time.time())
    valid_count = 0

    for env in pending_envelopes:
        pending = {'c_data': env['c_data'], 'iv': env['iv'], 'k': env['k']}
        try:
            result = open_envelope_layer2(pending, ta_private_key, tpa_e, tpa_n)
            db.execute(
                "INSERT INTO valid_votes (vote, m_hex, verified_at) VALUES (?, ?, ?)",
                (result['vote'], result['m_hex'], now),
            )
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

    # 步驟 5：建構 Merkle Tree
    valid_votes = db.fetchall("SELECT vote, m_hex FROM valid_votes ORDER BY id")
    m_hex_list = [v['m_hex'] for v in valid_votes]

    if m_hex_list:
        tree = MerkleTree(m_hex_list)
        merkle_root = tree.get_root()
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

    # 步驟 6：推送結果至 BB
    try:
        bb_payload = {
            "root_official": merkle_root,
            "tally":         tally,
            "valid_votes":   valid_votes,
            # Unix timestamp（後端標準）
            "tallied_at":    now,
        }
        http_requests.post(f"{BB_URL}/api/publish", json=bb_payload, timeout=10)
        print(f"[CC] 結果已推送至 BB")
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
