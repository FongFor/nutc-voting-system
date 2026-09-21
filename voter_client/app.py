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

投票回執（voter_id、SN、投票內容、m_hex）僅存於選民瀏覽器本地的
IndexedDB（跟私鑰放在一起），伺服器端不保存、也查詢不到任何一筆
「選民身分 ↔ 投票內容」的對應關係。

批次混合（v3.0 新增）：
  信封不再收到就立刻轉送給 CC，而是先進本地佇列（pending_envelope
  表），等湊到 ENVELOPE_BATCH_SIZE 封或快到截止時間才打亂順序一次
  送出，降低「送出時間點」洩漏投票行為的風險。這張表本身仍會短暫
  存放 AAD（其中的 voter_id 只是 Base64，不是加密），是這個設計已
  知、且經過討論後接受的取捨，不對外提供任何讀取這張表的 API。
"""

import os
import sys
import json
import time
import base64
import random
import hashlib
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string
import requests as http_requests

from shared.db_utils import Database
from shared.config_loader import get_candidates as cfg_get_candidates, make_reload_endpoint, get_service_registration_token
from shared.key_manager import load_or_fetch_ca_cert, verify_cert_chain_and_cn, get_public_key_from_cert  # <3 v4.0
from shared.crypto_utils import verify_signature
from shared.tls_utils import load_or_request_tls_certificate, build_mtls_server_context, mtls_client_kwargs  # <3 v4.0：mTLS

# ============================================================
# 常數設定
# ============================================================
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR    = os.path.join(SERVICE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH     = os.path.join(DATA_DIR, "voter_queue.db")
KEYS_DIR    = os.path.join(SERVICE_DIR, "keys")   # 快取 CA 根憑證＋v4.0 新增的 TLS 專用金鑰對；voter_client 沒有應用層身分金鑰對
os.makedirs(KEYS_DIR, exist_ok=True)

# v4.0 新增：是否驗證 CC 對 /api/receive_envelope 的簽章收據（見
# cc_server/app.py 的 receipt 欄位）。批次送出信封是這個 Flask 後端
# （_flush_pending）直接對 CC 發 HTTP 請求，不是瀏覽器 JS，所以驗證邏輯
# 放在這裡而不是 voter-crypto.js。
#   false（預設）：只看 HTTP 狀態碼，不驗證回應內容是否真的來自 CC。
#   true：額外驗證 cc_cert_pem 的 CA 憑證鏈與 Subject CN、收據的 RSA-PSS
#     簽章、以及 envelope_hash 是否對應到剛剛送出的這份信封——只有驗證
#     通過才視為「CC 真的收到了」，否則保留在佇列裡等下一輪重試，而不是
#     被一個偽造的假 200 回應騙走、從佇列裡刪掉。
VERIFY_CC_RECEIPT = False

VOTER_ID      = os.environ.get("VOTER_ID", "")   # 僅作表單預設值，不強制
VOTER_HOSTNAME = os.environ.get("VOTER_HOSTNAME", "voter")  # <3 v4.0：填入 TLS 憑證的 SAN
CA_URL   = os.environ.get("CA_URL",  "https://localhost:5001")
TPA_URL  = os.environ.get("TPA_URL", "https://localhost:5000")
TA_URL   = os.environ.get("TA_URL",  "https://localhost:5002")
CC_URL   = os.environ.get("CC_URL",  "https://localhost:5003")
BB_URL   = os.environ.get("BB_URL",  "https://localhost:5004")
# <3 v4.0 新增：BB 實際對外的公開網域，跟內部呼叫用的 BB_URL（容器間
# https://bb:5004）不同——這個是給瀏覽器點擊連結用的，不能用 BB_URL。
BB_ADDRESS = os.environ.get("BB_ADDRESS", "localhost:5004")

# v4.0 新增：先快取 CA 根憑證，才有材料可以驗證 CA 自己的 TLS 伺服器
# 憑證，也才有東西可以驗證後續其他實體的憑證鏈——順序必須在申請 TLS
# 憑證之前，否則下面 mtls_client_kwargs() 組出來的 verify= 路徑會指向
# 一個還不存在的檔案。
try:
    load_or_fetch_ca_cert(KEYS_DIR, CA_URL)
except Exception as ex:
    print(f"[Voter] 警告：無法取得 CA 憑證（{ex}）")

# 向 CA 申請本服務專用的 TLS 憑證（跟應用層身分憑證概念一樣，但
# voter_client 本來就沒有應用層身分憑證，這裡是它第一次、也是唯一一次
# 持有金鑰對——純粹用於 HTTPS 監聽與對外呼叫，不涉及任何簽章身分主張）。
try:
    _TLS_CERT_PATH, _TLS_KEY_PATH = load_or_request_tls_certificate(
        KEYS_DIR, "VOTER", VOTER_HOSTNAME, CA_URL,
        registration_token=get_service_registration_token(),
    )
except Exception as ex:
    print(f"[Voter] 警告：無法取得 TLS 憑證（{ex}）")
    _TLS_CERT_PATH = _TLS_KEY_PATH = None

# 供本檔案所有對外呼叫共用的 mTLS 參數，直接以 **_VOTER_MTLS 展開進
# http_requests.get/post(...)。
_VOTER_MTLS = mtls_client_kwargs(_TLS_CERT_PATH, _TLS_KEY_PATH, os.path.join(KEYS_DIR, "ca_cert.pem"))

# 批次混合參數：湊滿 K 封就送；否則距截止只剩安全緩衝時間就強制全送。
ENVELOPE_BATCH_SIZE            = int(os.environ.get("ENVELOPE_BATCH_SIZE", "10"))
ENVELOPE_FLUSH_SAFETY_MARGIN_S = int(os.environ.get("ENVELOPE_FLUSH_SAFETY_MARGIN_SECONDS", "30"))
ENVELOPE_FLUSH_POLL_S          = int(os.environ.get("ENVELOPE_FLUSH_POLL_SECONDS", "3"))

def _get_candidates():
    env_val = os.environ.get("CANDIDATES")
    if env_val:
        return [c.strip() for c in env_val.split(",") if c.strip()]
    return cfg_get_candidates()

# ============================================================
# 待送信封佇列（批次混合用）
# ============================================================
db = Database(DB_PATH)
db.execute("""
    CREATE TABLE IF NOT EXISTS pending_envelope (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        c_data      TEXT NOT NULL,
        iv          TEXT NOT NULL,
        tag         TEXT NOT NULL,
        aad         TEXT NOT NULL,
        c_key       TEXT NOT NULL,
        token_hash  TEXT NOT NULL UNIQUE,
        queued_at   INTEGER NOT NULL
    )
""")


_ca_cert_pem_cache = None


def _get_ca_cert_pem() -> str:
    """快取載入 CA 根憑證，供 _verify_cc_receipt 驗證 cc_cert_pem 的憑證鏈用。"""
    global _ca_cert_pem_cache
    if _ca_cert_pem_cache is None:
        _ca_cert_pem_cache = load_or_fetch_ca_cert(KEYS_DIR, CA_URL)
    return _ca_cert_pem_cache


def _verify_cc_receipt(resp_json: dict, envelope: dict) -> bool:
    """驗證 CC 對 /api/receive_envelope 回應裡的簽章收據（VERIFY_CC_RECEIPT=True 時使用）。

    對應 cc_server/app.py 產生 receipt 的邏輯：
      1. cc_cert_pem 須通過 CA 憑證鏈驗證，且 Subject CN 必須是 'CC'
      2. 用該憑證公鑰驗證 receipt 的 RSA-PSS 簽章
      3. envelope_hash 必須等於本地對這次送出的信封（c_data/iv/tag/aad/
         c_key/token_hash）重算出的 SHA-256——確保這張收據對應的就是這
         份信封，而不是別次提交的收據被重放過來。
    任一步失敗回傳 False，呼叫端應視為「尚未確認送達」，保留於佇列重試。
    """
    try:
        receipt       = resp_json.get('receipt') or {}
        cc_cert_pem   = resp_json.get('cc_cert_pem', '')
        payload       = receipt.get('payload') or {}
        signature_b64 = receipt.get('signature', '')
        if not cc_cert_pem or not payload or not signature_b64:
            return False

        # v4.0 修正：改用共用的 verify_cert_chain_and_cn()（見
        # shared/key_manager.py），跟其他服務對「驗憑證鏈 + 核對 CN」這組
        # 檢查共用同一份實作，不再各自手刻。 <3
        cc_cert = verify_cert_chain_and_cn(cc_cert_pem, _get_ca_cert_pem(), 'CC')
        if cc_cert is None or payload.get('sender_id') != 'CC':
            return False

        expected_hash = hashlib.sha256(
            json.dumps(
                {
                    'c_data':     envelope.get('c_data'),
                    'iv':         envelope.get('iv'),
                    'tag':        envelope.get('tag', ''),
                    'aad':        envelope.get('aad', ''),
                    'c_key':      envelope.get('c_key'),
                    'token_hash': envelope.get('token_hash'),
                },
                sort_keys=True, ensure_ascii=False, separators=(',', ':'),
            ).encode('utf-8')
        ).hexdigest()
        if payload.get('envelope_hash') != expected_hash:
            return False

        payload_bytes = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        cc_public_key = get_public_key_from_cert(cc_cert_pem)
        return verify_signature(payload_bytes, base64.b64decode(signature_b64), cc_public_key)
    except Exception:
        return False


def _flush_pending(rows):
    """打亂順序後逐一送給 CC。

    v3.0 修正：原本不論成功或失敗一律從佇列刪除，理由是「反正拒絕了
    重試也不會成功」——但這個推論只對 CC「明確拒絕」（如 token_hash
    重複、截止時間已過，皆回傳 403）成立，對「網路暫時連不上、CC 短暫
    無回應、CC 內部錯誤」這類暫時性失敗完全不成立。原本的寫法會讓
    選民的票在這類暫時性狀況下被永久靜默丟棄、不會重試，選民卻已經
    看過「已收到」的訊息，完全不知道自己的票消失了。
    現在改成：只有明確成功（200）或 CC 明確拒絕（403，代表不管重試
    幾次都不會成功）才移除；連線例外或其他非預期狀態碼一律保留在
    佇列裡，留給下一輪排程重試。 <3
    """
    rows = list(rows)
    random.SystemRandom().shuffle(rows)
    for row in rows:
        envelope = {k: row[k] for k in ('c_data', 'iv', 'tag', 'aad', 'c_key', 'token_hash')}
        try:
            r = http_requests.post(f"{CC_URL}/api/receive_envelope", json=envelope, timeout=10, **_VOTER_MTLS)
        except Exception as e:
            print(f"[Voter] 批次送出信封失敗（連線錯誤，保留於佇列待重試）：{e}")  # <3
            continue  # <3 不刪除，留待下一輪重試

        if r.status_code == 200:
            if VERIFY_CC_RECEIPT:
                try:
                    resp_json = r.json()
                except Exception:
                    resp_json = {}
                if not _verify_cc_receipt(resp_json, envelope):
                    print(
                        f"[Voter] 警告：CC 回應的收據驗證失敗，可能遭偽造或竄改，"
                        f"保留於佇列待重試（token_hash={row['token_hash'][:16]}...）"
                    )
                    continue  # 不刪除，留待下一輪重試
            print(f"[Voter] 批次送出信封成功（token_hash={row['token_hash'][:16]}...）")
            db.execute("DELETE FROM pending_envelope WHERE id = ?", (row['id'],))
        elif r.status_code == 403:
            # CC 明確拒絕（token_hash 重複、選舉已截止等），重試也不會
            # 成功，才允許移除。 <3
            print(f"[Voter] 批次送出信封被 CC 明確拒絕（403，從佇列移除）：{r.text[:200]}")  # <3
            db.execute("DELETE FROM pending_envelope WHERE id = ?", (row['id'],))
        else:
            # 非預期狀態碼（例如 CC 內部錯誤 500），保留待重試。 <3
            print(f"[Voter] 批次送出信封收到非預期狀態碼 {r.status_code}（保留於佇列待重試）：{r.text[:200]}")  # <3


def _remaining_seconds():
    """查詢投票剩餘秒數；選舉尚未開始、查詢失敗、或投票時間不限制
    （TA 的 deadline<=0）皆回傳 None。只用於「距截止還有多久、是否該
    提早強制 flush」這種需要具體秒數的場景——deadline 不限制時本來就
    沒有「快到期」這回事，回傳 None 讓呼叫端跳過強制 flush 判斷是正確
    的；但這不代表選舉沒有在進行中，判斷「現在能不能投票」請改用
    _voting_open()，不要直接把這裡的 None 當成「已截止」。 <3
    """
    try:
        r = http_requests.get(f"{TA_URL}/api/deadline", timeout=5, **_VOTER_MTLS)
        d = r.json()
        if d.get("election_state") != "running":
            return None
        return d.get("remaining_seconds")
    except Exception:
        return None


def _voting_open():
    """確認選舉目前是否真的還能接受投票。

    v3.0 修正：submit_envelope() 原本直接用 `_remaining_seconds() is
    None` 判斷「已截止」，但 TA 對「投票時間不限制」（deadline<=0）的
    合法運行狀態，remaining_seconds 欄位本來就是 None——導致啟用不限
    時投票模式時，每一筆信封提交都會被誤判成截止而拒收。這裡改成直接
    採信 TA 自己算好的 is_expired 欄位（TA 內部已正確處理 deadline<=0
    代表不限制、永遠不算過期的邏輯），不要自己用 remaining_seconds
    重新推導一次容易出錯的等價判斷。查詢失敗一律 fail-secure 視為
    不能投票。 <3
    """
    try:
        r = http_requests.get(f"{TA_URL}/api/deadline", timeout=5, **_VOTER_MTLS)
        d = r.json()
    except Exception:
        return False  # <3 查不到就 fail-secure 拒絕，不要樂觀放行
    if d.get("election_state") != "running":
        return False
    return not d.get("is_expired", True)


def _batch_scheduler_loop():
    """背景排程：湊滿 K 封就送；否則距截止進入安全緩衝時間就強制全送。"""
    while True:
        try:
            count = db.count("pending_envelope")
            if count >= ENVELOPE_BATCH_SIZE:
                rows = db.fetchall("SELECT * FROM pending_envelope ORDER BY id")
                print(f"[Voter] 批次池達到 {count} 封（門檻 {ENVELOPE_BATCH_SIZE}），送出")
                _flush_pending(rows)
            elif count > 0:
                remaining = _remaining_seconds()
                if remaining is not None and remaining <= ENVELOPE_FLUSH_SAFETY_MARGIN_S:
                    rows = db.fetchall("SELECT * FROM pending_envelope ORDER BY id")
                    print(f"[Voter] 距截止僅剩 {remaining} 秒，強制送出池內剩餘 {count} 封")
                    _flush_pending(rows)
        except Exception as e:
            print(f"[Voter] 批次排程例外：{e}")
        time.sleep(ENVELOPE_FLUSH_POLL_S)


threading.Thread(target=_batch_scheduler_loop, daemon=True).start()

# ============================================================
# Flask App
# ============================================================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))

# v3.0 新增：voter_client 現在是唯一對外開放的服務（見 Caddyfile），前面
# 有 Caddy 這個反向代理擋著。Flask 預設 request.remote_addr 抓到的是
# 「直接跟它建立 TCP 連線的那一端」，加了反向代理之後那會是 Caddy 自己
# 的容器 IP，不是選民的真實來源 IP，限流會把所有人誤判成同一個來源。
# ProxyFix 讓 Flask 改讀 Caddy 轉發過來的 X-Forwarded-For 表頭（Caddy
# 的 reverse_proxy 預設就會加這個表頭），還原出真正的來源 IP。 <3
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # <3

# v3.0 新增：投票截止前的流量管制。防的不是精密攻擊，是最單純的「灌爆
# 流量讓還沒投票的真選民卡住投不進去」——選舉截止時間是硬性的，投票期
# 間被灌爆而延誤，沒有辦法事後補救。單一選民一次完整投票流程（認證、
# 取簽章、提交信封）加起來也就個位數次請求，這裡的門檻對正常使用完全
# 不構成阻礙。 <3
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[os.environ.get("RATE_LIMIT_DEFAULT", "30 per minute")],
    storage_uri="memory://",
)  # <3


@app.errorhandler(429)
def _rate_limit_exceeded(e):
    return jsonify({
        "status":  "error",
        "code":    "RATE_LIMITED",
        "message": "請求過於頻繁，請稍後再試",
    }), 429  # <3

# ── 代理工具 ──────────────────────────────────────────────────

def _proxy(method, url, data=None, params=None):
    try:
        if method == "GET":
            r = http_requests.get(url, params=params, timeout=10, **_VOTER_MTLS)
        else:
            r = http_requests.post(url, json=data, timeout=15, **_VOTER_MTLS)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"status": "error", "message": f"代理錯誤：{e}"}), 502

# ── API 代理路由 ────────────────────────────────────────────

@app.route('/api/proxy/ca/issue_cert', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_ISSUE_CERT", "10 per minute"))  # <3
def proxy_ca_issue_cert():
    return _proxy("POST", f"{CA_URL}/api/issue_cert", request.get_json())

@app.route('/api/proxy/ca/voter_status', methods=['GET'])
def proxy_ca_voter_status():
    voter_id = request.args.get('voter_id', '')
    return _proxy("GET", f"{CA_URL}/api/voter_status", params={'voter_id': voter_id})

@app.route('/api/proxy/ca/ca_cert', methods=['GET'])
def proxy_ca_ca_cert():
    """v3.0 新增：讓選民端瀏覽器能拿到 CA 根憑證，作為驗證 TA/CC/TPA
    憑證鏈的信任錨點。"""
    return _proxy("GET", f"{CA_URL}/api/ca_cert")

@app.route('/api/proxy/tpa/public_key', methods=['GET'])
def proxy_tpa_pk():
    return _proxy("GET", f"{TPA_URL}/api/public_key")

@app.route('/api/proxy/tpa/auth', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_AUTH", "10 per minute"))  # <3
def proxy_tpa_auth():
    return _proxy("POST", f"{TPA_URL}/api/auth", request.get_json())

@app.route('/api/proxy/tpa/blind_sign', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_AUTH", "10 per minute"))  # <3
def proxy_tpa_blind_sign():
    return _proxy("POST", f"{TPA_URL}/api/blind_sign", request.get_json())

@app.route('/api/proxy/cc/public_key', methods=['GET'])
def proxy_cc_pk():
    return _proxy("GET", f"{CC_URL}/api/public_key")

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

@app.route('/api/submit_envelope', methods=['POST'])
@limiter.limit(os.environ.get("RATE_LIMIT_AUTH", "10 per minute"))  # <3
def submit_envelope():
    """
    [POST] 選民提交數位信封（v3.0 改為批次混合，不再即時轉送給 CC）。
    收下後先進本地佇列，由背景排程（見 _batch_scheduler_loop）湊滿
    ENVELOPE_BATCH_SIZE 封、或距投票截止進入安全緩衝時間時，才打亂
    順序一次送出，降低「提交時間點」洩漏投票行為的風險。
    """
    data = request.get_json()
    required = ('c_data', 'iv', 'tag', 'aad', 'c_key', 'token_hash')
    if not data or not all(k in data for k in required):
        return jsonify({"status": "error", "message": "缺少信封欄位"}), 400

    # 先確認選舉確實還在進行中，避免快截止前收進佇列的信封，稍後送給 CC
    # 時才被默默拒絕，選民卻已經看到「已收到」的誤導訊息。查不到（TA
    # 連不上）也一併拒絕，維持 fail-secure。
    # v3.0 修正：原本用 `_remaining_seconds() is None` 判斷已截止，但
    # 「投票時間不限制」的合法運行狀態下 remaining_seconds 本來就是
    # None，會讓每一筆提交都被誤判成截止而拒收；改用 _voting_open()
    # 正確處理這個情況。 <3
    if not _voting_open():
        return jsonify({
            "status":  "error",
            "code":    "DEADLINE_PASSED",
            "message": "投票已截止或選舉尚未開始，無法提交",
        }), 403  # <3

    now = int(time.time())
    try:
        db.execute(
            "INSERT INTO pending_envelope (c_data, iv, tag, aad, c_key, token_hash, queued_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (data['c_data'], data['iv'], data['tag'], data['aad'], data['c_key'], data['token_hash'], now),
        )
    except Exception as e:
        # token_hash 已在佇列中（同一封信封被重複提交），視為已收到即可，
        # 不需要因為前端重試就回傳錯誤讓選民誤以為投票失敗。
        return jsonify({"status": "queued", "message": "此信封已在佇列中"}), 202

    return jsonify({
        "status":  "queued",
        "message": "已收到您的選票，將於稍後批次送出以保護您的匿名性",
    }), 202

# v3.0 修正：/api/all_receipts、/api/vote_status、/api/save_vote_receipt
# 三個端點已移除。這三個端點原本讓伺服器端保存 voter_id 與 vote 的明文
# 一一對應（vote_record 表），其中 /api/all_receipts 甚至完全沒有任何
# 存取控制，任何人一個未驗證的 GET 請求就能匯出全體選民「誰投給誰」的
# 完整明細——直接繞過本系統以盲簽章、Merkle Tree 建立的所有匿名性保護。
# 投票回執改為僅存放於選民瀏覽器本地的 IndexedDB（見下方 idbSave），
# 伺服器端不再持有、也查詢不到任何一筆「身分 ↔ 選票內容」的對應關係。 <3

# ── 共用 JS（瀏覽器端密碼學工具集） ─────────────────────────────

_CRYPTO_JS = r"""
/* =====================================================================
   voter-crypto.js  —  瀏覽器端密碼學工具集
   - Web Crypto API：RSA-2048 keygen / RSA-PSS sign / RSA-OAEP encrypt / AES-GCM
   - BigInt：modpow, modinv, FDH (MGF1-SHA256), 盲化 / 去盲化
   - IndexedDB：keypair + cert 本地持久化
   ===================================================================== */

/* ---------- 功能開關：選民是否驗證 TPA 回應封包（雙向認證的第二半） ----------
   TPA 在 /api/auth 的回應裡會用自己的私鑰簽一個 response_packet（含
   nonce_echo、voter_sig_ref），協定上支援選民反過來驗證「這真的是 TPA
   簽的」。是否啟用由這個常數決定，兩種模式都能正常完成投票：

   false（預設）：不驗證，只信任 HTTPS 傳輸層 + 下游 /api/blind_sign 對
     Voting Token 簽章／TPA 自己資料庫記錄的把關。回應就算被竄改，最壞
     結果是這一輪認證失敗（可用性問題），因為偽造的 Token 換不到真正的
     盲簽章——TPA 只認自己簽發、自己資料庫裡有記錄的 token_id。
   true：額外做完整的雙向認證——驗證 tpa_cert_pem 的 CA 憑證鏈與
     Subject CN、用憑證公鑰驗 response_packet 的 RSA-PSS 簽章、核對
     nonce_echo 與 voter_sig_ref。能在這一步就偵測到竄改，代價是多一次
     憑證 DER 解析與驗簽的本地運算。
   見下方 Step 2（TPA 身分認證）呼叫處。 */
const VERIFY_TPA_RESPONSE_SIGNATURE = false;

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
function b64decode(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

/* ---------- 最小 DER/ASN.1 解析器 ---------------------------------------
   v3.0 新增：這份設計的重點之一是降低所有實體之間的信任感——過去 TA/CC/
   TPA 的 /api/public_key 只回傳裸公鑰，選民瀏覽器完全沒有材料能驗證這把
   公鑰真的是 CA 認證過的那一把，中間人只要偽造一次回應、替換掉公鑰，就
   能在不被發現的情況下竊聽或竄改選票內容。Web Crypto API 沒有內建 X.509
   解析器，這裡手刻一個最小、只服務本系統固定憑證結構的 DER TLV 解析器：
   只支援 definite-length 編碼（DER 恆定如此），足以走完
   Certificate → tbsCertificate/signatureValue、
   tbsCertificate → subject/subjectPublicKeyInfo，
   以及從 subjectPublicKeyInfo 內的 RSAPublicKey 直接解出 n、e。 <3
   ------------------------------------------------------------------- */
function derReadTLV(bytes, offset) {
  const tag = bytes[offset];
  const lenByte = bytes[offset + 1];
  let lenOfLen = 0, length;
  if (lenByte & 0x80) {
    lenOfLen = lenByte & 0x7f;
    length = 0;
    for (let i = 0; i < lenOfLen; i++) length = (length << 8) | bytes[offset + 2 + i];
  } else {
    length = lenByte;
  }
  const headerLen     = 2 + lenOfLen;
  const contentStart  = offset + headerLen;
  const contentEnd    = contentStart + length;
  return { tag, start: offset, end: contentEnd, contentStart, contentEnd };
}
function derChildren(bytes, start, end) {
  const out = [];
  for (let o = start; o < end;) {
    const tlv = derReadTLV(bytes, o);
    out.push(tlv);
    o = tlv.end;
  }
  return out;
}
function derFindOid(bytes, oidValueBytes, start, end) {
  /* 在 [start,end) 範圍內找 tag=0x06(OBJECT IDENTIFIER) 且值等於 oidValueBytes
     的 TLV，回傳其「緊接在後」的 TLV（即該 RDN AttributeTypeAndValue 的值）。
     用位元組樣式搜尋取代完整 RDN/SET 結構解析——本系統 CA 核發的憑證 subject
     恆為固定的 [organizationName, commonName] 兩個屬性，足夠安全地簡化。 */
  search:
  for (let i = start; i + 2 + oidValueBytes.length <= end; i++) {
    if (bytes[i] !== 0x06 || bytes[i + 1] !== oidValueBytes.length) continue;
    for (let j = 0; j < oidValueBytes.length; j++) {
      if (bytes[i + 2 + j] !== oidValueBytes[j]) continue search;
    }
    return derReadTLV(bytes, derReadTLV(bytes, i).end);
  }
  return null;
}
function parseCertificate(certPem) {
  const der = new Uint8Array(pemToDer(certPem));
  const top = derReadTLV(der, 0);
  const [tbs, , sigValTlv] = derChildren(der, top.contentStart, top.contentEnd);

  // signatureValue 是 BIT STRING，內容第一個位元組是 unused-bits 計數
  // （RSA 簽章恆為 0x00），要跳過它才是真正的簽章 bytes。
  const sigValue = der.slice(sigValTlv.contentStart + 1, sigValTlv.contentEnd);
  // 簽章驗證對象是 tbsCertificate「完整的 DER 編碼」（含自己的 tag/length）
  const tbsBytes = der.slice(tbs.start, tbs.end);

  let tbsChildren = derChildren(der, tbs.contentStart, tbs.contentEnd);
  if (tbsChildren[0].tag === 0xa0) tbsChildren = tbsChildren.slice(1);  // 跳過可選的 [0] version
  // 剩餘依序：serialNumber, signature(AlgId), issuer, validity, subject, subjectPublicKeyInfo
  const subjectTlv = tbsChildren[4];
  const spkiTlv    = tbsChildren[5];
  const spkiBytes  = der.slice(spkiTlv.start, spkiTlv.end);

  const cnTlv = derFindOid(der, [0x55, 0x04, 0x03], subjectTlv.contentStart, subjectTlv.contentEnd);
  const commonName = cnTlv ? new TextDecoder().decode(der.slice(cnTlv.contentStart, cnTlv.contentEnd)) : null;

  return { tbsBytes, sigValue, spkiBytes, commonName };
}
function parseRsaPublicKeyFromSpki(spkiBytes) {
  const top = derReadTLV(spkiBytes, 0);                       // SubjectPublicKeyInfo SEQUENCE
  const [, bitStrTlv] = derChildren(spkiBytes, top.contentStart, top.contentEnd);
  // BIT STRING 內容跳過 unused-bits 位元組後，就是 RSAPublicKey SEQUENCE { n, e }
  const rsaPkBytes = spkiBytes.slice(bitStrTlv.contentStart + 1, bitStrTlv.contentEnd);
  const rsaTop = derReadTLV(rsaPkBytes, 0);
  const [nTlv, eTlv] = derChildren(rsaPkBytes, rsaTop.contentStart, rsaTop.contentEnd);
  return {
    n: hexToBigInt(bytesToHex(rsaPkBytes.slice(nTlv.contentStart, nTlv.contentEnd))),
    e: hexToBigInt(bytesToHex(rsaPkBytes.slice(eTlv.contentStart, eTlv.contentEnd))),
  };
}
async function importOaepKeyFromSpki(spkiBytes) {
  return crypto.subtle.importKey('spki', spkiBytes, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
}
async function rsaOaepEncryptWithKey(key, plaintext) {
  const data = plaintext instanceof Uint8Array ? plaintext : new TextEncoder().encode(plaintext);
  return b64encode(new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, data)));
}

/* CA 根憑證是信任錨點（trust anchor），本身不需要（也無法有意義地）驗證
   自己的簽章，只需要從中取出 SPKI 作為驗證其他實體憑證用的公鑰。整個頁面
   生命週期內只需抓取一次，故做簡單快取。 */
let _caPublicKeyPromise = null;
function getCaPublicKey() {
  if (!_caPublicKeyPromise) {
    _caPublicKeyPromise = (async () => {
      const r = await fetch('/api/proxy/ca/ca_cert').then(x => x.json());
      if (r.status !== 'success' || !r.ca_certificate) throw new Error('無法取得 CA 根憑證：' + (r.message || ''));
      const { spkiBytes } = parseCertificate(r.ca_certificate);
      return crypto.subtle.importKey('spki', spkiBytes, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    })();
  }
  return _caPublicKeyPromise;
}
/* 用 CA 根公鑰驗證某實體憑證的簽章，並檢查 Subject CommonName 是否為預期
   實體名稱；驗證通過才回傳該憑證內的 subjectPublicKeyInfo bytes 供後續
   匯入使用——確保實際拿去加密/驗證盲簽章的公鑰，是「通過憑證鏈驗證」的
   那一把，而不是伺服器回應中未受保護、可被中間人竄改的裸公鑰欄位。 */
async function verifyCertChain(certPem, expectedCN, caPublicKey) {
  if (!certPem) throw new Error(`伺服器未提供 ${expectedCN} 的憑證，無法驗證公鑰來源`);
  const { tbsBytes, sigValue, spkiBytes, commonName } = parseCertificate(certPem);
  if (commonName !== expectedCN) {
    throw new Error(`憑證主體 CN 不符（預期 ${expectedCN}，實際 ${commonName}），拒絕信任此公鑰`);
  }
  const ok = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, caPublicKey, sigValue, tbsBytes);
  if (!ok) throw new Error(`${expectedCN} 憑證簽章驗證失敗，可能遭偽造或竄改，拒絕信任此公鑰`);
  return spkiBytes;
}

/* ---------- VERIFY_TPA_RESPONSE_SIGNATURE=true 時使用：驗證 TPA 回應封包 ---------- */
async function importPssVerifyKeyFromSpki(spkiBytes) {
  return crypto.subtle.importKey('spki', spkiBytes, { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify']);
}
/* 與 Python padding.PSS.MAX_LENGTH（create_auth_packet 簽 TPA 回應時所用）
   算法一致：emLen - hLen - 2，emLen = ceil((模數位元長度 - 1) / 8)，
   hLen = SHA-256 = 32 bytes。用實際解出的模數計算，不寫死 2048 位元，
   金鑰長度改變也不會跟著壞掉。 */
function pssMaxSaltLength(spkiBytes) {
  const { n } = parseRsaPublicKeyFromSpki(spkiBytes);
  const modulusBits = n.toString(2).length;
  const emLen = Math.ceil((modulusBits - 1) / 8);
  return emLen - 32 - 2;
}
/* 驗證 TPA /api/auth 回應封包（雙向認證的第二半）：
     1. tpa_cert_pem 走 CA 憑證鏈驗證 + Subject CN 必須是 'TPA'
     2. 用該憑證公鑰驗 response_packet 的 RSA-PSS 簽章
     3. nonce_echo 必須等於這次請求送出的 nonce（防止回應被替換成別次
        認證、或別的選民那次認證的封包）
     4. voter_sig_ref 必須等於這次請求簽章的 SHA-256（對應 TPA 端
        tpa_server/app.py 的稽核綁定設計）
   任一步失敗即 throw，呼叫端視同認證失敗處理。 */
async function verifyAuthResponsePacket(responsePacket, tpaCertPem, expectedReceiverId, expectedNonceEcho, expectedVoterSigRef, caPublicKey) {
  const tpaSpki = await verifyCertChain(tpaCertPem, 'TPA', caPublicKey);
  const pssKey  = await importPssVerifyKeyFromSpki(tpaSpki);
  const saltLength = pssMaxSaltLength(tpaSpki);

  const payload = responsePacket.payload;
  if (payload.sender_id !== 'TPA') throw new Error('TPA 回應封包 sender_id 不是 TPA');
  if (payload.receiver_id !== expectedReceiverId) throw new Error('TPA 回應封包 receiver_id 與本次選民 ID 不符');
  if (payload.nonce_echo !== expectedNonceEcho) throw new Error('TPA 回應封包 nonce_echo 與本次請求 nonce 不符（可能是重放或竄改）');
  if (payload.voter_sig_ref !== expectedVoterSigRef) throw new Error('TPA 回應封包 voter_sig_ref 與本次請求簽章不符');

  /* sort_keys=True + separators=(',',':') — 與 Python _serialize_payload 一致 */
  const sorted    = Object.fromEntries(Object.keys(payload).sort().map(k => [k, payload[k]]));
  const bytes     = new TextEncoder().encode(JSON.stringify(sorted));
  const sigBytes  = b64decode(responsePacket.signature);
  const ok = await crypto.subtle.verify({ name: 'RSA-PSS', saltLength }, pssKey, sigBytes, bytes);
  if (!ok) throw new Error('TPA 回應封包簽章驗證失敗，可能遭偽造或竄改');
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
function bigintGcd(a, b) {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b) { [a, b] = [b, a % b]; }
  return a;
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
  // v3.0 修正：原本只檢查 r > 1，沒檢查 gcd(r,n)==1，跟 Python 版
  // shared/blind_signature.py 的 generate_blinding_factor() 不一致——
  // 若 r 剛好跟 n 不互質（RSA-2048 下機率微乎其微，但不是不可能），
  // modinv(r, n) 會靜默算出錯誤結果，導致去盲化失敗且錯誤訊息完全
  //看不出原因。補上跟 Python 版一致的互質檢查。 <3
  const bytes = new Uint8Array(Math.ceil(n.toString(16).length / 2) + 4);
  let r;
  do {
    crypto.getRandomValues(bytes);
    r = hexToBigInt(bytesToHex(bytes)) % n;
  } while (r <= 1n || bigintGcd(r, n) !== 1n);  // <3
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

// <3 v4.0 新增：現場 QR code 掃碼帶入學號／OTP，方便 demo。刻意讀網址的
// fragment（# 後面），不是 ?query=——fragment 天生不會被送到伺服器，
// 瀏覽器也不會把它放進 Referer，掃碼裝置以外的任何人都看不到。只做
// 自動「帶入」，不自動送出：保留讓使用者看到金鑰生成／PoP／憑證申請
// 這幾個步驟的展示效果，也避免掃到舊/重複的碼時被動觸發註冊。
(function() {
  if (!location.hash) return;
  const params = new URLSearchParams(location.hash.slice(1));
  const vid = params.get('vid');
  const otp = params.get('otp');
  if (!vid || !otp) return;

  document.getElementById('voterId').value = vid;
  document.getElementById('otp').value = otp;
  // 帶入後立刻清掉網址列上的 fragment，OTP 不留在網址列/瀏覽紀錄裡。
  history.replaceState(null, '', location.pathname + location.search);

  const el = document.getElementById('regStatus');
  el.classList.remove('hidden');
  el.className = 'mt-4 text-sm p-3 rounded-lg text-green-700 dark:text-green-400 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800/50';
  el.textContent = `✓ 已透過 QR code 自動帶入學號與 OTP，請確認學號無誤後按下方按鈕完成註冊。`;
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
    <div class="mt-3 flex items-center justify-center gap-4">
      <a href="/status" class="text-xs text-msblue hover:underline">查看完整回執 →</a>
      <a id="votedBbLink" href="#" target="_blank" rel="noopener"
        class="inline-flex items-center gap-1 text-xs px-3 py-1.5 rounded-lg bg-msblue hover:bg-msblueHover text-white font-medium transition">
        前往公告板驗證
        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
      </a>
    </div>
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
    <p class="text-green-700 dark:text-green-400 font-semibold text-base mb-3">已收到您的選票</p>
    <p class="text-xs text-gray-500 mb-1">
      為保護匿名性，選票會與其他選民一起批次送出，不會立即出現在計票中心，
      請放心，這是正常流程。開票後可用 m_hex 到公告板（BB）驗證是否已計入：
    </p>
    <code id="successMhex" class="block bg-gray-100 dark:bg-gray-800/60 rounded-lg p-3 text-xs font-mono break-all text-gray-700 dark:text-gray-300 mt-2"></code>
    <div class="mt-4 flex items-center gap-4">
      <a href="/status" class="text-xs text-msblue hover:underline">查看完整回執 →</a>
      <a id="successBbLink" href="#" target="_blank" rel="noopener"
        class="inline-flex items-center gap-1 text-xs px-3 py-1.5 rounded-lg bg-msblue hover:bg-msblueHover text-white font-medium transition">
        前往公告板驗證
        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
      </a>
    </div>
  </div>

  <!-- 錯誤提示 -->
  <div id="errorCard" class="hidden mt-4 bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800/50 rounded-xl p-4 text-sm text-red-700 dark:text-red-400"></div>
</div>

<script>
const BB_ADDRESS = "{{ bb_address }}";  // <3 v4.0：公告板公開網域，用來組「前往公告板驗證」連結
function bbVerifyUrl(mHex) { return `https://${BB_ADDRESS}/verify?m_hex=${encodeURIComponent(mHex)}`; }

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

  // 2. 確認未重複投票（v3.0 修正：回執只存在本機 IndexedDB，不再問伺服器；
  //    這裡查得到的只是「這台裝置」是否投過票，真正防重複投票的關卡在
  //    TPA /api/auth 的 ALREADY_VOTED 檢查，跟這個本地提示無關） <3
  const voteReceipt = await idbLoad('voteReceipt');
  if (voteReceipt) {
    document.getElementById('votedBanner').classList.remove('hidden');
    document.getElementById('votedMhex').textContent = voteReceipt.m_hex;
    document.getElementById('votedBbLink').href = bbVerifyUrl(voteReceipt.m_hex);
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

    // Step 1: 取得公鑰 + 憑證
    addStep('取得 TPA / CC / TA 公鑰與憑證...');
    const [tpaR, ccR, taR] = await Promise.all([
      fetch('/api/proxy/tpa/public_key').then(r=>r.json()),
      fetch('/api/proxy/cc/public_key').then(r=>r.json()),
      fetch('/api/proxy/ta/public_key').then(r=>r.json()),
    ]);
    if (tpaR.status !== 'success') throw new Error('無法取得 TPA 公鑰：' + (tpaR.message || ''));
    if (ccR.status  !== 'success') throw new Error('無法取得 CC 公鑰：'  + (ccR.message  || ''));
    if (taR.status  !== 'success') throw new Error('無法取得 TA 公鑰：'  + (taR.message  || ''));
    addStep('公鑰取得完成，驗證憑證鏈...');

    // v3.0 新增：不再盲目信任各實體回應中的裸公鑰欄位（public_key_pem /
    // e / n），改為用 CA 根憑證驗證 TPA/CC/TA 各自憑證的簽章與 Subject
    // CommonName，之後一律使用「從已驗證憑證解出的公鑰」——避免中間人偽
    // 造回應、替換公鑰後竊聽選票內容或偽造盲簽章結果。 <3
    const caPubKey = await getCaPublicKey();
    const tpaSpki  = await verifyCertChain(tpaR.cert_pem, 'TPA', caPubKey);
    const ccSpki   = await verifyCertChain(ccR.cert_pem,  'CC',  caPubKey);
    const taSpki   = await verifyCertChain(taR.cert_pem,  'TA',  caPubKey);
    const { e: tpa_e, n: tpa_n } = parseRsaPublicKeyFromSpki(tpaSpki);
    const cc_key = await importOaepKeyFromSpki(ccSpki);
    const ta_key = await importOaepKeyFromSpki(taSpki);
    addStep('憑證鏈驗證通過', true);

    // Step 2: TPA 身分認證
    addStep('向 TPA 進行雙向認證...');
    const authPkt = await createAuthPacket(_voterId, 'TPA', _privateKey, _certPem);
    const authResp = await fetch('/api/proxy/tpa/auth', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ auth_packet: authPkt, voter_cert_pem: _certPem }),
    });
    const authData = await authResp.json();
    if (authData.status !== 'success') throw new Error('TPA 認證失敗：' + (authData.message || authData.code || ''));

    // 雙向認證的第二半——選民驗證 TPA 回應封包，是否啟用由檔案開頭的
    // VERIFY_TPA_RESPONSE_SIGNATURE 開關決定（見該處註解說明兩種模式的
    // 差異與取捨）。
    if (VERIFY_TPA_RESPONSE_SIGNATURE) {
      const voterSigRef = await sha256Hex(b64decode(authPkt.signature));
      await verifyAuthResponsePacket(
        authData.response_packet, authData.tpa_cert_pem,
        _voterId, authPkt.payload.nonce, voterSigRef, caPubKey,
      );
      addStep('TPA 回應簽章驗證通過（雙向認證完整）', true);
    }

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
    const inner_enc_b64 = await rsaOaepEncryptWithKey(ta_key, innerHash + '|' + candidate);
    const aes_pt        = inner_enc_b64 + '|' + s_prime_hex + '|' + m_hex;
    const aad_str       = 'voting-system-v2|' + _voterId + '|' + sn;
    const { k, iv, c_data, tag, aad } = await aesGcmEncrypt(aes_pt, aad_str);
    const c_key  = await rsaOaepEncryptWithKey(cc_key, k);
    // v2.0 修正：之前 token_hash 寫死空字串，CC 端的一人一票去重機制對所有
    // 選票永遠不會生效。規格書 §3.4：token_hash = H(Token.payload.token_id)。 <3
    const token_hash = await sha256Hex(votingToken.payload.token_id);  // <3
    const envelope = { c_data, iv, tag, aad, c_key, token_hash };
    addStep('信封封裝完成', true);

    // Step 8: 提交信封（v3.0 修正：不再直接送到 CC，而是先進選民端本地
    // 佇列，由背景排程湊滿批次或接近截止時間才打亂順序一次送出，避免
    // 每個人的提交時間點各自暴露投票行為。 <3
    addStep('提交數位信封...');
    const submitResp = await fetch('/api/submit_envelope', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(envelope),
    });
    const submitData = await submitResp.json();
    if (submitData.status !== 'queued') throw new Error('信封提交失敗：' + (submitData.message || submitData.code || ''));
    addStep('已收到，將於稍後批次送出', true);

    // Step 9: 儲存回執（v3.0 修正：只存本機 IndexedDB，伺服器端完全不接觸
    // 「voter_id ↔ vote」的對應關係，避免留下一份能直接匯出全體選民投票
    // 明細的伺服器端資料。 <3
    await idbSave({
      voteReceipt: {
        voter_id: _voterId, sn, vote: candidate, m_hex, s_prime_hex,
        voted_at: Math.floor(Date.now() / 1000),
      },
    });

    document.getElementById('successCard').classList.remove('hidden');
    document.getElementById('successMhex').textContent = m_hex;
    document.getElementById('successBbLink').href = bbVerifyUrl(m_hex);
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

  <div id="recordCard" class="hidden bg-white/70 dark:bg-cardblack/80 rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-6 space-y-4">
    <div class="flex items-center gap-2 mb-2">
      <span class="px-2.5 py-1 rounded-full text-xs font-medium bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800/50">已投票</span>
      <span id="recVotedAt" class="text-xs text-gray-400"></span>
    </div>
    <div>
      <p class="text-xs text-gray-400 uppercase tracking-wider mb-1">選民 ID</p>
      <p id="recVoterId" class="font-mono text-sm text-gray-800 dark:text-gray-200"></p>
    </div>
    <div>
      <p class="text-xs text-gray-400 uppercase tracking-wider mb-1">SN</p>
      <p id="recSn" class="font-mono text-sm text-gray-800 dark:text-gray-200"></p>
    </div>
    <div>
      <p class="text-xs text-gray-400 uppercase tracking-wider mb-1">投票對象</p>
      <p id="recVote" class="font-mono text-sm text-gray-800 dark:text-gray-200"></p>
    </div>
    <div>
      <p class="text-xs text-gray-400 uppercase tracking-wider mb-1">m_hex（可至 BB 驗證）</p>
      <code id="recMhex" class="block bg-gray-50 dark:bg-[#050505] rounded-lg p-3 text-xs font-mono break-all text-gray-700 dark:text-gray-300 border border-gray-100 dark:border-gray-800/80"></code>
    </div>
  </div>
  <div id="emptyCard" class="hidden text-center py-16 text-gray-400">
    <p>尚未找到投票記錄。</p>
    <a href="/" class="mt-3 inline-block text-sm text-msblue hover:underline">前往投票</a>
  </div>
</div>
<script>
// v3.0 修正：回執只存在本機 IndexedDB，這裡直接讀本機資料渲染，
// 伺服器端完全不參與、也看不到任何一筆「身分 ↔ 投票內容」的對應。 <3
(async function () {
  const rec = await idbLoad('voteReceipt');
  if (rec) {
    document.getElementById('recVotedAt').textContent = rec.voted_at
      ? new Date(rec.voted_at * 1000).toLocaleString() : '';
    document.getElementById('recVoterId').textContent = rec.voter_id || '';
    document.getElementById('recSn').textContent = rec.sn || '';
    document.getElementById('recVote').textContent = rec.vote || '';
    document.getElementById('recMhex').textContent = rec.m_hex || '';
    document.getElementById('recordCard').classList.remove('hidden');
  } else {
    document.getElementById('emptyCard').classList.remove('hidden');
  }
})();
</script>
</body>
</html>"""

# ── 路由 ─────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template_string(_VOTE_HTML, bb_address=BB_ADDRESS)

@app.route('/register')
def register_page():
    return render_template_string(_REGISTER_HTML, default_voter_id=VOTER_ID)

@app.route('/status')
def status():
    return render_template_string(_STATUS_HTML)

make_reload_endpoint(app)

if __name__ == '__main__':
    # v4.0 新增：voter 的監聽埠除了 Admin 稽核查詢，主要是接受一般選民
    # 瀏覽器（經 Caddy）的公開連線——瀏覽器不會持有這套內部 PKI 的用戶端
    # 憑證，所以刻意不要求 CERT_REQUIRED（require_client_cert=False）。
    _ca_cert_path = os.path.join(KEYS_DIR, "ca_cert.pem")
    _ssl_ctx = build_mtls_server_context(
        _TLS_CERT_PATH, _TLS_KEY_PATH, _ca_cert_path, require_client_cert=False,
    )
    app.run(host='0.0.0.0', port=5005, debug=False, ssl_context=_ssl_ctx)
