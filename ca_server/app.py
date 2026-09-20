"""
ca_server/app.py  —  憑證授權中心 (CA)

整個系統的信任根。負責簽發和驗證各服務的 X.509 憑證，
讓各方可以確認對方的身分是合法的。

啟動時會自動生成 CA 金鑰對（如果還沒有的話），
其他服務啟動時會來這裡申請憑證。

端點：
  GET  /api/ca_cert       取得 CA 根憑證（PEM 格式）
  POST /api/issue_cert    申請憑證（提供公鑰和 ID）

注意：本檔案沒有 /api/verify_cert 端點；各服務改用
shared/key_manager.py 的 verify_cert_with_ca() 在本地驗證憑證。
"""

import os
import sys
import hashlib
import hmac
import time
import datetime

# 確保 shared/ 可被 import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID  # <3 v4.0：TLS 憑證用
from cryptography import x509

from shared.db_utils import Database
from shared.admin_auth import check_admin_token, admin_auth_error  # <3 Admin 端點認證
from shared.config_loader import get_service_registration_token  # <3 服務憑證一次性驗證
from shared.tls_utils import build_mtls_server_context  # <3 v4.0：mTLS
from shared.crypto_generate_key_pair import generate_rsa_keypair  # <3 v4.0：CA 自己的 TLS 金鑰對

# ============================================================
# 常數設定
# ============================================================
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR    = os.path.join(SERVICE_DIR, "keys")
DB_PATH     = os.path.join(SERVICE_DIR, "ca.db")

# ============================================================
# 資料庫初始化
# ============================================================
db = Database(DB_PATH)
db.execute("""
    CREATE TABLE IF NOT EXISTS issued_certs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_id   TEXT NOT NULL,
        cert_pem    TEXT NOT NULL,
        issued_at   TEXT NOT NULL,
        cert_serial TEXT,
        revoked_at  INTEGER
    )
""")
# v2.0 修正：為舊資料庫補上憑證撤銷所需欄位（規格書 §19.1）。 <3
for _cert_col_sql in [
    "ALTER TABLE issued_certs ADD COLUMN cert_serial TEXT",
    "ALTER TABLE issued_certs ADD COLUMN revoked_at  INTEGER",
]:
    try:
        db.execute(_cert_col_sql)
    except Exception:
        pass  # 欄位已存在
db.execute("""
    CREATE TABLE IF NOT EXISTS voter_registry (
        voter_id            TEXT PRIMARY KEY,
        otp_hash            TEXT NOT NULL,
        status              TEXT NOT NULL DEFAULT 'pending',
        registered_at       INTEGER NOT NULL,
        issued_cert_serial  TEXT,
        fail_count          INTEGER NOT NULL DEFAULT 0,
        locked_until        INTEGER,
        expires_at          INTEGER
    )
""")
# v2.0 修正：為舊資料庫（本欄位加入前就存在的 voter_registry）補上新欄位。 <3
for _voter_col_sql in [
    "ALTER TABLE voter_registry ADD COLUMN fail_count   INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE voter_registry ADD COLUMN locked_until INTEGER",
    "ALTER TABLE voter_registry ADD COLUMN expires_at   INTEGER",
]:
    try:
        db.execute(_voter_col_sql)
    except Exception:
        pass  # 欄位已存在
# v2.0 修正：服務帳號（TPA/TA/CC）憑證核發原本只檢查 entity_id 是否在
# 硬編碼的 _SERVICE_IDS 集合中，任何人知道服務 ID 字串就能換發憑證。
# 新增 service_registrations 表記錄每個服務帳號是否已兌換過一次性
# SERVICE_REGISTRATION_TOKEN（規格書 §0.5 Step 0.5、§1.4 Step 1.3）。 <3
db.execute("""
    CREATE TABLE IF NOT EXISTS service_registrations (
        entity_id     TEXT PRIMARY KEY,
        registered_at INTEGER NOT NULL
    )
""")
# v4.0 新增：TLS 憑證核發記錄，跟上面的 service_registrations（應用層身分
# 憑證）分開追蹤，避免同一個 entity_id 因為已經兌換過應用層憑證的 token
# 而被誤判成「已註冊」，導致無法再申請 TLS 憑證——兩者是獨立的一次性
# 兌換流程，各自互不影響。 <3
db.execute("""
    CREATE TABLE IF NOT EXISTS tls_registrations (
        entity_id     TEXT PRIMARY KEY,
        registered_at INTEGER NOT NULL
    )
""")
db.execute("""
    CREATE TABLE IF NOT EXISTS issued_tls_certs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_id   TEXT NOT NULL,
        hostname    TEXT NOT NULL,
        cert_pem    TEXT NOT NULL,
        issued_at   TEXT NOT NULL,
        cert_serial TEXT
    )
""")

# 服務帳號（不需 OTP 驗證，改用 SERVICE_REGISTRATION_TOKEN 一次性驗證）
_SERVICE_IDS = {'TPA', 'TA', 'CC', 'BB', 'CA', 'ADMIN'}
# v4.0 新增：可申請 TLS 憑證的實體——比 _SERVICE_IDS 多了 VOTER（選民端
# 後端本身沒有應用層身分憑證，但一樣需要 TLS 專用金鑰對來對外呼叫其他
# 服務、並在自己的公開監聽埠上出示伺服器憑證）。 <3
_TLS_ENTITY_IDS = _SERVICE_IDS | {'VOTER'}
# 時間誤差容許值（秒）
_DELTA_T = int(os.environ.get("DELTA_T", "300"))
# v2.0 修正：OTP 連續失敗鎖定與過期時間（規格書 §0.5、§0.6 S-0.2） <3
_OTP_MAX_ATTEMPTS    = 3
_OTP_LOCKOUT_SECONDS = 86400       # 24 小時
_OTP_EXPIRY_SECONDS  = 7 * 86400   # 7 天


def _hash_otp(otp: str) -> str:
    return hashlib.sha256(otp.encode('utf-8')).hexdigest()

# ============================================================
# CA 核心邏輯
# ============================================================

def _save_pem_file(path: str, data: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(data)


def _load_or_generate_ca_keys():
    """從磁碟載入 CA 金鑰與根憑證；若不存在則生成並儲存。"""
    priv_path = os.path.join(KEYS_DIR, "ca_private_key.pem")
    cert_path = os.path.join(KEYS_DIR, "ca_root_cert.pem")

    if os.path.exists(priv_path) and os.path.exists(cert_path):
        with open(priv_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(cert_path, 'rb') as f:
            root_cert = x509.load_pem_x509_certificate(f.read())
        print("[CA] 已從磁碟載入 CA 金鑰與根憑證。")
    else:
        print("[CA] 生成新的 CA 金鑰與根憑證...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key  = private_key.public_key()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NUTC Voting System Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Voting CA"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        root_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            # v4.0 新增：這張自簽根憑證一直沒有標準的 CA 擴充欄位。過去
            # 沒出過問題，是因為 verify_cert_with_ca() 自己手刻簽章驗證
            # （直接拿 CA 公鑰驗 cert.signature），完全不檢查
            # BasicConstraints；但 Python 標準 ssl/OpenSSL 的憑證鏈驗證
            # （requests 的 verify=、ssl.SSLContext.load_verify_locations）
            # 會檢查——沒有 BasicConstraints(ca=True) 的憑證，OpenSSL 視為
            # 一般終端憑證，不接受它簽發／驗證別的憑證，會直接報
            # 「invalid CA certificate」而不是可讀的錯誤。這是實際跑
            # docker compose 起服務時才發現的真實 bug，不是理論推測。 <3
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False, key_encipherment=False, content_commitment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True,
                    crl_sign=True, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )

        os.makedirs(KEYS_DIR, exist_ok=True)
        priv_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode('utf-8')
        cert_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        _save_pem_file(priv_path, priv_pem)
        _save_pem_file(cert_path, cert_pem)
        print("[CA] CA 金鑰與根憑證已儲存至磁碟。")

    return private_key, root_cert


# 啟動時初始化
_ca_private_key, _ca_root_cert = _load_or_generate_ca_keys()


def get_root_cert_pem() -> str:
    return _ca_root_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')


def issue_certificate(entity_id: str, public_key_pem: str) -> str:
    entity_public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NUTC Voting System"),
        x509.NameAttribute(NameOID.COMMON_NAME, entity_id),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    serial = x509.random_serial_number()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(_ca_root_cert.subject)
        .public_key(entity_public_key)
        .serial_number(serial)
        .not_valid_before(now)
        # v2.0 修正：規格書 §0.4 Step 0.4 訂為 365 天，先前寫死 30 天，
        # 教學/測試環境放著超過一個月沒重建就會出現「憑證已過期」的假性失敗。 <3
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(_ca_private_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    # 記錄至資料庫（含序號，供後續撤銷查詢用；規格書 §19.1）
    db.execute(
        "INSERT INTO issued_certs (entity_id, cert_pem, issued_at, cert_serial) VALUES (?, ?, ?, ?)",
        (entity_id, cert_pem, now.isoformat(), str(serial)),
    )  # <3
    print(f"[CA] 已核發憑證給 {entity_id}")
    return cert_pem


def issue_tls_certificate(entity_id: str, hostname: str, public_key_pem: str) -> str:
    """
    v4.0 新增：核發 TLS 專用憑證（服務間 mTLS 用），跟上面 issue_certificate()
    核發的應用層身分憑證是完全不同的一張憑證、不同的金鑰——刻意不重用同一把
    私鑰身兼「簽應用層封包」與「TLS handshake」兩種角色，外洩一把金鑰的
    影響範圍才不會疊在一起。

    跟應用層憑證的關鍵差異：多加了標準 TLS 函式庫（瀏覽器、curl、Python
    ssl 模組）驗證主機名所必需的 SubjectAlternativeName，以及表明這張
    憑證可合法用於 TLS 伺服器／用戶端驗證的 KeyUsage／ExtendedKeyUsage——
    這三個擴充欄位是 issue_certificate() 完全沒有的，沒有它們這張憑證
    連基本的 TLS handshake 都會被拒絕。
    """
    entity_public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NUTC Voting System"),
        x509.NameAttribute(NameOID.COMMON_NAME, entity_id),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    serial = x509.random_serial_number()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(_ca_root_cert.subject)
        .public_key(entity_public_key)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True, content_commitment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(_ca_private_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    db.execute(
        "INSERT INTO issued_tls_certs (entity_id, hostname, cert_pem, issued_at, cert_serial) VALUES (?, ?, ?, ?, ?)",
        (entity_id, hostname, cert_pem, now.isoformat(), str(serial)),
    )
    print(f"[CA] 已核發 TLS 憑證給 {entity_id}（hostname={hostname}）")
    return cert_pem


# ============================================================
# CA 自己的 TLS 身分（v4.0 新增）
# ============================================================
# CA 不能像其他服務一樣打 /api/issue_tls_cert 跟自己申請（那個端點還沒
# 啟動），所以直接在本地呼叫 issue_tls_certificate()，邏輯完全一致，只是
# 省了一趟 HTTP 來回。
CA_HOSTNAME = os.environ.get("CA_HOSTNAME", "ca")
_tls_key_path  = os.path.join(KEYS_DIR, "tls_private_key.pem")
_tls_cert_path = os.path.join(KEYS_DIR, "tls_certificate.pem")

if os.path.exists(_tls_key_path) and os.path.exists(_tls_cert_path):
    print(f"[CA] 已從磁碟載入自己的 TLS 憑證：{_tls_cert_path}")
else:
    _tls_private_key, _tls_public_key, _, _, _ = generate_rsa_keypair()
    _tls_private_key_pem = _tls_private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode('utf-8')
    _tls_public_key_pem = _tls_public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')
    _tls_cert_pem = issue_tls_certificate('CA', CA_HOSTNAME, _tls_public_key_pem)
    _save_pem_file(_tls_key_path, _tls_private_key_pem)
    _save_pem_file(_tls_cert_path, _tls_cert_pem)
    print(f"[CA] 已生成並核發自己的 TLS 憑證（hostname={CA_HOSTNAME}）")


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
  <title>CA 憑證授權中心</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    // 啟用 Tailwind 的 class 模式深色切換
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
    /* 隱藏捲軸但保留功能 */
    pre::-webkit-scrollbar { height: 8px; }
    pre::-webkit-scrollbar-track { background: transparent; }
    pre::-webkit-scrollbar-thumb { background: rgba(156, 163, 175, 0.5); border-radius: 4px; }
  </style>
  <script>
    // 頁面載入時檢查主題設定
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
  <div class="max-w-5xl mx-auto px-4 py-10">

    <div class="flex items-center gap-4 mb-8">
      <div class="w-12 h-12 rounded-xl bg-white/70 dark:bg-cardblack/80 backdrop-blur-md shadow-sm flex items-center justify-center border border-gray-200 dark:border-gray-800">
        <svg class="w-6 h-6 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
      </div>
      <div>
        <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">憑證授權中心 (CA)</h1>
        <p class="text-gray-500 dark:text-gray-400 text-sm">NUTC Voting System · Certificate Authority</p>
      </div>
      
      <div class="ml-auto flex items-center gap-3">
        <span class="px-3 py-1.5 rounded-full text-xs font-medium border bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border-green-200 dark:border-green-800/50 backdrop-blur-sm flex items-center">
          <span class="inline-block w-1.5 h-1.5 rounded-full bg-green-500 mr-1.5 shadow-[0_0_4px_#22c55e]"></span> 運作中
        </span>
        
        <button onclick="toggleTheme()" class="p-2 rounded-lg bg-white/70 dark:bg-cardblack/80 border border-gray-200 dark:border-gray-800 shadow-sm hover:bg-gray-100 dark:hover:bg-gray-900 transition-colors text-gray-600 dark:text-gray-300 focus:outline-none focus:ring-2 focus:ring-msblue/50">
          <svg class="w-4 h-4 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
          <svg class="w-4 h-4 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
        </button>
      </div>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-3 gap-5 mb-8">
      <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-5 flex flex-col justify-center transition-all hover:shadow-lg">
        <p class="text-gray-500 dark:text-gray-400 text-xs font-medium uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <svg class="w-3.5 h-3.5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
          已核發憑證
        </p>
        <p class="text-3xl font-semibold text-gray-900 dark:text-white">{{ cert_count }}</p>
      </div>
      <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-5 flex flex-col justify-center transition-all hover:shadow-lg">
        <p class="text-gray-500 dark:text-gray-400 text-xs font-medium uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <svg class="w-3.5 h-3.5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>
          根憑證有效期
        </p>
        <p class="text-lg font-medium text-gray-800 dark:text-gray-200">365 天</p>
      </div>
      <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-5 flex flex-col justify-center transition-all hover:shadow-lg">
        <p class="text-gray-500 dark:text-gray-400 text-xs font-medium uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <svg class="w-3.5 h-3.5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
          金鑰演算法
        </p>
        <p class="text-lg font-medium text-gray-800 dark:text-gray-200">RSA-2048 <span class="text-gray-400 dark:text-gray-600 font-light mx-1">/</span> SHA-256</p>
      </div>
    </div>

    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-100 dark:border-gray-800/60 bg-gray-50/50 dark:bg-[#0a0a0a]/50 flex items-center justify-between">
        <h2 class="font-medium text-gray-800 dark:text-gray-200">已核發憑證記錄</h2>
        <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"></path></svg>
      </div>
      {% if certs %}
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead class="bg-gray-50 dark:bg-[#0a0a0a] text-gray-500 dark:text-gray-400 text-xs uppercase tracking-wider">
            <tr>
              <th class="px-6 py-3.5 text-left font-medium">#</th>
              <th class="px-6 py-3.5 text-left font-medium">實體 ID</th>
              <th class="px-6 py-3.5 text-left font-medium">核發時間</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100 dark:divide-gray-800">
            {% for c in certs %}
            <tr class="hover:bg-gray-50 dark:hover:bg-[#1a1a1a] transition-colors">
              <td class="px-6 py-4 text-gray-500">{{ loop.index }}</td>
              <td class="px-6 py-4 font-mono font-medium text-msblue dark:text-[#3399FF]">{{ c.entity_id }}</td>
              <td class="px-6 py-4 text-gray-600 dark:text-gray-400 font-mono text-xs">{{ c.issued_at }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% else %}
      <div class="px-6 py-12 text-center text-gray-500 dark:text-gray-500">
        <svg class="w-12 h-12 mx-auto text-gray-300 dark:text-gray-700 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"></path></svg>
        <p>尚未核發任何憑證</p>
      </div>
      {% endif %}
    </div>

    <div class="mt-6 bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-6">
      <div class="flex justify-between items-center mb-4">
        <h2 class="font-medium text-gray-800 dark:text-gray-200 flex items-center gap-2">
          <svg class="w-4 h-4 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>
          根憑證（PEM 預覽）
        </h2>
        <span class="text-xs text-gray-400 dark:text-gray-500 border border-gray-200 dark:border-gray-700 px-2 py-1 rounded-md">公開資訊</span>
      </div>
      <div class="bg-gray-50 dark:bg-[#050505] rounded-lg p-5 border border-gray-100 dark:border-gray-800/80 shadow-inner">
        <pre class="text-[11px] leading-relaxed text-gray-600 dark:text-gray-400 font-mono overflow-x-auto whitespace-pre-wrap break-all">{{ ca_cert_pem }}</pre>
      </div>
    </div>

  </div>
</body>
</html>"""

# ── 路由 ──────────────────────────────────────────────────

@app.route('/')
def dashboard():
    certs = db.fetchall("SELECT id, entity_id, issued_at FROM issued_certs ORDER BY id DESC")
    cert_count = db.count("issued_certs")
    return render_template_string(
        _DASHBOARD_HTML,
        certs=certs,
        cert_count=cert_count,
        ca_cert_pem=get_root_cert_pem(),
    )


@app.route('/api/ca_cert', methods=['GET'])
def api_get_ca_cert():
    """[GET] 提供 CA 根憑證"""
    return jsonify({"status": "success", "ca_certificate": get_root_cert_pem()}), 200


@app.route('/api/admin/register_voter', methods=['POST'])
def api_admin_register_voter():
    """
    [POST] 管理員預先註冊選民（Phase 0 Step 0.1）。

    Zero-knowledge 模式（唯一支援的模式）：
        Body: {"voter_id": str, "otp_hash": str}
        呼叫端（管理者工具或其他自動化腳本）自行在本地生成 OTP，僅傳入
        H(OTP)；CA 永不接觸 OTP 明文。
        回傳: {"status", "voter_id"}（不含 otp）

    若 voter_id 已存在且 status='registered' 則回傳 409。
    若 voter_id 存在但 status='pending' 則允許重新派發 OTP。

    v2.0 修正：需要 Admin Bearer Token（規格書 §18.1.3）。先前此端點完全
    沒有驗證，任何能連到 CA port 的人都能任意新增選民名冊。 <3

    v3.0 修正：拿掉原本「缺少 otp_hash 就退回 Legacy 模式、由 CA 自己生成
    明文 OTP 並在回應中直接回傳」的相容路徑。這條路徑等於 CA 本身仍保留
    一條會經手明文 OTP 的後門，跟「CA 永不接觸 OTP 明文」的零知識設計互
    相矛盾——而且不是假設情境，測試套件過去就是圖方便一路走這條路徑。
    現在強制要求 otp_hash，呼叫端必須自行生成 OTP、只送雜湊值過來。 <3
    """
    if not check_admin_token():
        return jsonify(admin_auth_error()), 401  # <3

    data = request.get_json()
    if not data or 'voter_id' not in data:
        return jsonify({"status": "error", "message": "缺少 voter_id"}), 400

    voter_id = str(data['voter_id']).strip()
    if not voter_id:
        return jsonify({"status": "error", "message": "voter_id 不可為空"}), 400

    now = int(time.time())
    existing = db.fetchone("SELECT status FROM voter_registry WHERE voter_id = ?", (voter_id,))
    if existing and existing['status'] == 'registered':
        return jsonify({
            "status": "error",
            "code":   "ALREADY_REGISTERED",
            "message": f"{voter_id} 已完成憑證申請",
        }), 409

    # ── Zero-knowledge 模式：呼叫端提供 H(OTP)，CA 永不知曉明文 ──
    # v3.0 修正：`data.get('otp_hash', '')` 只有在完全沒有這個 key 時
    # 才會用預設值 ''；若呼叫端明確傳 `"otp_hash": null`，get() 會拿到
    # 貨真價實的 None，對 None 呼叫 .strip() 會丟 AttributeError，變成
    # 沒處理過的 500，而不是原本設計要給的 400 MISSING_OTP_HASH。改用
    # `or ''` 讓「缺欄位」和「欄位是 null」兩種情況都正確落到空字串。 <3
    otp_hash = (data.get('otp_hash') or '').strip()  # <3
    if not otp_hash:
        return jsonify({
            "status":  "error",
            "code":    "MISSING_OTP_HASH",
            "message": "缺少 otp_hash：CA 不再接受由自己生成明文 OTP 的請求，"
                       "請於呼叫端本地生成 OTP 並只提交其雜湊值",
        }), 400  # <3

    # v2.0 修正：OTP 過期時間（規格書 §0.6 S-0.2 建議 7 天），可由 Admin
    # 指定 expires_at，否則預設 now + 7 天。重新派發 OTP 時一併清除鎖定
    # 狀態與失敗次數，讓選民能重新開始嘗試。 <3
    expires_at = data.get('expires_at') or (now + _OTP_EXPIRY_SECONDS)

    if existing:
        db.execute(
            "UPDATE voter_registry SET otp_hash = ?, registered_at = ?, expires_at = ?, "
            "fail_count = 0, locked_until = NULL WHERE voter_id = ?",
            (otp_hash, now, expires_at, voter_id),
        )
    else:
        db.execute(
            "INSERT INTO voter_registry (voter_id, otp_hash, status, registered_at, expires_at) "
            "VALUES (?, ?, 'pending', ?, ?)",
            (voter_id, otp_hash, now, expires_at),
        )

    print(f"[CA] 已預先註冊選民：{voter_id}（zero-knowledge 模式）")
    return jsonify({"status": "success", "voter_id": voter_id}), 200


@app.route('/api/issue_cert', methods=['POST'])
def api_issue_cert():
    """
    [POST] 核發憑證。
    服務帳號（TPA/TA/CC/BB）：Body: {"entity_id": str, "public_key": str}
    選民：Body: {"entity_id": str, "public_key": str, "otp": str,
                 "timestamp": int, "pop_signature": str (base64)}
    """
    import base64 as _b64

    data = request.get_json()
    if not data or 'entity_id' not in data or 'public_key' not in data:
        return jsonify({"status": "error", "message": "缺少 entity_id 或 public_key"}), 400

    entity_id = data['entity_id']

    # 服務帳號：跳過 OTP/PoP 驗證，改用一次性 SERVICE_REGISTRATION_TOKEN
    # v2.0 修正：先前只檢查 entity_id 是否在硬編碼白名單中，任何人知道
    # 服務 ID 字串（例如 "CC"）就能換發合法憑證，等同重現 v1.0「CA 對任意
    # entity_id 都簽發憑證」的根本性漏洞。現在要求提供正確的
    # registration_token，且每個 entity_id 只能成功兌換一次。 <3
    if entity_id in _SERVICE_IDS:
        registration_token = data.get('registration_token', '')
        expected_token = get_service_registration_token()

        if db.exists("SELECT 1 FROM service_registrations WHERE entity_id = ?", (entity_id,)):
            return jsonify({
                "status": "error",
                "code": "ALREADY_REGISTERED",
                "message": f"{entity_id} 已核發過服務憑證，registration_token 已失效",
            }), 403  # <3

        # v3.0 修正：改用固定時間比較，避免時序側通道洩漏
        # SERVICE_REGISTRATION_TOKEN。 <3
        if not expected_token or not hmac.compare_digest(registration_token, expected_token):  # <3
            return jsonify({
                "status": "error",
                "code": "SERVICE_TOKEN_INVALID",
                "message": "SERVICE_REGISTRATION_TOKEN 無效或缺漏",
            }), 403  # <3

        try:
            cert_pem = issue_certificate(entity_id, data['public_key'])
            db.execute(
                "INSERT INTO service_registrations (entity_id, registered_at) VALUES (?, ?)",
                (entity_id, int(time.time())),
            )  # <3 標記此服務帳號的 token 已使用，防止重複兌換
            return jsonify({
                "status":      "success",
                "message":     f"憑證核發成功 ({entity_id})",
                "certificate": cert_pem,
            }), 200
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    # 選民：需要 OTP + PoP 驗證
    otp           = data.get('otp', '')
    timestamp     = data.get('timestamp', 0)
    pop_sig_b64   = data.get('pop_signature', '')

    if not otp or not timestamp or not pop_sig_b64:
        return jsonify({
            "status":  "error",
            "code":    "MISSING_FIELDS",
            "message": "選民申請憑證需提供 otp、timestamp、pop_signature",
        }), 400

    # 1. 檢查 voter_registry
    row = db.fetchone(
        "SELECT otp_hash, status, fail_count, locked_until, expires_at "
        "FROM voter_registry WHERE voter_id = ?",
        (entity_id,)
    )
    if not row:
        return jsonify({"status": "error", "code": "ENTITY_NOT_REGISTERED",
                        "message": f"{entity_id} 尚未在系統中預先註冊"}), 403

    if row['status'] == 'registered':
        return jsonify({"status": "error", "code": "ALREADY_REGISTERED",
                        "message": f"{entity_id} 已申請過憑證"}), 403

    now = int(time.time())

    # v2.0 修正：帳號鎖定檢查（規格書 §0.5：連續 3 次 OTP 失敗鎖定 24 小時）。
    # 先前完全沒有此機制，OTP 可以無限次嘗試。 <3
    locked_until = row['locked_until']
    if locked_until and now < locked_until:
        return jsonify({
            "status":  "error",
            "code":    "ACCOUNT_LOCKED",
            "message": f"OTP 連續錯誤次數過多，帳號已鎖定，請於 {locked_until - now} 秒後再試",
        }), 403  # <3

    # v2.0 修正：OTP 過期檢查（規格書 §0.6 S-0.2：建議 7 天）。先前 OTP
    # 派發後永久有效。 <3
    otp_expires_at = row['expires_at']
    if otp_expires_at and now > otp_expires_at:
        return jsonify({
            "status":  "error",
            "code":    "OTP_EXPIRED",
            "message": "OTP 已過期，請聯繫管理員重新派發",
        }), 403  # <3

    # 2. 驗證 OTP 雜湊
    if _hash_otp(otp) != row['otp_hash']:
        # v2.0 修正：累計失敗次數，達到上限就鎖定 24 小時。 <3
        new_fail_count = row['fail_count'] + 1
        if new_fail_count >= _OTP_MAX_ATTEMPTS:
            db.execute(
                "UPDATE voter_registry SET fail_count = 0, locked_until = ? WHERE voter_id = ?",
                (now + _OTP_LOCKOUT_SECONDS, entity_id),
            )
            print(f"[CA] {entity_id} OTP 連續錯誤 {_OTP_MAX_ATTEMPTS} 次，帳號已鎖定 24 小時")
        else:
            db.execute(
                "UPDATE voter_registry SET fail_count = ? WHERE voter_id = ?",
                (new_fail_count, entity_id),
            )
        return jsonify({"status": "error", "code": "OTP_INVALID",
                        "message": "OTP 不正確"}), 403

    # 3. 驗證時間誤差（雙向）
    if abs(now - int(timestamp)) > _DELTA_T:
        return jsonify({"status": "error", "code": "TIMESTAMP_OUT_OF_RANGE",
                        "message": f"時間偏差超過 {_DELTA_T} 秒"}), 403

    # 4. 驗證 PoP 簽章
    try:
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        pub_key = serialization.load_pem_public_key(data['public_key'].encode('utf-8'))
        challenge = f"REGISTER|{entity_id}|{timestamp}".encode('utf-8')
        pop_sig = _b64.b64decode(pop_sig_b64)
        pub_key.verify(
            pop_sig,
            challenge,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.AUTO,
            ),
            hashes.SHA256(),
        )
    except Exception as e:
        return jsonify({"status": "error", "code": "POP_INVALID",
                        "message": f"PoP 簽章驗證失敗：{e}"}), 403

    # 5. 核發憑證
    try:
        cert_pem = issue_certificate(entity_id, data['public_key'])
        serial = x509.load_pem_x509_certificate(cert_pem.encode('utf-8')).serial_number
        db.execute(
            "UPDATE voter_registry SET status = 'registered', issued_cert_serial = ? WHERE voter_id = ?",
            (str(serial), entity_id),
        )
        return jsonify({
            "status":      "success",
            "message":     f"憑證核發成功 ({entity_id})",
            "certificate": cert_pem,
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/issue_tls_cert', methods=['POST'])
def api_issue_tls_cert():
    """
    [POST] 核發 TLS 專用憑證（v4.0 新增，服務間 mTLS 用）。
    Body: {"entity_id": str, "hostname": str, "public_key": str, "registration_token": str}

    跟 /api/issue_cert 是兩個完全獨立的一次性兌換流程（各自的 DB 表、
    各自的「是否已兌換過」判斷），可以用同一組 SERVICE_REGISTRATION_TOKEN
    分別跟這兩個端點各換一次，互不影響、互不消耗對方的額度。
    """
    data = request.get_json()
    if not data or not all(k in data for k in ('entity_id', 'hostname', 'public_key', 'registration_token')):
        return jsonify({
            "status":  "error",
            "code":    "MISSING_FIELDS",
            "message": "需要 entity_id、hostname、public_key、registration_token",
        }), 400

    entity_id = data['entity_id']
    hostname  = data['hostname']

    if entity_id not in _TLS_ENTITY_IDS:
        return jsonify({
            "status":  "error",
            "code":    "UNKNOWN_ENTITY",
            "message": f"不支援核發 TLS 憑證給此 entity_id：{entity_id}",
        }), 403

    if db.exists("SELECT 1 FROM tls_registrations WHERE entity_id = ?", (entity_id,)):
        return jsonify({
            "status":  "error",
            "code":    "ALREADY_REGISTERED",
            "message": f"{entity_id} 已核發過 TLS 憑證，registration_token 已失效",
        }), 403

    registration_token = data.get('registration_token', '')
    expected_token = get_service_registration_token()
    # 固定時間比較，避免時序側通道洩漏 SERVICE_REGISTRATION_TOKEN（比照
    # /api/issue_cert 的既有作法）。
    if not expected_token or not hmac.compare_digest(registration_token, expected_token):
        return jsonify({
            "status":  "error",
            "code":    "SERVICE_TOKEN_INVALID",
            "message": "SERVICE_REGISTRATION_TOKEN 無效或缺漏",
        }), 403

    try:
        cert_pem = issue_tls_certificate(entity_id, hostname, data['public_key'])
        db.execute(
            "INSERT INTO tls_registrations (entity_id, registered_at) VALUES (?, ?)",
            (entity_id, int(time.time())),
        )
        return jsonify({
            "status":      "success",
            "message":     f"TLS 憑證核發成功（{entity_id}）",
            "certificate": cert_pem,
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/admin/voter_registry', methods=['GET'])
def api_admin_voter_registry():
    """
    [GET] 回傳全部選民的註冊狀態（供 admin_tool 同步 ca_status）。
    v2.0 修正：需要 Admin Bearer Token（規格書 §18.1.3）。 <3
    """
    if not check_admin_token():
        return jsonify(admin_auth_error()), 401  # <3
    rows = db.fetchall(
        "SELECT voter_id, status, registered_at, issued_cert_serial FROM voter_registry ORDER BY registered_at"
    )
    return jsonify({"status": "success", "voters": rows}), 200


@app.route('/api/voter_status', methods=['GET'])
def api_voter_status():
    """[GET] 查詢特定選民的 CA 註冊狀態（供選民端自動偵測新一輪重置）。"""
    voter_id = request.args.get('voter_id', '').strip()
    if not voter_id:
        return jsonify({"registered": False, "voter_id": ""}), 200
    row = db.fetchone("SELECT status FROM voter_registry WHERE voter_id = ?", (voter_id,))
    if not row:
        return jsonify({"registered": False, "voter_id": voter_id}), 200
    return jsonify({"registered": True, "status": row['status'], "voter_id": voter_id}), 200


@app.route('/api/admin/reset_voter_registry', methods=['POST'])
def api_admin_reset_voter_registry():
    """
    [POST] 清除 CA 選民名冊（新一輪前使用）。刪除全部 voter_registry 記錄。
    v2.0 修正：需要 Admin Bearer Token（規格書 §18.1.3）。先前任何人都能
    清空選民名冊。 <3
    """
    if not check_admin_token():
        return jsonify(admin_auth_error()), 401  # <3
    count = db.count("voter_registry")
    db.execute("DELETE FROM voter_registry")
    print(f"[CA] 選民名冊已清除（共 {count} 筆）。")
    return jsonify({"status": "success", "deleted_count": count}), 200


@app.route('/api/admin/revoke_cert', methods=['POST'])
def api_admin_revoke_cert():
    """
    [POST] 撤銷指定選民已核發之憑證（規格書 §19.1：voter_registry.status
    允許轉為 'revoked'）。

    Body: {"voter_id": str, "reason": str (optional)}

    需要 Admin Bearer Token。 <3

    注意：本端點只負責記錄撤銷狀態（voter_registry.status = 'revoked'、
    issued_certs.revoked_at），不會即時讓其他服務停止接受該憑證 ——
    即時撤銷查詢（OCSP/CRL）是規格書 §22.2 列為 v3.0 候選議題的未來工作，
    本次僅落實資料模型與撤銷動作本身。
    """
    if not check_admin_token():
        return jsonify(admin_auth_error()), 401  # <3

    data = request.get_json() or {}
    voter_id = str(data.get('voter_id', '')).strip()
    if not voter_id:
        return jsonify({"status": "error", "code": "MISSING_FIELDS",
                        "message": "缺少 voter_id"}), 400

    row = db.fetchone("SELECT status, issued_cert_serial FROM voter_registry WHERE voter_id = ?", (voter_id,))
    if not row:
        return jsonify({"status": "error", "code": "ENTITY_NOT_REGISTERED",
                        "message": f"{voter_id} 不在選民名冊中"}), 404

    if row['status'] != 'registered':
        return jsonify({"status": "error", "code": "NOT_REGISTERED_YET",
                        "message": f"{voter_id} 尚未核發過憑證，無需撤銷"}), 409

    now = int(time.time())
    db.execute("UPDATE voter_registry SET status = 'revoked' WHERE voter_id = ?", (voter_id,))
    db.execute(
        "UPDATE issued_certs SET revoked_at = ? WHERE entity_id = ? AND revoked_at IS NULL",
        (now, voter_id),
    )
    print(f"[CA] 已撤銷 {voter_id} 的憑證（序號：{row['issued_cert_serial']}）")
    return jsonify({
        "status":      "success",
        "voter_id":    voter_id,
        "revoked_at":  now,
        "cert_serial": row['issued_cert_serial'],
    }), 200


@app.route('/api/revocation_list', methods=['GET'])
def api_revocation_list():
    """
    [GET] 公開撤銷清單（簡化版 CRL）。任何人可查詢已撤銷之憑證序號，
    供未來 OCSP/CRL 整合使用（規格書 §22.2）。
    """
    rows = db.fetchall(
        "SELECT entity_id, cert_serial, revoked_at FROM issued_certs "
        "WHERE revoked_at IS NOT NULL ORDER BY revoked_at DESC"
    )
    return jsonify({"status": "success", "revoked": rows}), 200


if __name__ == '__main__':
    # v4.0 修正：CA 不能要求 CERT_REQUIRED。CA 是整條信任鏈的起點——每個
    # 實體第一次呼叫 CA（下載根憑證、申請應用層憑證、申請 TLS 憑證）都
    # 發生在它自己還沒有任何憑證的時候，如果 CA 強制要求對方先出示合法
    # 憑證才能連線，等於沒有任何實體能完成 bootstrap（先有雞還是先有蛋）。
    # CA 端點本來就各自有自己的身分驗證機制（SERVICE_REGISTRATION_TOKEN
    # 一次性權杖、選民的 OTP+PoP、Admin Bearer Token），不依賴傳輸層的
    # 用戶端憑證，所以拿掉 mTLS 的雙向要求不會削弱安全性，純粹是解決
    # 這個先後順序上的矛盾。 <3
    _ca_root_cert_path = os.path.join(KEYS_DIR, "ca_root_cert.pem")
    _ssl_ctx = build_mtls_server_context(
        _tls_cert_path, _tls_key_path, _ca_root_cert_path, require_client_cert=False,
    )
    app.run(host='0.0.0.0', port=5001, debug=False, ssl_context=_ssl_ctx)
