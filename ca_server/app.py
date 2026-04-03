"""
ca_server/app.py  —  憑證授權中心 (CA)

整個系統的信任根。負責簽發和驗證各服務的 X.509 憑證，
讓各方可以確認對方的身分是合法的。

啟動時會自動生成 CA 金鑰對（如果還沒有的話），
其他服務啟動時會來這裡申請憑證。

端點：
  GET  /api/ca_cert       取得 CA 根憑證（PEM 格式）
  POST /api/issue_cert    申請憑證（提供公鑰和 ID）
  POST /api/verify_cert   驗證憑證是否由本 CA 簽發
"""

import os
import sys
import datetime

# 確保 shared/ 可被 import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from cryptography import x509

from shared.db_utils import Database

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
        issued_at   TEXT NOT NULL
    )
""")

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
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(_ca_root_cert.subject)
        .public_key(entity_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(_ca_private_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    # 記錄至資料庫
    db.execute(
        "INSERT INTO issued_certs (entity_id, cert_pem, issued_at) VALUES (?, ?, ?)",
        (entity_id, cert_pem, now.isoformat()),
    )
    print(f"[CA] 已核發憑證給 {entity_id}")
    return cert_pem


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
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">
  <div class="max-w-5xl mx-auto px-4 py-10">

    <!-- Header -->
    <div class="flex items-center gap-4 mb-8">
      <div class="w-12 h-12 rounded-xl bg-violet-600 flex items-center justify-center text-2xl">🔐</div>
      <div>
        <h1 class="text-2xl font-bold text-white">憑證授權中心 (CA)</h1>
        <p class="text-gray-400 text-sm">NUTC Voting System · Certificate Authority</p>
      </div>
      <span class="ml-auto px-3 py-1 rounded-full bg-green-900 text-green-300 text-xs font-semibold">● 運作中</span>
    </div>

    <!-- Stats -->
    <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
      <div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
        <p class="text-gray-400 text-xs mb-1">已核發憑證</p>
        <p class="text-3xl font-bold text-violet-400">{{ cert_count }}</p>
      </div>
      <div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
        <p class="text-gray-400 text-xs mb-1">根憑證有效期</p>
        <p class="text-sm font-semibold text-gray-200">365 天</p>
      </div>
      <div class="bg-gray-900 rounded-xl p-5 border border-gray-800">
        <p class="text-gray-400 text-xs mb-1">金鑰演算法</p>
        <p class="text-sm font-semibold text-gray-200">RSA-2048 / SHA-256</p>
      </div>
    </div>

    <!-- Issued Certs Table -->
    <div class="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-800">
        <h2 class="font-semibold text-gray-200">已核發憑證記錄</h2>
      </div>
      {% if certs %}
      <table class="w-full text-sm">
        <thead class="bg-gray-800 text-gray-400 text-xs uppercase">
          <tr>
            <th class="px-6 py-3 text-left">#</th>
            <th class="px-6 py-3 text-left">實體 ID</th>
            <th class="px-6 py-3 text-left">核發時間</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-800">
          {% for c in certs %}
          <tr class="hover:bg-gray-800/50 transition">
            <td class="px-6 py-3 text-gray-500">{{ c.id }}</td>
            <td class="px-6 py-3 font-mono text-violet-300">{{ c.entity_id }}</td>
            <td class="px-6 py-3 text-gray-400">{{ c.issued_at }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <div class="px-6 py-10 text-center text-gray-500">尚未核發任何憑證</div>
      {% endif %}
    </div>

    <!-- CA Cert Preview -->
    <div class="mt-6 bg-gray-900 rounded-xl border border-gray-800 p-5">
      <h2 class="font-semibold text-gray-200 mb-3">根憑證（PEM 預覽）</h2>
      <pre class="text-xs text-green-400 bg-gray-950 rounded-lg p-4 overflow-x-auto whitespace-pre-wrap break-all">{{ ca_cert_pem }}</pre>
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


@app.route('/api/issue_cert', methods=['POST'])
def api_issue_cert():
    """[POST] 核發憑證。Body: {"entity_id": str, "public_key": str}"""
    data = request.get_json()
    if not data or 'entity_id' not in data or 'public_key' not in data:
        return jsonify({"status": "error", "message": "缺少 entity_id 或 public_key"}), 400
    try:
        cert_pem = issue_certificate(data['entity_id'], data['public_key'])
        return jsonify({
            "status":      "success",
            "message":     f"憑證核發成功 ({data['entity_id']})",
            "certificate": cert_pem,
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
