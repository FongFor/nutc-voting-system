"""
shared/key_manager.py  —  金鑰管理

處理 RSA 金鑰對的生成、儲存和載入，以及向 CA 申請憑證。
各服務啟動時會呼叫這裡的函式，如果金鑰檔案已存在就直接載入，
不存在才重新生成。
"""

import os
import requests

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

from shared.crypto_generate_key_pair import generate_rsa_keypair


# ============================================================
# 金鑰讀寫輔助函式
# ============================================================

def _save_pem(path: str, data: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(data)


def _load_pem(path: str) -> str | None:
    if os.path.exists(path):
        with open(path, 'r') as f:
            return f.read()
    return None


# ============================================================
# 主要函式：載入或生成金鑰對
# ============================================================

def load_or_generate_keypair(keys_dir: str) -> tuple:
    """
    從 keys_dir 載入 RSA 金鑰對；若不存在則生成並儲存。

    回傳：(private_key, public_key, e, n, d, private_key_pem, public_key_pem)
    """
    priv_path = os.path.join(keys_dir, "private_key.pem")
    pub_path  = os.path.join(keys_dir, "public_key.pem")

    if os.path.exists(priv_path) and os.path.exists(pub_path):
        # 從磁碟載入
        with open(priv_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(pub_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())

        e = public_key.public_numbers().e
        n = public_key.public_numbers().n
        d = private_key.private_numbers().d

        private_key_pem = open(priv_path).read()
        public_key_pem  = open(pub_path).read()

        print(f"[KeyManager] 已從磁碟載入金鑰：{keys_dir}")
    else:
        # 生成新金鑰對
        private_key, public_key, e, n, d = generate_rsa_keypair()

        private_key_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode('utf-8')

        public_key_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')

        os.makedirs(keys_dir, exist_ok=True)
        _save_pem(priv_path, private_key_pem)
        _save_pem(pub_path,  public_key_pem)

        print(f"[KeyManager] 已生成並儲存新金鑰：{keys_dir}")

    return private_key, public_key, e, n, d, private_key_pem, public_key_pem


# ============================================================
# 憑證管理：向 CA 申請或從磁碟載入
# ============================================================

def load_or_request_certificate(
    keys_dir: str,
    entity_id: str,
    public_key_pem: str,
    ca_url: str,
    registration_token: str = None,
) -> str:
    """
    從 keys_dir 載入憑證；若不存在則向 CA 申請並儲存。

    registration_token：服務帳號（TPA/TA/CC）申請憑證時需附帶的一次性
    SERVICE_REGISTRATION_TOKEN（規格書 §0.5 Step 0.5、§1.4 Step 1.3）。 <3

    v4.0 新增：呼叫本函式前，呼叫端必須已經跑過 load_or_fetch_ca_cert()
    （每個服務的啟動順序皆是如此），所以這裡一定拿得到本地已快取的
    ca_cert.pem，用它驗證 CA 這一端的 TLS 伺服器憑證（ca_url 升級為
    https:// 之後，不驗證的話等於白裝了 TLS）。這個時間點本服務自己
    還沒有 TLS 用戶端憑證可以出示，所以只做伺服器端驗證，不是完整
    mTLS——這是正常的，CA 本來就不對這幾個 bootstrap 端點要求用戶端
    憑證（見 shared/tls_utils.py 的說明），身分驗證由
    SERVICE_REGISTRATION_TOKEN／OTP+PoP 負責。

    回傳：certificate PEM 字串
    """
    cert_path    = os.path.join(keys_dir, "certificate.pem")
    ca_cert_path = os.path.join(keys_dir, "ca_cert.pem")

    if os.path.exists(cert_path):
        cert_pem = open(cert_path).read()
        print(f"[KeyManager] 已從磁碟載入憑證：{cert_path}")
        return cert_pem

    # 向 CA 申請憑證
    try:
        payload = {"entity_id": entity_id, "public_key": public_key_pem}
        if registration_token:
            payload["registration_token"] = registration_token  # <3
        resp = requests.post(
            f"{ca_url}/api/issue_cert",
            json=payload,
            timeout=10,
            verify=ca_cert_path if os.path.exists(ca_cert_path) else False,  # <3 v4.0
        )
        resp.raise_for_status()
        data = resp.json()
        cert_pem = data["certificate"]
        _save_pem(cert_path, cert_pem)
        print(f"[KeyManager] 已向 CA 申請並儲存憑證：{entity_id}")
        return cert_pem
    except Exception as e:
        print(f"[KeyManager] 向 CA 申請憑證失敗：{e}")
        raise


def load_or_fetch_ca_cert(keys_dir: str, ca_url: str) -> str:
    """
    從 keys_dir 載入 CA 根憑證；若不存在則從 CA 下載並儲存。

    v4.0 新增：ca_url 升級為 https:// 之後，這裡的下載請求面臨一個
    無可避免的「先有雞還是先有蛋」問題——驗證 CA 的 TLS 伺服器憑證，
    本來就需要 CA 的根憑證，但根憑證正是這支函式要下載的東西，此刻
    本地還沒有任何材料可以驗證。這正是 v4.0 規格書第 27 章討論的
    TOFU（Trust-On-First-Use）bootstrap 問題：這一次、僅此一次的請求
    刻意不驗證伺服器身分（verify=False），下載回來的內容會被永久釘選
    （下方 os.path.exists 判斷式確保之後再也不會重新下載／覆蓋），之後
    所有對 CA 的請求都會改用這裡存下來的根憑證做驗證。降低這個 race
    window 的風險，屬於部署階段的責任（見第 27 章的縮小暴露窗口／指紋
    人工核對等緩解措施），不是這支函式能單獨解決的。

    回傳：CA certificate PEM 字串
    """
    ca_cert_path = os.path.join(keys_dir, "ca_cert.pem")

    if os.path.exists(ca_cert_path):
        ca_cert_pem = open(ca_cert_path).read()
        print(f"[KeyManager] 已從磁碟載入 CA 憑證：{ca_cert_path}")
        return ca_cert_pem

    try:
        resp = requests.get(f"{ca_url}/api/ca_cert", timeout=10, verify=False)  # <3 v4.0：見上方 TOFU 說明
        resp.raise_for_status()
        data = resp.json()
        ca_cert_pem = data["ca_certificate"]
        _save_pem(ca_cert_path, ca_cert_pem)
        print(f"[KeyManager] 已從 CA 下載並儲存根憑證")
        return ca_cert_pem
    except Exception as e:
        print(f"[KeyManager] 下載 CA 根憑證失敗：{e}")
        raise


# ============================================================
# CA 憑證驗證輔助函式
# ============================================================

def load_cert_if_exists(keys_dir: str) -> str | None:
    """
    嘗試從 keys_dir 載入憑證 PEM；若不存在則回傳 None。
    用於 Phase 0：選民可能尚未完成 OTP 註冊，不強制要求憑證存在。
    """
    cert_path = os.path.join(keys_dir, "certificate.pem")
    if os.path.exists(cert_path):
        with open(cert_path, 'r') as f:
            return f.read()
    return None


def request_certificate_with_otp(
    keys_dir: str,
    voter_id: str,
    public_key_pem: str,
    private_key,
    otp: str,
    ca_url: str,
) -> str:
    """
    Phase 0 Step 0.3：Voter 攜帶 OTP + PoP 向 CA 申請憑證。

    流程：
      1. 取得當前 timestamp
      2. 構建 challenge = "REGISTER|{voter_id}|{timestamp}"
      3. 用 SK_Voter（RSA-PSS）對 challenge 簽章 → pop_signature
      4. POST /api/issue_cert 帶 {entity_id, public_key, otp, timestamp, pop_signature}
      5. 成功則儲存 certificate.pem 並回傳

    回傳：certificate PEM 字串
    """
    import time as _time
    import base64 as _b64
    from cryptography.hazmat.primitives.asymmetric import padding as _padding
    from cryptography.hazmat.primitives import hashes as _hashes

    timestamp = int(_time.time())
    challenge = f"REGISTER|{voter_id}|{timestamp}".encode('utf-8')

    pop_sig = private_key.sign(
        challenge,
        _padding.PSS(
            mgf=_padding.MGF1(_hashes.SHA256()),
            salt_length=_padding.PSS.MAX_LENGTH,
        ),
        _hashes.SHA256(),
    )
    pop_sig_b64 = _b64.b64encode(pop_sig).decode('utf-8')

    resp = requests.post(
        f"{ca_url}/api/issue_cert",
        json={
            "entity_id":     voter_id,
            "public_key":    public_key_pem,
            "otp":           otp,
            "timestamp":     timestamp,
            "pop_signature": pop_sig_b64,
        },
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get('status') != 'success':
        code = data.get('code', 'UNKNOWN')
        msg  = data.get('message', str(data))
        raise ValueError(f"CA 拒絕申請（{code}）：{msg}")

    cert_pem = data['certificate']
    cert_path = os.path.join(keys_dir, "certificate.pem")
    os.makedirs(keys_dir, exist_ok=True)
    with open(cert_path, 'w') as f:
        f.write(cert_pem)
    print(f"[KeyManager] Phase 0 憑證已核發並儲存：{voter_id}")
    return cert_pem


def verify_cert_with_ca(cert_pem: str, ca_cert_pem: str) -> bool:
    """
    用 CA 根憑證驗證實體憑證的合法性（簽章 + 有效期）。
    回傳 True/False。
    """
    try:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode('utf-8'))
        cert    = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))

        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            return False

        return True
    except Exception:
        return False


def get_public_key_from_cert(cert_pem: str):
    """從 PEM 憑證提取公鑰物件"""
    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
    return cert.public_key()
