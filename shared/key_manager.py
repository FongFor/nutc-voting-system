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
) -> str:
    """
    從 keys_dir 載入憑證；若不存在則向 CA 申請並儲存。

    回傳：certificate PEM 字串
    """
    cert_path = os.path.join(keys_dir, "certificate.pem")

    if os.path.exists(cert_path):
        cert_pem = open(cert_path).read()
        print(f"[KeyManager] 已從磁碟載入憑證：{cert_path}")
        return cert_pem

    # 向 CA 申請憑證
    try:
        resp = requests.post(
            f"{ca_url}/api/issue_cert",
            json={"entity_id": entity_id, "public_key": public_key_pem},
            timeout=10,
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

    回傳：CA certificate PEM 字串
    """
    ca_cert_path = os.path.join(keys_dir, "ca_cert.pem")

    if os.path.exists(ca_cert_path):
        ca_cert_pem = open(ca_cert_path).read()
        print(f"[KeyManager] 已從磁碟載入 CA 憑證：{ca_cert_path}")
        return ca_cert_pem

    try:
        resp = requests.get(f"{ca_url}/api/ca_cert", timeout=10)
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
