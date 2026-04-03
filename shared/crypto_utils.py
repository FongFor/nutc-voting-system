"""
shared/crypto_utils.py  —  加密工具

數位信封的封裝和解封函式。
投票時用 CC 的公鑰加密對稱金鑰，再用對稱金鑰加密選票內容，
這樣 CC 在截止前就算收到信封也看不到選票。
"""

import os
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from shared.format_utils import sha256_hex, bytes_to_b64, b64_to_bytes


def encapsulate_vote(
    voter_id: str,
    sn: str,
    vote_content: str,
    s_prime_hex: str,
    m_hex: str,
    cc_public_key_pem: str,
    ta_public_key_pem: str,
) -> dict:
    """
    建立數位信封。

    規範：P = (C_Data || C_Key)
      C_Data = E_k( E_PK_TA(H(ID||SN||Vote) || Vote), S', m )
      C_Key  = E_PK_CC(k)

    流程：
      1. 計算內層明文雜湊：hash_inner = H(ID || SN || Vote)
      2. 用 TA 公鑰加密 (hash_inner || Vote) → inner_enc（Base64）
      3. 組合 AES 明文：inner_enc_b64 | S'(hex) | m(hex)
      4. 生成隨機 AES-256 金鑰 k，AES-CFB 加密 → C_Data
      5. 用 CC 公鑰加密 k → C_Key

    回傳：dict（所有 bytes 均以 Base64 表示）
    """
    cc_pub_key = serialization.load_pem_public_key(cc_public_key_pem.encode('utf-8'))
    ta_pub_key = serialization.load_pem_public_key(ta_public_key_pem.encode('utf-8'))

    # 步驟 1：計算內層雜湊 H(ID || SN || Vote)
    hash_inner = sha256_hex(f"{voter_id}|{sn}|{vote_content}".encode('utf-8'))

    # 步驟 2：用 TA 公鑰加密 (hash_inner || Vote)
    inner_plaintext = f"{hash_inner}|{vote_content}".encode('utf-8')
    inner_enc = ta_pub_key.encrypt(
        inner_plaintext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    inner_enc_b64 = bytes_to_b64(inner_enc)

    # 步驟 3：組合 AES 明文：E_PK_TA(...)(Base64) | S'(hex) | m(hex)
    aes_plaintext = f"{inner_enc_b64}|{s_prime_hex}|{m_hex}".encode('utf-8')

    # 步驟 4：生成隨機 AES-256 金鑰 k，AES-CFB 加密
    k = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(k), modes.CFB(iv))
    encryptor = cipher.encryptor()
    c_data_bytes = encryptor.update(aes_plaintext) + encryptor.finalize()

    # 步驟 5：用 CC 公鑰加密 k → C_Key
    c_key_bytes = cc_pub_key.encrypt(
        k,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "c_data": bytes_to_b64(c_data_bytes),
        "iv":     bytes_to_b64(iv),
        "c_key":  bytes_to_b64(c_key_bytes),
    }


def open_envelope_layer1(envelope: dict, cc_private_key) -> dict:
    """
    Phase 3（CC 接收時）：用 SK_CC 解密 C_Key 取得對稱金鑰 k。
    回傳含 k（Base64）的暫存記錄，等待 TA 私鑰後再解密驗證。
    """
    c_key = b64_to_bytes(envelope["c_key"])
    k = cc_private_key.decrypt(
        c_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return {
        "c_data": envelope["c_data"],
        "iv":     envelope["iv"],
        "k":      bytes_to_b64(k),
    }


def open_envelope_layer2(pending: dict, ta_private_key, tpa_e: int, tpa_n: int) -> dict:
    """
    Phase 5（CC 開票時）：用 k 解密 C_Data，再用 SK_TA 解開內層，驗證選票。

    規範驗證流程：
      1. 用 k 解密 C_Data，取得 (inner_enc_b64 | S'_hex | m_hex)
      2. 用 SK_TA 解開內層 E_PK_TA(...)，取得 (hash_inner | vote_content)
      3. 重新計算 m_check = H(hash_inner || vote_content)，與外層 m 比對
      4. 驗證 TPA 盲簽章：S'^e ≡ m (mod n)

    回傳：{"vote": str, "m_hex": str} 或拋出 Exception
    """
    from shared.crypto_utils_test import verify_blind_signature
    from shared.format_utils import hex_to_int

    # 步驟 1：用 k 解密 C_Data
    k = b64_to_bytes(pending["k"])
    c_data = b64_to_bytes(pending["c_data"])
    iv = b64_to_bytes(pending["iv"])
    cipher = Cipher(algorithms.AES(k), modes.CFB(iv))
    decryptor = cipher.decryptor()
    aes_plaintext = decryptor.update(c_data) + decryptor.finalize()

    # 解析 AES 明文：inner_enc_b64 | S'_hex | m_hex
    parts = aes_plaintext.decode('utf-8').split("|", 2)
    inner_enc_b64 = parts[0]
    s_prime_hex   = parts[1]
    m_hex         = parts[2]

    # 步驟 2：用 SK_TA 解開內層 E_PK_TA(hash_inner | vote_content)
    inner_enc = b64_to_bytes(inner_enc_b64)
    inner_plaintext = ta_private_key.decrypt(
        inner_enc,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    inner_parts = inner_plaintext.decode('utf-8').split("|", 1)
    hash_inner_from_env = inner_parts[0]
    vote_content        = inner_parts[1]

    # 步驟 3：重新計算 m_check = H(hash_inner || vote_content)
    m_check_hex = sha256_hex(f"{hash_inner_from_env}|{vote_content}".encode('utf-8'))
    m_check_int = int(m_check_hex, 16)
    m_int       = hex_to_int(m_hex)

    if m_check_int != m_int:
        raise ValueError("雜湊比對失敗（m 不一致）")

    # 步驟 4：驗證 TPA 盲簽章 S'^e ≡ m (mod n)
    s_prime_int = hex_to_int(s_prime_hex)
    if not verify_blind_signature(s_prime_int, tpa_e, tpa_n, m_int):
        raise ValueError("盲簽章驗證失敗")

    return {"vote": vote_content, "m_hex": m_hex}
