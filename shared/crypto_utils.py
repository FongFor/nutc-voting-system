"""
shared/crypto_utils.py  —  加密工具

v2.0 升級：AES-GCM (AEAD) 取代 AES-CFB

數位信封的封裝和解封函式。
投票時用 CC 的公鑰加密對稱金鑰，再用對稱金鑰加密選票內容，
這樣 CC 在截止前就算收到信封也看不到選票。

v2.0 變更：
  - AES-CFB → AES-256-GCM (AEAD)
  - 新增 AAD (Additional Authenticated Data) 綁定 ID_Voter 與 SN
  - 新增 token_hash 欄位
  - IV 從 16 bytes 改為 12 bytes (GCM 標準)
  - 新增 Tag (16 bytes) 認證碼

v2.0 規範 §9.6, §3.4
"""

import os
import json
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from shared.format_utils import sha256_hex, bytes_to_b64, b64_to_bytes


def encapsulate_vote(
    voter_id: str,
    sn: str,
    vote_content: str,
    s_prime_hex: str,
    m_hex: str,
    cc_public_key_pem: str,
    ta_public_key_pem: str,
    token_id: str = None,
) -> dict:
    """
    建立數位信封 (v2.0 AES-GCM 版本)

    v2.0 規範：P = (C_Data, IV, Tag, AAD, C_Key, token_hash)
      C_Data = AES-GCM-Enc_k(AAD, IV, plaintext) → (ciphertext, tag)
      C_Key  = E_PK_CC(k)
      AAD    = "voting-system-v2|" || ID_Voter || "|" || SN
      token_hash = H(token_id)

    流程：
      1. 計算內層明文雜湊：hash_inner = H(ID || "|" || SN || "|" || Vote)
      2. 用 TA 公鑰加密 (hash_inner || "|" || Vote) → inner_enc（Base64）
      3. 組合 AES 明文：inner_enc_b64 | S'(hex) | m(hex)
      4. 生成隨機 AES-256 金鑰 k 和 IV (12 bytes)
      5. 構造 AAD = "voting-system-v2|" || ID_Voter || "|" || SN
      6. AES-256-GCM 加密 → (C_Data, Tag)
      7. 用 CC 公鑰加密 k → C_Key
      8. 計算 token_hash = H(token_id)

    v2.0 規範 §3.4, §9.6

    回傳：dict（所有 bytes 均以 Base64 表示）
    """
    cc_pub_key = serialization.load_pem_public_key(cc_public_key_pem.encode('utf-8'))
    ta_pub_key = serialization.load_pem_public_key(ta_public_key_pem.encode('utf-8'))

    # 步驟 1：計算內層雜湊 H(ID || "|" || SN || "|" || Vote)
    hash_inner = sha256_hex(f"{voter_id}|{sn}|{vote_content}".encode('utf-8'))

    # 步驟 2：用 TA 公鑰加密 (hash_inner || "|" || Vote)
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

    # 步驟 4：生成隨機 AES-256 金鑰 k 和 IV (12 bytes for GCM)
    k = os.urandom(32)  # 256-bit key
    iv = os.urandom(12)  # 96-bit nonce (GCM 標準)

    # 步驟 5：構造 AAD (Additional Authenticated Data)
    # AAD = "voting-system-v2|" || ID_Voter || "|" || SN
    aad = f"voting-system-v2|{voter_id}|{sn}".encode('utf-8')

    # 步驟 6：AES-256-GCM 加密
    aesgcm = AESGCM(k)
    # GCM encrypt 回傳 ciphertext + tag (16 bytes) 連接在一起
    c_data_with_tag = aesgcm.encrypt(iv, aes_plaintext, aad)
    
    # 分離 ciphertext 和 tag
    c_data_bytes = c_data_with_tag[:-16]  # 密文
    tag_bytes = c_data_with_tag[-16:]      # 認證碼 (16 bytes)

    # 步驟 7：用 CC 公鑰加密 k → C_Key
    c_key_bytes = cc_pub_key.encrypt(
        k,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 步驟 8：計算 token_hash = H(token_id)
    token_hash = ""
    if token_id:
        h = hashlib.sha256()
        h.update(token_id.encode('utf-8'))
        token_hash = h.hexdigest()

    return {
        "c_data":     bytes_to_b64(c_data_bytes),
        "iv":         bytes_to_b64(iv),
        "tag":        bytes_to_b64(tag_bytes),
        "aad":        bytes_to_b64(aad),
        "c_key":      bytes_to_b64(c_key_bytes),
        "token_hash": token_hash,
    }


def open_envelope_layer1(envelope: dict, cc_private_key) -> dict:
    """
    Phase 3（CC 接收時）：用 SK_CC 解密 C_Key 取得對稱金鑰 k。
    回傳含 k（Base64）的暫存記錄，等待 TA 私鑰後再解密驗證。
    
    v2.0 變更：新增 tag 和 aad 欄位
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
        "tag":    envelope.get("tag", ""),      # v2.0 新增
        "aad":    envelope.get("aad", ""),      # v2.0 新增
        "k":      bytes_to_b64(k),
    }


def open_envelope_layer2(pending: dict, ta_private_key, tpa_e: int, tpa_n: int) -> dict:
    """
    Phase 5（CC 開票時）：用 k 解密 C_Data，再用 SK_TA 解開內層，驗證選票。

    v2.0 規範驗證流程：
      1. 用 k 和 AAD 解密 C_Data (AES-GCM)，驗證 Tag
      2. 用 SK_TA 解開內層 E_PK_TA(...)，取得 (hash_inner | vote_content)
      3. 重新計算 m_check = H(hash_inner || "|" || vote_content)，與外層 m 比對
      4. 驗證 TPA 盲簽章：(S')^e ≡ FDH(m) (mod n)  [v2.0 使用 FDH]

    v2.0 規範 §4.4

    回傳：{"vote": str, "m_hex": str} 或拋出 Exception
    """
    from shared.blind_signature import verify_blind_signature
    from shared.format_utils import hex_to_int

    # 步驟 1：用 k 解密 C_Data (AES-GCM)
    k = b64_to_bytes(pending["k"])
    c_data = b64_to_bytes(pending["c_data"])
    iv = b64_to_bytes(pending["iv"])
    tag = b64_to_bytes(pending.get("tag", ""))
    aad = b64_to_bytes(pending.get("aad", ""))

    # AES-GCM 解密（需要 tag 驗證）
    aesgcm = AESGCM(k)
    try:
        # GCM decrypt 需要 ciphertext + tag
        c_data_with_tag = c_data + tag
        aes_plaintext = aesgcm.decrypt(iv, c_data_with_tag, aad)
    except Exception as e:
        raise ValueError(f"AES-GCM 認證失敗（Tag 驗證失敗）: {e}")

    # 解析 AES 明文：inner_enc_b64 | S'_hex | m_hex
    parts = aes_plaintext.decode('utf-8').split("|", 2)
    if len(parts) != 3:
        raise ValueError("AES 明文格式錯誤")
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
    if len(inner_parts) != 2:
        raise ValueError("內層明文格式錯誤")
    hash_inner_from_env = inner_parts[0]
    vote_content        = inner_parts[1]

    # 步驟 3：重新計算 m_check = H(hash_inner || "|" || vote_content)
    m_check_hex = sha256_hex(f"{hash_inner_from_env}|{vote_content}".encode('utf-8'))
    m_check_int = int(m_check_hex, 16)
    m_int       = hex_to_int(m_hex)

    if m_check_int != m_int:
        raise ValueError("雜湊比對失敗（m 不一致）")

    # 步驟 4：驗證 TPA 盲簽章 (v2.0 使用 FDH)
    # verify_blind_signature 現在接受 bytes 並內部計算 FDH
    # m_hex 可能含 "0x" 前綴（int_to_hex 的設計），bytes.fromhex 不接受 0x 前綴
    s_prime_int = hex_to_int(s_prime_hex)
    m_hex_clean = m_hex[2:] if m_hex.startswith(("0x", "0X")) else m_hex
    m_bytes = bytes.fromhex(m_hex_clean)
    if not verify_blind_signature(s_prime_int, tpa_e, tpa_n, m_bytes):
        raise ValueError("盲簽章驗證失敗（FDH 驗證不通過）")

    # 統一去除 0x 前綴，與 Merkle Proof 查詢格式一致
    m_hex_out = m_hex[2:] if m_hex.startswith(("0x", "0X")) else m_hex
    return {"vote": vote_content, "m_hex": m_hex_out}


def sign_data(data: bytes, private_key) -> bytes:
    """
    使用 RSA-PSS 對資料進行數位簽章
    
    v2.0 規範 §9.4：
      - RSA-2048
      - MGF1+SHA-256
      - salt_length: 32 bytes (PSS.MAX_LENGTH)
      - hash: SHA-256
    
    參數：
      data: 要簽章的資料（bytes）
      private_key: RSA 私鑰物件
    
    回傳：簽章（bytes）
    """
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,  # 32 bytes
        ),
        hashes.SHA256(),
    )
    return signature


def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    """
    使用 RSA-PSS 驗證數位簽章
    
    v2.0 規範 §9.4
    
    參數：
      data: 原始資料（bytes）
      signature: 簽章（bytes）
      public_key: RSA 公鑰物件
    
    回傳：True 表示驗證通過，False 表示驗證失敗
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
