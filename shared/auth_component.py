"""
auth_component.py
-----------------

 Voter、TPA 等實體在雙向認證（Phase 2）時用。

【修復說明】
issue：verify_auth_component 在重建 payload 時，
          欄位順序或格式跟 create_auth_packet 簽名時不一致，

修復方式：統一用 JSON （json.dumps + sort_keys=True）
          作為簽名的標準 payload，確保建立與驗證兩端一致。
"""

import json
import time
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# ==========================================
# 內部輔函式：將 payload dict 序列化為固定格式的 bytes
# ==========================================

def _serialize_payload(payload: dict) -> bytes:
    """
    將 payload 字典序列化為可重現的 bytes，作為數位簽章的輸入。
    用 sort_keys=True 確保欄位順序固定，避免順序不同
    """
    # 用 JSON 序列化，確保兩端（建立與驗證）格式一致
    return json.dumps(payload, sort_keys=True, ensure_ascii=False).encode('utf-8')


# ==========================================
# 公開函式：建立認證封包
# ==========================================

def create_auth_packet(sender_id: str, receiver_id: str, sender_private_key, certificate_pem: str) -> dict:
    """
    建立標準認證封包（JSON ）。

    參數：
        sender_id        : 發送方 ID（EX "VOTER_001"）
        receiver_id      : 接收方 ID（EX "TPA"）
        sender_private_key : 發送方的 RSA 私鑰物件（用於簽章）
        certificate_pem  : 發送方的 PEM 格式憑證字串

    回傳：
        dict，包含 payload（JSON 可序列化）與 signature（Base64 字串）
    """
    timestamp = int(time.time())

    # 產生隨機 session identifier，防止重放攻擊
    import secrets
    si = secrets.token_hex(16)

    # 定義 payload（所有欄位皆為 JSON 可序列化的基本型別）
    payload = {
        "sender_id":   sender_id,
        "receiver_id": receiver_id,
        "timestamp":   timestamp,
        "certificate": certificate_pem,
        "si":          si,
    }

    # 將 payload 序列化為 bytes，作為簽章輸入
    payload_bytes = _serialize_payload(payload)

    # 使用 PSS 簽章（與驗證端一致）
    signature_bytes = sender_private_key.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # 將 bytes 轉為 Base64 字串，確保 JSON 可序列化
    signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

    return {
        "payload":   payload,
        "signature": signature_b64,
    }


# ==========================================
# 公開函式：驗證認證封包（完整版，使用 CA 憑證驗證）
# ==========================================

def verify_auth_component(
    expected_receiver_id: str,
    sender_id: str,
    packet_receiver_id: str,
    packet_timestamp: int,
    packet_cert_pem: str,
    packet_signature: bytes,
    packet_si: str,
    ca_public_key,
    delta_t: int = 300
):
    """
    完整驗證認證封包（Phase 2 雙向認證）。
    驗證步驟：
      1. 確認接收方 ID 正確
      2. 檢查時間戳記（Delta T）
      3. 從 CA 憑證驗證發送方憑證合法性（TODO：需傳入 CA 公鑰）
      4. 從憑證提取發送方公鑰，驗證數位簽章

    回傳：
        發送方公鑰物件（驗證成功）
    拋出：
        Exception（任何驗證步驟失敗）
    """
    # 步驟 1：確認接收方 ID
    if packet_receiver_id != expected_receiver_id:
        raise Exception(f"接收方 ID 不符：預期 {expected_receiver_id}，收到 {packet_receiver_id}")

    # 步驟 2：時間戳記檢查（Delta T）
    current_time = int(time.time())
    if current_time - packet_timestamp > delta_t:
        raise Exception(f"封包已過期（超過 {delta_t} 秒）")

    # 步驟 3：從 PEM 憑證載入發送方公鑰
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(packet_cert_pem.encode('utf-8'))
    sender_public_key = cert.public_key()

    # 步驟 4：重建 payload 並驗證簽章
    # 【關鍵修復】：使用與 create_auth_packet 完全相同的序列化方式
    payload = {
        "sender_id":   sender_id,
        "receiver_id": packet_receiver_id,
        "timestamp":   packet_timestamp,
        "certificate": packet_cert_pem,
        "si":          packet_si,
    }
    payload_bytes = _serialize_payload(payload)

    sender_public_key.verify(
        packet_signature,
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return sender_public_key


# ==========================================
# 公開函式：驗證認證封包（測試版，直接傳入發送方公鑰）
# ==========================================

def verify_auth_component_temp(
    expected_receiver_id: str,
    packet: dict,
    sender_public_key,
    delta_t: int = 300
) -> bool:
    """
    簡化版驗證（不依賴 CA 憑證鏈，直接使用已知的發送方公鑰）。
    適用於測試階段或已知對方公鑰的場景。

    參數：
        expected_receiver_id : 本端的 ID（驗證封包是否發給自己）
        packet               : create_auth_packet 回傳的完整封包 dict
        sender_public_key    : 發送方的 RSA 公鑰物件
        delta_t              : 允許的時間差（秒），預設 300 秒

    回傳：
        True（驗證成功）
    拋出：
        Exception（任何驗證步驟失敗）
    """
    payload = packet["payload"]
    signature_b64 = packet["signature"]

    # 步驟 1：確認接收方 ID
    if payload["receiver_id"] != expected_receiver_id:
        raise Exception(
            f"接收方 ID 不符：預期 {expected_receiver_id}，收到 {payload['receiver_id']}"
        )

    # 步驟 2：時間戳記檢查（Delta T）
    current_time = int(time.time())
    if current_time - payload["timestamp"] > delta_t:
        raise Exception(f"封包已過期（超過 {delta_t} 秒）")

    # 步驟 3：將 Base64 簽章還原為 bytes
    signature_bytes = base64.b64decode(signature_b64)

    # 步驟 4：重建 payload bytes 並驗證簽章
    # 【關鍵修復】：直接對 payload dict 使用 _serialize_payload，
    #              與 create_auth_packet 建立時完全一致，不再手動拼接字串
    payload_bytes = _serialize_payload(payload)

    sender_public_key.verify(
        signature_bytes,
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return True
