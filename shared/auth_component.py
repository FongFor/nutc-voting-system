<<<<<<< HEAD
import hashlib
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from flask import json
def create_auth_packet(
    sender_id: str, 
    receiver_id: str, 
    private_key, 
    certificate: str, 
) -> dict:
    """
    通用的身分認證封包產生器。
    自動產生時間戳記、組裝基礎 payload 並進行 RSA (PSS) 簽章。
    """
    timestamp = int(time.time())
    
    base_payload = f"{sender_id}|{receiver_id}|{timestamp}"

    SI = hashlib.sha256(base_payload.encode('utf-8')).hexdigest()
    #inner_payload = f"{base_payload}|{SI}" 
    data_to_sign = {
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "certificate": certificate,
        "timestamp": timestamp,
        "si": SI
    }
    json_payload = json.dumps(data_to_sign, sort_keys=True, separators=(',', ':'))
    
    signature = private_key.sign(
        json_payload.encode('utf-8'),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    
    return {
        "payload": data_to_sign,
        "signature": signature.hex()
    }

def verify_auth_component(
    expected_receiver_id: str,  # 自己的 ID (預期的接收者)
    sender_id: str,              # 需要發送者 ID 來重建 payload
    packet_receiver_id: str,    # 封包內寫的接收者 ID
    packet_timestamp: int,      # 封包內的時間戳記
    packet_cert_pem: str,       # 封包內的發送者憑證
    packet_signature: bytes,    # 封包內的簽章
    packet_si: str,              # 新增：封包內傳來的 SI
    ca_public_key,              # CA 的公鑰
    delta_t: int = 300          # 容許的時間誤差(秒)
):
    """
    通用的雙向身分認證驗證模組。
    驗證成功會回傳發送者的公鑰，失敗則拋出 ValueError。
    """
    # 1. 檢查接收者 ID
    if packet_receiver_id != expected_receiver_id:
        raise ValueError(f"接收者 ID 不符 (預期 {expected_receiver_id}，收到 {packet_receiver_id})")

    # 2. 檢查時間戳記 (防重放攻擊)
    current_time = int(time.time())
    if abs(current_time - packet_timestamp) > delta_t:
        raise ValueError("時間戳記已過期")

    # 3. 驗證發送者的 X.509 憑證
    try:
        cert = x509.load_pem_x509_certificate(packet_cert_pem.encode('utf-8'))
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        sender_public_key = cert.public_key()
    except Exception:
        raise ValueError("數位憑證無效或非由合法 CA 核發")
    # 4. 重算 SI 並驗證其正確性 (驗證 Sid|Rid|Time 的關聯)
    base_payload = f"{sender_id}|{packet_receiver_id}|{packet_timestamp}"
    calculated_si = hashlib.sha256(base_payload.encode('utf-8')).hexdigest()
    
    if calculated_si != packet_si:
        raise ValueError("SI (Hash) 驗證失敗，基礎資料不一致")
    # 5. 拼湊完整的簽署原文 {Sid|Rid|Time|SI}
    # 必須與發送端產生的 inner_payload 格式完全一致
    expected_payload = f"{base_payload}|{packet_si}"   

    # 4. 驗證數位簽章

    try:
        sender_public_key.verify(
            packet_signature,
            expected_payload.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except Exception:
        raise ValueError("數位簽章驗證錯誤 (訊息可能遭到竄改)")

    # 5. 全部驗證過關，回傳對方的公鑰
    return sender_public_key
def verify_auth_component_temp(
    expected_receiver_id: str,
    packet: dict,               # 傳入整個回傳的 dict (包含 payload 和 signature)
    sender_public_key,          # 直接傳入對方的公鑰物件 (Voter 或 TPA 的)
    delta_t: int = 300
):
    """
    跳過憑證與 CA 檢查的臨時驗證模組。
    """
    # 0. 取得內部資料
    data = packet.get("payload")
    signature_hex = packet.get("signature")

    # 1. 檢查接收者 ID (防丟錯包)
    if data['receiver_id'] != expected_receiver_id:
        raise ValueError(f"接收者 ID 不符 (預期 {expected_receiver_id}，收到 {data['receiver_id']})")

    # 2. 檢查時間戳記 (防重放攻擊)
    current_time = int(time.time())
    if abs(current_time - data['timestamp']) > delta_t:
        raise ValueError("時間戳記已過期")

    # 3. 驗證 SI (Hash) 的正確性
    # 重算 base_payload = f"{sender_id}|{receiver_id}|{timestamp}"
    base_payload = f"{data['sender_id']}|{data['receiver_id']}|{data['timestamp']}"
    calculated_si = hashlib.sha256(base_payload.encode('utf-8')).hexdigest()
    
    if calculated_si != data['si']:
        raise ValueError("SI (Hash) 驗證失敗，資料不一致")

    # 4. 核心：重建 JSON Payload 並驗證簽章
    # 必須使用與 create_auth_packet 相同的參數 (sort_keys=True)
    try:
        json_payload = json.dumps(data, sort_keys=True, separators=(',', ':'))
        
        sender_public_key.verify(
            bytes.fromhex(signature_hex), # 將 hex 轉回 bytes
            json_payload.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), 
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        raise ValueError("數位簽章驗證錯誤 (內容遭竄改或金鑰不匹配)")
=======
"""
shared/auth_component.py  —  認證封包工具

v2.0 升級：符號統一與 nonce_echo 機制

建立和驗證認證封包的函式。
封包裡包含發送方 ID、接收方 ID、時間戳、憑證和簽章，
用來做雙向身分認證，同時防止重放攻擊。

v2.0 變更：
  - si → nonce (符號統一，N_x)
  - 新增 nonce_echo 機制（回應封包需包含對方的 nonce）
  - 時間檢查改為雙向：|T_now - T| ≤ ΔT
  - 更新欄位名稱：certificate → cert_pem

v2.0 規範 §2.3, §2.4
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
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


# ==========================================
# 公開函式：建立認證封包
# ==========================================

def create_auth_packet(
    sender_id: str, 
    receiver_id: str, 
    sender_private_key, 
    certificate_pem: str,
    nonce_echo: str = None
) -> dict:
    """
    建立標準認證封包（v2.0 版本）

    v2.0 變更：
      - si → nonce (128-bit hex string)
      - 新增 nonce_echo 參數（回應封包時使用）
      - certificate → cert_pem

    參數：
        sender_id        : 發送方 ID（例如 "VOTER_001"）
        receiver_id      : 接收方 ID（例如 "TPA"）
        sender_private_key : 發送方的 RSA 私鑰物件（用於簽章）
        certificate_pem  : 發送方的 PEM 格式憑證字串
        nonce_echo       : 回應對方的 nonce（建立雙向關聯）

    回傳：
        dict，包含 payload（JSON 可序列化）與 signature（Base64 字串）
    
    v2.0 規範 §2.3, §2.4
    """
    timestamp = int(time.time())

    # 產生隨機 nonce (128-bit)，防止重放攻擊
    import secrets
    nonce = secrets.token_hex(16)  # 16 bytes = 128 bits = 32 hex chars

    # 定義 payload（所有欄位皆為 JSON 可序列化的基本型別）
    payload = {
        "sender_id":   sender_id,
        "receiver_id": receiver_id,
        "timestamp":   timestamp,
        "nonce":       nonce,
        "cert_pem":    certificate_pem,
    }
    
    # v2.0 新增：如果是回應封包，加入 nonce_echo
    if nonce_echo:
        payload["nonce_echo"] = nonce_echo

    # 將 payload 序列化為 bytes，作為簽章輸入
    payload_bytes = _serialize_payload(payload)

    # 使用 RSA-PSS 簽章（v2.0 規範 §9.4）
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
    packet_nonce: str,
    ca_public_key,
    delta_t: int = 300,
    packet_nonce_echo: str = None,
    expected_nonce_echo: str = None
):
    """
    完整驗證認證封包（v2.0 Phase 2 雙向認證）
    
    v2.0 變更：
      - 時間檢查改為雙向：|T_now - T| ≤ ΔT
      - si → nonce
      - 新增 nonce_echo 驗證
    
    驗證步驟：
      1. 確認接收方 ID 正確
      2. 檢查時間戳記（雙向 Delta T）
      3. 驗證 nonce_echo（如果是回應封包）
      4. 從 CA 憑證驗證發送方憑證合法性
      5. 從憑證提取發送方公鑰，驗證數位簽章

    v2.0 規範 §2.4, §2.5

    回傳：
        發送方公鑰物件（驗證成功）
    拋出：
        Exception（任何驗證步驟失敗）
    """
    # 步驟 1：確認接收方 ID
    if packet_receiver_id != expected_receiver_id:
        raise Exception(f"接收方 ID 不符：預期 {expected_receiver_id}，收到 {packet_receiver_id}")

    # 步驟 2：時間戳記檢查（v2.0 雙向檢查）
    current_time = int(time.time())
    time_diff = abs(current_time - packet_timestamp)
    if time_diff > delta_t:
        raise Exception(f"時間誤差超過容許範圍：{time_diff} 秒 > {delta_t} 秒")

    # 步驟 3：驗證 nonce_echo（如果是回應封包）
    if expected_nonce_echo and packet_nonce_echo != expected_nonce_echo:
        raise Exception(f"nonce_echo 不符：預期 {expected_nonce_echo}，收到 {packet_nonce_echo}")

    # 步驟 4：從 PEM 憑證載入發送方公鑰，並驗證 CA 簽章（若 ca_public_key 提供）
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import padding as _asym_padding
    cert = x509.load_pem_x509_certificate(packet_cert_pem.encode('utf-8'))
    sender_public_key = cert.public_key()

    if ca_public_key is not None:
        try:
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                _asym_padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except Exception:
            raise Exception("CERT_INVALID: 憑證未由合法 CA 簽發")

    # 步驟 5：重建 payload 並驗證簽章
    payload = {
        "sender_id":   sender_id,
        "receiver_id": packet_receiver_id,
        "timestamp":   packet_timestamp,
        "nonce":       packet_nonce,
        "cert_pem":    packet_cert_pem,
    }
    
    # 如果有 nonce_echo，加入 payload
    if packet_nonce_echo:
        payload["nonce_echo"] = packet_nonce_echo
    
    payload_bytes = _serialize_payload(payload)

    sender_public_key.verify(
        packet_signature,
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.AUTO,
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
    delta_t: int = 300,
    expected_nonce_echo: str = None
) -> bool:
    """
    簡化版驗證（v2.0 版本）
    
    不依賴 CA 憑證鏈，直接使用已知的發送方公鑰。
    適用於測試階段或已知對方公鑰的場景。

    v2.0 變更：
      - 時間檢查改為雙向
      - 新增 nonce_echo 驗證

    參數：
        expected_receiver_id : 本端的 ID（驗證封包是否發給自己）
        packet               : create_auth_packet 回傳的完整封包 dict
        sender_public_key    : 發送方的 RSA 公鑰物件
        delta_t              : 允許的時間差（秒），預設 300 秒
        expected_nonce_echo  : 預期的 nonce_echo 值（如果是回應封包）

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

    # 步驟 2：時間戳記檢查（v2.0 雙向檢查）
    current_time = int(time.time())
    time_diff = abs(current_time - payload["timestamp"])
    if time_diff > delta_t:
        raise Exception(f"時間誤差超過容許範圍：{time_diff} 秒 > {delta_t} 秒")

    # 步驟 3：驗證 nonce_echo（如果預期有）
    if expected_nonce_echo:
        packet_nonce_echo = payload.get("nonce_echo")
        if packet_nonce_echo != expected_nonce_echo:
            raise Exception(f"nonce_echo 不符：預期 {expected_nonce_echo}，收到 {packet_nonce_echo}")

    # 步驟 4：將 Base64 簽章還原為 bytes
    signature_bytes = base64.b64decode(signature_b64)

    # 步驟 5：重建 payload bytes 並驗證簽章
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
>>>>>>> Fong
