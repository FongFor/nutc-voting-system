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