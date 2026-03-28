import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
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
    
    inner_payload = f"{sender_id}|{receiver_id}|{timestamp}"
    auth_signature = private_key.sign(
            inner_payload.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
            )
   
    # 回傳通用的封包格式
    return {
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "certificate": certificate,
        "timestamp": timestamp,
        "signature": auth_signature
    }

def verify_auth_component(
    expected_receiver_id: str,  # 自己的 ID (預期的接收者)
    packet_receiver_id: str,    # 封包內寫的接收者 ID
    packet_timestamp: int,      # 封包內的時間戳記
    packet_cert_pem: str,       # 封包內的發送者憑證
    packet_signature: bytes,    # 封包內的簽章
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
    if current_time - packet_timestamp > delta_t:
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

    # 4. 驗證數位簽章
    try:
        sender_public_key.verify(
            packet_signature,
            expected_payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except Exception:
        raise ValueError("數位簽章驗證錯誤 (訊息可能遭到竄改)")

    # 5. 全部驗證過關，回傳對方的公鑰
    return sender_public_key
