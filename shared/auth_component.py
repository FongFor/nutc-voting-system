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
      4.5. 核對憑證 Subject CN 是否與宣稱的 sender_id 一致（防止身分冒用）
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

    # 步驟 4.5：核對憑證 Subject CN 是否與宣稱的 sender_id 一致
    # 只驗證憑證合法性與簽章正確性還不夠——任何合法選民（或服務帳號）的憑證
    # 都是 CA 簽的。sender_id 只是 payload 裡的一個自由文字欄位，簽章驗證本身
    # 完全不會檢查這個欄位「講的是不是實話」，只證明「payload（不論內容為何）
    # 確實是這張憑證對應私鑰的持有人簽的」。若不額外核對憑證的 Subject CN 是
    # 否等於 sender_id，任何持有合法憑證者都能自稱是別人，冒用他人身分取得
    # 投票授權票。
    from cryptography.x509.oid import NameOID
    try:
        cert_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        cert_cn = None
    if cert_cn != sender_id:
        raise Exception(
            f"SENDER_ID_CERT_MISMATCH: 憑證身分（{cert_cn}）與宣稱之 sender_id（{sender_id}）不符"
        )

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
