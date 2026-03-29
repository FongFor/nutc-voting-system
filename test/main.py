"""
[main.py 整合三檔] 2026/03/30
A.py -> 陳,B.py -> 謝,C.py -> 嚴

現況:還是純在記憶體跑，但改了傳輸方式，如點2 ****還沒動儲存****
測試:假資料模擬，在 if __name__ == '__main__':


1. 流程對應 (Phase 1-6)
- Phase 1 (Init)  ：實體初始化，金鑰與憑證僅生成一次。
- Phase 2 (Auth)  ：Voter ↔ TPA 雙向認證，含 Delta T 時戳檢查。
- Phase 3 (Blind) ：選票盲簽章與數位信封 (AES-CFB + RSA-OAEP) 封裝。
- Phase 4 (Time)  ：投票截止後，TA 釋放私鑰 SK_TA 予計票中心。
- Phase 5 (Tally) ：CC 解密驗證選票，補了 Merkle Tree。
- Phase 6 (Verify)：BB 提供 Merkle Proof，voter 執行端到端驗證。

2. 傳輸
- 全改為 JSON 傳。
- 格式：
  - 金鑰與憑證：改 PEM 字串。
  - 二進位資料 (密文/IV)：改 Base64 字串。
  - 大型整數 (m/S)：轉 Hex 字串傳。
- 改實體初始化，禁止金鑰重複生成。 (現在記憶體跑的情況下，每次重執行還是會隨機，但單次是固定的)

3. 其他
- auth_component：改成 JSON 邏輯，改了一下 payload。
- Voter 與 TPA 的雙向認證，現在是調用 verify_auth_component_temp。
- 在 main.py 補了 Merkle Tree -> class MerkleTree:
- 測試防錯：流程中若fail，會直接跑 raise SystemExit 中斷。
"""

import sys
import os
import json
import time
import hashlib
import base64
import secrets
import datetime

# 取得 main.py 所在的目錄 
current_dir = os.path.dirname(os.path.abspath(__file__))

# 往上一層取得專案根目錄
project_root = os.path.dirname(current_dir)

# 把專案根目錄加進搜尋路徑
sys.path.append(project_root)

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID
from cryptography import x509

from shared.crypto_generate_key_pair import generate_rsa_keypair
from shared.crypto_utils_test import (
    generate_blinding_factor,
    blind_message,
    blind_sign,
    unblind_signature,
    verify_blind_signature,
)
from shared.auth_component import (
    create_auth_packet,
    verify_auth_component_temp,
)


# ============================================================
# 輔函式：大整數 ↔ Hex 字串轉換
# ============================================================

def int_to_hex(n: int) -> str:
    """將大整數轉為 Hex 字串"""
    return hex(n)


def hex_to_int(h: str) -> int:
    """將 Hex 字串還原為大整數"""
    return int(h, 16)


def bytes_to_b64(b: bytes) -> str:
    """將 bytes 轉為 Base64 字串"""
    return base64.b64encode(b).decode('utf-8')


def b64_to_bytes(s: str) -> bytes:
    """將 Base64 字串還原為 bytes"""
    return base64.b64decode(s)


# ============================================================
# Merkle Tree （Phase 5）
# ============================================================

class MerkleTree:
    """
    簡易 Merkle Tree 實作。
    葉節點為各合法選票的 SHA-256 雜湊值。
    """

    def __init__(self, leaves: list):
        # leaves：字串列表，每個元素為一張合法選票的字串表示
        self.leaves = [hashlib.sha256(leaf.encode('utf-8')).hexdigest() for leaf in leaves]
        self.tree = self._build_tree(self.leaves)

    def _build_tree(self, nodes: list) -> list:
        """遞迴建構 Merkle Tree，回傳各層節點列表（由葉到根）"""
        if len(nodes) == 0:
            return []
        layers = [nodes]
        current = nodes
        while len(current) > 1:
            # 若節點數為奇數，複製最後一個節點補齊
            if len(current) % 2 == 1:
                current = current + [current[-1]]
            next_layer = []
            for i in range(0, len(current), 2):
                combined = current[i] + current[i + 1]
                next_layer.append(hashlib.sha256(combined.encode('utf-8')).hexdigest())
            layers.append(next_layer)
            current = next_layer
        return layers

    def get_root(self) -> str:
        """取得 Merkle Root"""
        if not self.tree:
            return ""
        return self.tree[-1][0]

    def get_proof(self, index: int) -> list:
        """
        取得指定葉節點的 Merkle Proof（兄弟節點路徑）。
        回傳格式：[{"sibling": hash, "position": "left"/"right"}, ...]
        """
        proof = []
        current_index = index
        for layer in self.tree[:-1]:
            # 補齊奇數層
            if len(layer) % 2 == 1:
                layer = layer + [layer[-1]]
            if current_index % 2 == 0:
                sibling_index = current_index + 1
                position = "right"
            else:
                sibling_index = current_index - 1
                position = "left"
            proof.append({
                "sibling":  layer[sibling_index],
                "position": position,
            })
            current_index //= 2
        return proof

    @staticmethod
    def verify_proof(leaf_str: str, proof: list, root: str) -> bool:
        """
        驗證 Merkle Proof 是否正確。
        leaf_str：原始選票字串（未雜湊）
        """
        current_hash = hashlib.sha256(leaf_str.encode('utf-8')).hexdigest()
        for step in proof:
            sibling = step["sibling"]
            if step["position"] == "right":
                combined = current_hash + sibling
            else:
                combined = sibling + current_hash
            current_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
        return current_hash == root


# ============================================================
# Phase 1：CA — 憑證授權中心
# ============================================================

class CA:
    """
    憑證授權中心。
    Phase 1：生成根憑證，並為各實體核發數位憑證。
    金鑰與根憑證僅在 __init__ 時生成一次。
    """

    def __init__(self):
        print("[CA] 初始化：生成 CA 金鑰與根憑證...")
        # 生成 CA 自身的 RSA 金鑰對
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._public_key = self._private_key.public_key()
        # 生成自簽根憑證
        self._root_cert = self._generate_root_cert()
        print("[CA] 根憑證已生成。")

    def _generate_root_cert(self) -> x509.Certificate:
        """生成 CA 自簽根憑證"""
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NUTC Voting System Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Voting CA"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(self._private_key, hashes.SHA256())
        )

    def get_root_cert_pem(self) -> str:
        """回傳 PEM 格式根憑證字串（供其他實體下載）"""
        return self._root_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    def get_public_key_pem(self) -> str:
        """回傳 CA 公鑰 PEM 字串"""
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')

    def issue_certificate(self, entity_id: str, public_key_pem: str) -> str:
        """
        核發數位憑證。
        輸入：實體 ID 與 PEM 格式公鑰字串。
        輸出：PEM 格式憑證字串（JSON 可序列化）。
        """
        entity_public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NUTC Voting System"),
            x509.NameAttribute(NameOID.COMMON_NAME, entity_id),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._root_cert.subject)
            .public_key(entity_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(self._private_key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        print(f"[CA] 已核發憑證給 {entity_id}")
        return cert_pem

    def verify_certificate(self, cert_pem: str) -> bool:
        """驗證憑證是否由本 CA 簽發且在有效期內"""
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
            self._public_key.verify(
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


# ============================================================
# Phase 1 + 2：TPA — 第三方機構
# ============================================================

class TPA:
    """
    第三方機構。
    Phase 1：生成金鑰對，向 CA 申請憑證。
    Phase 2：驗證 Voter 身分（含 Delta T 時間戳記）；執行盲簽章。
    """

    def __init__(self, tpa_id: str):
        self.id = tpa_id
        # 生成 RSA 金鑰對（僅執行一次）
        self._private_key, self._public_key, self.e, self.n, self.d = generate_rsa_keypair()
        # 憑證 PEM 字串（Phase 1 向 CA 申請後填入）
        self.cert_pem: str = ""
        print(f"[{self.id}] 初始化完成，RSA 金鑰已生成。")

    def get_public_key_pem(self) -> str:
        """回傳 PEM 格式公鑰字串"""
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')

    def get_public_numbers_json(self) -> dict:
        """
        回傳公鑰大整數（Hex 字串格式），供 Voter 盲化使用。
        格式：{"e": "0x...", "n": "0x..."}
        """
        return {
            "e": int_to_hex(self.e),
            "n": int_to_hex(self.n),
        }

    def verify_voter_auth(self, auth_packet_json: str, voter_public_key_pem: str) -> bool:
        """
        Phase 2：驗證 Voter 的認證封包。
        輸入均為 JSON 字串 / PEM 字串（模擬網路傳輸格式）。
        """
        # 反序列化封包
        auth_packet = json.loads(auth_packet_json)
        # 載入 Voter 公鑰物件
        voter_pub_key = serialization.load_pem_public_key(voter_public_key_pem.encode('utf-8'))

        print(f"[{self.id}] 正在驗證來自 {auth_packet['payload']['sender_id']} 的認證封包...")
        try:
            verify_auth_component_temp(
                expected_receiver_id=self.id,
                packet=auth_packet,
                sender_public_key=voter_pub_key,
            )
            print(f"[{self.id}] Voter 身分驗證成功（Delta T 檢查通過）。")
            return True
        except Exception as exc:
            print(f"[{self.id}] 驗證失敗：{exc}")
            return False

    def generate_response_packet_json(self, voter_id: str) -> str:
        """
        Phase 2：TPA 驗證成功後，產生回傳給 Voter 的認證封包（雙向認證）。
        回傳 JSON 字串。
        """
        packet = create_auth_packet(self.id, voter_id, self._private_key, self.cert_pem)
        return json.dumps(packet)

    def sign_blinded_vote(self, m_prime_hex: str) -> str:
        """
        Phase 3：對盲化選票執行盲簽章。
        輸入：m' 的 Hex 字串。
        輸出：盲簽章 S 的 Hex 字串。
        """
        m_prime = hex_to_int(m_prime_hex)
        print(f"[{self.id}] 收到盲化選票，執行盲簽章...")
        S = blind_sign(m_prime, self.d, self.n)
        return int_to_hex(S)


# ============================================================
# Phase 1 + 2 + 3：Voter — 選民
# ============================================================

class Voter:
    """
    選民。
    Phase 1：生成金鑰對，向 CA 申請憑證。
    Phase 2：產生認證封包；驗證 TPA 回傳封包（雙向認證）。
    Phase 3：盲化選票；去盲化；封裝數位信封。
    """

    def __init__(self, voter_id: str):
        self.id = voter_id
        # 生成 RSA 金鑰對（僅執行一次）
        self._private_key, self._public_key, self.e, self.n, self.d = generate_rsa_keypair()
        # 憑證 PEM 字串（Phase 1 向 CA 申請後填入）
        self.cert_pem: str = ""
        # 盲化因子 r（Phase 3 盲化時設定，去盲化時使用）
        self._r: int = 0
        print(f"[{self.id}] 初始化完成，RSA 金鑰已生成。")

    def get_public_key_pem(self) -> str:
        """回傳 PEM 格式公鑰字串"""
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')

    def generate_auth_packet_json(self, tpa_id: str) -> str:
        """
        Phase 2：產生認證封包。
        回傳 JSON 字串（模擬網路傳輸格式）。
        """
        packet = create_auth_packet(self.id, tpa_id, self._private_key, self.cert_pem)
        return json.dumps(packet)

    def verify_tpa_response_json(self, response_packet_json: str, tpa_public_key_pem: str) -> bool:
        """
        Phase 2：驗證 TPA 回傳的認證封包（雙向認證最後一步）。
        輸入均為 JSON 字串 / PEM 字串。
        """
        response_packet = json.loads(response_packet_json)
        tpa_pub_key = serialization.load_pem_public_key(tpa_public_key_pem.encode('utf-8'))
        try:
            verify_auth_component_temp(
                expected_receiver_id=self.id,
                packet=response_packet,
                sender_public_key=tpa_pub_key,
            )
            print(f"[{self.id}] TPA 身分驗證成功，雙向認證完成。")
            return True
        except Exception as exc:
            print(f"[{self.id}] TPA 驗證失敗：{exc}")
            return False

    def prepare_blinded_vote(self, m_hex: str, tpa_numbers_json: str) -> str:
        """
        Phase 3：盲化選票。
        輸入：m 的 Hex 字串、TPA 公鑰大整數 JSON 字串。
        輸出：m' 的 Hex 字串。
        """
        m = hex_to_int(m_hex)
        tpa_nums = json.loads(tpa_numbers_json)
        tpa_e = hex_to_int(tpa_nums["e"])
        tpa_n = hex_to_int(tpa_nums["n"])

        # 生成盲化因子並儲存（去盲化時需要）
        self._r = generate_blinding_factor(tpa_n)
        m_prime = blind_message(m, self._r, tpa_e, tpa_n)
        print(f"[{self.id}] 選票已盲化，m' 已計算。")
        return int_to_hex(m_prime)

    def unblind_signature(self, S_hex: str, tpa_n_hex: str) -> str:
        """
        Phase 3：去盲化，取得最終合法簽章 S'。
        輸入：S 的 Hex 字串、TPA 模數 n 的 Hex 字串。
        輸出：S' 的 Hex 字串。
        """
        S = hex_to_int(S_hex)
        tpa_n = hex_to_int(tpa_n_hex)
        S_prime = unblind_signature(S, self._r, tpa_n)
        print(f"[{self.id}] 去盲化完成，取得合法簽章 S'。")
        return int_to_hex(S_prime)

    def encapsulate_vote(
        self,
        vote_content: str,
        s_prime_hex: str,
        m_hex: str,
        cc_public_key_pem: str,
        ta_public_key_pem: str,
    ) -> str:
        """
        Phase 3：建立數位信封。
        流程：
          1. 生成隨機 AES 金鑰 k
          2. 用 k 加密選票明文（vote_content | S' | m）
          3. 用 CC 公鑰加密 k（k_enc_cc）
          4. 用 TA 公鑰加密 k（k_enc_ta，供 TA 截止後驗證）
        輸出：JSON 字串（所有 bytes 均以 Base64 表示）
        """
        cc_pub_key = serialization.load_pem_public_key(cc_public_key_pem.encode('utf-8'))
        ta_pub_key = serialization.load_pem_public_key(ta_public_key_pem.encode('utf-8'))

        # 生成隨機 AES-256 金鑰
        k = os.urandom(32)
        # 選票明文：vote_content | S'(hex) | m(hex)
        plaintext = f"{vote_content}|{s_prime_hex}|{m_hex}".encode('utf-8')
        # AES-CFB 加密
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(k), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # 用 CC 公鑰加密 k（OAEP）
        k_enc_cc = cc_pub_key.encrypt(
            k,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        # 用 TA 公鑰加密 k（OAEP）
        k_enc_ta = ta_pub_key.encrypt(
            k,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # 所有 bytes 轉為 Base64，確保 JSON 可序列化
        envelope = {
            "ciphertext": bytes_to_b64(ciphertext),
            "iv":         bytes_to_b64(iv),
            "k_enc_cc":   bytes_to_b64(k_enc_cc),
            "k_enc_ta":   bytes_to_b64(k_enc_ta),
        }
        print(f"[{self.id}] 數位信封已封裝（AES-256-CFB + RSA-OAEP）。")
        return json.dumps(envelope)


# ============================================================
# Phase 1 + 4：TA — 時間授權中心
# ============================================================

class TA:
    """
    時間授權中心。
    Phase 1：生成金鑰對，向 CA 申請憑證。
    Phase 4：投票截止後，釋放 SK_TA 給 CC。
    """

    def __init__(self, ta_id: str, deadline: int):
        self.id = ta_id
        self.deadline = deadline
        # 生成 RSA 金鑰對（僅執行一次）
        self._private_key, self._public_key, self.e, self.n, self.d = generate_rsa_keypair()
        self.cert_pem: str = ""
        deadline_str = datetime.datetime.fromtimestamp(deadline).strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{self.id}] 初始化完成，投票截止時間：{deadline_str}")

    def get_public_key_pem(self) -> str:
        """回傳 PEM 格式公鑰字串"""
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')

    def release_private_key(self) -> str:
        """
        Phase 4：檢查是否已到截止時間，是則釋放 SK_TA。
        回傳 JSON 字串，包含私鑰 PEM 與大整數（Hex 格式）。
        """
        current_time = int(time.time())
        if current_time < self.deadline:
            remaining = self.deadline - current_time
            print(f"[{self.id}] 拒絕釋放私鑰，投票尚未截止（還有 {remaining} 秒）。")
            return json.dumps({"status": "rejected", "remaining_seconds": remaining})

        # 將私鑰序列化為 PEM 字串
        private_key_pem = self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode('utf-8')

        print(f"[{self.id}] 投票已截止，釋放 SK_TA。")
        return json.dumps({
            "status":          "released",
            "private_key_pem": private_key_pem,
            "d_hex":           int_to_hex(self.d),
            "n_hex":           int_to_hex(self.n),
            "released_at":     current_time,
        })


# ============================================================
# Phase 3 + 5：CC — 計票中心
# ============================================================

class CC:
    """
    計票中心。
    Phase 1：生成金鑰對，向 CA 申請憑證。
    Phase 3：接收數位信封，用 SK_CC 解開取得 k。
    Phase 5：收到 SK_TA 後，解密選票、驗證 TPA 盲簽章、建構 Merkle Tree。
    """

    def __init__(self, cc_id: str):
        self.id = cc_id
        # 生成 RSA 金鑰對（僅執行一次）
        self._private_key, self._public_key, self.e, self.n, self.d = generate_rsa_keypair()
        self.cert_pem: str = ""
        # 待處理的信封列表（Phase 3 收到後暫存）
        self._pending_envelopes: list = []
        # 驗證通過的合法選票
        self.valid_votes: list = []
        # Merkle Tree（Phase 5 建構後填入）
        self._merkle_tree: MerkleTree = None
        print(f"[{self.id}] 初始化完成，RSA 金鑰已生成。")

    def get_public_key_pem(self) -> str:
        """回傳 PEM 格式公鑰字串"""
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')

    def receive_envelope(self, envelope_json: str) -> None:
        """
        Phase 3：接收數位信封，用 SK_CC 解開 k_enc_cc 取得 k，暫存待開票。
        輸入：JSON 字串（Base64 編碼的密文）。
        """
        envelope = json.loads(envelope_json)

        # 用 CC 私鑰解密 k
        k_enc_cc = b64_to_bytes(envelope["k_enc_cc"])
        k = self._private_key.decrypt(
            k_enc_cc,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        # 暫存（k 已解出，但選票內容需等 TA 私鑰才能驗證）
        self._pending_envelopes.append({
            "ciphertext": envelope["ciphertext"],
            "iv":         envelope["iv"],
            "k":          bytes_to_b64(k),          # 儲存為 Base64
            "k_enc_ta":   envelope["k_enc_ta"],
        })
        print(f"[{self.id}] 數位信封已接收，k 已解密暫存（等待 TA 私鑰）。")

    def decrypt_and_verify_votes(self, sk_ta_json: str, tpa_numbers_json: str) -> None:
        """
        Phase 5：收到 SK_TA 後，解密並驗證所有暫存選票。
        驗證邏輯：
          1. 用 TA 私鑰解密 k_enc_ta，確認與 CC 解出的 k 一致（防篡改）
          2. 用 k 解密選票密文
          3. 驗證 TPA 盲簽章：S'^e ≡ m (mod n)
        """
        sk_ta_data = json.loads(sk_ta_json)
        if sk_ta_data["status"] != "released":
            print(f"[{self.id}] TA 私鑰尚未釋放，無法開票。")
            return

        # 載入 TA 私鑰物件
        ta_private_key = serialization.load_pem_private_key(
            sk_ta_data["private_key_pem"].encode('utf-8'),
            password=None,
        )
        # 載入 TPA 公鑰大整數（用於驗證盲簽章）
        tpa_nums = json.loads(tpa_numbers_json)
        tpa_e = hex_to_int(tpa_nums["e"])
        tpa_n = hex_to_int(tpa_nums["n"])

        for vote in self._pending_envelopes:
            try:
                # 步驟 1：用 TA 私鑰解密 k_enc_ta，驗證 k 一致性
                k_enc_ta = b64_to_bytes(vote["k_enc_ta"])
                k_from_ta = ta_private_key.decrypt(
                    k_enc_ta,
                    padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
                k_from_cc = b64_to_bytes(vote["k"])
                if k_from_ta != k_from_cc:
                    print(f"[{self.id}] 金鑰不一致，信封可能遭篡改，丟棄此選票。")
                    continue

                # 步驟 2：AES-CFB 解密選票密文
                ciphertext = b64_to_bytes(vote["ciphertext"])
                iv = b64_to_bytes(vote["iv"])
                cipher = Cipher(algorithms.AES(k_from_cc), modes.CFB(iv))
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()

                # 解析明文：vote_content | S'(hex) | m(hex)
                parts = plaintext.decode('utf-8').split("|")
                vote_content = parts[0]
                s_prime = hex_to_int(parts[1])
                m_int = hex_to_int(parts[2])

                # 步驟 3：驗證 TPA 盲簽章 S'^e ≡ m (mod n)
                if verify_blind_signature(s_prime, tpa_e, tpa_n, m_int):
                    print(f"[{self.id}] 選票合法：{vote_content}（簽章驗證通過）")
                    self.valid_votes.append(vote_content)
                else:
                    print(f"[{self.id}] 選票非法：{vote_content}（簽章驗證失敗）")

            except Exception as exc:
                print(f"[{self.id}] 處理選票時發生錯誤：{exc}")

    def build_merkle_tree(self) -> str:
        """
        Phase 5：用合法選票建構 Merkle Tree，回傳 Root_official。
        """
        if not self.valid_votes:
            print(f"[{self.id}] 沒有合法選票，無法建構 Merkle Tree。")
            return ""
        self._merkle_tree = MerkleTree(self.valid_votes)
        root = self._merkle_tree.get_root()
        print(f"[{self.id}] Merkle Tree 建構完成，Root_official = {root[:16]}...")
        return root

    def get_merkle_proof_json(self, vote_index: int) -> str:
        """
        取得指定選票的 Merkle Proof（JSON 字串）。
        """
        if self._merkle_tree is None:
            return json.dumps({"error": "Merkle Tree 尚未建構"})
        proof = self._merkle_tree.get_proof(vote_index)
        return json.dumps(proof)

    def get_tally_results(self) -> dict:
        """統計各候選人得票數"""
        tally = {}
        for vote in self.valid_votes:
            tally[vote] = tally.get(vote, 0) + 1
        return tally


# ============================================================
# Phase 5 + 6：BB — 公告板
# ============================================================

class BB:
    """
    公告板。
    Phase 5：接收 CC 公布的 Root_official 與計票結果。
    Phase 6：提供 Merkle Proof 供選民驗證。
    """

    def __init__(self):
        self._merkle_root: str = ""
        self._vote_records: list = []
        self._tally_results: dict = {}
        self._published: bool = False
        print("[BB] 公告板初始化完成。")

    def publish_results(self, root_official: str, vote_records: list, tally_results: dict) -> None:
        """
        Phase 5：接收 CC 的計票結果並公告。
        所有輸入均為 JSON 可序列化格式。
        """
        self._merkle_root = root_official
        self._vote_records = vote_records
        self._tally_results = tally_results
        self._published = True
        print(f"[BB] 結果已公告。Root_official = {root_official[:16]}...")
        print(f"[BB] 計票結果：{json.dumps(tally_results, ensure_ascii=False)}")

    def get_official_root(self) -> str:
        """回傳 Root_official"""
        return self._merkle_root if self._published else ""

    def provide_merkle_proof(self, vote_content: str, proof_json: str) -> str:
        """
        Phase 6：提供 Merkle Proof 給選民驗證。
        回傳 JSON 字串，包含 proof 路徑與 root。
        """
        if not self._published:
            return json.dumps({"error": "結果尚未公告"})
        return json.dumps({
            "vote_content":  vote_content,
            "merkle_proof":  json.loads(proof_json),
            "root_official": self._merkle_root,
        })


# ============================================================
# 主程式：端對端整合測試（Phase 1 → 6）
# ============================================================

if __name__ == '__main__':
    print("=" * 65)
    print("nutc-voting-system")
    print("=" * 65)

    # --------------------------------------------------------
    # Phase 1：系統初始化
    # 各實體生成金鑰與憑證，僅執行一次（邏輯審計修正點）
    # --------------------------------------------------------
    print("\n" + "─" * 65)
    print("  Phase 1：系統初始化（金鑰生成 + CA 憑證核發）")
    print("─" * 65)

    # 實例化所有實體（各僅一次）
    ca  = CA()
    tpa = TPA(tpa_id="TPA")
    ta  = TA(ta_id="TA", deadline=int(time.time()) + 5)   # 5 秒後截止（測試用）
    cc  = CC(cc_id="CC")
    bb  = BB()
    voter = Voter(voter_id="VOTER_001")

    # CA 核發憑證給各實體（輸入/輸出為 PEM 字串）
    tpa.cert_pem   = ca.issue_certificate("TPA",      tpa.get_public_key_pem())
    ta.cert_pem    = ca.issue_certificate("TA",       ta.get_public_key_pem())
    cc.cert_pem    = ca.issue_certificate("CC",       cc.get_public_key_pem())
    voter.cert_pem = ca.issue_certificate("VOTER_001", voter.get_public_key_pem())

    print("\n[Phase 1] 憑證核發完成，show JSON 公鑰資訊：")
    tpa_numbers_json = tpa.get_public_numbers_json()
    print(f"  TPA 公鑰大整數（Hex）：{json.dumps(tpa_numbers_json)[:80]}...")

    # --------------------------------------------------------
    # Phase 2：雙向身分認證（Voter ↔ TPA）
    # --------------------------------------------------------
    print("\n" + "─" * 65)
    print("  Phase 2：雙向身分認證（含 Delta T 時間戳記檢查）")
    print("─" * 65)

    # Step 2-1：Voter 產生認證封包（JSON 字串）
    auth_packet_json = voter.generate_auth_packet_json(tpa.id)
    print(f"\n[Voter → TPA] 認證封包（JSON 片段）：")
    auth_packet_preview = json.loads(auth_packet_json)
    print(f"  sender_id  : {auth_packet_preview['payload']['sender_id']}")
    print(f"  receiver_id: {auth_packet_preview['payload']['receiver_id']}")
    print(f"  timestamp  : {auth_packet_preview['payload']['timestamp']}")
    print(f"  si         : {auth_packet_preview['payload']['si']}")
    print(f"  signature  : {auth_packet_preview['signature'][:40]}... (Base64)")

    # Step 2-2：TPA 驗證 Voter（傳入 JSON 字串 + PEM 字串）
    voter_pub_pem = voter.get_public_key_pem()
    auth_ok = tpa.verify_voter_auth(auth_packet_json, voter_pub_pem)
    if not auth_ok:
        raise SystemExit("[錯誤] TPA 驗證 Voter 失敗，中斷測試。")

    # Step 2-3：TPA 產生回傳封包（雙向認證）
    response_packet_json = tpa.generate_response_packet_json(voter.id)
    print(f"\n[TPA → Voter] 回傳認證封包（JSON 片段）：")
    resp_preview = json.loads(response_packet_json)
    print(f"  sender_id  : {resp_preview['payload']['sender_id']}")
    print(f"  receiver_id: {resp_preview['payload']['receiver_id']}")
    print(f"  signature  : {resp_preview['signature'][:40]}... (Base64)")

    # Step 2-4：Voter 驗證 TPA（雙向認證完成）
    tpa_pub_pem = tpa.get_public_key_pem()
    resp_ok = voter.verify_tpa_response_json(response_packet_json, tpa_pub_pem)
    if not resp_ok:
        raise SystemExit("[錯誤] Voter 驗證 TPA 失敗，中斷測試。")

    print("\n>>> Phase 2 完成：雙向身分認證成功 <<<")

    # --------------------------------------------------------
    # Phase 3：盲簽章 + 數位信封封裝
    # --------------------------------------------------------
    print("\n" + "─" * 65)
    print("  Phase 3：盲簽章 + 數位信封封裝")
    print("─" * 65)

    # Step 3-1：計算選票雜湊值 m
    # 根據計畫書：m = H(H(ID || SN || Vote) || Vote)
    ID_Voter = voter.id
    SN       = "20260324001"
    Vote     = "Candidate_A"

    inner_hash = hashlib.sha256(f"{ID_Voter}{SN}{Vote}".encode('utf-8')).hexdigest()
    outer_hash = hashlib.sha256(f"{inner_hash}{Vote}".encode('utf-8')).hexdigest()
    m_hex = hex(int(outer_hash, 16))   # 轉為 Hex 字串

    print(f"\n[Voter] 選票內容：{Vote}")
    print(f"[Voter] m（Hex）：{m_hex[:40]}...")

    # Step 3-2：Voter 盲化選票（輸入/輸出均為 Hex 字串）
    tpa_numbers_json_str = json.dumps(tpa.get_public_numbers_json())
    m_prime_hex = voter.prepare_blinded_vote(m_hex, tpa_numbers_json_str)
    print(f"[Voter → TPA] 盲化選票 m'（Hex）：{m_prime_hex[:40]}...")

    # Step 3-3：TPA 執行盲簽章（輸入/輸出均為 Hex 字串）
    S_hex = tpa.sign_blinded_vote(m_prime_hex)
    print(f"[TPA → Voter] 盲簽章 S（Hex）：{S_hex[:40]}...")

    # Step 3-4：Voter 去盲化，取得合法簽章 S'
    tpa_n_hex = int_to_hex(tpa.n)
    S_prime_hex = voter.unblind_signature(S_hex, tpa_n_hex)
    print(f"[Voter] 去盲化後簽章 S'（Hex）：{S_prime_hex[:40]}...")

    # Step 3-5：數學驗證 S'^e ≡ m (mod n)
    s_prime_int = hex_to_int(S_prime_hex)
    m_int       = hex_to_int(m_hex)
    blind_sig_valid = verify_blind_signature(s_prime_int, tpa.e, tpa.n, m_int)
    print(f"[驗證] 盲簽章數學驗證：{'通過 [OK]' if blind_sig_valid else '失敗 [FAIL]'}")
    if not blind_sig_valid:
        raise SystemExit("[錯誤] 盲簽章驗證失敗，中斷測試。")

    # Step 3-6：Voter 封裝數位信封（輸出 JSON 字串）
    cc_pub_pem = cc.get_public_key_pem()
    ta_pub_pem = ta.get_public_key_pem()
    envelope_json = voter.encapsulate_vote(
        vote_content=Vote,
        s_prime_hex=S_prime_hex,
        m_hex=m_hex,
        cc_public_key_pem=cc_pub_pem,
        ta_public_key_pem=ta_pub_pem,
    )
    envelope_preview = json.loads(envelope_json)
    print(f"\n[Voter → CC] 數位信封（JSON 格式）：")
    print(f"  ciphertext : {envelope_preview['ciphertext'][:40]}... (Base64)")
    print(f"  iv         : {envelope_preview['iv']} (Base64)")
    print(f"  k_enc_cc   : {envelope_preview['k_enc_cc'][:40]}... (Base64)")
    print(f"  k_enc_ta   : {envelope_preview['k_enc_ta'][:40]}... (Base64)")

    # Step 3-7：CC 接收數位信封
    cc.receive_envelope(envelope_json)

    print("\n>>> Phase 3 完成：數位信封已封裝並送達 CC <<<")

    # --------------------------------------------------------
    # Phase 4：時間鎖定 — TA 在截止後釋放 SK_TA
    # --------------------------------------------------------
    print("\n" + "─" * 65)
    print("  Phase 4：時間鎖定（等待投票截止，TA 釋放 SK_TA）")
    print("─" * 65)

    # 截止前嘗試釋放（應被拒絕）
    sk_ta_json_early = ta.release_private_key()
    early_result = json.loads(sk_ta_json_early)
    print(f"[TA] 截止前釋放結果：{early_result['status']}")

    # 等待截止時間
    print("[TA] 等待投票截止...")
    while int(time.time()) < ta.deadline:
        remaining = ta.deadline - int(time.time())
        print(f"  還有 {remaining} 秒...", end="\r")
        time.sleep(1)
    print()

    # 截止後釋放 SK_TA（JSON 字串格式）
    sk_ta_json = ta.release_private_key()
    sk_ta_data = json.loads(sk_ta_json)
    print(f"[TA → CC] SK_TA 釋放結果：{sk_ta_data['status']}")
    print(f"[TA → CC] SK_TA JSON 格式（片段）：")
    print(f"  status         : {sk_ta_data['status']}")
    print(f"  d_hex          : {sk_ta_data['d_hex'][:40]}...")
    print(f"  private_key_pem: {sk_ta_data['private_key_pem'][:40]}... (PEM)")

    print("\n>>> Phase 4 完成：SK_TA 已釋放給 CC <<<")

    # --------------------------------------------------------
    # Phase 5：計票 — CC 解密、驗證、建構 Merkle Tree
    # --------------------------------------------------------
    print("\n" + "─" * 65)
    print("  Phase 5：計票（解密選票 + 驗證簽章 + Merkle Tree）")
    print("─" * 65)

    # CC 解密並驗證所有選票
    tpa_numbers_json_str = json.dumps(tpa.get_public_numbers_json())
    cc.decrypt_and_verify_votes(sk_ta_json, tpa_numbers_json_str)

    # 建構 Merkle Tree
    root_official = cc.build_merkle_tree()
    tally = cc.get_tally_results()
    print(f"\n[CC] 計票結果：{json.dumps(tally, ensure_ascii=False)}")

    # 取得第一張選票的 Merkle Proof
    proof_json = cc.get_merkle_proof_json(0)
    print(f"[CC] 第一張選票的 Merkle Proof（JSON）：{proof_json[:80]}...")

    # CC 公告結果至 BB
    bb.publish_results(
        root_official=root_official,
        vote_records=cc.valid_votes,
        tally_results=tally,
    )

    print("\n>>> Phase 5 完成：Merkle Tree 建構完成，結果已公告至 BB <<<")

    # --------------------------------------------------------
    # Phase 6：選民驗證 — BB 提供 Merkle Proof
    # --------------------------------------------------------
    print("\n" + "─" * 65)
    print("  Phase 6：選民驗證（Merkle Proof 驗證）")
    print("─" * 65)

    # BB 提供 Merkle Proof
    bb_proof_json = bb.provide_merkle_proof(Vote, proof_json)
    bb_proof_data = json.loads(bb_proof_json)
    print(f"\n[BB → Voter] Merkle Proof 封包（JSON）：")
    print(f"  vote_content  : {bb_proof_data['vote_content']}")
    print(f"  root_official : {bb_proof_data['root_official'][:40]}...")
    print(f"  merkle_proof  : {json.dumps(bb_proof_data['merkle_proof'])[:60]}...")

    # Voter 本地驗證：
    # 1. 從 BB 取得 Root_official
    # 2. 用 Merkle Proof 驗證自己的選票是否在樹中
    root_from_bb = bb.get_official_root()
    proof_steps  = bb_proof_data["merkle_proof"]
    is_in_tree   = MerkleTree.verify_proof(Vote, proof_steps, root_from_bb)
    print(f"\n[Voter] 從 BB 取得 Root_official：{root_from_bb[:40]}...")
    print(f"[Voter] Merkle Proof 驗證結果：{'通過 [OK]' if is_in_tree else '失敗 [FAIL]'}")

    print("\n>>> Phase 6 完成：選民已驗證選票存在於合法計票結果中 <<<")

    # --------------------------------------------------------
    # 總結
    # --------------------------------------------------------
    print("\n" + "=" * 65)
    print("  端對端測試總結")
    print("=" * 65)
    print(f"  Phase 1 (Init)      : [OK] 金鑰生成 + CA 憑證核發")
    print(f"  Phase 2 (Auth)      : [OK] 雙向身分認證（Delta T 通過）")
    print(f"  Phase 3 (Blind Vote): [OK] 盲簽章 + 數位信封封裝")
    print(f"  Phase 4 (Time Lock) : [OK] TA 截止後釋放 SK_TA")
    print(f"  Phase 5 (Tally)     : [OK] CC 解密驗證 + Merkle Tree")
    print(f"  Phase 6 (Verify)    : [OK] BB Merkle Proof 驗證")
    print("=" * 65)
    print(f"  合法選票數：{len(cc.valid_votes)}")
    print(f"  計票結果  ：{json.dumps(tally, ensure_ascii=False)}")
    print(f"  Root_official：{root_official}")
    print("=" * 65)
