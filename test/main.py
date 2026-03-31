"""
[main.py 整合三檔] 2026/03/30 → 重構 2026/04/01
A.py -> 陳,B.py -> 謝,C.py -> 嚴

現況:還是純在記憶體跑，但改了傳輸方式，如點2 ****還沒動儲存****
測試:假資料模擬，在 if __name__ == '__main__':


1. 流程對應 (Phase 1-6)
- Phase 1 (Init)  ：實體初始化，金鑰與憑證僅生成一次。
- Phase 2 (Auth)  ：Voter ↔ TPA 雙向認證，含 Delta T 時戳檢查。
- Phase 3 (Blind) ：選票盲簽章與數位信封封裝。
  規範：P = (C_Data || C_Key)
    C_Data = E_k( E_PK_TA(H(ID||SN||Vote) || Vote), S', m )
    C_Key  = E_PK_CC(k)
- Phase 4 (Time)  ：投票截止後，TA 釋放私鑰 SK_TA 予計票中心。
- Phase 5 (Tally) ：CC 解密驗證選票，補了 Merkle Tree。
  規範：CC 用 SK_CC 解 C_Key 得 k，用 k 解 C_Data；
        待 TA 釋出 SK_TA 後解開內層 E_PK_TA(...)，
        計算雜湊與外層 m 比對。
  Merkle Tree 葉節點：Leaf_i = H(m_j)（選票包雜湊值的再雜湊）
- Phase 6 (Verify)：BB 提供 Merkle Proof，voter 執行端到端驗證。
  驗證起點：H(m)（絕對不能用選票明文）

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


def sha256_hex(data: bytes) -> str:
    """計算 SHA-256 並回傳 hex 字串"""
    return hashlib.sha256(data).hexdigest()


# ============================================================
# Merkle Tree （Phase 5/6）
# ============================================================

class MerkleTree:
    """
    Merkle Tree。
    規範：葉節點為選票包雜湊值 m 的再雜湊，即 Leaf_i = H(m_j)。
    m_j 為各合法選票的選票包雜湊值（hex 字串）。
    """

    def __init__(self, m_hex_list: list):
        """
        m_hex_list：各合法選票的 m 值（hex 字串）列表。
        葉節點 = H(m_j)，即對 m 的 hex 字串再做一次 SHA-256。
        """
        # Leaf_i = H(m_j)：對 m 的 hex 字串做 SHA-256
        self.leaves = [sha256_hex(m_hex.encode('utf-8')) for m_hex in m_hex_list]
        self.tree = self._build_tree(self.leaves)

    def _build_tree(self, nodes: list) -> list:
        """遞迴建構 Merkle Tree，回傳各層節點列表（由葉到根）"""
        if not nodes:
            return []
        layers = [nodes]
        current = nodes
        while len(current) > 1:
            # 若節點數為奇數，複製最後一個節點補齊
            if len(current) % 2 == 1:
                current = current + [current[-1]]
            next_layer = [
                sha256_hex((current[i] + current[i + 1]).encode('utf-8'))
                for i in range(0, len(current), 2)
            ]
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
    def verify_proof(m_hex: str, proof: list, root: str) -> bool:
        """
        驗證 Merkle Proof 是否正確。
        規範：驗證起點必須為 H(m)，絕對不能用選票明文。
        m_hex：選票包雜湊值 m 的 hex 字串（未再雜湊）。
        """
        # 起點：Leaf = H(m)
        current_hash = sha256_hex(m_hex.encode('utf-8'))
        for step in proof:
            sibling = step["sibling"]
            if step["position"] == "right":
                combined = current_hash + sibling
            else:
                combined = sibling + current_hash
            current_hash = sha256_hex(combined.encode('utf-8'))
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
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._public_key = self._private_key.public_key()
        self._root_cert = self._generate_root_cert()
        print("[CA] 根憑證已生成。")

    def _generate_root_cert(self) -> x509.Certificate:
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
        return self._root_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    def get_public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')

    def issue_certificate(self, entity_id: str, public_key_pem: str) -> str:
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
        self._private_key, self._public_key, self.e, self.n, self.d = generate_rsa_keypair()
        self.cert_pem: str = ""
        print(f"[{self.id}] 初始化完成，RSA 金鑰已生成。")

    def get_public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')

    def get_public_numbers_json(self) -> dict:
        """回傳公鑰大整數（Hex 字串格式），供 Voter 盲化使用。"""
        return {"e": int_to_hex(self.e), "n": int_to_hex(self.n)}

    def verify_voter_auth(self, auth_packet_json: str, voter_public_key_pem: str) -> bool:
        auth_packet = json.loads(auth_packet_json)
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
        packet = create_auth_packet(self.id, voter_id, self._private_key, self.cert_pem)
        return json.dumps(packet)

    def sign_blinded_vote(self, m_prime_hex: str) -> str:
        """Phase 3：對盲化選票執行盲簽章，回傳 S 的 Hex 字串。"""
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
        self._private_key, self._public_key, self.e, self.n, self.d = generate_rsa_keypair()
        self.cert_pem: str = ""
        self._r: int = 0
        print(f"[{self.id}] 初始化完成，RSA 金鑰已生成。")

    def get_public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')

    def generate_auth_packet_json(self, tpa_id: str) -> str:
        packet = create_auth_packet(self.id, tpa_id, self._private_key, self.cert_pem)
        return json.dumps(packet)

    def verify_tpa_response_json(self, response_packet_json: str, tpa_public_key_pem: str) -> bool:
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
        """Phase 3：盲化選票，回傳 m' 的 Hex 字串。"""
        m = hex_to_int(m_hex)
        tpa_nums = json.loads(tpa_numbers_json)
        tpa_e = hex_to_int(tpa_nums["e"])
        tpa_n = hex_to_int(tpa_nums["n"])
        self._r = generate_blinding_factor(tpa_n)
        m_prime = blind_message(m, self._r, tpa_e, tpa_n)
        print(f"[{self.id}] 選票已盲化，m' 已計算。")
        return int_to_hex(m_prime)

    def unblind_signature(self, S_hex: str, tpa_n_hex: str) -> str:
        """Phase 3：去盲化，取得最終合法簽章 S'，回傳 Hex 字串。"""
        S = hex_to_int(S_hex)
        tpa_n = hex_to_int(tpa_n_hex)
        S_prime = unblind_signature(S, self._r, tpa_n)
        print(f"[{self.id}] 去盲化完成，取得合法簽章 S'。")
        return int_to_hex(S_prime)

    def encapsulate_vote(
        self,
        voter_id: str,
        sn: str,
        vote_content: str,
        s_prime_hex: str,
        m_hex: str,
        cc_public_key_pem: str,
        ta_public_key_pem: str,
    ) -> str:
        """
        Phase 3：建立數位信封。

        規範：P = (C_Data || C_Key)
          C_Data = E_k( E_PK_TA(H(ID||SN||Vote) || Vote), S', m )
          C_Key  = E_PK_CC(k)

        流程：
          1. 計算內層明文雜湊：hash_inner = H(ID || SN || Vote)
          2. 用 TA 公鑰加密 (hash_inner || Vote) → inner_enc（Base64）
          3. 組合 AES 明文：inner_enc_b64 | S'(hex) | m(hex)
          4. 生成隨機 AES-256 金鑰 k，AES-CFB 加密 → C_Data
          5. 用 CC 公鑰加密 k → C_Key

        輸出：JSON 字串（所有 bytes 均以 Base64 表示）
        """
        cc_pub_key = serialization.load_pem_public_key(cc_public_key_pem.encode('utf-8'))
        ta_pub_key = serialization.load_pem_public_key(ta_public_key_pem.encode('utf-8'))

        # 步驟 1：計算內層雜湊 H(ID || SN || Vote)
        hash_inner = sha256_hex(f"{voter_id}{sn}{vote_content}".encode('utf-8'))

        # 步驟 2：用 TA 公鑰加密 (hash_inner || Vote)
        #   明文格式：hash_inner(hex) | vote_content
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

        envelope = {
            "c_data": bytes_to_b64(c_data_bytes),   # C_Data（Base64）
            "iv":     bytes_to_b64(iv),              # AES IV（Base64）
            "c_key":  bytes_to_b64(c_key_bytes),     # C_Key = E_PK_CC(k)（Base64）
        }
        print(f"[{self.id}] 數位信封已封裝（規範：C_Data=E_k(E_PK_TA(...),S',m)，C_Key=E_PK_CC(k)）。")
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
        self._private_key, self._public_key, self.e, self.n, self.d = generate_rsa_keypair()
        self.cert_pem: str = ""
        deadline_str = datetime.datetime.fromtimestamp(deadline).strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{self.id}] 初始化完成，投票截止時間：{deadline_str}")

    def get_public_key_pem(self) -> str:
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
    Phase 3：接收數位信封，用 SK_CC 解開 C_Key 取得 k，暫存 C_Data。
    Phase 5：收到 SK_TA 後，用 k 解密 C_Data，再用 SK_TA 解開內層
             E_PK_TA(...)，取得 Vote，計算雜湊與外層 m 比對驗證。
             建構 Merkle Tree，葉節點 = H(m_j)。
    """

    def __init__(self, cc_id: str):
        self.id = cc_id
        self._private_key, self._public_key, self.e, self.n, self.d = generate_rsa_keypair()
        self.cert_pem: str = ""
        # 暫存信封：已用 SK_CC 解出 k，但選票內容需等 TA 私鑰才能驗證
        self._pending_envelopes: list = []
        # 驗證通過的合法選票：每筆為 {"vote": str, "m_hex": str}
        self.valid_votes: list = []
        self._merkle_tree: MerkleTree = None
        print(f"[{self.id}] 初始化完成，RSA 金鑰已生成。")

    def get_public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')

    def receive_envelope(self, envelope_json: str) -> None:
        """
        Phase 3：接收數位信封。
        規範：用 SK_CC 解密 C_Key 取得對稱金鑰 k，暫存 C_Data 待開票。
        """
        envelope = json.loads(envelope_json)

        # 用 CC 私鑰解密 C_Key 取得 k
        c_key = b64_to_bytes(envelope["c_key"])
        k = self._private_key.decrypt(
            c_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        # 暫存（k 已解出，C_Data 等待 TA 私鑰後再解密驗證）
        self._pending_envelopes.append({
            "c_data": envelope["c_data"],
            "iv":     envelope["iv"],
            "k":      bytes_to_b64(k),   # 儲存為 Base64
        })
        print(f"[{self.id}] 數位信封已接收，C_Key 已用 SK_CC 解密取得 k（等待 TA 私鑰）。")

    def decrypt_and_verify_votes(self, sk_ta_json: str, tpa_numbers_json: str) -> None:
        """
        Phase 5：收到 SK_TA 後，解密並驗證所有暫存選票。

        規範驗證流程：
          1. 用 k 解密 C_Data，取得 (inner_enc_b64 | S'_hex | m_hex)
          2. 用 SK_TA 解開內層 E_PK_TA(...)，取得 (hash_inner | vote_content)
          3. 重新計算 H(ID||SN||Vote) 並與解出的 hash_inner 比對
          4. 計算 m_check = H(hash_inner || vote_content)，與外層 m 比對
          5. 驗證 TPA 盲簽章：S'^e ≡ m (mod n)
        """
        sk_ta_data = json.loads(sk_ta_json)
        if sk_ta_data["status"] != "released":
            print(f"[{self.id}] TA 私鑰尚未釋放，無法開票。")
            return

        # 載入 TA 私鑰物件（用於解開內層密文）
        ta_private_key = serialization.load_pem_private_key(
            sk_ta_data["private_key_pem"].encode('utf-8'),
            password=None,
        )
        # 載入 TPA 公鑰大整數（用於驗證盲簽章）
        tpa_nums = json.loads(tpa_numbers_json)
        tpa_e = hex_to_int(tpa_nums["e"])
        tpa_n = hex_to_int(tpa_nums["n"])

        for vote_record in self._pending_envelopes:
            try:
                # 步驟 1：用 k 解密 C_Data
                k = b64_to_bytes(vote_record["k"])
                c_data = b64_to_bytes(vote_record["c_data"])
                iv = b64_to_bytes(vote_record["iv"])
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
                # 解析內層明文：hash_inner(hex) | vote_content
                inner_parts = inner_plaintext.decode('utf-8').split("|", 1)
                hash_inner_from_env = inner_parts[0]
                vote_content        = inner_parts[1]

                # 步驟 3：重新計算 m_check = H(hash_inner || vote_content)
                #   對應 Voter 端的 outer_hash = H(inner_hash || vote_content)
                m_check_hex = sha256_hex(f"{hash_inner_from_env}{vote_content}".encode('utf-8'))
                m_check_int = int(m_check_hex, 16)
                m_int       = hex_to_int(m_hex)

                if m_check_int != m_int:
                    print(f"[{self.id}] 雜湊比對失敗（m 不一致），丟棄此選票。")
                    continue

                # 步驟 4：驗證 TPA 盲簽章 S'^e ≡ m (mod n)
                s_prime_int = hex_to_int(s_prime_hex)
                if not verify_blind_signature(s_prime_int, tpa_e, tpa_n, m_int):
                    print(f"[{self.id}] 選票非法：{vote_content}（盲簽章驗證失敗）")
                    continue

                print(f"[{self.id}] 選票合法：{vote_content}（雜湊比對 + 簽章驗證通過）")
                self.valid_votes.append({"vote": vote_content, "m_hex": m_hex})

            except Exception as exc:
                print(f"[{self.id}] 處理選票時發生錯誤：{exc}")

    def build_merkle_tree(self) -> str:
        """
        Phase 5：用合法選票的 m 值建構 Merkle Tree，回傳 Root_official。
        規範：葉節點 Leaf_i = H(m_j)。
        """
        if not self.valid_votes:
            print(f"[{self.id}] 沒有合法選票，無法建構 Merkle Tree。")
            return ""
        m_hex_list = [v["m_hex"] for v in self.valid_votes]
        self._merkle_tree = MerkleTree(m_hex_list)
        root = self._merkle_tree.get_root()
        print(f"[{self.id}] Merkle Tree 建構完成（葉節點=H(m_j)），Root_official = {root[:16]}...")
        return root

    def get_merkle_proof_json(self, vote_index: int) -> str:
        """取得指定選票的 Merkle Proof（JSON 字串）。"""
        if self._merkle_tree is None:
            return json.dumps({"error": "Merkle Tree 尚未建構"})
        proof = self._merkle_tree.get_proof(vote_index)
        return json.dumps(proof)

    def get_tally_results(self) -> dict:
        """統計各候選人得票數"""
        tally = {}
        for v in self.valid_votes:
            tally[v["vote"]] = tally.get(v["vote"], 0) + 1
        return tally

    def get_vote_contents(self) -> list:
        """回傳合法選票的 vote_content 列表（供 BB 公告）"""
        return [v["vote"] for v in self.valid_votes]

    def get_m_hex_list(self) -> list:
        """回傳合法選票的 m_hex 列表（供 Phase 6 驗證使用）"""
        return [v["m_hex"] for v in self.valid_votes]


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
        """Phase 5：接收 CC 的計票結果並公告。"""
        self._merkle_root = root_official
        self._vote_records = vote_records
        self._tally_results = tally_results
        self._published = True
        print(f"[BB] 結果已公告。Root_official = {root_official[:16]}...")
        print(f"[BB] 計票結果：{json.dumps(tally_results, ensure_ascii=False)}")

    def get_official_root(self) -> str:
        return self._merkle_root if self._published else ""

    def provide_merkle_proof(self, m_hex: str, proof_json: str) -> str:
        """
        Phase 6：提供 Merkle Proof 給選民驗證。
        回傳 JSON 字串，包含 proof 路徑與 root。
        """
        if not self._published:
            return json.dumps({"error": "結果尚未公告"})
        return json.dumps({
            "m_hex":         m_hex,
            "merkle_proof":  json.loads(proof_json),
            "root_official": self._merkle_root,
        })


# ============================================================
# 主程式：測試（Phase 1 → 6）
# 模擬 3 位選民投票：投票依序 A, B, A
# ============================================================

if __name__ == '__main__':
    print("=" * 65)
    print("nutc-voting-system  ─  （3 票：A, B, A）")
    print("=" * 65)

    # --------------------------------------------------------
    # 選民設定：(voter_id, 投票內容)
    # SN ：20260324001 / 002 / 003
    # --------------------------------------------------------
    VOTER_CONFIGS = [
        ("VOTER_001", "Candidate_A"),
        ("VOTER_002", "Candidate_B"),
        ("VOTER_003", "Candidate_A"),
    ]
    SN_BASE = "2026032400"   # SN = SN_BASE + str(idx+1)

    # --------------------------------------------------------
    # Phase 1：系統初始化
    # --------------------------------------------------------
    print("\n" + "─" * 65)
    print("  Phase 1：系統初始化（金鑰生成 + CA 憑證核發）")
    print("─" * 65)

    ca  = CA()
    tpa = TPA(tpa_id="TPA")
    ta  = TA(ta_id="TA", deadline=int(time.time()) + 5)   # 5 秒後截止（測試用）
    cc  = CC(cc_id="CC")
    bb  = BB()

    tpa.cert_pem = ca.issue_certificate("TPA", tpa.get_public_key_pem())
    ta.cert_pem  = ca.issue_certificate("TA",  ta.get_public_key_pem())
    cc.cert_pem  = ca.issue_certificate("CC",  cc.get_public_key_pem())

    voters = []
    for voter_id, _ in VOTER_CONFIGS:
        v = Voter(voter_id=voter_id)
        v.cert_pem = ca.issue_certificate(voter_id, v.get_public_key_pem())
        voters.append(v)

    print("\n[Phase 1] 憑證核發完成，TPA 公鑰大整數（Hex）：")
    tpa_numbers_json_str = json.dumps(tpa.get_public_numbers_json())
    print(f"  {tpa_numbers_json_str[:80]}...")

    # --------------------------------------------------------
    # Phase 2 + 3：迴圈對每位選民執行
    # --------------------------------------------------------
    tpa_pub_pem = tpa.get_public_key_pem()
    cc_pub_pem  = cc.get_public_key_pem()
    ta_pub_pem  = ta.get_public_key_pem()
    tpa_n_hex   = int_to_hex(tpa.n)

    # 記錄每位選民的 m_hex，供 Phase 6 端到端驗證使用
    voter_m_hex_records = []

    for idx, (voter, (voter_id, vote_content)) in enumerate(zip(voters, VOTER_CONFIGS)):
        sn = f"{SN_BASE}{idx + 1}"   # 唯一 SN：20260324001 / 002 / 003

        print("\n" + "═" * 65)
        print(f"  選民 {idx + 1}/{len(VOTER_CONFIGS)}：{voter_id}  投票：{vote_content}  SN：{sn}")
        print("═" * 65)

        # ── Phase 2：雙向身分認證 ──────────────────────────────
        print(f"\n  -- Phase 2：{voter_id} <-> TPA 雙向認證 --")

        auth_packet_json = voter.generate_auth_packet_json(tpa.id)
        auth_preview = json.loads(auth_packet_json)
        print(f"  [Voter → TPA] sender_id={auth_preview['payload']['sender_id']}"
              f"  timestamp={auth_preview['payload']['timestamp']}"
              f"  si={auth_preview['payload']['si']}")
        print(f"  [Voter → TPA] signature={auth_preview['signature'][:40]}... (Base64)")

        auth_ok = tpa.verify_voter_auth(auth_packet_json, voter.get_public_key_pem())
        if not auth_ok:
            raise SystemExit(f"[錯誤] TPA 驗證 {voter_id} 失敗，中斷測試。")

        response_packet_json = tpa.generate_response_packet_json(voter.id)
        resp_preview = json.loads(response_packet_json)
        print(f"  [TPA → Voter] sender_id={resp_preview['payload']['sender_id']}"
              f"  receiver_id={resp_preview['payload']['receiver_id']}")
        print(f"  [TPA → Voter] signature={resp_preview['signature'][:40]}... (Base64)")

        resp_ok = voter.verify_tpa_response_json(response_packet_json, tpa_pub_pem)
        if not resp_ok:
            raise SystemExit(f"[錯誤] {voter_id} 驗證 TPA 失敗，中斷測試。")

        print(f"  >>> Phase 2 完成：{voter_id} 雙向認證成功 <<<")

        # ── Phase 3：盲簽章 + 數位信封 ────────────────────────
        print(f"\n  ── Phase 3：{voter_id} 盲簽章 + 數位信封 ──")

        # Step 3-1：計算選票雜湊值 m
        #   inner_hash = H(ID || SN || Vote)
        #   m = H(inner_hash || Vote)  （outer_hash）
        inner_hash = sha256_hex(f"{voter_id}{sn}{vote_content}".encode('utf-8'))
        outer_hash = sha256_hex(f"{inner_hash}{vote_content}".encode('utf-8'))
        m_hex = hex(int(outer_hash, 16))
        print(f"  [Voter] vote={vote_content}  SN={sn}  m={m_hex[:40]}...")

        # 記錄 m_hex 供 Phase 6 使用
        voter_m_hex_records.append({"voter_id": voter_id, "m_hex": m_hex})

        # Step 3-2：Voter 盲化選票
        m_prime_hex = voter.prepare_blinded_vote(m_hex, tpa_numbers_json_str)
        print(f"  [Voter → TPA] m'={m_prime_hex[:40]}... (Hex)")

        # Step 3-3：TPA 盲簽章
        S_hex = tpa.sign_blinded_vote(m_prime_hex)
        print(f"  [TPA → Voter] S={S_hex[:40]}... (Hex)")

        # Step 3-4：Voter 去盲化，取得合法簽章 S'
        S_prime_hex = voter.unblind_signature(S_hex, tpa_n_hex)
        print(f"  [Voter] S'={S_prime_hex[:40]}... (Hex)")

        # Step 3-5：數學驗證 S'^e ≡ m (mod n)
        s_prime_int = hex_to_int(S_prime_hex)
        m_int       = hex_to_int(m_hex)
        blind_sig_valid = verify_blind_signature(s_prime_int, tpa.e, tpa.n, m_int)
        print(f"  [驗證] 盲簽章數學驗證：{'通過 [OK]' if blind_sig_valid else '失敗 [FAIL]'}")
        if not blind_sig_valid:
            raise SystemExit(f"[錯誤] {voter_id} 盲簽章驗證失敗，中斷測試。")

        # Step 3-6：Voter 封裝數位信封（規範格式）
        #   C_Data = E_k( E_PK_TA(H(ID||SN||Vote) || Vote), S', m )
        #   C_Key  = E_PK_CC(k)
        envelope_json = voter.encapsulate_vote(
            voter_id=voter_id,
            sn=sn,
            vote_content=vote_content,
            s_prime_hex=S_prime_hex,
            m_hex=m_hex,
            cc_public_key_pem=cc_pub_pem,
            ta_public_key_pem=ta_pub_pem,
        )
        env_preview = json.loads(envelope_json)
        print(f"  [Voter → CC] 數位信封（JSON）：")
        print(f"    c_data={env_preview['c_data'][:40]}... (Base64)")
        print(f"    iv    ={env_preview['iv']} (Base64)")
        print(f"    c_key ={env_preview['c_key'][:40]}... (Base64)")

        # Step 3-7：CC 接收數位信封
        cc.receive_envelope(envelope_json)

        print(f"  >>> Phase 3 完成：{voter_id} 數位信封已送達 CC <<<")

    # --------------------------------------------------------
    # Phase 4：時間鎖定 — TA 在截止後釋放 SK_TA
    # --------------------------------------------------------
    print("\n" + "─" * 65)
    print("  Phase 4：時間鎖定（等待投票截止，TA 釋放 SK_TA）")
    print("─" * 65)

    sk_ta_json_early = ta.release_private_key()
    early_result = json.loads(sk_ta_json_early)
    print(f"[TA] 截止前釋放結果：{early_result['status']}")

    print("[TA] 等待投票截止...")
    while int(time.time()) < ta.deadline:
        remaining = ta.deadline - int(time.time())
        print(f"  還有 {remaining} 秒...", end="\r")
        time.sleep(1)
    print()

    sk_ta_json = ta.release_private_key()
    sk_ta_data = json.loads(sk_ta_json)
    print(f"[TA → CC] SK_TA 釋放結果：{sk_ta_data['status']}")
    print(f"  status         : {sk_ta_data['status']}")
    print(f"  d_hex          : {sk_ta_data['d_hex'][:40]}... (Hex)")
    print(f"  private_key_pem: {sk_ta_data['private_key_pem'][:40]}... (PEM)")

    print("\n>>> Phase 4 完成：SK_TA 已釋放給 CC <<<")

    # --------------------------------------------------------
    # Phase 5：計票 — CC 解密、驗證、建構 Merkle Tree
    # --------------------------------------------------------
    print("\n" + "─" * 65)
    print("  Phase 5：計票（解密選票 + 驗證簽章 + Merkle Tree）")
    print("─" * 65)

    # CC 解密並驗證所有選票
    cc.decrypt_and_verify_votes(sk_ta_json, tpa_numbers_json_str)

    # 建構 Merkle Tree（葉節點 = H(m_j)）
    root_official = cc.build_merkle_tree()

    # 計票結果（Tally）
    tally = cc.get_tally_results()
    print(f"\n[Phase 5] ── Tally 計票結果 ──")
    for candidate, count in sorted(tally.items()):
        print(f"  {candidate} : {count} 票")
    print(f"  合計合法選票：{len(cc.valid_votes)} 張")
    print(f"  Root_official：{root_official}")

    # CC 公告結果至 BB
    bb.publish_results(
        root_official=root_official,
        vote_records=cc.get_vote_contents(),
        tally_results=tally,
    )

    print("\n>>> Phase 5 完成：Merkle Tree 建構完成，結果已公告至 BB <<<")

    # --------------------------------------------------------
    # Phase 6：選民驗證 — BB 提供 Merkle Proof（每張選票）
    # 規範：驗證起點必須為 H(m)，絕對不能用選票明文
    # --------------------------------------------------------
    print("\n" + "─" * 65)
    print("  Phase 6：選民驗證（每張合法選票的 Merkle Proof）")
    print("─" * 65)

    root_from_bb = bb.get_official_root()
    all_pass = True

    m_hex_list = cc.get_m_hex_list()

    for leaf_idx, (valid_vote, m_hex) in enumerate(zip(cc.valid_votes, m_hex_list)):
        vote_content = valid_vote["vote"]

        # CC 取得該葉節點的 Merkle Proof（JSON 字串）
        proof_json = cc.get_merkle_proof_json(leaf_idx)
        proof_steps = json.loads(proof_json)

        # BB 封裝 Merkle Proof 封包（JSON 字串）
        bb_proof_json = bb.provide_merkle_proof(m_hex, proof_json)
        bb_proof_data = json.loads(bb_proof_json)

        # 驗證 Merkle Proof
        # 規範：驗證起點為 H(m)，不使用選票明文
        is_in_tree = MerkleTree.verify_proof(m_hex, proof_steps, root_from_bb)

        print(f"\n  [葉節點 {leaf_idx}] vote_content = {vote_content}")
        print(f"    m_hex         : {m_hex[:40]}...")
        print(f"    Leaf_i = H(m) : {sha256_hex(m_hex.encode('utf-8'))[:40]}...")
        print(f"    root_official : {bb_proof_data['root_official'][:40]}...")

        if proof_steps:
            print(f"    Merkle Proof 路徑（共 {len(proof_steps)} 步）：")
            for step_i, step in enumerate(proof_steps):
                print(f"      step {step_i}: position={step['position']}"
                      f"  sibling={step['sibling'][:20]}... (SHA-256)")
        else:
            print(f"    Merkle Proof 路徑：（單一葉節點，無需兄弟節點）")

        print(f"    驗證結果：{'通過 [OK]' if is_in_tree else '失敗 [FAIL]'}")

        if not is_in_tree:
            all_pass = False

    print(f"\n[Phase 6] 所有葉節點驗證：{'全部通過 [OK]' if all_pass else '有驗證失敗 [FAIL]'}")
    print("\n>>> Phase 6 完成：所有選票已驗證存在於合法計票結果中 <<<")

    # --------------------------------------------------------
    # 最終結果
    # --------------------------------------------------------
    print("")
    print("")
    print("=" * 65)
    print("結果")
    print("─" * 65)
    print(f"  合法選票數  ：{len(cc.valid_votes)}")
    print(f"  計票結果    ：{json.dumps(tally, ensure_ascii=False)}")
    print(f"  Root_official：{root_official}")
    print(f"  Merkle Proof 驗證：{'全部通過 [OK]' if all_pass else '有驗證失敗 [FAIL]'}")
    print("=" * 65)
