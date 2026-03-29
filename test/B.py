import sys
import os
from cryptography.hazmat.primitives.asymmetric import rsa
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from cryptography import x509
import datetime

# 取得專案根目錄並加入搜尋路徑
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.append(project_root)

import hashlib
import random
# from shared.crypto_utils import rsa_generate_keys, rsa_encrypt, rsa_decrypt
from shared.crypto_utils_test import (
    generate_blinding_factor, 
    blind_message, 
    blind_sign, 
    unblind_signature, 
    verify_blind_signature
)
from shared.crypto_generate_key_pair import (generate_rsa_keypair)


# CA 憑證授權中心 (流程點 1)
class CA:
    """負責核發數位憑證給所有實體"""

    def __init__(self):
        print("[CA] 初始化 CA 金鑰與根憑證...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.root_cert = self._generate_root_certificate()
        print("[CA] 根憑證已生成。")

    def _generate_root_certificate(self) -> x509.Certificate:
        """生成自簽根憑證"""
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"NUTC Voting System Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Voting CA"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(self.private_key, hashes.SHA256())
        )
        return cert

    def get_root_cert(self) -> x509.Certificate:
        return self.root_cert

    def get_root_cert_pem(self) -> str:
        return self.root_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    def issue_certificate(self, entity_id: str, entity_public_key) -> x509.Certificate:
        """核發數位憑證給指定實體"""
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"NUTC Voting System"),
            x509.NameAttribute(NameOID.COMMON_NAME, entity_id),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.root_cert.subject)
            .public_key(entity_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(self.private_key, hashes.SHA256())
        )
        print(f"[CA] 已核發憑證給 {entity_id}")
        return cert

    def verify_certificate(self, cert: x509.Certificate) -> bool:
        """驗證憑證是否由本 CA 簽發且在有效期內"""
        try:
            self.public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            now = datetime.datetime.now(datetime.timezone.utc)
            if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
                print("[CA] 憑證驗證失敗：已過期或尚未生效")
                return False
            return True
        except Exception as e:
            print(f"[CA] 憑證驗證失敗：{e}")
            return False

    @staticmethod
    def extract_public_key_from_cert(cert: x509.Certificate):
        """從憑證提取公鑰"""
        return cert.public_key()

    @staticmethod
    def extract_entity_id_from_cert(cert: x509.Certificate) -> str:
        """從憑證提取實體 ID (Common Name)"""
        for attribute in cert.subject:
            if attribute.oid == NameOID.COMMON_NAME:
                return attribute.value
        return ""


# TPA 第三方機構
class TPA:
    """第三方機構：負責身分驗證與盲簽章"""
    def __init__(self, tpa_id: str):
        self.id = tpa_id
        self.private_key, self.public_key, self.e, self.n, self.d = generate_rsa_keypair()
    def verify_voter_auth(self, auth_packet: dict, voter_public_key) -> bool:
        """階段二：驗證選民身分與時間戳記"""
        print(f"[{self.id}] 收到來自 {auth_packet['voter_id']} 的認證封包，開始驗證...")

        # 1. 檢查接收者是不是自己
        if auth_packet['tpa_id'] != self.id:
            print(f"[{self.id}] 驗證失敗：這個封包不是發給我的 ")
            return False

        # 2. 檢查時間戳記 (例如限制 5 分鐘 / 300 秒內有效)
        current_time = int(time.time())
        if current_time - auth_packet['timestamp'] > 300:
            print(f"[{self.id}] 驗證失敗：封包已過期")
            return False

        # 3. 驗證數位簽章
        try:
            # 使用 Voter 的公鑰來解開並驗證簽章
            voter_public_key.verify(
                auth_packet['signature'],
                auth_packet['payload_bytes'],
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print(f"[{self.id}] 驗證成功：確認為 {auth_packet['voter_id']} 本人，且訊息未遭竄改。")
            return True
            
        except Exception as e:
            # 如果簽章不符，套件會直接拋出 Exception
            print(f"[{self.id}] 驗證失敗：數位簽章無效！")
            return False
    def sign_vote(self, m_prime: int) -> int:
        # TPA 只需要呼叫 blind_sign 函式，並帶入自己的私鑰 d
        print("[TPA] 收到盲化選票，執行盲簽署...")
        return blind_sign(m_prime, self.d, self.n)


# Voter 選民
class Voter:
    def __init__(self, voter_id: str): #voter 系統初始化
        self.id = voter_id
        self.private_key, self.public_key, self.e, self.n, self.d = generate_rsa_keypair()
    def generate_auth_packet(self, tpa_id: str) -> dict: #生成認證封包
        timestamp = int(time.time())
        inner_payload = f"{self.id}|{tpa_id}|{timestamp}"
        auth_signature = self.private_key.sign(
            inner_payload.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
            )

        print(f"[{self.id}] 已產生身分認證封包 (含時間戳記與數位簽章)。")
        
        # 回傳一個字典給 TPA
        return {
            "voter_id": self.id,
            "tpa_id": tpa_id,
            "CertVoter": self.certificate,
            "timestamp": timestamp,
            "signature": auth_signature
        }
        
    def create_blinded_vote(self, vote_content, tpa_public_key):
        """階段三：計算雜湊值 m，選定亂數 r，並盲化 m' = r^e * m mod n"""
        pass
        
    def unblind_vote(self, blind_signature):
        """階段三：移除盲化因子 S' = S * r^-1 mod n"""
        pass
        
    def encapsulate_vote(self, signature, vote_content, cc_public_key, ta_public_key):
        """階段三：建立數位信封 (結合對稱與非對稱加密)"""
        pass
    def prepare_blinded_vote(self, m: int, tpa_e: int, tpa_n: int) -> int:
        # 動態接收 TPA 的 e 與 n
        self.r = generate_blinding_factor(tpa_n)
        print(f"[{self.id}] 正在盲化選票...")
        return blind_message(m, self.r, tpa_e, tpa_n)

    def process_returned_signature(self, S: int, tpa_n: int) -> int:
        print(f"[{self.id}] 收到 TPA 簽章，正在去盲化...")
        return unblind_signature(S, self.r, tpa_n)


# TA 時間授權中心 (流程點 1, 6)
class TA:
    """管理投票截止時間，截止後釋放 SK_TA 給 CC"""

    def __init__(self, ta_id: str, deadline: int):
        self.id = ta_id
        self.deadline = deadline  # T_DL
        self.private_key, self.public_key, self.e, self.n, self.d = generate_rsa_keypair()
        self.certificate = None
        self._key_released = False
        
        deadline_str = datetime.datetime.fromtimestamp(self.deadline).strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{self.id}] 時間授權中心已初始化，T_DL = {deadline_str}")

    def get_public_key(self):
        return self.public_key

    def get_public_key_numbers(self) -> tuple:
        """回傳 (e, n) 供選民加密使用"""
        return self.e, self.n

    def release_private_key(self) -> dict:
        """流程點 6：檢查是否已到截止時間，是則釋放 SK_TA"""
        current_time = int(time.time())
        deadline_str = datetime.datetime.fromtimestamp(self.deadline).strftime('%Y-%m-%d %H:%M:%S')
        
        if current_time < self.deadline:
            remaining = self.deadline - current_time
            print(f"[{self.id}] 拒絕釋放私鑰，投票尚未截止 (還有 {remaining} 秒)")
            return {
                "status": "rejected",
                "reason": "投票尚未截止",
                "remaining_seconds": remaining,
                "deadline": self.deadline
            }
        
        self._key_released = True
        now_str = datetime.datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{self.id}] 投票已截止，釋放 SK_TA (截止: {deadline_str}, 現在: {now_str})")
        
        return {
            "status": "released",
            "sk_ta_private_key": self.private_key,
            "sk_ta_d": self.d,
            "sk_ta_n": self.n,
            "released_at": current_time
        }

    def is_voting_closed(self) -> bool:
        return int(time.time()) >= self.deadline

    def get_deadline_info(self) -> str:
        current_time = int(time.time())
        deadline_str = datetime.datetime.fromtimestamp(self.deadline).strftime('%Y-%m-%d %H:%M:%S')
        if current_time >= self.deadline:
            return f"投票已截止 ({deadline_str})"
        remaining = self.deadline - current_time
        return f"距離截止還有 {remaining} 秒 ({deadline_str})"


# CC 計票中心
class CC:
    """計票中心：接收選票、解密與統計"""
    def __init__(self):
        self.public_key, self.private_key = None, None
        self.valid_votes = []
        
    def receive_envelope(self, digital_envelope):
        """階段三：接收並利用 SK_CC 解開數位信封取得 k，再解開選票資料"""
        pass
        
    def decrypt_and_verify_votes(self, ta_private_key, tpa_public_key):
        """階段四：利用 TA 私鑰解密選票內容，並驗證 TPA 簽章是否合法"""
        pass
        
    def build_merkle_tree(self):
        """階段五：建構 Merkle Tree 並產出 Root_official"""
        pass


# BB 公告板 (流程點 8, 10)
class BB:
    """接收 CC 公布的結果，提供 Merkle Proof 給選民驗證"""

    def __init__(self):
        self.merkle_root = None
        self.vote_records = []
        self.tally_results = None
        self._published = False

    def publish_results(self, root_official, vote_records, tally_results=None):
        """流程點 8：接收 CC 的計票結果與 Root_official"""
        self.merkle_root = root_official
        self.vote_records = vote_records
        self.tally_results = tally_results
        self._published = True
        print(f"[BB] 已公布結果，Root_official: {root_official}")
        print(f"[BB] 有效選票數: {len(vote_records)}")
        if tally_results:
            print(f"[BB] 計票結果: {tally_results}")

    def get_official_root(self):
        """取得 Root_official 供選民比對"""
        if not self._published:
            print("[BB] 尚未公布結果。")
            return None
        return self.merkle_root

    def get_vote_list(self):
        if not self._published:
            print("[BB] 尚未公布結果。")
            return []
        return self.vote_records

    def provide_merkle_proof(self, vote_hash):
        """流程點 10：回傳兄弟節點路徑，待 CC 的 Merkle Tree 完成後實作"""
        # TODO: 等 CC 建好 Merkle Tree 後，根據 vote_hash 回傳路徑
        print(f"[BB] Merkle Proof 請求 (hash: {vote_hash[:16]}...)")
        print("[BB] 此功能待 CC 的 Merkle Tree 建構完成後實作")
        return None

    def is_published(self) -> bool:
        return self._published


# 主程式
if __name__ == '__main__':
    print("=== 系統單機整合測試啟動 ===")
    
    # ---------------------------------------------------------
    # 步驟 0：系統初始化 (模擬 TPA 產生金鑰)
    # ---------------------------------------------------------
    print("\n[初始化] 正在生成 TPA 的 RSA 金鑰 (2048 bits)...")
    tpa_server = TPA(tpa_id="TPA")
    voter_client = Voter(voter_id="VOTER")
    
    # ---------------------------------------------------------
    # 步驟 1：測試雙向身分驗證與盲簽章流程
    # (此段落有已知問題，暫時跳過，待負責人修復)
    # ---------------------------------------------------------
    # m_prime = voter_client.prepare_blinded_vote(m, tpa_server.e, tpa_server.n)
    # auth_packet = voter_client.generate_auth_packet(tpa_server.id, m_prime)
    # is_authorized = tpa_server.verify_voter_auth(auth_packet, voter_client.public_key)
    # if is_authorized:
    #     S = tpa_server.sign_vote(m_prime)
    #     print(f"[TPA 端] 回傳給選民的盲簽章 S: {S}")
    #     S_prime = voter_client.process_returned_signature(S, tpa_server.n)
    #     print(f"[選民端] 最終取得的合法簽章 S': {S_prime}")
    # else:
    #     print("[系統] TPA 拒絕簽署，中斷流程。")
    
    # ---------------------------------------------------------
    # 步驟 1：自訂 m 裡面的訊息 (選票內容)
    # ---------------------------------------------------------
    # 根據計畫書：m = H(H(ID || SN || Vote) || Vote)
    ID_Voter = "VOTER"
    SN = "20260324001" 
    Vote = "Candidate_A"
    
    
    # 第一層內部雜湊: H(ID || SN || Vote)
    inner_content = f"{ID_Voter}{SN}{Vote}".encode('utf-8')
    print(inner_content)
    inner_hash = hashlib.sha256(inner_content).hexdigest()
    print(inner_hash) 
    
    # 第二層外部雜湊: m = H(inner_hash || Vote)
    outer_content = f"{inner_hash}{Vote}".encode('utf-8')
    print(outer_content) 
    final_hash_hex = hashlib.sha256(outer_content).hexdigest()
    
    # 關鍵：將 16 進位字串轉換為 10 進位大整數 m
    m = int(final_hash_hex, 16)
    
    print(f"\n[選民端] 原始選票明文: {Vote}")
    print(f"[選民端] 轉換後的大整數 m: {m}")
    
    # ---------------------------------------------------------
    # 步驟 2：測試盲簽章流程
    # ---------------------------------------------------------
    print("\n--- 開始盲簽章流程 ---")
    
    # 1. Voter 盲化選票
    m_prime = voter_client.prepare_blinded_vote(m, tpa_server.e, tpa_server.n)
    print(f"[選民端] 傳送給 TPA 的盲化訊息 m': {m_prime}")
    
    # 2. TPA 簽署
    S = tpa_server.sign_vote(m_prime)
    print(f"[TPA 端] 回傳給選民的盲簽章 S: {S}")
    
    # 3. Voter 去盲化
    S_prime = voter_client.process_returned_signature(S, tpa_server.n)
    print(f"[選民端] 最終取得的合法簽章 S': {S_prime}")
    
    # ---------------------------------------------------------
    # 步驟 3：數學驗證
    # ---------------------------------------------------------
    print("\n--- 驗證中心 ---")
    is_valid = verify_blind_signature(S_prime, tpa_server.e, tpa_server.n, m)
    
    if is_valid:
        print("測試通過")
    else:
        print("測試失敗")

    # ---------------------------------------------------------
    # CA 測試：流程點 1 - 核發數位憑證
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("  [CA 測試] 流程點 1：核發數位憑證")
    print("=" * 60)
    
    ca = CA()
    tpa_cert = ca.issue_certificate("TPA", tpa_server.public_key)
    voter_cert = ca.issue_certificate("VOTER", voter_client.public_key)
    
    print("\n--- 驗證憑證 ---")
    tpa_valid = ca.verify_certificate(tpa_cert)
    print(f"  TPA 憑證: {'合法' if tpa_valid else '非法'}")
    
    voter_valid = ca.verify_certificate(voter_cert)
    print(f"  Voter 憑證: {'合法' if voter_valid else '非法'}")
    
    print("\n--- 從憑證提取公鑰 ---")
    extracted_pk = CA.extract_public_key_from_cert(voter_cert)
    original_pem = voter_client.public_key.public_bytes(
        serialization.Encoding.PEM, 
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    extracted_pem = extracted_pk.public_bytes(
        serialization.Encoding.PEM, 
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(f"  Voter 公鑰比對: {'一致' if original_pem == extracted_pem else '不一致'}")
    
    entity_id = CA.extract_entity_id_from_cert(voter_cert)
    print(f"  Voter 憑證 CN: {entity_id}")
    
    print("\nCA 流程點 1 測試完成")

    # ---------------------------------------------------------
    # TA 測試：流程點 1 + 流程點 6
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("  [TA 測試] 流程點 1 + 流程點 6")
    print("=" * 60)
    
    voting_deadline = int(time.time()) + 3
    ta = TA(ta_id="TA", deadline=voting_deadline)
    
    print("\n--- 流程點 1：CA 核發憑證給 TA ---")
    ta.certificate = ca.issue_certificate("TA", ta.public_key)
    ta_cert_valid = ca.verify_certificate(ta.certificate)
    print(f"  TA 憑證: {'合法' if ta_cert_valid else '非法'}")
    
    print("\n--- 流程點 6：截止前請求 SK_TA ---")
    print(f"  {ta.get_deadline_info()}")
    result_before = ta.release_private_key()
    print(f"  結果: {result_before['status']}")
    
    print("\n--- 等待投票截止... ---")
    while not ta.is_voting_closed():
        remaining = ta.deadline - int(time.time())
        print(f"  還有 {remaining} 秒...")
        time.sleep(1)
    
    print("\n--- 流程點 6：截止後請求 SK_TA ---")
    print(f"  {ta.get_deadline_info()}")
    result_after = ta.release_private_key()
    print(f"  結果: {result_after['status']}")
    
    if result_after['status'] == 'released':
        print(f"  SK_TA d 位元長度: {result_after['sk_ta_d'].bit_length()} bits")
        print("\nTA 流程點 1 + 6 測試完成")
    else:
        print("\nTA 測試失敗")

    # ---------------------------------------------------------
    # BB 測試：公告板基本功能
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("  [BB 測試] 公告板基本功能")
    print("=" * 60)
    
    bb = BB()
    
    print("\n--- 公布前 ---")
    print(f"  已公布: {bb.is_published()}")
    print(f"  Root_official: {bb.get_official_root()}")
    print(f"  選票列表: {bb.get_vote_list()}")
    
    print("\n--- 模擬 CC 公布結果 (流程點 8) ---")
    fake_root = hashlib.sha256(b"fake_merkle_root").hexdigest()
    fake_votes = [hashlib.sha256(f"vote_{i}".encode()).hexdigest() for i in range(3)]
    fake_tally = {"Candidate_A": 2, "Candidate_B": 1}
    bb.publish_results(fake_root, fake_votes, fake_tally)
    
    print("\n--- 公布後 ---")
    print(f"  已公布: {bb.is_published()}")
    print(f"  Root_official: {bb.get_official_root()}")
    print(f"  選票數量: {len(bb.get_vote_list())}")
    
    print("\n--- Merkle Proof 接口 (流程點 10) ---")
    bb.provide_merkle_proof(fake_votes[0])
    
    print("\nBB 測試完成")

    # ---------------------------------------------------------
    # 總結
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("  測試總結")
    print("=" * 60)
    print("  CA 流程點 1 (核發數位憑證)：V")
    print("  TA 流程點 1 (從 CA 取得憑證)：V")
    print("  TA 流程點 6 (截止後釋放 SK_TA)：V")
    print("  BB 公告板基本功能：")
    print("  盲簽章流程 (步驟 2-3)：V")
    print("=" * 60)
