import sys
import os
from cryptography.hazmat.primitives.asymmetric import rsa
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# 1. 取得目前 test.py 所在的絕對路徑
current_dir = os.path.dirname(os.path.abspath(__file__))

# 2. 往上一層找到專案根目錄 (nutc-voting-system)
project_root = os.path.dirname(current_dir)

# 3. 把專案根目錄加進 Python 的搜尋路徑中
sys.path.append(project_root)
import hashlib
import random
# 先假設我們有一個自訂的 RSA 工具庫來處理大數運算
# from shared.crypto_utils import rsa_generate_keys, rsa_encrypt, rsa_decrypt
from shared.crypto_utils_test import (
    generate_blinding_factor, 
    blind_message, 
    blind_sign, 
    unblind_signature, 
    verify_blind_signature
)
from shared.crypto_generate_key_pair import (generate_rsa_keypair)
from shared.auth_component import (create_auth_packet, verify_auth_component , verify_auth_component_temp)

class CA:
    """憑證授權中心：負責核發與驗證數位憑證"""
    def __init__(self):
        # 生成 CA 的金鑰對與根憑證
        pass
    def issue_certificate(self, entity_id, public_key):
        pass

class TPA:
    """第三方機構：負責身分驗證與盲簽章"""
    def __init__(self, tpa_id: str):
        self.id = tpa_id
        self.private_key, self.public_key, self.e, self.n, self.d = generate_rsa_keypair()
        self.certificate = "TPA_CERT_PEM_DATA"
    # def verify_voter_auth(self, auth_packet: dict, ca_public_key) -> bool:
    #         """使用通用組件驗證選民"""
    #         try:
    #             # 調用 auth_component
    #             voter_pub_key = verify_auth_component(
    #                 expected_receiver_id=self.id,
    #                 sender_id=auth_packet['payload']['sender_id'],
    #                 packet_receiver_id=auth_packet['payload']['receiver_id'],
    #                 packet_timestamp=auth_packet['payload']['timestamp'],
    #                 packet_cert_pem=auth_packet['payload']['certificate'],
    #                 packet_signature=bytes.fromhex(auth_packet['signature']), # 轉回 bytes
    #                 packet_si=auth_packet['payload']['si'],
    #                 ca_public_key=ca_public_key
    #             )
    #             print(f"[{self.id}] 驗證成功：確認為 {auth_packet['payload']['sender_id']} 本人。")
    #             return voter_pub_key
    #         except Exception as e:
    #             print(f"[{self.id}] 驗證失敗：{str(e)}")
    #             return False
    def verify_voter_auth(self, auth_packet: dict, voter_public_key) -> bool:
        print(f"[{self.id}] 正在驗證來自 {auth_packet['payload']['sender_id']} 的封包...")
        try:
            # 調用臨時驗證組件
            return verify_auth_component_temp(
                expected_receiver_id=self.id,
                packet=auth_packet,
                sender_public_key=voter_public_key
            )
        except Exception as e:
            print(f"[{self.id}] 驗證失敗：{str(e)}")
            return False

    def generate_response_packet(self, voter_id: str) -> dict:
            """TPA 驗證後，產生回傳給選民的認證封包 (雙向認證)"""
            return create_auth_packet(self.id, voter_id, self.private_key, self.certificate)
    def sign_vote(self, m_prime: int) -> int:
        # TPA 只需要呼叫 blind_sign 函式，並帶入自己的私鑰 d
        print("[TPA] 收到盲化選票，執行盲簽署...")
        return blind_sign(m_prime, self.d, self.n)
class Voter:
    def __init__(self, voter_id: str): #voter 系統初始化
        self.id = voter_id
        self.private_key, self.public_key, self.e, self.n, self.d = generate_rsa_keypair()
        self.certificate = "VOTER_CERT_PEM_DATA" # 模擬已有的憑證
    def generate_auth_packet(self, tpa_id: str) -> dict:
        """使用通用組件生成認證封包"""
        return create_auth_packet(self.id, tpa_id, self.private_key, self.certificate)

    def verify_tpa_auth(self, response_packet: dict, ca_public_key) -> bool:
        """選民端驗證 TPA 的身分 (雙向認證的最後一步)"""
        try:
            # tpa_pub_key = verify_auth_component(
            #     expected_receiver_id=self.id,
            #     sender_id=response_packet['payload']['sender_id'],
            #     packet_receiver_id=response_packet['payload']['receiver_id'],
            #     packet_timestamp=response_packet['payload']['timestamp'],
            #     packet_cert_pem=response_packet['payload']['certificate'],
            #     packet_signature=bytes.fromhex(response_packet['signature']),
            #     packet_si=response_packet['payload']['si'],
            #     ca_public_key=ca_public_key
            # )
            # print(f"[{self.id}] 雙向認證成功：確認 TPA 為合法機構。")
            # return tpa_pub_key
            return verify_auth_component_temp(
                expected_receiver_id=self.id,
                packet=response_packet,
                sender_public_key=ca_public_key
            )
        except Exception as e:
            print(f"[{self.id}] 雙向認證失敗：{str(e)}")
            return False
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
class TA:
    """時間授權中心：管理開票時間"""
    def __init__(self):
        self.public_key, self.private_key = None, None
        
    def release_private_key(self, current_time, deadline):
        """階段四：時間截止後，釋放 SK_TA 給 CC"""
        pass

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

class BB:
    """公告板：公開透明的資訊發布平台"""
    def __init__(self):
        self.merkle_root = None
        self.vote_records = []
        
    def publish_results(self, root, records):
        """階段五：CC 公布結果至此"""
        pass
        
    def provide_merkle_proof(self, vote_hash):
        """階段六：提供選民驗證所需的兄弟節點路徑 (Merkle Proof)"""
        pass
if __name__ == '__main__':
    print("=== 系統單機整合測試啟動 ===")
    
    # ---------------------------------------------------------
    # 步驟 0：系統初始化 (模擬 TPA 與VOTER 產生金鑰)
    # ---------------------------------------------------------
    print("\n[初始化] 正在生成 TPA 與 VOTER 的 RSA 金鑰 (2048 bits)...")
    tpa_server = TPA(tpa_id="TPA")
    voter_client = Voter(voter_id="VOTER")
    
    # ---------------------------------------------------------
    # 步驟 1：測試雙向身分驗證與盲簽章流程
    # ---------------------------------------------------------
    print("\n--- 開始身分驗證流程 ---")
    # 假設我們有一個模擬的 CA 公鑰用於測試憑證 (實際中需從憑證庫讀取)
    mock_ca_public_key = tpa_server.public_key # 簡化測試：暫時拿 TPA 的湊合

    # 1. Voter 產生認證封包
    auth_packet = voter_client.generate_auth_packet(tpa_server.id)
    
    # 2. TPA 驗證選民
    # 注意：需傳入 CA 公鑰
    if tpa_server.verify_voter_auth(auth_packet, voter_client.public_key):
        
        # 3. TPA 驗證成功後，產生回傳封包給 Voter
        response_packet = tpa_server.generate_response_packet(voter_client.id)
        
        # 4. Voter 驗證 TPA (完成雙向認證)
        if voter_client.verify_tpa_auth(response_packet, tpa_server.public_key):
            print("\n>>> 雙向身分認證達成，進入盲簽章階段 <<<")
            
            # 5. 執行盲簽章邏輯
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
            # ... 你的雜湊計算邏輯 ...
            m_prime = voter_client.prepare_blinded_vote(m, tpa_server.e, tpa_server.n)
            S = tpa_server.sign_vote(m_prime)
            S_prime = voter_client.process_returned_signature(S, tpa_server.n)
    
    
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
            
    
