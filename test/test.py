import sys
import os
from cryptography.hazmat.primitives.asymmetric import rsa

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

class CA:
    """憑證授權中心：負責核發與驗證數位憑證"""
    def __init__(self):
        # 生成 CA 的金鑰對與根憑證
        pass
    def issue_certificate(self, entity_id, public_key):
        pass

class TPA:
    """第三方機構：負責身分驗證與盲簽章"""
    def __init__(self, e,d,n):
        self.e = e
        self.d = d
        self.n = n
    def verify_voter_auth(self, auth_packet):
        """階段二：驗證選民身分與時間戳記"""
        pass
        
    def blind_sign(self, blinded_message):
        """階段三：使用私鑰對盲化選票進行簽署 S = (m')^d mod n"""
        pass
    def sign_vote(self, m_prime: int) -> int:
        # TPA 只需要呼叫 blind_sign 函式，並帶入自己的私鑰 d
        print("[TPA] 收到盲化選票，執行盲簽署...")
        return blind_sign(m_prime, self.d, self.n)
class Voter:
    """選民：系統的主要使用者"""
    def __init__(self, tpa_e, tpa_n):
        # Voter 已經從憑證中心或公告板拿到了 TPA 的公鑰參數
        self.tpa_e = tpa_e
        self.tpa_n = tpa_n
        self.r = None # 準備存放盲化因子
    def generate_auth_packet(self, tpa_id):
        """階段二：產生雙向身分認證封包"""
        pass
        
    def create_blinded_vote(self, vote_content, tpa_public_key):
        """階段三：計算雜湊值 m，選定亂數 r，並盲化 m' = r^e * m mod n"""
        pass
        
    def unblind_vote(self, blind_signature):
        """階段三：移除盲化因子 S' = S * r^-1 mod n"""
        pass
        
    def encapsulate_vote(self, signature, vote_content, cc_public_key, ta_public_key):
        """階段三：建立數位信封 (結合對稱與非對稱加密)"""
        pass
    def prepare_blinded_vote(self, m: int) -> int:
        # 1. 產生盲化因子
        self.r = generate_blinding_factor(self.tpa_n)
        # 2. 呼叫 blind_message 函式進行盲化
        print("[Voter] 正在盲化選票...")
        return blind_message(m, self.r, self.tpa_e, self.tpa_n)

    def process_returned_signature(self, S: int) -> int:
        # 3. 呼叫 unblind_signature 函式去盲化
        print("[Voter] 收到 TPA 簽章，正在去盲化...")
        return unblind_signature(S, self.r, self.tpa_n)
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
    # 步驟 0：系統初始化 (模擬 TPA 產生金鑰)
    # ---------------------------------------------------------
    print("\n[初始化] 正在生成 TPA 的 RSA 金鑰 (2048 bits)...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    tpa_e = public_key.public_numbers().e
    tpa_n = public_key.public_numbers().n
    tpa_d = private_key.private_numbers().d
    
    # 實例化 TPA 與 Voter
    tpa_server = TPA(e=tpa_e, d=tpa_d, n=tpa_n)
    voter_client = Voter(tpa_e=tpa_e, tpa_n=tpa_n)
    
    # ---------------------------------------------------------
    # 步驟 1：自訂 m 裡面的訊息 (選票內容)
    # ---------------------------------------------------------
    # 根據計畫書：m = H(H(ID || SN || Vote) || Vote)
    ID_Voter = "Weilun_001"
    SN = "20260312001" 
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
    m_prime = voter_client.prepare_blinded_vote(m)
    print(f"[選民端] 傳送給 TPA 的盲化訊息 m': {m_prime}")
    
    # 2. TPA 簽署
    S = tpa_server.sign_vote(m_prime)
    print(f"[TPA 端] 回傳給選民的盲簽章 S: {S}")
    
    # 3. Voter 去盲化
    S_prime = voter_client.process_returned_signature(S)
    print(f"[選民端] 最終取得的合法簽章 S': {S_prime}")
    
    # ---------------------------------------------------------
    # 步驟 3：數學驗證
    # ---------------------------------------------------------
    print("\n--- 驗證中心 ---")
    is_valid = verify_blind_signature(S_prime, tpa_e, tpa_n, m)
    
    if is_valid:
        print("測試通過")
    else:
        print("測試失敗")