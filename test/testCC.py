import sys
import os
import time
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from shared.crypto_utils_test import (
    generate_blinding_factor,
    blind_message,
    blind_sign,
    unblind_signature,
    verify_blind_signature
)
from shared.crypto_generate_key_pair import generate_rsa_keypair

# -----------------------------
# 類別定義
# -----------------------------
class TPA:
    def __init__(self, tpa_id: str):
        self.id = tpa_id
        self.private_key, self.public_key, self.e, self.n, self.d = generate_rsa_keypair()

    def verify_voter_auth(self, auth_packet: dict, voter_public_key) -> bool:
        print(f"[{self.id}] 收到 {auth_packet['voter_id']} 的認證封包，開始驗證...")
        if auth_packet['tpa_id'] != self.id:
            print("[TPA] 封包不是發給我的")
            return False
        current_time = int(time.time())
        if current_time - auth_packet['timestamp'] > 300:
            print("[TPA] 封包已過期")
            return False
        try:
            voter_public_key.verify(
                auth_packet['signature'],
                auth_packet['payload_bytes'],
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("[TPA] 驗證成功")
            return True
        except Exception as e:
            print("[TPA] 驗證失敗")
            return False

    def sign_vote(self, m_prime: int) -> int:
        print("[TPA] 收到盲化選票，執行盲簽署...")
        return blind_sign(m_prime, self.d, self.n)

class Voter:
    def __init__(self, voter_id: str):
        self.id = voter_id
        self.private_key, self.public_key, self.e, self.n, self.d = generate_rsa_keypair()
        self.r = None

    # 修改 generate_auth_packet 支援 m_prime
    def generate_auth_packet(self, tpa_id: str, m_prime: int) -> dict:
        timestamp = int(time.time())
        inner_payload = f"{self.id}|{tpa_id}|{timestamp}|{m_prime}"
        auth_signature = self.private_key.sign(
            inner_payload.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"[{self.id}] 已產生身分認證封包")
        return {
            "voter_id": self.id,
            "tpa_id": tpa_id,
            "payload_bytes": inner_payload.encode('utf-8'),
            "signature": auth_signature
        }

    def prepare_blinded_vote(self, m: int, tpa_e: int, tpa_n: int) -> int:
        self.r = generate_blinding_factor(tpa_n)
        print(f"[{self.id}] 正在盲化選票...")
        return blind_message(m, self.r, tpa_e, tpa_n)

    def process_returned_signature(self, S: int, tpa_n: int) -> int:
        print(f"[{self.id}] 收到 TPA 簽章，正在去盲化...")
        return unblind_signature(S, self.r, tpa_n)

    def encapsulate_vote(self, S_prime, vote_content, m_int, cc_public_key, ta_public_key):
        k = os.urandom(32)
        plaintext = f"{vote_content}|{S_prime}|{m_int}".encode('utf-8')
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(k), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        k_enc_cc = cc_public_key.encrypt(
            k,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        k_enc_ta = ta_public_key.encrypt(
            k,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {
            "ciphertext": ciphertext,
            "iv": iv,
            "k_enc_cc": k_enc_cc,
            "k_enc_ta": k_enc_ta
        }

class TA:
    def __init__(self):
        self.private_key, self.public_key, _, _, _ = generate_rsa_keypair()

    def release_private_key(self, current_time, deadline):  # 給私鑰
        if current_time >= deadline:
            print("[TA] 時間到，釋放私鑰")
            return self.private_key
        return None

class CC:
    def __init__(self):
        self.private_key, self.public_key, _, _, _ = generate_rsa_keypair()
        self.pending_votes = []     # 放選票
        self.valid_votes = []       # 放TA資料

    def receive_envelope(self, digital_envelope):
        k = self.private_key.decrypt(
            digital_envelope['k_enc_cc'],       # 拿加密過的 k_enc_cc
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # 儲存未解密過的選票資料
        self.pending_votes.append({
            "ciphertext": digital_envelope['ciphertext'],
            "iv": digital_envelope['iv'],
            "k": k,
            "k_enc_ta": digital_envelope['k_enc_ta']
        })
        print("[CC] 接收數位信封完成")

    def decrypt_and_verify_votes(self, ta_private_key, tpa_e, tpa_n):
        for vote in self.pending_votes:
            k_ta = ta_private_key.decrypt(      # 使用 ta_private_key 解密
                vote['k_enc_ta'],
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            if k_ta != vote['k']:
                print("[CC] 金鑰不一致，信封被篡改")
                continue
            
            cipher = Cipher(algorithms.AES(vote['k']), modes.CFB(vote['iv']))
            decryptor = cipher.decryptor()        # 解密器
            plaintext = decryptor.update(vote['ciphertext']) + decryptor.finalize()     # 解密文
            vote_content, s_prime_str, m_str = plaintext.decode('utf-8').split("|")     # 解碼及分割字串
            # 轉整數
            s_prime = int(s_prime_str)
            m_int = int(m_str)

            if pow(s_prime, tpa_e, tpa_n) == m_int:
                print(f"[CC] 選票合法: {vote_content}")
                self.valid_votes.append((vote_content, s_prime, m_int))
            else:
                print(f"[CC] 選票非法: {vote_content}")

# -----------------------------
# 主程式
# -----------------------------
if __name__ == '__main__':
    print("=== 系統單機整合測試啟動 ===")

    # 系統初始化
    tpa_server = TPA("TPA")
    voter_client = Voter("VOTER")
    voter = voter_client
    tpa = tpa_server
    ta = TA()
    cc = CC()

    # 選票內容
    ID_Voter = "VOTER"
    SN = "20260324001"
    Vote = "Candidate_A"

    # 計算選票雜湊 m
    inner_hash = hashlib.sha256(f"{ID_Voter}{SN}{Vote}".encode('utf-8')).hexdigest()
    outer_hash = hashlib.sha256(f"{inner_hash}{Vote}".encode('utf-8')).hexdigest()
    m = int(outer_hash, 16)
    
    print(f"[選民端] 原始選票明文: {Vote}")
    print(f"[選民端] 轉換後的大整數 m: {m}")

    # 盲簽流程
    m_prime = voter.prepare_blinded_vote(m, tpa.e, tpa.n)
    auth_packet = voter.generate_auth_packet(tpa.id, m_prime)
    is_authorized = tpa.verify_voter_auth(auth_packet, voter.public_key)

    if is_authorized:
        S = tpa.sign_vote(m_prime)
        S_prime = voter.process_returned_signature(S, tpa.n)
    else:
        raise Exception("TPA 拒絕簽署，中斷流程")

    # 建立數位信封
    digital_envelope = voter.encapsulate_vote(S_prime, Vote, m, cc.public_key, ta.public_key)
    cc.receive_envelope(digital_envelope)

    # 投票截止，TA 釋出私鑰
    ta_private_key = ta.release_private_key(int(time.time()), int(time.time())-1)

    # CC 解密並驗證
    cc.decrypt_and_verify_votes(ta_private_key, tpa.e, tpa.n)

    print(f"\n=== 最終合法選票: {cc.valid_votes} ===")

    # 數學驗證
    is_valid = verify_blind_signature(S_prime, tpa.e, tpa.n, m)
    print("--- 驗證中心 ---")
    print("測試通過" if is_valid else "測試失敗")