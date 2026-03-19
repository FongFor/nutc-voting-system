import random
import math

# ==========================================
# 盲簽章 (Blind Signature) 核心數學模組
# ==========================================

def generate_blinding_factor(n: int) -> int:
    """
    選民 (Voter) 使用：生成一個與模數 n 互質的隨機盲化因子 r
    """
    while True:
        r = random.randrange(2, n - 1)
        if math.gcd(r, n) == 1:
            return r

def blind_message(m: int, r: int, e: int, n: int) -> int:
    """
    選民 (Voter) 使用：盲化選票雜湊值
    計算: m' = (m * r^e) mod n
    """
    r_pow_e = pow(r, e, n)
    m_prime = (m * r_pow_e) % n
    return m_prime

def blind_sign(m_prime: int, d: int, n: int) -> int:
    """
    第三方機構 (TPA) 使用：對盲化訊息進行簽署
    計算: S = (m')^d mod n
    """
    S = pow(m_prime, d, n)
    return S

def unblind_signature(S: int, r: int, n: int) -> int:
    """
    選民 (Voter) 使用：移除盲化因子，取得最終合法簽章
    計算: S' = (S * r^-1) mod n
    """
    # pow(r, -1, n) 會計算 r 在模 n 下的乘法反元素
    r_inv = pow(r, -1, n)
    S_prime = (S * r_inv) % n
    return S_prime

def verify_blind_signature(S_prime: int, e: int, n: int, m: int) -> bool:
    """
    計票中心 (CC) 或任何人使用：驗證簽章是否合法
    根據計畫書，檢查 S'^{PK_TPA} == m 是否成立 [cite: 92]
    也就是檢查: (S')^e mod n == m
    """
    return pow(S_prime, e, n) == m