"""
shared/blind_signature.py  —  盲簽章 (Blind Signature) 核心數學模組

v2.0 升級：採用 RSA-FDH-Blind (Full-Domain Hash Blind Signature)

RSA-FDH-Blind 盲簽章流程：
  1. Voter：計算 μ = FDH(m, n_bits)，生成盲化因子 r，計算 m' = μ * r^e mod n
  2. TPA：對盲化訊息簽章，計算 S = (m')^d mod n
  3. Voter：去盲化，計算 S' = S * r^-1 mod n
  4. 任何人：驗證 (S')^e mod n == FDH(m, n_bits)

v2.0 變更：
  - 新增 FDH (Full-Domain Hash) 擴展，抵抗存在性偽造攻擊
  - 驗證時使用 FDH(m) 而非直接使用 m
  - 基於 MGF1-SHA256 實作 FDH

各角色使用的函式：
  - Voter：fdh, generate_blinding_factor, blind_message, unblind_signature, verify_blind_signature
  - TPA：blind_sign
  - CC：verify_blind_signature
"""

import secrets
import math
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def fdh(m: bytes, n_bits: int) -> int:
    """
    Full-Domain Hash (FDH) 實作
    
    將訊息 m 擴展為接近 RSA 模數 n 的位元長度的整數。
    使用 MGF1-SHA256 作為擴展函數。
    
    參數:
        m: 訊息 (bytes)，通常是 SHA-256 雜湊值
        n_bits: RSA 模數的位元長度 (例如 2048)
    
    回傳:
        擴展後的整數，範圍在 [0, 2^n_bits)
    
    v2.0 規範 §9.5.1
    """
    target_bytes = (n_bits + 7) // 8  # 向上取整，例如 2048 bits = 256 bytes
    
    # 使用 MGF1-SHA256 擴展（手動實作 MGF1）
    # MGF1(seed, length) = T = T_1 || T_2 || ... || T_ceil(length/hLen)
    # 其中 T_i = Hash(seed || C)，C 是 4-byte 計數器
    mask = b''
    counter = 0
    hash_len = 32  # SHA-256 輸出 32 bytes
    
    while len(mask) < target_bytes:
        # C 是 4-byte big-endian 整數
        c_bytes = counter.to_bytes(4, byteorder='big')
        hash_input = m + c_bytes
        hash_output = hashlib.sha256(hash_input).digest()
        mask += hash_output
        counter += 1
    
    # 截取所需長度
    mask = mask[:target_bytes]
    
    # 將最高位元清零以確保結果 < n
    # 簡化版：清除超出 n_bits 的位元
    excess_bits = (8 * target_bytes) - n_bits + 1  # +1 ensures result < n (top bit cleared)
    if excess_bits > 0:
        mask = bytearray(mask)
        mask[0] &= (0xFF >> excess_bits)
        mask = bytes(mask)
    
    # 轉換為整數
    result = int.from_bytes(mask, byteorder='big')
    return result


def generate_blinding_factor(n: int) -> int:
    """
    選民 (Voter) 使用：生成一個與模數 n 互質的隨機盲化因子 r
    
    v2.0 規範 §9.5.2 Step 3
    """
    while True:
        r = secrets.randbelow(n - 2) + 2
        if math.gcd(r, n) == 1:
            return r


def blind_message(mu: int, r: int, e: int, n: int) -> int:
    """
    選民 (Voter) 使用：盲化已經過 FDH 擴展的訊息
    
    計算: m' = (μ * r^e) mod n
    其中 μ = FDH(m, bit_length(n))
    
    v2.0 規範 §9.5.2 Step 4
    
    參數:
        mu: 已經過 FDH 擴展的訊息
        r: 盲化因子
        e: RSA 公鑰指數
        n: RSA 模數
    """
    r_pow_e = pow(r, e, n)
    m_prime = (mu * r_pow_e) % n
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
    r_inv = pow(r, -1, n)
    S_prime = (S * r_inv) % n
    return S_prime


def verify_blind_signature(S_prime: int, e: int, n: int, m: bytes) -> bool:
    """
    計票中心 (CC) 或任何人使用：驗證 RSA-FDH-Blind 簽章是否合法
    
    v2.0 變更：驗證 (S')^e mod n == FDH(m, bit_length(n))
    而非 v1.0 的 (S')^e mod n == m
    
    v2.0 規範 §9.5.2 Step 10
    
    參數:
        S_prime: 去盲化後的簽章
        e: RSA 公鑰指數
        n: RSA 模數
        m: 原始訊息 (bytes)，通常是選票雜湊值
    
    回傳:
        True 如果簽章合法，否則 False
    """
    n_bits = n.bit_length()
    mu_check = fdh(m, n_bits)
    return pow(S_prime, e, n) == mu_check
