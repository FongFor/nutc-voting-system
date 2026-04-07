"""
shared/blind_signature.py  —  盲簽章 (Blind Signature) 核心數學模組

RSA 盲簽章流程：
  1. Voter：生成盲化因子 r，計算 m' = m * r^e mod n
  2. TPA：對盲化訊息簽章，計算 S = (m')^d mod n
  3. Voter：去盲化，計算 S' = S * r^-1 mod n
  4. 任何人：驗證 (S')^e mod n == m

各角色使用的函式：
  - Voter：generate_blinding_factor, blind_message, unblind_signature, verify_blind_signature
  - TPA：blind_sign
  - CC：verify_blind_signature
"""

import secrets
import math


def generate_blinding_factor(n: int) -> int:
    """
    選民 (Voter) 使用：生成一個與模數 n 互質的隨機盲化因子 r
    """
    while True:
        r = secrets.randbelow(n - 2) + 2
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
    r_inv = pow(r, -1, n)
    S_prime = (S * r_inv) % n
    return S_prime


def verify_blind_signature(S_prime: int, e: int, n: int, m: int) -> bool:
    """
    計票中心 (CC) 或任何人使用：驗證簽章是否合法
    檢查: (S')^e mod n == m
    """
    return pow(S_prime, e, n) == m
