import random
import math
from cryptography.hazmat.primitives.asymmetric import rsa

# ==========================================
# 0. 系統初始化 (生成 RSA 金鑰的底層數字)
# ==========================================
print("--- 0. 初始化階段 ---")
# 模擬 TPA 生成 RSA 金鑰
tpa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
tpa_public_key = tpa_private_key.public_key()

# 提取 RSA 的底層大整數 (e, d, n)
e = tpa_public_key.public_numbers().e
n = tpa_public_key.public_numbers().n
d = tpa_private_key.private_numbers().d

print(f"取得 TPA 公鑰指數 (e): {e}")
print(f"取得 TPA 模數 (n) 的長度: {n.bit_length()} bits")

# ==========================================
# 1. 盲化階段 (Blinding) - 由 Voter 執行
# ==========================================
print("\n--- 1. 盲化階段 (Voter) ---")
# 假設選票經過雜湊後轉成一個大整數 m (必須小於 n)
m = 1234567890987654321
print(f"原始選票雜湊值 (m): {m}")

# 選民挑選一個隨機亂數 r 作為盲化因子，條件是 gcd(r, n) == 1
while True:
    r = random.randrange(2, n - 1)
    if math.gcd(r, n) == 1:
        break

# 計算盲化訊息 m' = m * r^e mod n
# 在 Python 中，pow(x, y, z) 就是計算 (x^y) mod z，這比自己寫迴圈快非常多
r_pow_e = pow(r, e, n)
m_prime = (m * r_pow_e) % n
print(f"盲化後的選票 (m'): {m_prime}")

# ==========================================
# 2. 簽署階段 (Signing) - 由 TPA 執行
# ==========================================
print("\n--- 2. 簽署階段 (TPA) ---")
# TPA 收到 m_prime，在不知道 m 的情況下，用私鑰 d 進行簽名
# 計算 S = (m')^d mod n
S = pow(m_prime, d, n)
print(f"TPA 簽署的盲簽章 (S): {S}")

# ==========================================
# 3. 去盲化階段 (Unblinding) - 由 Voter 執行
# ==========================================
print("\n--- 3. 去盲化階段 (Voter) ---")
# Voter 收到 S 後，計算 r 的模反元素 (Modular Inverse)
# Python 3.8 以後，pow() 支援傳入負數次方來計算模反元素：pow(r, -1, n)
r_inv = pow(r, -1, n)

# 計算最終的合法簽章 S' = S * r^-1 mod n
S_prime = (S * r_inv) % n
print(f"去盲化後的最終簽章 (S'): {S_prime}")

# ==========================================
# 4. 驗證階段 (Verification)
# ==========================================
print("\n--- 4. 數學驗證 ---")
# 我們來驗證這個 S' 是否真的是 TPA 對原始選票 m 的合法簽章？
# 正常 RSA 簽章的算法是：m^d mod n
expected_signature = pow(m, d, n)

print(f"預期的合法簽章: {expected_signature}")
if S_prime == expected_signature:
    print("🎉 驗證成功！盲簽章的數學邏輯完全正確！")
    print("S' 確實等於 m^d mod n，且 TPA 過程中完全不知道 m 的內容。")
else:
    print("❌ 驗證失敗！")