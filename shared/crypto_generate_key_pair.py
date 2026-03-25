from cryptography.hazmat.primitives.asymmetric import rsa

# ==========================================
# 金鑰生成
# ==========================================

def generate_rsa_keypair(key_size: int = 2048):
    """
    統一生成 RSA 金鑰對，並提取底層的大整數供盲簽章等密碼學運算使用。
    
    回傳值 (Tuple):
        private_key: 密碼學套件的私鑰物件 (可用於標準簽章、解密)
        public_key: 密碼學套件的公鑰物件 (可用於標準驗證、加密)
        e: 公鑰指數 (供盲化運算)
        n: 模數 (供盲化運算)
        d: 私鑰指數 (供簽署運算)
    """
    # 1. 生成 RSA 私鑰
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    
    # 2. 取得對應的公鑰
    public_key = private_key.public_key()
    
    # 3. 提取底層的數學大整數 (e, n, d)
    e = public_key.public_numbers().e
    n = public_key.public_numbers().n
    d = private_key.private_numbers().d
    
    return private_key, public_key, e, n, d