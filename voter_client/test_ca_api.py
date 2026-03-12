import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

print("--- 選民端 (Voter) 測試啟動 ---")

# 1. Voter 自己在本地端生成金鑰對
print("1. 正在生成 Voter 的 RSA 金鑰對...")
voter_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
voter_public_key = voter_private_key.public_key()

# 2. 將公鑰轉成 PEM 字串格式，準備透過網路傳送
public_key_pem = voter_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# 3. 準備發送 API 請求給 CA 伺服器
ca_url = "http://127.0.0.1:5000/api/issue_cert"
payload = {
    "entity_id": "Voter_001",
    "public_key": public_key_pem
}

print(f"2. 正在向 CA 伺服器申請憑證 (發送 POST 請求至 {ca_url})...")

try:
    # 發送 POST 請求 (使用 json 參數會自動將字典轉為 JSON 並加上正確的 Header)
    response = requests.post(ca_url, json=payload)
    
    # 解析回傳結果
    if response.status_code == 200:
        result = response.json()
        print("\n🎉 [成功] 成功取得 CA 核發的憑證！")
        print("伺服器訊息:", result["message"])
        print("\n--- 憑證內容預覽 ---")
        
        # 為了避免終端機畫面太亂，我們只印出憑證的頭尾
        cert_lines = result["certificate"].strip().split('\n')
        print('\n'.join(cert_lines[:3] + ['... (中間的亂碼省略) ...'] + cert_lines[-3:]))
    else:
        print(f"\n❌ [失敗] 伺服器回傳錯誤代碼: {response.status_code}")
        print("錯誤訊息:", response.text)

except requests.exceptions.ConnectionError:
    print("\n❌ [連線失敗] 找不到 CA 伺服器，請確認 Docker 中的 voting_ca 是否正在運作 (Port 5000)。")
except Exception as e:
    print(f"\n❌ [發生未知的錯誤]: {e}")