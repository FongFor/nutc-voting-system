from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from cryptography import x509
import datetime

# ==========================================
# 1. 核心密碼學邏輯：CA 類別
# ==========================================
class VotingSystemCA:
    def __init__(self):
        print("正在初始化 CA 金鑰與根憑證...")
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.root_cert = self._generate_root_certificate()

    def _generate_root_certificate(self):
        # 這裡的組織名稱可以換成你們的專案名稱 nutc-voting-system
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"NUTC Voting System Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Voting CA"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(self.private_key, hashes.SHA256())
        return cert

    def get_root_cert_pem(self):
        """將 CA 的根憑證匯出為 PEM 字串，供其他節點下載驗證用"""
        return self.root_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    def issue_certificate(self, entity_id: str, public_key_pem: str) -> str:
        """接收實體 ID 與 PEM 格式的公鑰，回傳 PEM 格式的憑證"""
        # 將傳進來的 PEM 字串轉換回 Python 的公鑰物件
        entity_public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Voting System Participant"),
            x509.NameAttribute(NameOID.COMMON_NAME, entity_id),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.root_cert.subject
        ).public_key(
            entity_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=30)
        ).sign(self.private_key, hashes.SHA256())
        
        # 將簽發好的憑證轉為 PEM 字串回傳
        return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

# ==========================================
# 2. Flask API 路由設定
# ==========================================
app = Flask(__name__)

# 在伺服器啟動時，實例化 CA 物件 (確保金鑰在伺服器運行期間只生成一次)
ca_instance = VotingSystemCA()

@app.route('/')
def home():
    return "CA (憑證授權中心) 伺服器運作中！"

@app.route('/api/ca_cert', methods=['GET'])
def get_ca_cert():
    """
    [GET] 提供 CA 的公開根憑證。
    系統中所有實體(Voter, TPA, CC)都需要先呼叫這個 API 取得 CA 憑證，
    未來才能驗證彼此憑證的合法性。
    """
    return jsonify({
        "status": "success",
        "ca_certificate": ca_instance.get_root_cert_pem()
    }), 200

@app.route('/api/issue_cert', methods=['POST'])
def handle_issue_cert():
    """
    [POST] 接收申請者的 ID 與公鑰，核發數位憑證。
    預期收到的 JSON 格式: {"entity_id": "Voter_001", "public_key": "-----BEGIN PUBLIC KEY-----\n..."}
    """
    # 取得前端或其它微服務發送過來的 JSON 資料
    data = request.get_json()
    
    # 基本防呆：檢查資料是否齊全
    if not data or 'entity_id' not in data or 'public_key' not in data:
        return jsonify({"status": "error", "message": "缺少 entity_id 或 public_key"}), 400
        
    entity_id = data['entity_id']
    public_key_pem = data['public_key']
    
    try:
        # 呼叫 CA 核心邏輯進行簽發
        issued_cert_pem = ca_instance.issue_certificate(entity_id, public_key_pem)
        
        return jsonify({
            "status": "success",
            "message": f"憑證核發成功 ({entity_id})",
            "certificate": issued_cert_pem
        }), 200
        
    except Exception as e:
        # 若金鑰格式錯誤或其他密碼學錯誤，回傳 500
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
    # host='0.0.0.0' 非常重要！這樣 Docker 容器外的電腦才連得進去
    app.run(host='0.0.0.0', port=5000)