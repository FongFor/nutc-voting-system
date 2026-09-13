"""
shared/tls_utils.py  —  服務間 mTLS 工具

每個服務除了原本用來簽 RSA-PSS 應用層封包的身分金鑰對之外，另外持有一把
「TLS 專用」金鑰對，供 Flask 內建 HTTPS 監聽（伺服器端）與 requests 對外
呼叫（用戶端）使用，跟應用層那把私鑰完全獨立——同一把私鑰身兼兩種密碼學
角色（應用層簽章 vs. 傳輸層 TLS handshake）會讓外洩時的影響範圍疊在一起，
這裡刻意分開，外洩一把金鑰的爆炸半徑只限一層。

TLS 憑證由 CA 的 /api/issue_tls_cert 核發，跟應用層 /api/issue_cert 是
兩個獨立、各自一次性的 SERVICE_REGISTRATION_TOKEN 兌換流程（CA 端用
分開的資料庫表追蹤，互不影響），且憑證上有應用層憑證缺少的
SubjectAlternativeName／KeyUsage／ExtendedKeyUsage 擴充欄位，才能被標準
TLS 函式庫接受為合法的伺服器／用戶端憑證。
"""

import os
import ssl

import requests

from cryptography.hazmat.primitives import serialization

from shared.crypto_generate_key_pair import generate_rsa_keypair


def _save_pem(path: str, data: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(data)


def load_or_request_tls_certificate(
    keys_dir: str,
    entity_id: str,
    hostname: str,
    ca_url: str,
    registration_token: str,
) -> tuple[str, str]:
    """
    載入（或生成＋向 CA 申請）本服務專用的 TLS 金鑰對與憑證。

    hostname：填進憑證的 SubjectAlternativeName，必須與其他服務實際用來
    連線本服務的主機名一致（本機測試為 docker service name，如 "ta"；
    未來獨立部署後應為真實網域），否則對方用 requests 的 verify= 驗證
    時會因主機名不符而拒絕連線。

    回傳：(tls_cert_path, tls_key_path)，檔案路徑，供
    build_mtls_server_context() / mtls_client_kwargs() 直接使用。
    """
    key_path     = os.path.join(keys_dir, "tls_private_key.pem")
    cert_path    = os.path.join(keys_dir, "tls_certificate.pem")
    ca_cert_path = os.path.join(keys_dir, "ca_cert.pem")

    if os.path.exists(key_path) and os.path.exists(cert_path):
        print(f"[TlsUtils] 已從磁碟載入 TLS 憑證：{cert_path}")
        return cert_path, key_path

    private_key, public_key, _e, _n, _d = generate_rsa_keypair()
    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode('utf-8')
    public_key_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')

    resp = requests.post(
        f"{ca_url}/api/issue_tls_cert",
        json={
            "entity_id":          entity_id,
            "hostname":           hostname,
            "public_key":         public_key_pem,
            "registration_token": registration_token,
        },
        timeout=10,
        # 跟 shared/key_manager.py 的 load_or_request_certificate 同一套
        # 邏輯：呼叫端若已經跑過 load_or_fetch_ca_cert() 快取了根憑證，
        # 就用它驗證 CA 的 TLS 伺服器憑證；若這是本服務第一次接觸 CA
        # （尚未快取任何東西），就是無可避免的 TOFU bootstrap，見
        # load_or_fetch_ca_cert() 的說明與 v4.0 規格書第 27 章。
        verify=ca_cert_path if os.path.exists(ca_cert_path) else False,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get('status') != 'success':
        raise RuntimeError(f"CA 拒絕核發 TLS 憑證（{data.get('code')}）：{data.get('message')}")

    _save_pem(key_path, private_key_pem)
    _save_pem(cert_path, data['certificate'])
    print(f"[TlsUtils] 已向 CA 申請並儲存 TLS 憑證：{entity_id}（hostname={hostname}）")
    return cert_path, key_path


def build_mtls_server_context(
    tls_cert_path: str,
    tls_key_path: str,
    ca_cert_path: str,
    require_client_cert: bool = True,
) -> ssl.SSLContext:
    """
    建立 Flask app.run(ssl_context=...) 用的 SSLContext。

    require_client_cert=True（預設；CA / TPA / TA / CC / Admin 適用）：
    要求對方也出示由同一張 CA 根憑證簽發的合法憑證，達成雙向（mTLS）
    驗證——這五個服務永遠不會被一般瀏覽器直接連線，強制要求用戶端憑證
    不會擋到任何合法流量。

    require_client_cert=False（Voter、BB 適用）：這兩個服務的監聽埠除了
    內部服務呼叫，還要接受一般瀏覽器（經 Caddy）的公開連線——瀏覽器不會
    持有這套內部 PKI 簽發的用戶端憑證，強制 CERT_REQUIRED 會直接擋掉
    所有公開流量。這兩個服務對「呼叫者是不是合法內部服務」的驗證，改由
    既有的應用層機制（簽章驗證、Admin Bearer Token）負責，不依賴這裡的
    傳輸層憑證。
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=tls_cert_path, keyfile=tls_key_path)
    if require_client_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=ca_cert_path)
    return ctx


def mtls_client_kwargs(tls_cert_path: str, tls_key_path: str, ca_cert_path: str) -> dict:
    """
    回傳可直接以 **kwargs 展開進 requests.get/post(...) 的 mTLS 參數：
      cert   -- 我方憑證＋私鑰，供對方驗證我方身分
      verify -- 用哪張根憑證驗證對方的伺服器憑證（不可填 True，因為對方
                的憑證不是公開受信任 CA 簽發的，系統內建信任清單裡沒有）
    """
    return {
        "cert":   (tls_cert_path, tls_key_path),
        "verify": ca_cert_path,
    }
