"""
shared/admin_auth.py  —  Admin API Bearer Token 驗證

供 CA 的 /api/admin/* 端點與 CC 的 /api/tally 端點共用，
用同一組 ADMIN_API_TOKEN 環境變數驗證呼叫者是否為系統管理員。

v2.0 規格書 §18.1.3（CA Admin 端點）、§18.4.4（CC /api/tally 內部存取控制）、
§23.3（ADMIN_API_TOKEN 環境變數：適用於 ca, cc）。
"""

import ipaddress
from flask import request

from shared.config_loader import get_admin_api_token

# 內部網路範圍：Docker bridge network、loopback、常見私有網段。
# 用於 CC /api/tally 的「內部 IP 白名單」防線（規格書 §18.4.4）。
_INTERNAL_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def is_internal_ip(remote_addr: str) -> bool:
    """
    檢查來源 IP 是否屬於內部網路範圍（loopback / Docker bridge / 私有網段）。
    解析失敗一律視為外部（fail-secure）。
    """
    if not remote_addr:
        return False
    try:
        addr = ipaddress.ip_address(remote_addr)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETWORKS)


def check_admin_token() -> bool:
    """
    檢查目前請求的 `Authorization: Bearer <token>` 標頭是否符合
    環境變數 ADMIN_API_TOKEN。

    Fail-secure：若 ADMIN_API_TOKEN 未設定，一律回傳 False（拒絕），
    而不是放行任何請求。
    """
    expected = get_admin_api_token()
    if not expected:
        return False

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return False

    token = auth_header[len("Bearer "):]
    return token == expected


def admin_auth_error():
    """回傳標準化的 401 錯誤 response body（呼叫端自行決定 jsonify 與 HTTP code）。"""
    return {
        "status": "error",
        "code": "ADMIN_AUTH_REQUIRED",
        "message": "此端點需要有效的 Admin Bearer Token（Authorization: Bearer <ADMIN_API_TOKEN>）",
    }
