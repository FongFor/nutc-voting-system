"""
shared/format_utils.py  —  格式轉換工具

一些常用的格式轉換函式，各服務都會用到。

時間顯示規則：
  後端和 API 一律用 Unix timestamp（整數秒），
  要顯示給人看的時候才呼叫 ts_to_human() 轉成 YYYY-MM-DD HH:MM:SS。
  預設時區是 UTC+8，可以用 DISPLAY_TIMEZONE_OFFSET 環境變數調整。
"""

import base64
import hashlib
import os
import datetime


# ── 時區設定 ──────────────────────────────────────────────────
def _get_display_tz() -> datetime.timezone:
    """
    取得顯示用時區（datetime.timezone 物件）。
    優先順序：
      1. 環境變數 DISPLAY_TIMEZONE_OFFSET（整數，單位：小時，例如 8 代表 UTC+8）
      2. 環境變數 TZ 解析（僅支援 "Asia/Taipei" → +8、"UTC" → 0 等常見值）
      3. 預設 UTC+8（Asia/Taipei）
    """
    # 方法 1：直接指定偏移小時數（最可靠）
    offset_env = os.environ.get("DISPLAY_TIMEZONE_OFFSET")
    if offset_env is not None:
        try:
            hours = float(offset_env)
            return datetime.timezone(datetime.timedelta(hours=hours))
        except ValueError:
            pass

    # 方法 2：嘗試解析 TZ 環境變數（常見值對照表）
    tz_env = os.environ.get("DISPLAY_TIMEZONE") or os.environ.get("TZ", "")
    _TZ_OFFSETS = {
        "Asia/Taipei": 8, "Asia/Shanghai": 8, "Asia/Hong_Kong": 8,
        "Asia/Tokyo": 9, "Asia/Seoul": 9,
        "America/New_York": -5, "America/Los_Angeles": -8,
        "Europe/London": 0, "Europe/Paris": 1, "Europe/Berlin": 1,
        "UTC": 0, "GMT": 0,
    }
    if tz_env in _TZ_OFFSETS:
        return datetime.timezone(datetime.timedelta(hours=_TZ_OFFSETS[tz_env]))

    # 方法 3：嘗試用 Python 本機時區（若容器有正確設定 TZ）
    try:
        local_offset = datetime.datetime.now(datetime.timezone.utc).astimezone().utcoffset()
        if local_offset is not None and local_offset.total_seconds() != 0:
            return datetime.timezone(local_offset)
    except Exception:
        pass

    # 預設：UTC+8（Asia/Taipei）
    return datetime.timezone(datetime.timedelta(hours=8))


# 模組載入時快取時區（可透過 reload 更新）
_DISPLAY_TZ = _get_display_tz()


def ts_to_human(ts) -> str:
    """
    將 Unix timestamp 轉為人類可讀格式（YYYY-MM-DD HH:MM:SS）。
    使用明確時區（預設 UTC+8），避免容器 UTC 時區導致顯示錯誤。
    僅用於 Web UI 顯示與日誌，後端/API 一律使用 Unix timestamp。
    """
    try:
        ts_int = int(ts)
        dt = datetime.datetime.fromtimestamp(ts_int, tz=datetime.timezone.utc).astimezone(_DISPLAY_TZ)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)


def ts_to_human_with_tz(ts) -> str:
    """
    將 Unix timestamp 轉為帶時區標記的人類可讀格式。
    例：2026-04-04 03:04:58 UTC+8
    """
    try:
        ts_int = int(ts)
        dt = datetime.datetime.fromtimestamp(ts_int, tz=datetime.timezone.utc).astimezone(_DISPLAY_TZ)
        offset_hours = int(_DISPLAY_TZ.utcoffset(None).total_seconds() / 3600)
        tz_label = f"UTC{'+' if offset_hours >= 0 else ''}{offset_hours}"
        return dt.strftime('%Y-%m-%d %H:%M:%S') + f" {tz_label}"
    except Exception:
        return str(ts)


# ── 整數 ↔ Hex ────────────────────────────────────────────────

def int_to_hex(n: int) -> str:
    """將大整數轉為 Hex 字串（含 0x 前綴）"""
    return hex(n)


def hex_to_int(h: str) -> int:
    """將 Hex 字串（含或不含 0x 前綴）還原為大整數"""
    return int(h, 16)


# ── bytes ↔ Base64 ────────────────────────────────────────────

def bytes_to_b64(b: bytes) -> str:
    """將 bytes 轉為 Base64 字串"""
    return base64.b64encode(b).decode('utf-8')


def b64_to_bytes(s: str) -> bytes:
    """將 Base64 字串還原為 bytes"""
    return base64.b64decode(s)


# ── SHA-256 ───────────────────────────────────────────────────

def sha256_hex(data: bytes) -> str:
    """計算 SHA-256 並回傳 hex 字串"""
    return hashlib.sha256(data).hexdigest()
