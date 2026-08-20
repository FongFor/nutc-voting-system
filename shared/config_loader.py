"""
shared/config_loader.py  —  設定檔載入器

讀取 config.json 的統一入口，支援熱重載。
修改 config.json 後不需要重啟容器，下次請求時會自動套用新設定。

基本用法：
    from shared.config_loader import get_candidates, local_url

    # 取得候選人清單
    cands = get_candidates()   # ["候選人A", "候選人B", ...]

    # 取得服務 URL（容器內部）
    ca_url = svc_url("ca")     # "http://ca:5001"

    # 取得服務 URL（本機測試用）
    ca_url = local_url("ca")   # "http://localhost:5001"
"""

import json
import os
import threading
import time
from pathlib import Path
from typing import Any


# ── 找到 config.json（從任意子目錄往上找）─────────────────────
def _find_config() -> Path:
    """從當前檔案往上搜尋 config.json，最多走 4 層。"""
    here = Path(__file__).resolve().parent
    for _ in range(5):
        candidate = here / "config.json"
        if candidate.exists():
            return candidate
        here = here.parent
    raise FileNotFoundError(
        "找不到 config.json，請確認它位於專案根目錄。"
    )


# ── 配置物件 ──────────────────────────────────────────────────
class _Config:
    """
    輕量配置物件，將 config.json 的 dict 包裝成屬性存取。
    支援 cfg.timing.vote_duration_seconds 等鏈式存取。
    """

    def __init__(self, data: dict):
        self._data = data
        for key, value in data.items():
            if key.startswith("_"):          # 跳過 _comment 等
                continue
            if isinstance(value, dict):
                setattr(self, key, _Config(value))
            elif isinstance(value, list):
                setattr(self, key, value)
            else:
                setattr(self, key, value)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def __repr__(self) -> str:
        return f"_Config({self._data!r})"


# ── Hot-Reload 管理器 ─────────────────────────────────────────
class _HotReloadConfig:
    """
    支援 Hot-Reload 的配置管理器。
    - 每次存取時檢查 config.json 的 mtime。
    - 若檔案已更新，自動重新載入（thread-safe）。
    - 亦可透過 force_reload() 強制重載。
    """

    def __init__(self, config_path: Path):
        self._path = config_path
        self._lock = threading.RLock()
        self._raw: dict = {}
        self._cfg: _Config = None
        self._mtime: float = 0.0
        self._load()

    def _load(self):
        """從磁碟載入 config.json（需持有鎖）"""
        with open(self._path, "r", encoding="utf-8") as f:
            self._raw = json.load(f)
        self._cfg = _Config(self._raw)
        self._mtime = self._path.stat().st_mtime

    def _check_reload(self):
        """檢查 mtime，若有變化則重新載入。"""
        try:
            current_mtime = self._path.stat().st_mtime
            if current_mtime != self._mtime:
                with self._lock:
                    # double-check after acquiring lock
                    current_mtime = self._path.stat().st_mtime
                    if current_mtime != self._mtime:
                        self._load()
                        print(f"[config_loader] config.json 已熱重載（mtime={current_mtime:.3f}）")
        except Exception as e:
            print(f"[config_loader] 熱重載失敗：{e}")

    def force_reload(self):
        """強制重新載入 config.json（可由外部呼叫）。"""
        with self._lock:
            self._load()
        print(f"[config_loader] config.json 已強制重載")

    @property
    def raw(self) -> dict:
        self._check_reload()
        return self._raw

    @property
    def cfg(self) -> _Config:
        self._check_reload()
        return self._cfg

    # ── 便利存取方法 ──────────────────────────────────────────

    def get_candidates(self) -> list:
        """取得候選人清單，優先讀取環境變數 CANDIDATES（逗號分隔）。"""
        env_val = os.environ.get("CANDIDATES")
        if env_val:
            return [c.strip() for c in env_val.split(",") if c.strip()]
        return list(self.raw.get("candidates", []))

    def get_voters(self) -> list:
        """取得選民配置清單。"""
        return list(self.raw.get("voters", []))

    def get_vote_duration(self) -> int:
        """取得投票時長（秒），優先讀取環境變數 VOTE_DURATION_SECONDS。"""
        env_val = os.environ.get("VOTE_DURATION_SECONDS")
        if env_val:
            return int(env_val)
        return int(self.raw.get("timing", {}).get("vote_duration_seconds", 120))

    def get_delta_t(self) -> int:
        """取得認證時間容差（秒），優先讀取環境變數 DELTA_T。"""
        env_val = os.environ.get("DELTA_T")
        if env_val:
            return int(env_val)
        return int(self.raw.get("timing", {}).get("delta_t_seconds", 300))

    def get_timing(self, key: str, default: Any = None) -> Any:
        """快速取得 timing 區塊的值。"""
        return self.raw.get("timing", {}).get(key, default)

    def svc_url(self, service: str) -> str:
        """
        回傳容器內部服務 URL（Docker 網路名稱解析）。
        例：svc_url("ca") → "http://ca:5001"
        """
        svc = self.raw["services"][service]
        return f"http://{svc['host']}:{svc['port']}"

    def local_url(self, service: str) -> str:
        """
        回傳本機 localhost URL（E2E 測試 / 外部腳本使用）。
        例：local_url("ca") → "http://localhost:5001"
        """
        svc = self.raw["services"][service]
        return f"http://localhost:{svc['local_port']}"

    def voter_local_url(self, voter_id: str) -> str:
        """
        回傳指定選民的本機 URL。
        例：voter_local_url("VOTER_001") → "http://localhost:5010"
        """
        for v in self.raw.get("voters", []):
            if v["id"] == voter_id:
                return f"http://localhost:{v['port']}"
        raise KeyError(f"找不到選民 {voter_id} 的配置")


# ── 全域單例 ──────────────────────────────────────────────────
_config_path = _find_config()
_hot_config = _HotReloadConfig(_config_path)


# ── 向後相容的公開 API ────────────────────────────────────────

def get_cfg() -> _Config:
    """取得最新的 _Config 物件（每次呼叫都會檢查 hot-reload）。"""
    return _hot_config.cfg


# 向後相容：保留 cfg 作為屬性存取（注意：此為啟動時快照，建議改用 get_cfg()）
cfg: _Config = _hot_config.cfg


def force_reload():
    """強制重新載入 config.json，並更新全域 cfg 快照。"""
    global cfg
    _hot_config.force_reload()
    cfg = _hot_config.cfg


def svc_url(service: str) -> str:
    """
    回傳容器內部服務 URL（Docker 網路名稱解析）。
    例：svc_url("ca") → "http://ca:5001"
    """
    return _hot_config.svc_url(service)


def local_url(service: str) -> str:
    """
    回傳本機 localhost URL（E2E 測試 / 外部腳本使用）。
    例：local_url("ca") → "http://localhost:5001"
    """
    return _hot_config.local_url(service)


def voter_local_url(voter_id: str) -> str:
    """
    回傳指定選民的本機 URL。
    例：voter_local_url("VOTER_001") → "http://localhost:5010"
    """
    return _hot_config.voter_local_url(voter_id)


def candidates() -> list:
    """回傳候選人清單（list of str）。每次呼叫都讀最新值。"""
    return _hot_config.get_candidates()


def voters() -> list:
    """回傳選民配置清單（list of dict）。每次呼叫都讀最新值。"""
    return _hot_config.get_voters()


def timing(key: str, default: Any = None) -> Any:
    """快速取得 timing 區塊的值。每次呼叫都讀最新值。"""
    return _hot_config.get_timing(key, default)


# ── 環境變數覆蓋支援 ─────────────────────────────────────────
# 允許 docker-compose 透過環境變數覆蓋特定值，
# 例如 VOTE_DURATION_SECONDS=60 會覆蓋 timing.vote_duration_seconds

def get_vote_duration() -> int:
    """取得投票時長（秒），優先讀取環境變數 VOTE_DURATION_SECONDS。"""
    return _hot_config.get_vote_duration()


def get_delta_t() -> int:
    """取得認證時間容差（秒），優先讀取環境變數 DELTA_T。"""
    return _hot_config.get_delta_t()


def get_candidates() -> list:
    """取得候選人清單，優先讀取環境變數 CANDIDATES（逗號分隔）。"""
    return _hot_config.get_candidates()


# ── Flask Hot-Reload API 端點輔助 ────────────────────────────
def make_reload_endpoint(app):
    """
    為 Flask app 注入 POST /api/config/reload 端點。
    呼叫後立即重載 config.json，回傳新的候選人與 timing 設定。

    使用方式（在各服務 app.py 中）：
        from shared.config_loader import make_reload_endpoint
        make_reload_endpoint(app)
    """
    from flask import jsonify as _jsonify

    @app.route('/api/config/reload', methods=['POST'])
    def _config_reload():
        try:
            force_reload()
            return _jsonify({
                "status":     "reloaded",
                "candidates": get_candidates(),
                "timing":     _hot_config.raw.get("timing", {}),
                "reloaded_at": int(time.time()),
            }), 200
        except Exception as e:
            return _jsonify({"status": "error", "message": str(e)}), 500

    @app.route('/api/config', methods=['GET'])
    def _config_get():
        """[GET] 回傳當前生效的配置（不含敏感資訊）。"""
        _hot_config._check_reload()
        return _jsonify({
            "status":     "ok",
            "candidates": get_candidates(),
            "timing":     _hot_config.raw.get("timing", {}),
            "voters":     [{"id": v["id"]} for v in get_voters()],
        }), 200
