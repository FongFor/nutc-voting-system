#!/usr/bin/env python3
"""
reset.py  —  一鍵重置腳本

每次重新測試前跑一下，確保系統回到乾淨狀態。

清除範圍：
  1. 停止並移除所有 Docker 容器
  2. 清除 Docker Named Volumes（容器內的金鑰）
  3. 刪除各服務目錄下的 .db 檔案（SQLite 資料庫）
  4. 刪除各服務目錄下的 keys/ 目錄（本機開發模式金鑰）
  5. 清除 test/e2e_keys/ 和 test/sim_keys/（測試腳本產生的金鑰）
  6. 清除 Python __pycache__

用法：
  python reset.py              完整重置（推薦）
  python reset.py --soft       僅清本機 DB + keys（不動 Docker）
  python reset.py --docker     僅清 Docker volumes
  python reset.py --dry-run    預覽將刪除的項目，不實際執行
"""

import sys
sys.stdout.reconfigure(encoding="utf-8")
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


# ── ANSI 顏色 ─────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def _ok(msg):   print(f"  {C.GREEN}✓{C.RESET} {msg}")
def _skip(msg): print(f"  {C.YELLOW}–{C.RESET} {msg}")
def _err(msg):  print(f"  {C.RED}✗{C.RESET} {msg}", file=sys.stderr)
def _info(msg): print(f"  {C.CYAN}→{C.RESET} {msg}")
def _head(msg): print(f"\n{C.BOLD}{C.CYAN}{msg}{C.RESET}")


# ── 專案根目錄 ────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent

# 各服務目錄（含 DB 與 keys）
SERVICE_DIRS = [
    ROOT / "ca_server",
    ROOT / "tpa_server",
    ROOT / "ta_server",
    ROOT / "cc_server",
    ROOT / "bb_server",
    ROOT / "voter_client",
]

# Docker Named Volumes（與 docker-compose.yml 一致）
DOCKER_VOLUMES = [
    "nutc-voting-system_ca_keys",
    "nutc-voting-system_tpa_keys",
    "nutc-voting-system_ta_keys",
    "nutc-voting-system_cc_keys",
    "nutc-voting-system_voter1_keys",
    "nutc-voting-system_voter2_keys",
    "nutc-voting-system_voter3_keys",
    # 舊版命名（無前綴）也一併嘗試清除
    "ca_keys", "tpa_keys", "ta_keys", "cc_keys",
    "voter1_keys", "voter2_keys", "voter3_keys",
]

# Docker 容器名稱
DOCKER_CONTAINERS = [
    "voting_ca", "voting_tpa", "voting_ta",
    "voting_cc", "voting_bb",
    "voting_voter1", "voting_voter2", "voting_voter3",
]


# ── 輔助函式 ──────────────────────────────────────────────────

def _run(cmd: list[str], dry_run: bool, check: bool = False) -> bool:
    """執行 shell 命令，dry_run 模式下只印出不執行。"""
    cmd_str = " ".join(cmd)
    if dry_run:
        _info(f"[DRY-RUN] {cmd_str}")
        return True
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return True
        if check:
            _err(f"命令失敗：{cmd_str}\n{result.stderr.strip()}")
        return False
    except Exception as e:
        _err(f"執行失敗：{cmd_str} → {e}")
        return False


def _remove_path(path: Path, dry_run: bool) -> None:
    """刪除檔案或目錄。"""
    if not path.exists():
        _skip(f"不存在，跳過：{path.relative_to(ROOT)}")
        return
    if dry_run:
        _info(f"[DRY-RUN] 刪除：{path.relative_to(ROOT)}")
        return
    try:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        _ok(f"已刪除：{path.relative_to(ROOT)}")
    except Exception as e:
        _err(f"刪除失敗：{path} → {e}")


# ── 重置步驟 ──────────────────────────────────────────────────

def step_stop_containers(dry_run: bool) -> None:
    _head("Step 1 > 停止並移除 Docker 容器")
    # 先嘗試 docker compose down（新版語法）
    compose_file = ROOT / "docker-compose.yml"
    if compose_file.exists():
        ok = _run(
            ["docker", "compose", "-f", str(compose_file), "down", "--remove-orphans"],
            dry_run,
        )
        if ok:
            _ok("docker compose down 完成")
            return
    # fallback：逐一停止容器
    for name in DOCKER_CONTAINERS:
        _run(["docker", "stop", name], dry_run)
        _run(["docker", "rm", "-f", name], dry_run)
    _ok("容器已停止並移除")


def step_remove_volumes(dry_run: bool) -> None:
    _head("Step 2 > 清除 Docker Named Volumes（金鑰）")
    removed = 0
    for vol in DOCKER_VOLUMES:
        ok = _run(["docker", "volume", "rm", vol], dry_run)
        if ok:
            _ok(f"已移除 volume：{vol}")
            removed += 1
        else:
            _skip(f"volume 不存在或移除失敗：{vol}")
    if removed == 0 and not dry_run:
        _skip("無 volume 需要清除")


def step_remove_local_db(dry_run: bool) -> None:
    _head("Step 3 > 清除本機 SQLite 資料庫 (.db)")
    for svc_dir in SERVICE_DIRS:
        for db_file in svc_dir.glob("*.db"):
            _remove_path(db_file, dry_run)


def step_remove_local_keys(dry_run: bool) -> None:
    _head("Step 4 > 清除本機 keys/ 目錄（開發模式金鑰）")
    for svc_dir in SERVICE_DIRS:
        keys_dir = svc_dir / "keys"
        _remove_path(keys_dir, dry_run)


def step_remove_test_keys(dry_run: bool) -> None:
    _head("Step 5 > 清除測試用金鑰（test/e2e_keys/ + test/sim_keys/）")
    test_key_dirs = [
        ROOT / "test" / "e2e_keys",
        ROOT / "test" / "sim_keys",
    ]
    found = False
    for d in test_key_dirs:
        if d.exists():
            _remove_path(d, dry_run)
            found = True
    if not found:
        _skip("無測試金鑰需要清除")


def step_remove_pycache(dry_run: bool) -> None:
    _head("Step 6 > 清除 Python __pycache__")
    count = 0
    for cache_dir in ROOT.rglob("__pycache__"):
        _remove_path(cache_dir, dry_run)
        count += 1
    if count == 0:
        _skip("無 __pycache__ 需要清除")


# ── 主程式 ────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NUTC Voting System — 一鍵狀態重置腳本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例：
  python reset.py              完整重置（推薦在每次測試前執行）
  python reset.py --soft       僅清本機 DB + keys（不動 Docker）
  python reset.py --docker     僅清 Docker volumes
  python reset.py --dry-run    預覽模式，不實際刪除任何東西
        """,
    )
    parser.add_argument("--soft",    action="store_true", help="僅清本機 DB 與 keys，不動 Docker")
    parser.add_argument("--docker",  action="store_true", help="僅清 Docker volumes，不清本機檔案")
    parser.add_argument("--dry-run", action="store_true", help="預覽模式，不實際執行任何刪除")
    args = parser.parse_args()

    dry = args.dry_run

    print(f"\n{C.BOLD}{'='*55}{C.RESET}")
    print(f"{C.BOLD}  NUTC Voting System — 狀態重置{C.RESET}")
    if dry:
        print(f"  {C.YELLOW}[DRY-RUN 模式：不會實際刪除任何東西]{C.RESET}")
    print(f"{C.BOLD}{'='*55}{C.RESET}")

    if args.soft:
        # 僅清本機
        step_remove_local_db(dry)
        step_remove_local_keys(dry)
        step_remove_test_keys(dry)
        step_remove_pycache(dry)

    elif args.docker:
        # 僅清 Docker
        step_stop_containers(dry)
        step_remove_volumes(dry)

    else:
        # 完整重置
        step_stop_containers(dry)
        step_remove_volumes(dry)
        step_remove_local_db(dry)
        step_remove_local_keys(dry)
        step_remove_test_keys(dry)
        step_remove_pycache(dry)

    print(f"\n{C.BOLD}{C.GREEN}{'='*55}{C.RESET}")
    if dry:
        print(f"{C.BOLD}{C.GREEN}  [DRY-RUN] 預覽完成，未實際刪除任何東西。{C.RESET}")
    else:
        print(f"{C.BOLD}{C.GREEN}  重置完成！系統已恢復乾淨狀態。{C.RESET}")
        print(f"  執行 {C.CYAN}docker compose up --build{C.RESET} 重新啟動服務。")
    print(f"{C.BOLD}{C.GREEN}{'='*55}{C.RESET}\n")


if __name__ == "__main__":
    main()
