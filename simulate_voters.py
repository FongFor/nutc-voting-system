#!/usr/bin/env python3
"""
simulate_voters.py  —  多人投票模擬腳本

在 docker compose up --build 之後執行，可以模擬多人同時投票。
預設 50 人，可以用 -n 指定人數。

用法：
  python simulate_voters.py              預設 50 人
  python simulate_voters.py -n 20        模擬 20 人
  python simulate_voters.py -n 100 --random   隨機分配候選人
  python simulate_voters.py -n 50 --random
  python simulate_voters.py --skip-wait  跳過等待截止（TA 已過期時用）
  python simulate_voters.py --verbose    顯示每個人的詳細步驟
"""

import argparse
import base64
import json
import os
import random
import secrets
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Optional

import requests

# ── 確保 shared/ 可被 import ──────────────────────────────────
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from shared.config_loader import local_url, candidates as cfg_candidates, timing
from shared.auth_component import verify_auth_component
from shared.crypto_utils import encapsulate_vote
from shared.blind_signature import (
    generate_blinding_factor,
    blind_message,
    verify_blind_signature,
)
from shared.format_utils import int_to_hex, hex_to_int, sha256_hex, ts_to_human
from shared.key_manager import (
    load_or_generate_keypair,
    load_or_request_certificate,
    load_or_fetch_ca_cert,
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ANSI 顏色
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

_print_lock = Lock()

def _p(*args, **kwargs):
    with _print_lock:
        print(*args, **kwargs)

def _ok(msg):   _p(f"  {C.GREEN}✓{C.RESET} {msg}")
def _fail(msg): _p(f"  {C.RED}✗{C.RESET} {msg}")
def _info(msg): _p(f"  {C.CYAN}→{C.RESET} {msg}")
def _warn(msg): _p(f"  {C.YELLOW}⚠{C.RESET} {msg}")
def _step(msg): _p(f"  {C.DIM}·{C.RESET} {msg}")

VERBOSE = False

def _vinfo(msg):
    if VERBOSE:
        _info(msg)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 進度追蹤
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class Progress:
    def __init__(self, total: int):
        self.total   = total
        self.done    = 0
        self.success = 0
        self.failed  = 0
        self._lock   = Lock()

    def update(self, success: bool):
        with self._lock:
            self.done += 1
            if success:
                self.success += 1
            else:
                self.failed += 1
            self._render()

    def _render(self):
        pct   = self.done / self.total
        width = 40
        filled = int(width * pct)
        bar = "█" * filled + "░" * (width - filled)
        rate = f"{self.success}/{self.done}"
        print(
            f"\r  [{C.GREEN}{bar}{C.RESET}] {pct*100:5.1f}%  "
            f"{C.GREEN}✓{self.success}{C.RESET} {C.RED}✗{self.failed}{C.RESET} / {self.total}",
            end="", flush=True
        )
        if self.done == self.total:
            print()  # 換行


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Clock Skew 同步器
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ClockSync:
    def __init__(self):
        self.skew   = 0
        self.synced = False

    def sync(self, ta_url: str) -> int:
        try:
            t0   = time.time()
            resp = requests.get(f"{ta_url}/api/deadline", timeout=10)
            t1   = time.time()
            data = resp.json()
            deadline  = data["deadline"]
            remaining = data["remaining_seconds"]
            server_now = deadline - remaining
            rtt_half   = (t1 - t0) / 2
            self.skew  = int(server_now - (t0 + rtt_half))
            self.synced = True
            if abs(self.skew) > 2:
                _warn(f"Clock Skew：偵測到時鐘偏差 {self.skew:+d} 秒，已補償")
            else:
                _info(f"Clock Skew：同步完成（偏差 {self.skew:+d} 秒）")
        except Exception as e:
            _warn(f"Clock Skew 同步失敗（{e}），使用本機時間")
            self.skew = 0
        return self.skew

    def now(self) -> int:
        return int(time.time()) + self.skew

_clock = ClockSync()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 建立時鐘補償後的認證封包
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _create_auth_packet(sender_id, receiver_id, private_key, cert_pem):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

    timestamp = _clock.now()
    si = secrets.token_hex(16)
    payload = {
        "sender_id":   sender_id,
        "receiver_id": receiver_id,
        "timestamp":   timestamp,
        "certificate": cert_pem,
        "si":          si,
    }
    payload_bytes = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    sig_bytes = private_key.sign(
        payload_bytes,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return {"payload": payload, "signature": base64.b64encode(sig_bytes).decode("utf-8")}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 單一選民投票（Phase 2 + 3）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def vote_one(voter_id: str, candidate: str, progress: Progress) -> dict:
    """
    執行單一選民的完整投票流程（Phase 2 + 3）。
    回傳 {"voter_id", "candidate", "m_hex", "success", "error"}
    """
    ca_url  = local_url("ca")
    tpa_url = local_url("tpa")
    ta_url  = local_url("ta")
    cc_url  = local_url("cc")

    # 每位模擬選民使用獨立的臨時金鑰目錄
    keys_dir = ROOT / "test" / "sim_keys" / voter_id
    keys_dir.mkdir(parents=True, exist_ok=True)

    result = {"voter_id": voter_id, "candidate": candidate, "m_hex": None, "success": False, "error": ""}

    try:
        # ── 金鑰 + 憑證 ──────────────────────────────────────
        (private_key, public_key, e, n, d, private_key_pem, public_key_pem) = \
            load_or_generate_keypair(str(keys_dir))
        ca_cert_pem = load_or_fetch_ca_cert(str(keys_dir), ca_url)
        cert_pem    = load_or_request_certificate(str(keys_dir), voter_id, public_key_pem, ca_url)

        # ── Phase 2：雙向認證（最多 3 次重試）────────────────
        tpa_e = tpa_n = None
        tpa_cert_pem = ""
        auth_ok = False
        last_err = ""

        for attempt in range(3):
            if attempt > 0:
                _clock.sync(ta_url)
                time.sleep(0.5 + random.random())

            try:
                resp = requests.get(f"{tpa_url}/api/public_key", timeout=10)
                tpa_data = resp.json()
                tpa_e = hex_to_int(tpa_data["e"])
                tpa_n = hex_to_int(tpa_data["n"])

                auth_packet = _create_auth_packet(voter_id, "TPA", private_key, cert_pem)
                resp = requests.post(
                    f"{tpa_url}/api/auth",
                    json={"auth_packet": auth_packet, "voter_cert_pem": cert_pem},
                    timeout=15,
                )
                auth_result = resp.json()

                if auth_result.get("status") != "success":
                    last_err = auth_result.get("message", "認證失敗")
                    # 截止時間錯誤不重試
                    if auth_result.get("code") == "DEADLINE_EXCEEDED":
                        raise Exception(f"投票已截止（TPA 拒絕）：{last_err}")
                    continue

                tpa_cert_pem = auth_result.get("tpa_cert_pem", "")
                rp = auth_result["response_packet"]
                sig_bytes = base64.b64decode(rp["signature"])
                verify_auth_component(
                    expected_receiver_id=voter_id,
                    sender_id=rp["payload"]["sender_id"],
                    packet_receiver_id=rp["payload"]["receiver_id"],
                    packet_timestamp=rp["payload"]["timestamp"],
                    packet_cert_pem=tpa_cert_pem,
                    packet_signature=sig_bytes,
                    packet_si=rp["payload"]["si"],
                    ca_public_key=None,
                    delta_t=timing("delta_t_seconds", 300),
                )
                auth_ok = True
                break

            except Exception as ex:
                last_err = str(ex)
                if "截止" in last_err or "DEADLINE" in last_err:
                    raise
                continue

        if not auth_ok:
            raise Exception(f"Phase 2 認證失敗（{last_err}）")

        # ── Phase 3：盲簽章 + 數位信封 ───────────────────────
        resp = requests.get(f"{cc_url}/api/public_key", timeout=10)
        cc_pub_pem = resp.json()["public_key_pem"]

        resp = requests.get(f"{ta_url}/api/public_key", timeout=10)
        ta_pub_pem = resp.json()["public_key_pem"]

        # 計算 m（選票雜湊值）
        now = int(time.time())
        sn  = f"SN{now}{voter_id[-6:]}{secrets.token_hex(4)}"
        inner_hash = sha256_hex(f"{voter_id}|{sn}|{candidate}".encode("utf-8"))
        outer_hash = sha256_hex(f"{inner_hash}|{candidate}".encode("utf-8"))
        m_hex = hex(int(outer_hash, 16))

        # 盲化
        m_int   = hex_to_int(m_hex)
        r       = generate_blinding_factor(tpa_n)
        m_prime = blind_message(m_int, r, tpa_e, tpa_n)

        # TPA 盲簽章
        resp = requests.post(
            f"{tpa_url}/api/blind_sign",
            json={"m_prime_hex": int_to_hex(m_prime)},
            timeout=15,
        )
        sign_result = resp.json()
        if sign_result.get("status") != "success":
            code = sign_result.get("code", "")
            if code == "DEADLINE_EXCEEDED":
                raise Exception(f"投票已截止（TPA 拒絕盲簽章）")
            raise Exception(f"盲簽章失敗：{sign_result.get('message')}")

        S_int       = hex_to_int(sign_result["S_hex"])
        r_inv       = pow(r, -1, tpa_n)
        S_prime_int = (S_int * r_inv) % tpa_n
        S_prime_hex = int_to_hex(S_prime_int)

        if not verify_blind_signature(S_prime_int, tpa_e, tpa_n, m_int):
            raise Exception("盲簽章數學驗證失敗")

        # 封裝數位信封
        envelope = encapsulate_vote(
            voter_id=voter_id,
            sn=sn,
            vote_content=candidate,
            s_prime_hex=S_prime_hex,
            m_hex=m_hex,
            cc_public_key_pem=cc_pub_pem,
            ta_public_key_pem=ta_pub_pem,
        )

        # 傳送至 CC
        resp = requests.post(f"{cc_url}/api/receive_envelope", json=envelope, timeout=15)
        cc_result = resp.json()
        if cc_result.get("status") != "success":
            code = cc_result.get("code", "")
            if code == "DEADLINE_EXCEEDED":
                raise Exception("投票已截止（CC 拒絕信封）")
            raise Exception(f"CC 接收失敗：{cc_result.get('message')}")

        result["m_hex"]   = m_hex
        result["success"] = True
        _vinfo(f"{voter_id} ✓ 投票成功（{candidate}）m={m_hex[:16]}...")

    except Exception as ex:
        result["error"] = str(ex)
        _vinfo(f"{voter_id} ✗ 投票失敗：{ex}")

    finally:
        progress.update(result["success"])

    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 1：健康檢查
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def phase1_health_check() -> bool:
    _p(f"\n{C.BOLD}[Phase 1]{C.RESET} 服務健康檢查")
    services = {
        "CA  (5001)": (local_url("ca"),  "/api/ca_cert"),
        "TPA (5000)": (local_url("tpa"), "/api/public_key"),
        "TA  (5002)": (local_url("ta"),  "/api/deadline"),
        "CC  (5003)": (local_url("cc"),  "/api/public_key"),
        "BB  (5004)": (local_url("bb"),  "/api/results"),
    }
    retries  = timing("health_check_retries", 15)
    interval = timing("health_check_interval", 3)
    all_ok   = True

    for name, (base, path) in services.items():
        url = base + path
        ok  = False
        for attempt in range(retries):
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    ok = True
                    break
            except Exception:
                pass
            if attempt < retries - 1:
                time.sleep(interval)
        if ok:
            _ok(f"{name} 就緒")
        else:
            _fail(f"{name} 無回應")
            all_ok = False

    if all_ok:
        _step("同步時鐘...")
        _clock.sync(local_url("ta"))

    return all_ok


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 4：等待截止
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def phase4_wait(skip_wait: bool = False) -> bool:
    _p(f"\n{C.BOLD}[Phase 4]{C.RESET} 等待投票截止")
    ta_url = local_url("ta")
    try:
        resp = requests.get(f"{ta_url}/api/deadline", timeout=10)
        data = resp.json()
        remaining  = data.get("remaining_seconds", 0)
        is_expired = data.get("is_expired", False)
        deadline   = data.get("deadline", 0)

        # 顯示截止時間（人類可讀格式）
        _info(f"截止時間：{ts_to_human(deadline)}（Unix ts：{deadline}）")

        if is_expired:
            _ok("投票已截止，可立即開票")
            return True

        if skip_wait:
            _warn(f"--skip-wait：跳過等待（剩餘 {remaining}s）")
            return True

        _info(f"倒數 {remaining} 秒，等待中...")
        poll = 5
        waited = 0
        while waited < remaining + 15:
            time.sleep(poll)
            waited += poll
            try:
                resp = requests.get(f"{ta_url}/api/deadline", timeout=10)
                data = resp.json()
                if data.get("is_expired", False):
                    _ok("投票截止，進入開票階段")
                    return True
                left = data.get("remaining_seconds", 0)
                print(f"\r  {C.CYAN}→{C.RESET} 剩餘 {left}s...   ", end="", flush=True)
            except Exception:
                pass
        print()
        _fail("等待截止逾時")
        return False

    except Exception as ex:
        _fail(f"取得截止時間失敗：{ex}")
        return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 5：開票
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def phase5_tally() -> Optional[dict]:
    _p(f"\n{C.BOLD}[Phase 5]{C.RESET} 觸發開票（CC → TA → BB）")
    cc_url = local_url("cc")
    try:
        resp = requests.post(f"{cc_url}/api/tally", timeout=60)
        data = resp.json()
        status = data.get("status")

        if status == "success":
            tally       = data.get("tally", {})
            valid_count = data.get("valid_count", 0)
            merkle_root = data.get("merkle_root", "")
            tallied_at  = data.get("tallied_at", 0)
            _ok(f"開票完成！合法選票 {valid_count} 張")
            _info(f"開票時間：{ts_to_human(tallied_at)}（Unix ts：{tallied_at}）")
            _info(f"Root_official：{merkle_root}")
            _p(f"\n  {C.BOLD}計票結果：{C.RESET}")
            total = sum(tally.values()) or 1
            for cand, cnt in sorted(tally.items(), key=lambda x: -x[1]):
                bar_len = int(cnt / total * 30)
                bar = "█" * bar_len + "░" * (30 - bar_len)
                pct = cnt / total * 100
                _p(f"    {C.CYAN}{cand:<20}{C.RESET} [{C.GREEN}{bar}{C.RESET}] {cnt:4d} 票 ({pct:.1f}%)")
            return data

        elif status == "already_done":
            _warn("已完成開票（重複觸發），取得現有結果...")
            resp2 = requests.get(f"{cc_url}/api/results", timeout=10)
            return resp2.json()

        else:
            _fail(f"開票失敗：{data.get('message', '未知錯誤')}")
            return None

    except Exception as ex:
        _fail(f"開票異常：{ex}")
        if VERBOSE:
            traceback.print_exc()
        return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 6：Merkle Proof 驗證
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def phase6_verify(m_hex_list: list) -> tuple:
    _p(f"\n{C.BOLD}[Phase 6]{C.RESET} Merkle Proof 驗證（{len(m_hex_list)} 張選票）")
    bb_url = local_url("bb")

    # 等待 BB 公告
    published = False
    for _ in range(10):
        try:
            resp = requests.get(f"{bb_url}/api/results", timeout=10)
            if resp.json().get("status") == "success":
                published = True
                break
        except Exception:
            pass
        time.sleep(3)

    if not published:
        _fail("BB 尚未公告結果")
        return 0, 0

    _ok("BB 公告已發布")

    # 並發驗證所有 Merkle Proof
    verified = 0
    failed   = 0

    def _verify_one(m_hex):
        try:
            resp = requests.get(f"{bb_url}/api/merkle_proof/{m_hex}", timeout=10)
            data = resp.json()
            if data.get("status") == "success":
                return True, m_hex, len(data.get("merkle_proof", []))
            else:
                return False, m_hex, data.get("message", "")
        except Exception as ex:
            return False, m_hex, str(ex)

    _info(f"並發驗證 {len(m_hex_list)} 個 Merkle Proof...")
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_verify_one, m): m for m in m_hex_list if m}
        for fut in as_completed(futures):
            ok, m_hex, detail = fut.result()
            if ok:
                verified += 1
                _vinfo(f"✓ m={m_hex[:20]}... proof={detail} 步")
            else:
                failed += 1
                _vinfo(f"✗ m={m_hex[:20]}... {detail}")

    _ok(f"Merkle Proof 驗證：{verified} 通過 / {failed} 失敗")
    return verified, failed


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 主流程
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_simulation(
    n: int,
    workers: int,
    use_random: bool,
    skip_wait: bool,
) -> bool:
    cand_list = cfg_candidates()
    start_ts  = int(time.time())

    _p(f"\n{C.BOLD}{'━'*62}{C.RESET}")
    _p(f"{C.BOLD}  NUTC Voting System — 多人並發投票模擬{C.RESET}")
    _p(f"{'━'*62}")
    _p(f"  模擬選民數：{C.CYAN}{n}{C.RESET} 人")
    _p(f"  並發執行緒：{C.CYAN}{workers}{C.RESET}")
    _p(f"  候選人清單：{C.CYAN}{cand_list}{C.RESET}")
    _p(f"  分配方式：  {C.CYAN}{'隨機' if use_random else '輪流'}{C.RESET}")
    _p(f"  開始時間：  {C.CYAN}{ts_to_human(start_ts)}{C.RESET}（Unix ts：{start_ts}）")
    _p(f"{'━'*62}")

    # ── 初始等待（service_startup_wait）──────────────────────
    # 讓剛啟動的容器有足夠時間完成初始化，再進行健康檢查
    startup_wait = timing("service_startup_wait", 5)
    if startup_wait > 0:
        _info(f"等待服務初始化 {startup_wait} 秒（config.json timing.service_startup_wait）...")
        time.sleep(startup_wait)

    # ── Phase 1：健康檢查 ─────────────────────────────────────
    if not phase1_health_check():
        _fail("服務未就緒，終止模擬")
        return False

    # ── 生成選民清單 ──────────────────────────────────────────
    voters = []
    for i in range(1, n + 1):
        voter_id  = f"VOTER_SIM_{i:04d}"
        if use_random:
            candidate = random.choice(cand_list)
        else:
            candidate = cand_list[(i - 1) % len(cand_list)]
        voters.append((voter_id, candidate))

    # ── Phase 2+3：並發投票 ───────────────────────────────────
    _p(f"\n{C.BOLD}[Phase 2+3]{C.RESET} 並發投票（{n} 人，{workers} 執行緒）")
    progress = Progress(n)
    results  = []

    vote_start = time.time()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(vote_one, vid, cand, progress): (vid, cand)
            for vid, cand in voters
        }
        for fut in as_completed(futures):
            results.append(fut.result())
    vote_elapsed = time.time() - vote_start

    # 統計
    success_results = [r for r in results if r["success"]]
    failed_results  = [r for r in results if not r["success"]]
    m_hex_list      = [r["m_hex"] for r in success_results if r["m_hex"]]

    _p(f"\n  投票完成！耗時 {vote_elapsed:.1f}s")
    _ok(f"成功：{len(success_results)} / {n}（{len(success_results)/n*100:.1f}%）")
    if failed_results:
        _warn(f"失敗：{len(failed_results)} 人")
        # 顯示前 5 個失敗原因
        for r in failed_results[:5]:
            _p(f"    {C.RED}✗{C.RESET} {r['voter_id']}：{r['error'][:80]}")
        if len(failed_results) > 5:
            _p(f"    {C.DIM}... 還有 {len(failed_results)-5} 個失敗{C.RESET}")

    if not m_hex_list:
        _fail("所有選民投票均失敗，終止模擬")
        return False

    # ── Phase 4：等待截止 ─────────────────────────────────────
    if not phase4_wait(skip_wait=skip_wait):
        return False

    # ── Phase 5：開票 ─────────────────────────────────────────
    tally_data = phase5_tally()
    if not tally_data:
        return False

    # ── Phase 6：Merkle Proof 驗證 ────────────────────────────
    verified, verify_failed = phase6_verify(m_hex_list)

    # ── 最終報告 ──────────────────────────────────────────────
    end_ts      = int(time.time())
    total_elapsed = end_ts - start_ts

    _p(f"\n{C.BOLD}{'━'*62}{C.RESET}")
    _p(f"{C.BOLD}  模擬完成報告{C.RESET}")
    _p(f"{'━'*62}")
    _p(f"  開始時間：{ts_to_human(start_ts)}（Unix ts：{start_ts}）")
    _p(f"  結束時間：{ts_to_human(end_ts)}（Unix ts：{end_ts}）")
    _p(f"  總耗時：  {total_elapsed}s")
    _p(f"")
    _p(f"  模擬選民：{n} 人")
    _p(f"  投票成功：{C.GREEN}{len(success_results)}{C.RESET} 人（{len(success_results)/n*100:.1f}%）")
    _p(f"  投票失敗：{C.RED}{len(failed_results)}{C.RESET} 人")
    _p(f"  Merkle Proof 驗證通過：{C.GREEN}{verified}{C.RESET} / {len(m_hex_list)}")
    _p(f"")

    # 候選人得票分佈（模擬端統計）
    sim_tally: dict = {}
    for r in success_results:
        sim_tally[r["candidate"]] = sim_tally.get(r["candidate"], 0) + 1
    _p(f"  {C.BOLD}模擬端投票分佈（預期）：{C.RESET}")
    for cand, cnt in sorted(sim_tally.items(), key=lambda x: -x[1]):
        _p(f"    {C.CYAN}{cand:<20}{C.RESET} {cnt} 票")

    # CC 實際計票結果
    if tally_data and tally_data.get("tally"):
        _p(f"\n  {C.BOLD}CC 實際計票結果：{C.RESET}")
        tally = tally_data["tally"]
        total = sum(tally.values()) or 1
        for cand, cnt in sorted(tally.items(), key=lambda x: -x[1]):
            _p(f"    {C.CYAN}{cand:<20}{C.RESET} {cnt} 票（{cnt/total*100:.1f}%）")

    all_ok = len(failed_results) == 0 and verify_failed == 0
    verdict = (
        f"{C.GREEN}{C.BOLD}  ✓ 模擬全部通過{C.RESET}"
        if all_ok
        else f"{C.YELLOW}{C.BOLD}  ⚠ 模擬完成（有部分失敗）{C.RESET}"
    )
    _p(f"\n{verdict}")
    _p(f"{C.BOLD}{'━'*62}{C.RESET}\n")

    return all_ok


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CLI 入口
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    global VERBOSE

    parser = argparse.ArgumentParser(
        description="NUTC Voting System — 多人並發投票模擬腳本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例：
  python simulate_voters.py                   預設 50 人模擬
  python simulate_voters.py -n 10             模擬 10 人
  python simulate_voters.py -n 100            模擬 100 人
  python simulate_voters.py -n 20 --random    隨機分配候選人
  python simulate_voters.py -n 50 --skip-wait 跳過等待截止（TA 已過期時）
  python simulate_voters.py -n 50 --workers 20 最多 20 個並發執行緒
  python simulate_voters.py -n 50 --verbose   顯示每步詳細輸出
        """,
    )
    parser.add_argument(
        "-n", "--num-voters",
        type=int, default=50,
        metavar="N",
        help="模擬選民人數（預設：50）",
    )
    parser.add_argument(
        "--workers",
        type=int, default=10,
        metavar="W",
        help="最大並發執行緒數（預設：10）",
    )
    parser.add_argument(
        "--random",
        action="store_true",
        help="隨機分配候選人（預設：輪流分配）",
    )
    parser.add_argument(
        "--skip-wait",
        action="store_true",
        help="跳過等待投票截止（TA 已過期時使用）",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="顯示每位選民的詳細投票步驟",
    )

    args = parser.parse_args()
    VERBOSE = args.verbose

    if args.num_voters < 1:
        parser.error("選民人數必須 >= 1")
    if args.workers < 1:
        parser.error("執行緒數必須 >= 1")

    # workers 不超過選民數
    workers = min(args.workers, args.num_voters)

    success = run_simulation(
        n=args.num_voters,
        workers=workers,
        use_random=args.random,
        skip_wait=args.skip_wait,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
