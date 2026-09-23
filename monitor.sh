#!/bin/bash
# monitor.sh — NUTC 投票系統監控腳本
#
# 用途：在 Oracle VM 上執行，一次看完整個投票管線（Admin/CA/TA/TPA/
# Voter/CC/BB）目前的進度，並自動比對幾個「理論上不該發生」的狀態，
# 出現時直接印出警告。
#
# 用法：
#   bash monitor.sh
#
# 這幾個異常偵測規則，都是這次實測踩到真實 bug 之後歸納出來的：
#   1. BB 已公告結果，但 Voter 本地佇列還有未送出的票
#      → 這些票沒被算進結果，且會污染下一輪（除非先執行新一輪重置）
#   2. TPA 已投票人數 / CC 有效票數 / BB 公告票數 三者不一致
#      → 正常應該三者相等，不一致代表可能有幽靈選票或漏算
#   3. TPA 已投票人數超過 CA 已完成認證人數
#      → 理論上不可能發生（沒認證過不可能拿到 Voting Token）
#   4. CC 的 used_token_hashes 裡，有任何一筆對不上 TPA 目前核發過的
#      任何一個 token → 精確定位「幽靈選票」是哪一筆

set -uo pipefail

echo "======================================"
echo " NUTC 投票系統監控 - $(date '+%Y-%m-%d %H:%M:%S')"
echo "======================================"

echo
echo "=== 容器狀態 ==="
docker compose ps

echo
echo "=== 系統資源 ==="
free -h
df -h / 2>/dev/null | tail -1

echo
echo "=== Admin 名冊統計 ==="
docker exec voting_admin python3 -c "
import sqlite3
conn = sqlite3.connect('/app/admin_tool/data/admin.db')
c = conn.cursor()
c.execute('SELECT ca_status, COUNT(*) FROM voter_roster GROUP BY ca_status')
for r in c.fetchall(): print(' ', r)
"

CA_REGISTERED=$(docker exec voting_ca python3 -c "
import sqlite3
conn = sqlite3.connect('/app/ca_server/data/ca.db')
c = conn.cursor()
c.execute(\"SELECT COUNT(*) FROM voter_registry WHERE status='registered'\")
print(c.fetchone()[0])
" 2>/dev/null)
echo
echo "=== CA 已完成認證人數：${CA_REGISTERED:-N/A} ==="

echo
echo "=== TA 選舉狀態 ==="
docker exec voting_ta python3 -c "
import sqlite3
conn = sqlite3.connect('/app/ta_server/data/ta.db')
c = conn.cursor()
c.execute('SELECT * FROM election_state')
for r in c.fetchall(): print(' ', r)
"

TPA_USED=$(docker exec voting_tpa python3 -c "
import sqlite3
conn = sqlite3.connect('/app/tpa_server/data/tpa.db')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM issued_tokens WHERE used = 1')
print(c.fetchone()[0])
" 2>/dev/null)
echo
echo "=== TPA 已投票人數：${TPA_USED:-N/A} ==="

VOTER_PENDING=$(docker exec voting_voter python3 -c "
import sqlite3
conn = sqlite3.connect('/app/voter_client/data/voter_queue.db')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM pending_envelope')
print(c.fetchone()[0])
" 2>/dev/null)
echo "=== Voter 本地待送出佇列：${VOTER_PENDING:-N/A} 筆 ==="

CC_ENVELOPES=$(docker exec voting_cc python3 -c "
import sqlite3
conn = sqlite3.connect('/app/cc_server/data/cc.db')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM envelopes')
print(c.fetchone()[0])
" 2>/dev/null)
CC_VALID=$(docker exec voting_cc python3 -c "
import sqlite3
conn = sqlite3.connect('/app/cc_server/data/cc.db')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM valid_votes')
print(c.fetchone()[0])
" 2>/dev/null)
CC_DONE=$(docker exec voting_cc python3 -c "
import sqlite3
conn = sqlite3.connect('/app/cc_server/data/cc.db')
c = conn.cursor()
c.execute(\"SELECT value FROM tally_state WHERE key='done'\")
r = c.fetchone()
print(r[0] if r else '0')
" 2>/dev/null)
echo
echo "=== CC：envelopes=${CC_ENVELOPES:-N/A}  valid_votes=${CC_VALID:-N/A}  done=${CC_DONE:-N/A} ==="

BB_PUBLISHED=$(docker exec voting_bb python3 -c "
import sqlite3
conn = sqlite3.connect('/app/bb_server/data/bb.db')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM published_votes')
print(c.fetchone()[0])
" 2>/dev/null)
BB_STATE=$(docker exec voting_bb python3 -c "
import sqlite3
conn = sqlite3.connect('/app/bb_server/data/bb.db')
c = conn.cursor()
c.execute(\"SELECT value FROM bb_state WHERE key='published'\")
r = c.fetchone()
print(r[0] if r else '0')
" 2>/dev/null)
echo "=== BB：published_votes=${BB_PUBLISHED:-N/A}  published_flag=${BB_STATE:-N/A} ==="

echo
echo "======================================"
echo " 異常偵測"
echo "======================================"

FOUND_ISSUE=0

# 檢查 1：BB 已公告，但 Voter 本地還有未送出的票
if [ "${BB_STATE:-0}" = "1" ] && [ "${VOTER_PENDING:-0}" -gt 0 ] 2>/dev/null; then
  echo "[異常] BB 已公告結果，但 Voter 本地佇列還有 $VOTER_PENDING 筆未送出的票。"
  echo "        這些票沒被算進這次結果，且會污染下一輪（除非先執行新一輪重置）。"
  FOUND_ISSUE=1
fi

# 檢查 2：BB 已公告時，TPA/CC/BB 三方票數應該一致
if [ "${BB_STATE:-0}" = "1" ] && [ -n "${TPA_USED:-}" ] && [ -n "${CC_VALID:-}" ] && [ -n "${BB_PUBLISHED:-}" ]; then
  if [ "$TPA_USED" != "$CC_VALID" ] || [ "$CC_VALID" != "$BB_PUBLISHED" ]; then
    echo "[異常] 票數不一致：TPA 已投票=$TPA_USED，CC 有效票=$CC_VALID，BB 公告票數=$BB_PUBLISHED。"
    echo "        正常應該三者相等，不一致代表可能有幽靈選票或漏算。"
    FOUND_ISSUE=1
  fi
fi

# 檢查 3：TPA 已投票人數不應超過 CA 已完成認證人數
if [ -n "${TPA_USED:-}" ] && [ -n "${CA_REGISTERED:-}" ] && [ "$TPA_USED" -gt "$CA_REGISTERED" ] 2>/dev/null; then
  echo "[異常] TPA 已投票人數（$TPA_USED）超過 CA 已完成認證人數（$CA_REGISTERED）——理論上不可能發生。"
  FOUND_ISSUE=1
fi

# 檢查 4：CC 的 used_token_hashes 裡，有沒有任何一筆對不上 TPA 目前核發過的 token
ORPHAN_HASHES=$(
  comm -23 \
    <(docker exec voting_cc python3 -c "
import sqlite3
conn = sqlite3.connect('/app/cc_server/data/cc.db')
c = conn.cursor()
c.execute('SELECT token_hash FROM used_token_hashes ORDER BY token_hash')
for r in c.fetchall(): print(r[0])
" 2>/dev/null | sort) \
    <(docker exec voting_tpa python3 -c "
import sqlite3, hashlib
conn = sqlite3.connect('/app/tpa_server/data/tpa.db')
c = conn.cursor()
c.execute('SELECT token_id FROM issued_tokens')
for (token_id,) in c.fetchall():
    print(hashlib.sha256(token_id.encode()).hexdigest())
" 2>/dev/null | sort)
)
if [ -n "$ORPHAN_HASHES" ]; then
  echo "[異常] CC 收過以下 token_hash，但對不到任何一個 TPA 目前核發過的 token（疑似幽靈選票）："
  echo "$ORPHAN_HASHES" | sed 's/^/        /'
  FOUND_ISSUE=1
fi

if [ "$FOUND_ISSUE" -eq 0 ]; then
  echo "[正常] 沒有偵測到已知的異常模式。"
fi
