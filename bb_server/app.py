"""
bb_server/app.py  —  公告板 (BB)

公開展示計票結果的地方。CC 開票完成後會把結果推送過來，
包含 Merkle Root、各候選人得票數、以及所有合法選票的清單。

選民在 /receipt 匯入回執檔或輸入 m_hex 驗證選票：瀏覽器下載整份 CC 簽章
結果包，在本機驗章、比對清單、重建 Merkle Tree 並畫出驗證路徑。正常驗票
流程不會把選票識別碼送給伺服器——伺服器只要收到過 m_hex，存取紀錄就能把
「某個 IP 查了哪張票」串起來。

端點：
  GET  /                          公告板首頁（計票結果）
  GET  /receipt                   驗證選票（本機驗證，不送出 m_hex）
  GET  /verify                    已停用，導向 /receipt（舊連結相容）
  POST /api/publish               接收 CC 推送的計票結果
  GET  /api/results               查詢計票結果與 Merkle Root
  GET  /api/signed_bundle         CC 簽章的結果包原文（本機驗證用）
  GET  /api/config                查看目前設定
  POST /api/config/reload         重新載入 config.json
"""

import os
import sys
import json
import time
import re
import logging
import datetime

# 確保 shared/ 可被 import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string, redirect
import requests as http_requests

from shared.format_utils import sha256_hex, ts_to_human, b64_to_bytes
from shared.db_utils import Database
from shared.config_loader import make_reload_endpoint, get_service_registration_token  # <3 v4.0
from shared.crypto_utils import verify_signature
from shared.key_manager import load_or_fetch_ca_cert, verify_cert_chain_and_cn  # <3 v4.0
from shared.admin_auth import check_admin_token, admin_auth_error  # <3 v4.0：保護 /api/admin/reset
from shared.tls_utils import load_or_request_tls_certificate, build_mtls_server_context  # <3 v4.0：mTLS
from cryptography import x509
from shared.ui_style import UI_HEAD, THEME_TOGGLE

# 驗證頁在瀏覽器驗 CC 簽章時所用的 CA 根憑證來源：投票網站（voter_client），
# 刻意不由 BB 自己提供——BB 若被入侵，可以連同假的 CA 根憑證一起送出。
CA_CERT_URL_FOR_BROWSER = f"https://{os.environ.get('SITE_ADDRESS', 'localhost')}/api/proxy/ca/ca_cert"

# ============================================================
# 常數設定
# ============================================================
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR    = os.path.join(SERVICE_DIR, "keys")
# <3 v4.0：資料庫獨立放進 data/ 子目錄，才能掛載成持久化 volume——
# 原本直接放在 SERVICE_DIR 底下，跟隨容器可寫層一起被重建時清空，
# published_votes（已公告的開票結果）沒了會需要重新公告，任何一次
# 重新部署都可能連帶造成這個後果。
DATA_DIR    = os.path.join(SERVICE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH     = os.path.join(DATA_DIR, "bb.db")
BB_ID       = "BB"
BB_HOSTNAME = os.environ.get("BB_HOSTNAME", "bb")  # <3 v4.0：填入 TLS 憑證的 SAN
CC_URL      = os.environ.get("CC_URL", "https://localhost:5003")
CA_URL      = os.environ.get("CA_URL", "https://localhost:5001")

# ============================================================
# 資料庫初始化
# ============================================================
db = Database(DB_PATH)
db.execute("""
    CREATE TABLE IF NOT EXISTS bb_state (
        key     TEXT PRIMARY KEY,
        value   TEXT NOT NULL
    )
""")
db.execute("""
    CREATE TABLE IF NOT EXISTS published_votes (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        m_hex       TEXT NOT NULL,
        leaf_hash   TEXT NOT NULL
    )
""")
# v2.0 修正：規格書 §19.5 明定 BB 不得儲存 vote 對 m_hex 的對應關係，只能
# 存 m_hex 清單。這裡不再有 vote 欄位；若是延續舊資料庫（曾經有 vote
# 欄位），沿用該表仍可運作，只是新寫入的資料不會再填入 vote。 <3

print("[BB] 公告板初始化完成。")

# ============================================================
# 載入 CA 憑證（用於驗證 CC 憑證）
# ============================================================
try:
    _ca_cert_pem = load_or_fetch_ca_cert(KEYS_DIR, CA_URL)
    _ca_cert = x509.load_pem_x509_certificate(_ca_cert_pem.encode('utf-8'))
    print("[BB] CA 憑證已載入")
except Exception as ex:
    print(f"[BB] 警告：無法取得 CA 憑證（{ex}）")
    _ca_cert_pem = None
    _ca_cert = None

# v4.0 新增：BB 沒有應用層身分金鑰對（規格書一貫定位 BB「無自有金鑰」），
# 但一樣需要一把 TLS 專用金鑰對，供公開監聽埠出示伺服器憑證用。
try:
    _tls_cert_path, _tls_key_path = load_or_request_tls_certificate(
        KEYS_DIR, BB_ID, BB_HOSTNAME, CA_URL,
        registration_token=get_service_registration_token(),
    )
except Exception as ex:
    print(f"[BB] 警告：無法取得 TLS 憑證（{ex}）")
    _tls_cert_path = _tls_key_path = None

# ============================================================
# Flask App
# ============================================================
app = Flask(__name__)


@app.after_request
def _no_referrer(resp):
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


class _StripQueryString(logging.Filter):
    """Werkzeug 的存取紀錄會印出完整網址；拿掉查詢字串，避免有人用舊網址
    （例如 /verify?m_hex=…）查票時，把 m_hex 和時間留在容器日誌裡。"""
    _QUERY = re.compile(r'\?[^\s"]*')

    def filter(self, record):
        msg = record.getMessage()
        if '?' in msg:
            record.msg, record.args = self._QUERY.sub('', msg), ()
        return True


logging.getLogger('werkzeug').addFilter(_StripQueryString())


# ── Jinja2 自訂過濾器：Unix timestamp → 人類可讀 ──────────────
@app.template_filter('ts_to_str')
def ts_to_str(ts):
    """將 Unix timestamp 轉為 YYYY-MM-DD HH:MM:SS（僅用於 UI 顯示）"""
    try:
        return ts_to_human(int(ts))  # 明確使用 UTC+8，不受容器／主機時區影響
    except Exception:
        return str(ts)


# ── 瀏覽器本機驗證 JS（/receipt 使用）────────────────────────
# 本頁是 BB 自己提供的，BB 送來的任何資料（root、proof、結果包）都不能
# 直接相信：root 必須來自「CC 簽過章、且 CC 憑證由 CA 簽發」的結果包，
# CA 根憑證則向投票網站（不是 BB）索取。
_LOCAL_VERIFY_JS = """          async function sha256Hex(bytes) {
            const digest = await crypto.subtle.digest('SHA-256', bytes);
            return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
          }
          function concatBytes(...arrs) {
            const total = arrs.reduce((n, a) => n + a.length, 0);
            const out = new Uint8Array(total);
            let offset = 0;
            for (const a of arrs) { out.set(a, offset); offset += a.length; }
            return out;
          }
          // 必須跟 shared/merkle_tree.py 的 h_leaf/h_node 規則完全一致：
          // 前綴一個位元組（葉節點 0x00、中間節點 0x01），後面接的是雜湊值
          // 的「16進位字串本身」當文字編碼，不是先還原成二進位。
          async function hLeafLocal(mHex) {
            const enc = new TextEncoder();
            return sha256Hex(concatBytes(new Uint8Array([0x00]), enc.encode(mHex)));
          }
          async function hNodeLocal(left, right) {
            const enc = new TextEncoder();
            return sha256Hex(concatBytes(new Uint8Array([0x01]), enc.encode(left), enc.encode(right)));
          }
          async function verifyProofLocally(mHex, proof, rootOfficial) {
            let current = await hLeafLocal(mHex);
            for (const step of proof) {
              current = step.position === 'right'
                ? await hNodeLocal(current, step.sibling)
                : await hNodeLocal(step.sibling, current);
            }
            return current === rootOfficial;
          }


          // ── 驗證 CC 簽章用的工具（與 voter_client 的同名函式相同邏輯）──
          // 本頁是 BB 自己提供的，BB 送來的任何資料（root、proof、結果包）
          // 都不能直接相信：root 必須來自「CC 簽過章、且 CC 憑證由 CA 簽發」
          // 的結果包，CA 根憑證則向投票網站（不是 BB）索取。
          function pemToDer(pem) {
            const b64 = pem.split(/-----[^-]+-----/).join('').split('').filter(c => c.trim()).join('');
            return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
          }
          function b64decode(b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)); }
          function bytesToHexStr(bytes) { return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''); }
          function derReadTLV(bytes, offset) {
            const lenByte = bytes[offset + 1];
            let lenOfLen = 0, length;
            if (lenByte & 0x80) {
              lenOfLen = lenByte & 0x7f;
              length = 0;
              for (let i = 0; i < lenOfLen; i++) length = (length << 8) | bytes[offset + 2 + i];
            } else {
              length = lenByte;
            }
            const contentStart = offset + 2 + lenOfLen;
            return { tag: bytes[offset], start: offset, end: contentStart + length, contentStart, contentEnd: contentStart + length };
          }
          function derChildren(bytes, start, end) {
            const out = [];
            for (let o = start; o < end;) { const t = derReadTLV(bytes, o); out.push(t); o = t.end; }
            return out;
          }
          function derFindOid(bytes, oid, start, end) {
            search:
            for (let i = start; i + 2 + oid.length <= end; i++) {
              if (bytes[i] !== 0x06 || bytes[i + 1] !== oid.length) continue;
              for (let j = 0; j < oid.length; j++) if (bytes[i + 2 + j] !== oid[j]) continue search;
              return derReadTLV(bytes, derReadTLV(bytes, i).end);
            }
            return null;
          }
          function parseCertificate(certPem) {
            const der = pemToDer(certPem);
            const top = derReadTLV(der, 0);
            const [tbs, , sigValTlv] = derChildren(der, top.contentStart, top.contentEnd);
            const sigValue = der.slice(sigValTlv.contentStart + 1, sigValTlv.contentEnd);
            const tbsBytes = der.slice(tbs.start, tbs.end);
            let kids = derChildren(der, tbs.contentStart, tbs.contentEnd);
            if (kids[0].tag === 0xa0) kids = kids.slice(1);
            const subjectTlv = kids[4], spkiTlv = kids[5];
            const cnTlv = derFindOid(der, [0x55, 0x04, 0x03], subjectTlv.contentStart, subjectTlv.contentEnd);
            return {
              tbsBytes, sigValue,
              spkiBytes: der.slice(spkiTlv.start, spkiTlv.end),
              commonName: cnTlv ? new TextDecoder().decode(der.slice(cnTlv.contentStart, cnTlv.contentEnd)) : null,
            };
          }
          async function verifyCertChain(certPem, expectedCN, caKey) {
            const { tbsBytes, sigValue, spkiBytes, commonName } = parseCertificate(certPem);
            if (commonName !== expectedCN) throw new Error(`憑證 CN 不符（預期 ${expectedCN}，實際 ${commonName}）`);
            const ok = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, caKey, sigValue, tbsBytes);
            if (!ok) throw new Error(`${expectedCN} 憑證不是由 CA 簽發，可能遭偽造`);
            return spkiBytes;
          }
          // 與 Python padding.PSS.MAX_LENGTH 一致：emLen - hLen(32) - 2
          function pssMaxSaltLength(spkiBytes) {
            const top = derReadTLV(spkiBytes, 0);
            const [, bitStr] = derChildren(spkiBytes, top.contentStart, top.contentEnd);
            const rsa = spkiBytes.slice(bitStr.contentStart + 1, bitStr.contentEnd);
            const rsaTop = derReadTLV(rsa, 0);
            const [nTlv] = derChildren(rsa, rsaTop.contentStart, rsaTop.contentEnd);
            const modulusBits = BigInt('0x' + bytesToHexStr(rsa.slice(nTlv.contentStart, nTlv.contentEnd))).toString(2).length;
            return Math.ceil((modulusBits - 1) / 8) - 32 - 2;
          }

          // CA 根憑證向投票網站索取（不向 BB），驗 CC 憑證鏈與結果包簽章，
          // 通過才回傳結果包內容；任何一步不符都丟出例外。
          async function verifySignedBundle(sb, caCertUrl, onStep) {
            const caResp = await fetch(caCertUrl, { cache: 'no-store' }).then(r => r.json());
            if (caResp.status !== 'success' || !caResp.ca_certificate) throw new Error('無法從投票網站取得 CA 根憑證');
            const caKey = await crypto.subtle.importKey('spki', parseCertificate(caResp.ca_certificate).spkiBytes,
              { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
            onStep('已從投票網站取得 CA 根憑證');
            const ccSpki = await verifyCertChain(sb.cc_cert_pem, 'CC', caKey);
            onStep('CC 憑證由 CA 簽發');
            const ccKey = await crypto.subtle.importKey('spki', ccSpki, { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify']);
            const sigOk = await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: pssMaxSaltLength(ccSpki) },
              ccKey, b64decode(sb.signature), new TextEncoder().encode(sb.signed_bundle));
            if (!sigOk) throw new Error('結果包的 CC 簽章無效，公告內容可能遭竄改');
            onStep('開票結果包的 CC 簽章有效');
            return JSON.parse(sb.signed_bundle);
          }

          // 比照 shared/merkle_tree.py 的 _build_tree / get_proof：奇數節點上提、不複製。
          async function buildLayersLocal(mHexList) {
            const layers = [await Promise.all(mHexList.map(hLeafLocal))];
            while (layers[layers.length - 1].length > 1) {
              const cur = layers[layers.length - 1];
              const pairs = [];
              for (let i = 0; i + 1 < cur.length; i += 2) pairs.push(hNodeLocal(cur[i], cur[i + 1]));
              const next = await Promise.all(pairs);
              if (cur.length % 2) next.push(cur[cur.length - 1]);
              layers.push(next);
            }
            return layers;
          }
          function proofFromLayers(layers, index) {
            const proof = [];
            for (const layer of layers.slice(0, -1)) {
              if (index % 2 === 1) proof.push({ sibling: layer[index - 1], position: 'left' });
              else if (index + 1 < layer.length) proof.push({ sibling: layer[index + 1], position: 'right' });
              index = Math.floor(index / 2);
            }
            return proof;
          }
"""


# ── Merkle Tree 樹狀圖（/receipt 使用）──────────────────────
# 使用前必須先在頁面上放好 #tree-scroll-wrap、#tree-canvas、#treeLegend、
# #viewPath、#viewAll、#node-panel，並宣告全域變數 treeData（{layers, target_index, proof_path, virtual_nodes}，
# 見 /receipt 的 treeDataFromLayers()），
# 然後呼叫 initTree()。
_TREE_VIZ_HEAD = """  <style>
    /* 樹狀圖畫布：固定高度的拖曳容器，由 JS 控制畫布位置與縮放 */
    /* touch-action: pan-y：單指上下滑動交給頁面捲動，左右滑動與雙指縮放才由樹狀圖處理 */
    #tree-scroll-wrap { position: relative; width: 100%; height: clamp(300px, 52vh, 520px); overflow: hidden;
      background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius); cursor: grab; touch-action: pan-y; }
    #tree-scroll-wrap:active { cursor: grabbing; }
    #tree-canvas { display: block; position: absolute; top: 0; left: 0; max-width: none; }
    #node-panel { display: none; position: fixed; z-index: 200; max-width: min(420px, calc(100vw - 24px)); pointer-events: none;
      background: var(--surface); border: 1px solid var(--border-strong); border-radius: var(--radius); padding: 12px 14px; }
    #node-panel .panel-title { font-weight: 700; font-size: 0.85rem; margin-bottom: 4px; }
    #node-panel .panel-hash { font-family: var(--mono); font-size: 0.8rem; color: var(--accent); word-break: break-all; }
    #node-panel .panel-meta { color: var(--muted); font-size: 0.8rem; margin-top: 4px; }
    .legend { display: flex; flex-wrap: wrap; gap: 6px 14px; font-size: 0.85rem; color: var(--muted); }
    .legend span { display: inline-flex; align-items: center; gap: 6px; }
    .legend i { width: 12px; height: 12px; border-radius: 3px; border: 2px solid; display: inline-block; }
    .proof-step { display: grid; grid-template-columns: auto auto minmax(0, 1fr); gap: 4px 10px; align-items: baseline; padding: 8px 0; border-bottom: 1px solid var(--border); }
    .proof-step:last-child { border-bottom: 0; }
  </style>
  <script>
    // 切換深色模式後重畫樹狀圖（畫布顏色由 JS 決定）
    (function () { var t = window.toggleTheme; window.toggleTheme = function () { t(); if (typeof draw === 'function') draw(); }; })();
  </script>
"""

_TREE_VIZ_JS = """  // ════════════════════════════════════════════════════════════
  //  完美的金字塔佈局 — 自底向上精準尋跡 + Root 絕對置中演算法
  // ════════════════════════════════════════════════════════════

  const NODE_W    = 108;
  const NODE_H    = 34;
  const H_GAP     = 24;
  const V_GAP     = 72;   
  
  // Canvas 內部的固定 Padding（大面積留白，確保畫面宏大不貼邊）
  const PADDING_X  = 100;
  const PADDING_Y  = 100;
  const ROOT_LABEL_H = 26;
  // 層標籤區域寬度（左側保留給文字）
  const LABEL_W    = 80;
  const RADIUS     = 6;

  function getThemeColors() {
    const isDark = document.documentElement.classList.contains('dark');
    return {
      normal:  isDark ? { bg: '#1e1d1b', border: '#4d4a43', text: '#a6a299', glow: null }
                      : { bg: '#ffffff', border: '#b5afa2', text: '#5d5a53', glow: null },
      target:  isDark ? { bg: '#2f2615', border: '#e4b558', text: '#ecebe7', glow: null }
                      : { bg: '#fbf1dc', border: '#875800', text: '#1c1b19', glow: null },
      sibling: isDark ? { bg: '#18291e', border: '#72cf91', text: '#ecebe7', glow: null }
                      : { bg: '#e7f2ea', border: '#1d6b3a', text: '#1c1b19', glow: null },
      path:    isDark ? { bg: '#1f2a36', border: '#8db5df', text: '#ecebe7', glow: null }
                      : { bg: '#e8eef5', border: '#1f4e79', text: '#1c1b19', glow: null },
      root:    isDark ? { bg: '#8db5df', border: '#8db5df', text: '#0f2236', glow: null }
                      : { bg: '#1f4e79', border: '#1f4e79', text: '#ffffff', glow: null },
      virtual: isDark ? { bg: '#1e1d1b', border: '#6b675e', text: '#a6a299' }
                      : { bg: '#faf9f6', border: '#8f897c', text: '#5d5a53' },
      edgeNormal: isDark ? '#36342f' : '#d9d5cc',
      edgePath:   isDark ? '#8db5df' : '#1f4e79',
      layerText:  isDark ? '#a6a299' : '#5d5a53'
    };
  }

  // 畫布字型沿用頁面的字型 token
  function cssFont(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || 'sans-serif';
  }

  // 圖例顏色跟著主題，和畫布用同一組顏色
  const LEGEND = [['target', '您的選票'], ['sibling', '兄弟節點'], ['path', '路徑上的節點'], ['root', '樹根'], ['virtual', '補位節點']];
  function renderLegend(colors) {
    const box = document.getElementById('treeLegend');
    if (!box) return;
    box.textContent = '';
    for (const [role, label] of LEGEND) {
      const c = colors[role];
      const item = document.createElement('span');
      const sw = document.createElement('i');
      sw.style.background = c.bg;
      sw.style.borderColor = c.border;
      if (role === 'virtual') sw.style.borderStyle = 'dashed';
      item.append(sw, document.createTextNode(label));
      box.appendChild(item);
    }
  }

  let scale = 1.0;
  let nodePositions = [];
  let canvasW = 0, canvasH = 0;

  const canvas  = document.getElementById('tree-canvas');
  const ctx     = canvas.getContext('2d');
  const wrap    = document.getElementById('tree-scroll-wrap');
  const panel   = document.getElementById('node-panel');

  function shortHash(h) {
    if (!h) return '—';
    return h.slice(0, 6) + '..' + h.slice(-6);
  }

  function getNodeRole(layerIdx, nodeIdx) {
    for (const p of treeData.proof_path) {
      if (p.layer === layerIdx && p.index === nodeIdx) return p.role;
    }
    return 'normal';
  }

  function isVirtualNode(layerIdx, nodeIdx) {
    for (const v of (treeData.virtual_nodes || [])) {
      if (v.layer === layerIdx && v.index === nodeIdx) return true;
    }
    return false;
  }

  function isPathEdge(fromLayer, fromIdx, toLayer, toIdx) {
    const parentIdx = Math.floor(fromIdx / 2);
    if (parentIdx !== toIdx) return false;
    const fromRole = getNodeRole(fromLayer, fromIdx);
    const toRole   = getNodeRole(toLayer, toIdx);
    return (fromRole === 'target' || fromRole === 'path') &&
           (toRole   === 'path'   || toRole   === 'root');
  }

  // ── 自底向上精準尋跡 + Root 絕對置中演算法（防重疊終極版）──
  // 核心修復：奇數節點補齊後，父節點計算只使用「真實」子節點數量
  // 步驟：
  //   1. 計算每層的「真實」節點數（不含補齊的重複節點）
  //   2. 葉節點從 X=0 開始排列
  //   3. 由下往上，父節點精準對齊真實子節點中央
  //   4. 整體平移使 Root 落在畫布幾何正中央
  //   5. 確保邊界安全
  function computeLayout() {
    const layers = treeData.layers;
    const totalLayers = layers.length;

    // 計算每層的「真實」節點數（後端補齊前的原始數量）
    // 規則：若某層節點數為偶數，真實數 = 該數；若為奇數，真實數 = 該數（補齊後顯示的）
    // 但父節點數 = ceil(子節點真實數 / 2)，所以我們直接用 layers[li].length
    // 重疊問題的根源：layers[0] 可能包含補齊的重複節點（最後一個重複）
    // 解法：計算每層的「原始」節點數
    const realCounts = [];
    realCounts[totalLayers - 1] = 1; // Root 永遠只有 1 個
    for (let li = totalLayers - 2; li >= 0; li--) {
      // 子層的真實數 = 父層真實數 * 2（但不超過 layers[li].length）
      // 實際上：layers[li].length 已是補齊後的數，真實數可能少 1
      realCounts[li] = layers[li].length;
    }
    // 修正：若某層是奇數補齊的，最後一個節點是重複的
    // 判斷方式：若 layers[li].length 為偶數，且 layers[li+1].length * 2 < layers[li].length
    // 簡單做法：直接用 layers[li].length，但在計算父節點時只看「真實」的子節點
    // 真實子節點數 = 父層節點數 * 2（若父層節點數 * 2 < 子層節點數，則子層最後一個是補齊的）
    const trueChildCount = new Array(totalLayers).fill(0);
    trueChildCount[totalLayers - 1] = 1;
    for (let li = totalLayers - 2; li >= 0; li--) {
      const parentCount = trueChildCount[li + 1];
      // 子層真實節點數：父層每個節點最多有 2 個子節點
      // 但子層補齊後的數量 = layers[li].length
      // 真實數 = min(layers[li].length, parentCount * 2)
      // 實際上補齊只會讓最後一個重複，所以真實數 = layers[li].length 或 layers[li].length - 1
      // 判斷：若 layers[li].length 是奇數，則沒有補齊；若是偶數，可能有補齊
      // 最可靠的方式：從葉節點往上推
      trueChildCount[li] = layers[li].length;
    }
    // 從葉節點往上推算真實數
    const nLeaves = layers[0].length;
    trueChildCount[0] = nLeaves;
    for (let li = 1; li < totalLayers; li++) {
      const childTrue = trueChildCount[li - 1];
      trueChildCount[li] = Math.ceil(childTrue / 2);
    }

    // 先設定整體高度，由總層數決定（上下各留 PADDING_Y）
    canvasH = PADDING_Y * 2 + ROOT_LABEL_H + (totalLayers - 1) * (NODE_H + V_GAP) + NODE_H;

    nodePositions = [];
    const nodeMap = Array.from({length: totalLayers}, () => []);

    // ── 步驟 1：排列最底層的葉節點（從 X=0 開始，純相對座標）
    // 包含視覺補齊的虛擬佔位節點（layers[0].length 含補齊）
    const nDisplayLeaves = layers[0].length;
    for (let ni = 0; ni < nDisplayLeaves; ni++) {
      const hash = layers[0][ni];
      const role = getNodeRole(0, ni);
      const virtual = isVirtualNode(0, ni);
      const nodeX = ni * (NODE_W + H_GAP);
      const node = {
        x: nodeX,
        y: canvasH - PADDING_Y - NODE_H,
        w: NODE_W, h: NODE_H, hash, role, virtual,
        layerName: '選票', layerIdx: 0, nodeIdx: ni,
      };
      nodePositions.push(node);
      nodeMap[0][ni] = node;
    }

    // ── 步驟 2：由下往上，父節點精準對齊「真實」子節點中央
    for (let li = 1; li < totalLayers; li++) {
      const nReal = trueChildCount[li];
      const isRoot = li === totalLayers - 1;
      const layerName = isRoot ? '樹根' : `第 ${li} 層`;
      const layerY = canvasH - PADDING_Y - NODE_H - li * (NODE_H + V_GAP);

      for (let ni = 0; ni < nReal; ni++) {
        const hash = layers[li][ni];
        let role = getNodeRole(li, ni);
        if (isRoot) role = 'root';

        const leftChild  = nodeMap[li - 1][ni * 2];
        // 右子節點：只有在真實子節點數允許時才取
        const rightChildIdx = ni * 2 + 1;
        const rightChild = (rightChildIdx < trueChildCount[li - 1]) ? nodeMap[li - 1][rightChildIdx] : null;

        let nodeX = 0;
        if (leftChild && rightChild) {
          // 精準置中於兩個真實子節點的中間
          const leftCenter  = leftChild.x  + NODE_W / 2;
          const rightCenter = rightChild.x + NODE_W / 2;
          nodeX = (leftCenter + rightCenter) / 2 - NODE_W / 2;
        } else if (leftChild) {
          // 單獨子節點：直接垂直對齊
          nodeX = leftChild.x;
        } else {
          nodeX = ni * (NODE_W + H_GAP);
        }

        const virtual = isVirtualNode(li, ni);
        const node = {
          x: nodeX, y: layerY,
          w: NODE_W, h: NODE_H, hash, role, virtual,
          layerName, layerIdx: li, nodeIdx: ni,
        };
        nodePositions.push(node);
        nodeMap[li][ni] = node;
      }
    }

    // ── 步驟 3：計算所有節點的 X 範圍
    let minX = Infinity, maxX = -Infinity;
    for (const node of nodePositions) {
      if (node.x < minX) minX = node.x;
      if (node.x + node.w > maxX) maxX = node.x + node.w;
    }
    const treeContentW = maxX - minX;

    // ── 步驟 4：整體平移，使 Root 落在畫布幾何正中央
    canvasW = LABEL_W + PADDING_X + treeContentW + PADDING_X;
    const rootNode = nodeMap[totalLayers - 1][0];
    const rootRelCenterX = rootNode ? rootNode.x + NODE_W / 2 : minX + treeContentW / 2;
    const extraShift = treeContentW / 2 - (rootRelCenterX - minX);
    for (const node of nodePositions) {
      node.x = (node.x - minX) + LABEL_W + PADDING_X + extraShift;
    }

    // ── 步驟 5：確保最左節點不超出 LABEL_W 邊界
    let actualMinX = Infinity;
    for (const node of nodePositions) {
      if (node.x < actualMinX) actualMinX = node.x;
    }
    if (actualMinX < LABEL_W + 4) {
      const fixShift = LABEL_W + 4 - actualMinX;
      for (const node of nodePositions) { node.x += fixShift; }
      canvasW += fixShift;
    }

    // ── 步驟 6：確保最右節點不超出畫布右側邊界
    let actualMaxX = -Infinity;
    for (const node of nodePositions) {
      if (node.x + node.w > actualMaxX) actualMaxX = node.x + node.w;
    }
    if (actualMaxX > canvasW - PADDING_X / 2) {
      canvasW = actualMaxX + PADDING_X;
    }
  }

  function roundRect(ctx, x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h - r);
    ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    ctx.lineTo(x + r, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - r);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.closePath();
  }

  function draw() {
    if (!treeData) return;  // /receipt 匯入回執前還沒有樹
    const dpr = window.devicePixelRatio || 1;
    const displayW = Math.ceil(canvasW * scale);
    const displayH = Math.ceil(canvasH * scale);

    canvas.width  = displayW * dpr;
    canvas.height = displayH * dpr;
    canvas.style.width  = displayW + 'px';
    canvas.style.height = displayH + 'px';
    ctx.setTransform(dpr * scale, 0, 0, dpr * scale, 0, 0);

    ctx.clearRect(0, 0, canvasW, canvasH);

    const layers = treeData.layers;
    const totalLayers = layers.length;
    const colors = getThemeColors();
    const fontSans = cssFont('--font');
    const fontMono = cssFont('--mono');
    renderLegend(colors);

    // ── 繪製平滑 S 型連接線 ──
    for (let li = 0; li < totalLayers - 1; li++) {
      const childNodes  = nodePositions.filter(n => n.layerIdx === li);
      const parentNodes = nodePositions.filter(n => n.layerIdx === li + 1);

      for (let ci = 0; ci < childNodes.length; ci++) {
        const child  = childNodes[ci];
        const pi     = Math.floor(child.nodeIdx / 2);
        const parent = parentNodes.find(p => p.nodeIdx === pi);
        if (!child || !parent) continue;

        const onPath = isPathEdge(li, ci, li + 1, pi);
        const isVirtEdge = child.virtual || parent.virtual;

        const startX = child.x + child.w / 2;
        const startY = child.y;
        const endX   = parent.x + parent.w / 2;
        const endY   = parent.y + parent.h;
        const midY   = startY - (startY - endY) / 2;

        ctx.save();
        if (isVirtEdge) ctx.setLineDash([4, 3]);
        ctx.beginPath();
        ctx.moveTo(startX, startY);
        ctx.bezierCurveTo(startX, midY, endX, midY, endX, endY);
        ctx.strokeStyle = isVirtEdge ? colors.edgeNormal : (onPath ? colors.edgePath : colors.edgeNormal);
        ctx.lineWidth   = onPath && !isVirtEdge ? 4.0 : 1.2;
        ctx.globalAlpha = isVirtEdge ? 0.2 : (onPath ? 1.0 : 0.3);
        ctx.stroke();
        ctx.restore();
        ctx.globalAlpha = 1.0;
      }
    }

    // ── 繪製高亮重點節點 ──
    for (const node of nodePositions) {
      const { x, y, w, h } = node;

      if (node.virtual) {
        // 補位節點：奇數層上提時的視覺佔位，虛線邊框
        const v = colors.virtual;
        roundRect(ctx, x, y, w, h, RADIUS);
        ctx.fillStyle = v.bg;
        ctx.fill();
        roundRect(ctx, x, y, w, h, RADIUS);
        ctx.save();
        ctx.setLineDash([4, 3]);
        ctx.strokeStyle = v.border;
        ctx.lineWidth = 1.5;
        ctx.stroke();
        ctx.restore();
        ctx.fillStyle = v.text;
        ctx.font = `12px ${fontSans}`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('補位節點', x + w / 2, y + h / 2);
        continue;
      }

      const c = colors[node.role] || colors.normal;

      if (c.glow) {
        ctx.save();
        ctx.shadowColor = c.glow;
        ctx.shadowBlur  = 20;
        ctx.shadowOffsetX = 0;
        ctx.shadowOffsetY = 0;
        roundRect(ctx, x, y, w, h, RADIUS);
        ctx.fillStyle = c.bg;
        ctx.fill();
        ctx.restore();
      }

      roundRect(ctx, x, y, w, h, RADIUS);
      ctx.fillStyle = c.bg;
      ctx.fill();

      roundRect(ctx, x, y, w, h, RADIUS);
      ctx.strokeStyle = c.border;
      ctx.lineWidth   = node.role !== 'normal' ? 3.0 : 1.5;
      ctx.stroke();

      ctx.fillStyle  = c.text;
      ctx.font       = `${node.role === 'normal' ? 400 : 700} 11px ${fontMono}`;
      ctx.textAlign  = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(shortHash(node.hash), x + w / 2, y + h / 2);

      // 樹根：標出它就是 CC 簽章的那個值（能畫出樹表示驗證已通過）
      if (node.role === 'root') {
        ctx.fillStyle = colors.root.border;
        ctx.font = `700 12px ${fontSans}`;
        ctx.textBaseline = 'bottom';
        ctx.fillText('與 CC 簽章的 Merkle Root 相符', x + w / 2, y - 8);
      }
    }

    // ── 繪製層標籤 ──
    ctx.textAlign    = 'right';
    ctx.textBaseline = 'middle';
    ctx.font         = `12px ${fontSans}`;
    ctx.fillStyle    = colors.layerText;

    const drawnLayers = new Set();
    for (const node of nodePositions) {
      if (!drawnLayers.has(node.layerIdx)) {
        drawnLayers.add(node.layerIdx);
        // 層標籤固定在 LABEL_W 區域右側，不受整體平移影響
        ctx.fillText(node.layerName, LABEL_W - 8, node.y + node.h / 2);
      }
    }
  }

  // ── 拖曳狀態（用 canvas position:absolute + left/top 實現，無捲軸）──
  let canvasLeft = 0, canvasTop = 0;

  const MIN_SCALE = 0.15, MAX_SCALE = 1.2;
  let viewMode = 'path';
  function setViewMode(mode) {
    viewMode = mode;
    const p = document.getElementById('viewPath'), a = document.getElementById('viewAll');
    if (p) p.setAttribute('aria-pressed', String(mode === 'path'));
    if (a) a.setAttribute('aria-pressed', String(mode === 'all'));
  }

  // 將 Canvas 用 left/top 定位到容器正中央（overflow:hidden 模式）
  function _centerCanvas() {
    const scaledW = canvasW * scale;
    const scaledH = canvasH * scale;
    const wrapW   = wrap.clientWidth;
    const wrapH   = wrap.clientHeight;
    canvasLeft = Math.round((wrapW - scaledW) / 2);
    canvasTop  = Math.round((wrapH - scaledH) / 2);
    canvas.style.left = canvasLeft + 'px';
    canvas.style.top  = canvasTop  + 'px';
  }

  // 看整棵樹：整張畫布縮放到放得進容器，然後置中
  function fitTree() {
    setViewMode('all');
    const wrapW = wrap.clientWidth;
    const wrapH = wrap.clientHeight;
    scale = Math.max(MIN_SCALE, Math.min(wrapW / canvasW, wrapH / canvasH, MAX_SCALE));
    draw();
    _centerCanvas();
  }

  // 看我的路徑：把「您的選票 → 路徑 → 樹根（含上方標註）」這條直線整段放進容器。
  // 兄弟節點可能遠在樹的另一側，算進去會把整棵樹縮到看不清楚（尤其手機），
  // 所以只在放得下時才納入；放不下時它們可以左右滑動看到。
  function fitPath() {
    setViewMode('path');
    const pathNodes = nodePositions.filter(n => ['target', 'path', 'root'].includes(n.role) && !n.virtual);
    if (!pathNodes.length) return fitTree();
    const pad = 24;
    const wrapW = wrap.clientWidth, wrapH = wrap.clientHeight;
    function bbox(nodes) {
      let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
      for (const n of nodes) {
        // 樹根標註比節點寬，左右各多留一些
        const extra = n.role === 'root' ? 50 : 0;
        x0 = Math.min(x0, n.x - extra); x1 = Math.max(x1, n.x + n.w + extra);
        y0 = Math.min(y0, n.y - (n.role === 'root' ? ROOT_LABEL_H : 0)); y1 = Math.max(y1, n.y + n.h);
      }
      return { x0, y0, x1, y1, s: Math.min((wrapW - pad * 2) / (x1 - x0), (wrapH - pad * 2) / (y1 - y0), 1) };
    }
    const core = bbox(pathNodes);
    const full = bbox(nodePositions.filter(n => n.role !== 'normal' && !n.virtual));
    const box = full.s >= 0.75 || full.s >= core.s ? full : core;
    const { x0, y0, x1, y1 } = box;
    scale = Math.max(0.45, box.s);
    draw();
    canvasLeft = Math.round(wrapW / 2 - ((x0 + x1) / 2) * scale);
    canvasTop  = Math.round(wrapH / 2 - ((y0 + y1) / 2) * scale);
    canvas.style.left = canvasLeft + 'px';
    canvas.style.top  = canvasTop  + 'px';
  }

  // ── 滾輪縮放（以滑鼠位置為中心縮放）──
  wrap.addEventListener('wheel', e => {
    if (!e.ctrlKey && !e.metaKey) return;
    e.preventDefault();
    const rect    = wrap.getBoundingClientRect();
    // 滑鼠在容器內的位置
    const mouseX  = e.clientX - rect.left;
    const mouseY  = e.clientY - rect.top;
    // 滑鼠在畫布邏輯座標中的位置（縮放前）
    const logicX  = (mouseX - canvasLeft) / scale;
    const logicY  = (mouseY - canvasTop)  / scale;

    const delta   = e.deltaY < 0 ? 0.1 : -0.1;
    const oldScale = scale;
    scale = Math.max(MIN_SCALE, Math.min(scale + delta, MAX_SCALE));

    if (scale === oldScale) return;
    draw();

    // 縮放後，讓滑鼠指向的邏輯座標保持在同一螢幕位置
    canvasLeft = Math.round(mouseX - logicX * scale);
    canvasTop  = Math.round(mouseY - logicY * scale);
    canvas.style.left = canvasLeft + 'px';
    canvas.style.top  = canvasTop  + 'px';
  }, { passive: false });

  let isDragging = false, dragStartX = 0, dragStartY = 0, canvasStartLeft = 0, canvasStartTop = 0;

  wrap.addEventListener('mousedown', e => {
    isDragging     = true;
    dragStartX     = e.clientX;
    dragStartY     = e.clientY;
    canvasStartLeft = canvasLeft;
    canvasStartTop  = canvasTop;
    wrap.style.cursor = 'grabbing';
    e.preventDefault();
  });
  window.addEventListener('mousemove', e => {
    if (!isDragging) return;
    canvasLeft = canvasStartLeft + (e.clientX - dragStartX);
    canvasTop  = canvasStartTop  + (e.clientY - dragStartY);
    canvas.style.left = canvasLeft + 'px';
    canvas.style.top  = canvasTop  + 'px';
  });
  window.addEventListener('mouseup', () => {
    isDragging = false;
    wrap.style.cursor = 'grab';
  });
  wrap.addEventListener('mouseleave', () => {
    if (isDragging) {
      isDragging = false;
      wrap.style.cursor = 'grab';
    }
  });

  let touchStartX = 0, canvasTouchLeft = 0, pinch = null;
  function touchMid(t) {
    const r = wrap.getBoundingClientRect();
    return { x: (t[0].clientX + t[1].clientX) / 2 - r.left, y: (t[0].clientY + t[1].clientY) / 2 - r.top,
             d: Math.hypot(t[0].clientX - t[1].clientX, t[0].clientY - t[1].clientY) };
  }
  wrap.addEventListener('touchstart', e => {
    if (e.touches.length === 2) {
      const m = touchMid(e.touches);
      pinch = { d: m.d, scale, lx: (m.x - canvasLeft) / scale, ly: (m.y - canvasTop) / scale };
    } else if (e.touches.length === 1) {
      pinch = null;
      touchStartX     = e.touches[0].clientX;
      canvasTouchLeft = canvasLeft;
    }
  }, { passive: true });
  wrap.addEventListener('touchmove', e => {
    if (e.touches.length === 2 && pinch) {
      e.preventDefault();
      const m = touchMid(e.touches);
      scale = Math.max(MIN_SCALE, Math.min(pinch.scale * m.d / pinch.d, MAX_SCALE));
      draw();
      canvasLeft = Math.round(m.x - pinch.lx * scale);
      canvasTop  = Math.round(m.y - pinch.ly * scale);
    } else if (e.touches.length === 1 && !pinch) {
      canvasLeft = canvasTouchLeft + (e.touches[0].clientX - touchStartX);
    } else {
      return;
    }
    canvas.style.left = canvasLeft + 'px';
    canvas.style.top  = canvasTop  + 'px';
  }, { passive: false });
  wrap.addEventListener('touchend', e => { if (e.touches.length < 2) pinch = null; }, { passive: true });

  canvas.addEventListener('click', e => {
    const rect  = canvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left) / scale;
    const my = (e.clientY - rect.top)  / scale;

    let hit = null;
    for (const node of nodePositions) {
      if (mx >= node.x && mx <= node.x + node.w &&
          my >= node.y && my <= node.y + node.h) {
        hit = node;
        break;
      }
    }

    if (hit) {
      const roleLabels = {
        target:  ['您的選票', 'H(0x00 ‖ m_hex)'],
        sibling: ['兄弟節點：和路徑上的節點一起算出上一層', 'H(0x00 ‖ m_hex) 或 H(0x01 ‖ 左 ‖ 右)'],
        path:    ['路徑上的節點：由下面兩個節點算出', 'H(0x01 ‖ 左 ‖ 右)'],
        root:    ['樹根：CC 簽章的 Merkle Root', 'H(0x01 ‖ 左 ‖ 右)'],
        normal:  ['其他選票的節點', '與您的驗證無關'],
      };
      if (hit.virtual) {
        document.getElementById('panel-title').textContent = '補位節點';
        document.getElementById('panel-hash').textContent  = hit.hash;
        document.getElementById('panel-meta').textContent  =
          `${hit.layerName}・第 ${hit.nodeIdx + 1} 個。這一層是奇數個，最後一個節點直接上提，這裡只是畫圖用的佔位，不參與計算。`;
      } else {
        const [title, formula] = roleLabels[hit.role] || ['節點', ''];
        document.getElementById('panel-title').textContent = title;
        document.getElementById('panel-hash').textContent  = hit.hash;
        document.getElementById('panel-meta').textContent  =
          `${hit.layerName}・第 ${hit.nodeIdx + 1} 個・${formula}`;
      }

      const px = Math.min(e.clientX + 16, window.innerWidth  - 440);
      const py = Math.min(e.clientY + 16, window.innerHeight - 120);
      panel.style.left    = px + 'px';
      panel.style.top     = py + 'px';
      panel.style.display = 'block';
    } else {
      panel.style.display = 'none';
    }
  });

  document.addEventListener('click', e => {
    if (!canvas.contains(e.target)) panel.style.display = 'none';
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') panel.style.display = 'none';
  });

  function initTree() {
    computeLayout();
    // 一打開就看得到整條「您的選票 → 樹根」路徑
    fitPath();
  }

  
  // 視窗寬度改變（旋轉手機、調整視窗）時，依目前的檢視模式重新排版。
  // 只看寬度：手機捲動時網址列收合會觸發「只有高度改變」的 resize，
  // 以前每次都 fitTree()，使用者一捲動畫面就被縮到 15%、看不清楚。
  let _lastWrapW = wrap.clientWidth;
  window.addEventListener('resize', () => {
    if (wrap.clientWidth === _lastWrapW) return;
    _lastWrapW = wrap.clientWidth;
    if (!treeData) return;
    if (viewMode === 'all') fitTree(); else fitPath();
  });

  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
    if (!localStorage.getItem('theme')) {
      if (e.matches) document.documentElement.classList.add('dark');
      else document.documentElement.classList.remove('dark');
      draw();
    }
  });
"""


# ── 共用：線條圖示與公告板專用樣式 ─────────────────────────────
# 圖示為自繪 SVG（24×24、2px 線條、currentColor），不用 emoji／符號字元。
def _icon(paths, cls="icon"):
    return ('<svg class="' + cls + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
            'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' + paths + '</svg>')

_ICON_CHECK   = _icon('<path d="M20 6 9 17l-5-5"/>')
_ICON_X       = _icon('<path d="M18 6 6 18M6 6l12 12"/>')
_ICON_EYE     = _icon('<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>')
_ICON_EYE_OFF = _icon('<path d="M3 3l18 18"/><path d="M10.6 5.1A10.8 10.8 0 0 1 12 5c6.4 0 10 7 10 7a17.6 17.6 0 0 1-3.1 4.1"/>'
                      '<path d="M6.6 6.6A17.4 17.4 0 0 0 2 12s3.6 7 10 7a10.4 10.4 0 0 0 5.4-1.6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>')
_ICON_ALERT   = _icon('<path d="M12 3 2 21h20L12 3z"/><path d="M12 10v4"/><path d="M12 17.5v.01"/>')
_ICON_CLOCK   = _icon('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>')

_BB_STYLE = """  <style>
    .icon { width: 1.15em; height: 1.15em; flex: none; vertical-align: -0.2em; }

    /* ── 首頁：匿名＋可驗證說明 ─────────────────────────── */
    .explain { display: grid; gap: 24px; padding: 28px 20px; border-radius: var(--radius);
      background: var(--surface-2); border: 1px solid var(--border); }
    @media (min-width: 640px) { .explain { padding: 36px 32px; } }
    .explain-head h2 { font-size: clamp(1.35rem, 1.1rem + 1vw, 1.75rem); line-height: 1.3; margin: 0 0 8px; text-wrap: balance; }
    .explain-head p { margin: 0; max-width: 62ch; color: var(--text); }
    .explain-head strong { color: var(--accent); }
    .flow { list-style: none; margin: 0; padding: 0; display: grid; gap: 0; }
    .flow-step { position: relative; padding: 0 0 24px 28px; }
    .flow-step:last-child { padding-bottom: 0; }
    /* 站點之間的連線：手機直向、桌機橫向 */
    .flow-step::before { content: ""; position: absolute; left: 6px; top: 6px; width: 12px; height: 12px;
      border-radius: 50%; background: var(--surface); border: 3px solid var(--accent); }
    .flow-step::after { content: ""; position: absolute; left: 11px; top: 24px; bottom: 0; width: 2px; background: var(--border-strong); }
    .flow-step:last-child::after { display: none; }
    @media (min-width: 860px) {
      .flow { grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 28px; }
      .flow-step { padding: 28px 0 0; }
      .flow-step::before { left: 0; top: 0; }
      .flow-step::after { left: 22px; right: -22px; top: 7px; bottom: auto; width: auto; height: 2px; }
    }
    .flow-role { margin: 0; font-weight: 700; font-size: 1.05rem; }
    .flow-role span { font-weight: 400; color: var(--muted); font-size: 0.9rem; margin-left: 6px; }
    .flow-what { margin: 4px 0 12px; color: var(--muted); font-size: 0.95rem; }
    .knows { list-style: none; margin: 0 0 12px; padding: 0; display: grid; gap: 6px; font-size: 0.95rem; }
    .knows li { display: flex; align-items: center; gap: 8px; }
    .knows .yes { color: var(--text); }
    .knows .yes .icon { color: var(--accent); }
    .knows .no { color: var(--muted); }
    .flow-note { margin: 0; font-size: 0.85rem; color: var(--muted); max-width: 40ch; }
    .explain-foot { margin: 0; padding-top: 16px; border-top: 1px solid var(--border); font-weight: 600; }

    /* ── 首頁：其他 ───────────────────────────────────── */
    .tally { list-style: none; margin: 0; padding: 0; display: grid; gap: 14px; }
    .cta-card { align-self: start; }
    .cta-card h2 { font-size: 1.15rem; }
    details.card > summary { list-style: none; display: flex; justify-content: space-between; align-items: center; gap: 12px; }
    details.card > summary::-webkit-details-marker { display: none; }
    details.card > summary::after { content: "展開"; font-weight: 400; font-size: 0.85rem; color: var(--accent); }
    details.card[open] > summary::after { content: "收合"; }

    /* ── 驗證頁：輸入 ─────────────────────────────────── */
    label.btn:has(+ input:focus-visible) { outline: 3px solid var(--focus); outline-offset: 2px; }
    .field-err { display: flex; gap: 8px; align-items: flex-start; margin: 0; color: var(--warn); font-size: 0.9rem; font-weight: 600; }
    .field-err .icon { margin-top: 0.15em; }
    .alt-entry { display: grid; gap: 10px; }
    .alt-entry h2 { font-size: 1rem; }

    /* ── 驗證頁：結果 ─────────────────────────────────── */
    .verdict { --tone: var(--accent); --tone-soft: var(--accent-soft);
      display: grid; gap: 18px; padding: 24px 20px; border-radius: var(--radius);
      background: var(--tone-soft); border: 1px solid var(--tone); scroll-margin-top: 16px; }
    @media (min-width: 640px) { .verdict { padding: 28px; } }
    .verdict[data-tone="ok"]   { --tone: var(--ok);   --tone-soft: var(--ok-soft); }
    .verdict[data-tone="warn"] { --tone: var(--warn); --tone-soft: var(--warn-soft); }
    .verdict[data-tone="err"]  { --tone: var(--err);  --tone-soft: var(--err-soft); }
    .verdict-head { display: flex; gap: 14px; align-items: center; }
    .verdict-icon { flex: none; width: 52px; height: 52px; border-radius: 50%; display: grid; place-items: center;
      background: var(--tone); color: var(--surface); }
    .verdict-icon .icon { width: 28px; height: 28px; stroke-width: 2.5; }
    .verdict-icon .spin { width: 24px; height: 24px; border-width: 3px; }
    .verdict-title { margin: 0; font-size: clamp(1.4rem, 1.15rem + 1.2vw, 1.9rem); line-height: 1.25; color: var(--tone); }
    .verdict-title:focus { outline: none; }
    .verdict-title:focus-visible { outline: 3px solid var(--focus); outline-offset: 4px; }
    .verdict-sub { margin: 2px 0 0; font-size: 1.05rem; font-weight: 600; }
    .verdict-detail { margin: 0; max-width: 65ch; }
    .verdict-next { margin: 0; padding: 14px 16px; border-radius: var(--radius); background: var(--surface);
      border: 1px solid var(--border); max-width: 65ch; }
    .verdict-next strong { display: block; margin-bottom: 2px; }
    .checks { list-style: none; margin: 0; padding: 0; display: grid; gap: 2px; background: var(--border);
      border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
    .check { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 4px 12px; padding: 14px 16px; background: var(--surface); }
    .check-mark { width: 28px; height: 28px; border-radius: 50%; display: grid; place-items: center;
      border: 2px solid var(--border-strong); color: var(--muted); }
    .check-mark .icon { width: 16px; height: 16px; stroke-width: 3; }
    .check[data-state="ok"]   .check-mark { border-color: var(--ok);  background: var(--ok);  color: var(--surface); }
    .check[data-state="fail"] .check-mark { border-color: var(--err); background: var(--err); color: var(--surface); }
    .check[data-state="run"]  .check-mark { border-color: var(--accent); }
    .check-title { margin: 0; font-weight: 700; align-self: center; }
    .check[data-state="skip"] .check-title, .check[data-state="wait"] .check-title { color: var(--muted); }
    .check-body { grid-column: 2; display: grid; gap: 6px; }
    .check-desc { margin: 0; font-size: 0.9rem; color: var(--muted); }
    .check-state { font-size: 0.85rem; color: var(--muted); }
    .check details summary { font-size: 0.85rem; font-weight: 600; color: var(--accent); }
    .check .steps { margin-top: 6px; font-size: 0.85rem; }
    .check .steps .mark .icon { width: 14px; height: 14px; stroke-width: 3; }
    @media (prefers-reduced-motion: no-preference) {
      .verdict:not(.hidden) .verdict-icon { animation: verdict-pop 420ms cubic-bezier(0.16, 1, 0.3, 1); }
      @keyframes verdict-pop { from { transform: scale(0.6); opacity: 0.4; } to { transform: scale(1); opacity: 1; } }
    }

    /* ── 驗證頁：樹狀圖工具列 ─────────────────────────── */
    .tree-tools { display: flex; flex-wrap: wrap; gap: 8px; }
    .tree-tools .btn { min-height: 44px; }
    .tree-tools .btn[aria-pressed="true"] { background: var(--accent-soft); border-color: var(--accent); color: var(--text); }
  </style>
"""


# ── 首頁：匿名＋可驗證說明（開票前後都顯示）──────────────────────
_ANON_EXPLAINER = """
    <section class="explain" aria-labelledby="explainTitle">
      <div class="explain-head">
        <h2 id="explainTitle">匿名，而且可以驗證</h2>
        <p>這套系統用<strong>盲簽章</strong>把「你是誰」和「你投給誰」拆給不同單位：沒有任何一方同時知道這兩件事，但每位選民都能確認自己的票有被算進去。</p>
      </div>
      <ol class="flow">
        <li class="flow-step">
          <p class="flow-role">資格驗證中心<span>TPA</span></p>
          <p class="flow-what">確認你有投票資格，替選票簽章</p>
          <ul class="knows">
            <li class="yes">""" + _ICON_EYE + """知道你是誰</li>
            <li class="no">""" + _ICON_EYE_OFF + """看不到你投給誰</li>
          </ul>
          <p class="flow-note">選票先用只有你知道的亂數「蒙住」才送去簽章，TPA 簽得到、看不到內容。</p>
        </li>
        <li class="flow-step">
          <p class="flow-role">計票中心<span>CC</span></p>
          <p class="flow-what">檢查 TPA 的簽章，打開選票計票</p>
          <ul class="knows">
            <li class="no">""" + _ICON_EYE_OFF + """不知道是誰投的</li>
            <li class="yes">""" + _ICON_EYE + """看得到選票內容</li>
          </ul>
          <p class="flow-note">選票送到時已經沒有身分，只剩 TPA 的簽章證明它是一張合法選票。</p>
        </li>
        <li class="flow-step">
          <p class="flow-role">公告板<span>BB・本頁</span></p>
          <p class="flow-what">公布 CC 簽章的結果與 Merkle Root</p>
          <ul class="knows">
            <li class="no">""" + _ICON_EYE_OFF + """不知道是誰在驗證</li>
            <li class="no">""" + _ICON_EYE_OFF + """不知道你查的是哪一張</li>
          </ul>
          <p class="flow-note">你用投票後下載的回執，在自己的手機上算出結果，公告板只提供整份公告。</p>
        </li>
      </ol>
      <p class="explain-foot">所以：投票紀錄裡沒有「誰投給誰」，但任何人都能檢查自己的票在 CC 簽章的名單裡。</p>
    </section>
"""


_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <title>開票公告｜NUTC 線上投票</title>""" + UI_HEAD + _BB_STYLE + """
  {% if not published %}<meta http-equiv="refresh" content="20">{% endif %}
</head>
<body>
<header class="topbar">
  <div class="container-wide topbar-inner">
    <a class="brand" href="/">
      <span class="brand-name">NUTC 線上投票</span>
      <span class="brand-sub">開票公告板</span>
    </a>
    <div class="topbar-actions">
      {% if published %}<span class="badge badge-ok">CC 已簽章公告</span>{% else %}<span class="badge badge-warn">等待開票</span>{% endif %}
      """ + THEME_TOGGLE + """
    </div>
  </div>
</header>

<main>
  <div class="container-wide stack-lg">
  {% if published %}
    <div class="stack-sm">
      <h1>開票結果</h1>
      <p class="lead">合法選票 {{ valid_count }} 張{% if tallied_at %}・開票時間 {{ tallied_at | ts_to_str }}（台灣時間）{% endif %}</p>
    </div>

    <div class="grid grid-main-side">
      <section class="card stack" aria-labelledby="tallyTitle">
        <h2 id="tallyTitle" class="section-title">各候選人得票</h2>
        <ol class="tally">
        {% for candidate, count in tally | dictsort(by='value', reverse=true) %}
        {% set pct = (count / valid_count * 100) if valid_count > 0 else 0 %}
          <li class="stack-sm">
            <div class="row-between">
              <span class="strong">{{ candidate }}</span>
              <span><span class="strong">{{ count }}</span> 票 <span class="muted small">{{ "%.1f"|format(pct) }}%</span></span>
            </div>
            <div class="bar" aria-hidden="true"><span style="width: {{ pct }}%"></span></div>
          </li>
        {% endfor %}
        </ol>
        <div class="row-between" style="border-top:1px solid var(--border); padding-top:14px">
          <span class="muted">合法選票合計</span><span class="strong">{{ valid_count }} 票</span>
        </div>
      </section>

      <section class="card stack cta-card" aria-labelledby="verifyTitle">
        <h2 id="verifyTitle">您的票有被算進去嗎？</h2>
        <p class="small muted">匯入投票後下載的回執檔，在您自己的裝置上確認。公告板不會知道您查的是哪一張票，也不會知道您投給誰。</p>
        <a class="btn btn-primary btn-block" href="/receipt">驗證我的選票</a>
      </section>
    </div>
""" + _ANON_EXPLAINER + """
    <section class="card stack-sm" aria-labelledby="rootTitle">
      <div class="row-between">
        <h2 id="rootTitle" class="section-title">CC 簽章的 Merkle Root</h2>
        <a class="small" href="/api/signed_bundle">下載 CC 簽章的結果包</a>
      </div>
      <code class="hash">{{ merkle_root }}</code>
      <p class="small muted">所有合法選票組成一棵 Merkle Tree，這是它的樹根。驗證時，您的票沿著樹往上算，必須剛好得到這個值。</p>
    </section>

    <details class="card" aria-labelledby="listTitle">
      <summary><span id="listTitle">合法選票清單（{{ valid_count }} 張選票識別碼）</span></summary>
      <div class="stack-sm" style="margin-top:16px">
        <p class="small muted">每一列是一張選票的識別碼（m_hex），看不出是誰投的、投給誰。{% if valid_count > votes|length %}這裡顯示前 {{ votes|length }} 張，{% endif %}<a href="/api/results">下載完整清單（JSON）</a></p>
        {% if votes %}
        <div class="table-wrap">
          <table class="table">
            <thead><tr><th class="num">#</th><th>選票識別碼（m_hex）</th></tr></thead>
            <tbody>
              {% for v in votes %}
              <tr>
                <td class="num muted">{{ loop.index }}</td>
                <td><span class="hash-inline">{{ v.m_hex }}</span></td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
        {% else %}
        <p class="muted">沒有合法選票。</p>
        {% endif %}
      </div>
    </details>
  {% else %}
    <section class="card text-center stack" style="padding:56px 24px">
      <h1>等待開票</h1>
      <p class="lead">投票截止並完成開票後，計票中心（CC）會在這裡公告簽章過的結果。</p>
      <p class="small muted">此頁每 20 秒自動重新整理。</p>
    </section>
""" + _ANON_EXPLAINER + """
  {% endif %}
  </div>
</main>
<footer class="footer">
  <div class="container-wide">驗證程式由公告板提供。想更放心，可以下載 CC 簽章的結果包與完整選票清單，用自己的工具重算 Merkle Root。</div>
</footer>
</body>
</html>"""


# ── HTML 模板：驗證選票 ──────────────────────────────────────
# 回執檔在瀏覽器內讀取、手動輸入的 m_hex 也只在瀏覽器裡用；向 BB 只索取
# 整份 CC 簽章結果包，BB 因此不知道這次查的是哪一張票。
_RECEIPT_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <title>驗證選票｜NUTC 線上投票</title>""" + UI_HEAD + _BB_STYLE + _TREE_VIZ_HEAD + """
</head>
<body>
<header class="topbar">
  <div class="container topbar-inner">
    <a class="brand" href="/">
      <span class="brand-name">NUTC 線上投票</span>
      <span class="brand-sub">驗證選票</span>
    </a>
    <div class="topbar-actions">
      <a class="btn btn-sm" href="/">回公告板</a>
      """ + THEME_TOGGLE + """
    </div>
  </div>
</header>

<main>
  <div class="container stack-lg">
    <div class="stack-sm">
      <h1>驗證我的選票</h1>
      <p class="lead">在您自己的裝置上確認選票已被計入。整個過程不會上傳回執，公告板也無從得知您查的是哪一張票。</p>
    </div>

    <section class="card stack">
      <h2 class="section-title">匯入驗票回執</h2>
      <label class="btn btn-primary btn-block" for="receiptFile">選擇回執檔</label>
      <input id="receiptFile" class="sr-only" type="file" accept=".json,.txt,application/json" aria-describedby="fileHelp">
      <p id="fileErr" class="field-err hidden" role="alert"></p>
      <p id="fileHelp" class="small muted">投票完成時下載的檔案，檔名像 <span class="mono">nutc-vote-receipt-xxxxxxxx.json</span>，通常在手機的「下載」資料夾。</p>

      <div class="alt-entry" style="border-top:1px solid var(--border); padding-top:16px">
        <h2 id="manualTitle">沒有回執檔？輸入選票識別碼</h2>
        <div class="row" style="align-items:stretch">
          <label class="sr-only" for="mhexInput">選票識別碼（m_hex）</label>
          <input id="mhexInput" class="input mono" style="flex:1 1 260px; width:auto" type="text" inputmode="text"
                 placeholder="64 位英數字，可在投票網站的「我的回執」找到" autocomplete="off" autocapitalize="off" spellcheck="false"
                 aria-describedby="mhexHelp">
          <button id="mhexBtn" type="button" class="btn" style="flex:0 0 auto">驗證</button>
        </div>
        <p id="mhexErr" class="field-err hidden" role="alert"></p>
        <p id="mhexHelp" class="small muted">手動輸入沒有選舉場次資訊，結果會列出這次公告的截止時間，請確認是您投票的那一場。</p>
      </div>
    </section>

    <section id="verdict" class="verdict hidden" aria-labelledby="verdictTitle">
      <div class="verdict-head" aria-live="polite">
        <span id="verdictIcon" class="verdict-icon" aria-hidden="true"><span class="spin"></span></span>
        <div>
          <h2 id="verdictTitle" class="verdict-title" tabindex="-1">驗證中…</h2>
          <p id="verdictSub" class="verdict-sub"></p>
        </div>
      </div>
      <p id="verdictDetail" class="verdict-detail"></p>
      <ol class="checks" aria-label="驗證項目">
        <li class="check" id="chk-sign" data-state="wait">
          <span class="check-mark" aria-hidden="true"></span>
          <p class="check-title">結果是計票中心（CC）簽章的</p>
          <div class="check-body">
            <p class="check-desc">不是公告板自己說了算：用 CA 簽發的 CC 憑證，檢查開票結果上的簽章。</p>
            <span class="check-state sr-only"></span>
            <details><summary>技術細節</summary><ul class="steps"></ul></details>
          </div>
        </li>
        <li class="check" id="chk-list" data-state="wait">
          <span class="check-mark" aria-hidden="true"></span>
          <p class="check-title">您的票在合法選票名單裡</p>
          <div class="check-body">
            <p class="check-desc">CC 簽章的名單裡，必須找得到您的選票識別碼。</p>
            <span class="check-state sr-only"></span>
            <details><summary>技術細節</summary><ul class="steps"></ul></details>
          </div>
        </li>
        <li class="check" id="chk-root" data-state="wait">
          <span class="check-mark" aria-hidden="true"></span>
          <p class="check-title">名單算得出 CC 簽章的樹根</p>
          <div class="check-body">
            <p class="check-desc">從您的票沿著 Merkle Tree 往上算，結果必須等於 CC 簽章的 Merkle Root。</p>
            <span class="check-state sr-only"></span>
            <details><summary>技術細節</summary><ul class="steps"></ul></details>
          </div>
        </li>
      </ol>
      <p id="verdictNext" class="verdict-next hidden"></p>
    </section>

    <section id="treeSection" class="card stack hidden" aria-labelledby="treeTitle">
      <div class="stack-sm">
        <h2 id="treeTitle" class="section-title">您的票如何連到 CC 簽章的樹根</h2>
        <p id="treePos"></p>
      </div>
      <div id="treeViz" class="stack">
        <div class="tree-tools" role="group" aria-label="樹狀圖檢視">
          <button type="button" class="btn btn-sm" id="viewPath" aria-pressed="true" onclick="fitPath()">看我的路徑</button>
          <button type="button" class="btn btn-sm" id="viewAll" aria-pressed="false" onclick="fitTree()">看整棵樹</button>
        </div>
        <div id="treeLegend" class="legend"></div>
        <div id="tree-scroll-wrap" aria-hidden="true">
          <canvas id="tree-canvas"></canvas>
        </div>
        <p class="small muted">點節點看完整雜湊・左右滑動移動・雙指或 Ctrl＋滾輪縮放。文字版本在下方「驗證路徑與雜湊資訊」。</p>
      </div>
      <p id="treeTooBig" class="small muted hidden"></p>
    </section>

    <details id="resultInfo" class="card hidden">
      <summary>驗證路徑與雜湊資訊</summary>
      <dl class="dl" style="margin-top:16px">
        <div><dt>選票識別碼（m_hex）</dt><dd><code id="infoMhex" class="hash"></code></dd></div>
        <div><dt>您的葉節點：H(0x00 ‖ m_hex)</dt><dd><code id="infoLeaf" class="hash"></code></dd></div>
        <div><dt id="infoProofTitle">驗證路徑</dt><dd id="infoProof"></dd></div>
        <div><dt>CC 簽章的 Merkle Root</dt><dd><code id="infoRoot" class="hash"></code></dd></div>
      </dl>
    </details>
  </div>
</main>

<div id="node-panel" role="status">
  <div class="panel-title" id="panel-title"></div>
  <div class="panel-hash" id="panel-hash"></div>
  <div class="panel-meta" id="panel-meta"></div>
</div>

<script>
// 樹狀圖放在獨立的頂層 script：按鈕的 onclick 需要全域函式。
let treeData = null;
""" + _TREE_VIZ_JS + """
function showMerkleTree(data) {
  treeData = data;
  initTree();
}
</script>

<script>
(function () {
""" + _LOCAL_VERIFY_JS + """
  const caCertUrl = {{ ca_cert_url | tojson }};
  const RECEIPT_TYPE = 'nutc-vote-receipt';
  const RECEIPT_VERSION = 1;
  const MAX_RECEIPT_BYTES = 4096;
  const VIZ_MAX_LEAVES = {{ viz_max_leaves }};
  const ICON_CHECK = {{ icon_check | tojson }};
  const ICON_X     = {{ icon_x | tojson }};
  const ICON_ALERT = {{ icon_alert | tojson }};
  const ICON_CLOCK = {{ icon_clock | tojson }};
  const $ = id => document.getElementById(id);
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // 結果分類：每一種都有自己的標題、語氣和下一步
  //   ok        已計入
  //   pending   還沒開票
  //   round     回執屬於另一場選舉
  //   notfound  名單裡找不到（手動輸入多半是貼錯；回執檔則是嚴重問題）
  //   mismatch  簽章或樹根對不起來（公告資料有問題）
  //   offline   網路或伺服器暫時連不上
  class Outcome extends Error {
    constructor(kind, detail, next) { super(detail); this.kind = kind; this.next = next || ''; }
  }
  // 輸入本身就不對：在輸入框旁邊提示，不顯示驗證結果
  class InputError extends Error {
    constructor(field, msg) { super(msg); this.field = field; }
  }

  const GROUPS = ['sign', 'list', 'root'];
  const STATE_TEXT = { wait: '尚未檢查', run: '檢查中', ok: '通過', fail: '未通過', skip: '未檢查' };
  let current = null;

  function setCheck(group, state) {
    const li = $('chk-' + group);
    li.dataset.state = state;
    li.querySelector('.check-mark').innerHTML = state === 'ok' ? ICON_CHECK : state === 'fail' ? ICON_X : '';
    li.querySelector('.check-state').textContent = STATE_TEXT[state];
  }
  function begin(group) { current = group; setCheck(group, 'run'); }
  function done(group) { setCheck(group, 'ok'); }
  function step(text, failed) {
    const li = document.createElement('li');
    li.className = failed ? 'step-err' : 'step-ok';
    const mark = document.createElement('span');
    mark.className = 'mark';
    mark.innerHTML = failed ? ICON_X : ICON_CHECK;
    const t = document.createElement('span');
    t.textContent = text;
    li.append(mark, t);
    $('chk-' + current).querySelector('.steps').appendChild(li);
  }

  // 一律以台灣時間顯示，與公告板首頁一致
  const TIME_FMT = new Intl.DateTimeFormat('sv-SE', { timeZone: 'Asia/Taipei', year: 'numeric', month: '2-digit',
    day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  function fmtTime(ts) { return TIME_FMT.format(new Date(ts * 1000)) + '（台灣時間）'; }

  // 比照 shared/merkle_tree.py get_proof() 的走訪：標出目標、兄弟、路徑、樹根，奇數層補一個補位節點。
  function treeDataFromLayers(layers, index) {
    const proofPath = [{ layer: 0, index, role: 'target' }];
    let cur = index;
    layers.slice(0, -1).forEach((layer, li) => {
      if (cur % 2 === 1) proofPath.push({ layer: li, index: cur - 1, role: 'sibling' });
      else if (cur + 1 < layer.length) proofPath.push({ layer: li, index: cur + 1, role: 'sibling' });
      cur = Math.floor(cur / 2);
      proofPath.push({ layer: li + 1, index: cur, role: 'path' });
    });
    proofPath.push({ layer: layers.length - 1, index: 0, role: 'root' });
    const virtualNodes = [];
    const padded = layers.map((layer, li) => {
      if (layer.length % 2 === 0 || layer.length === 1) return layer;
      virtualNodes.push({ layer: li, index: layer.length });
      return [...layer, layer[layer.length - 1]];
    });
    return { layers: padded, target_index: index, proof_path: proofPath, virtual_nodes: virtualNodes };
  }

  function renderProofSteps(proof) {
    const box = $('infoProof');
    box.textContent = '';
    if (!proof.length) {
      box.textContent = '只有一張選票時，您的葉節點就是樹根，不需要兄弟節點。';
      return;
    }
    proof.forEach((p, i) => {
      const row = document.createElement('div');
      row.className = 'proof-step';
      const n = document.createElement('span');
      n.className = 'small muted nowrap';
      n.textContent = `第 ${i + 1} 層`;
      const side = document.createElement('span');
      side.className = 'badge ' + (p.position === 'right' ? 'badge-info' : 'badge-warn');
      side.textContent = p.position === 'right' ? '兄弟在右' : '兄弟在左';
      const h = document.createElement('span');
      h.className = 'hash-inline small';
      h.textContent = p.sibling;
      row.append(n, side, h);
      box.appendChild(row);
    });
  }

  function showPosition(receipt, layers, index, proof, root) {
    const n = layers[0].length;
    $('treePos').textContent = proof.length
      ? `您的票是 ${n} 張中的第 ${index + 1} 張。往上 ${layers.length - 1} 層，每層和一個兄弟節點一起算出上一層，最後得到 CC 簽章的樹根。`
      : '這次只有一張合法選票，您的票本身就是樹根。';
    $('infoMhex').textContent = receipt.m_hex;
    $('infoLeaf').textContent = layers[0][index];
    $('infoProofTitle').textContent = `驗證路徑（由下往上，共 ${proof.length} 層）`;
    renderProofSteps(proof);
    $('infoRoot').textContent = root;
    $('resultInfo').classList.remove('hidden');
    $('treeSection').classList.remove('hidden');
    const tooBig = n > VIZ_MAX_LEAVES;
    $('treeViz').classList.toggle('hidden', tooBig);
    $('treeTooBig').classList.toggle('hidden', !tooBig);
    if (tooBig) {
      $('treeTooBig').textContent =
        `本次公告共 ${n} 張，超過 ${VIZ_MAX_LEAVES} 張時不繪製樹狀圖（手機畫不動）。下方「驗證路徑與雜湊資訊」列出您的票往上經過的每一個兄弟節點。`;
      $('resultInfo').open = true;
    } else {
      showMerkleTree(treeDataFromLayers(layers, index));
    }
  }

  function parseReceipt(text) {
    const bad = msg => new InputError('file', msg);
    let r;
    try { r = JSON.parse(text); } catch (_) { throw bad('這個檔案不是驗票回執（無法讀取內容）。請選擇投票完成時下載的 .json 檔。'); }
    if (!r || r.type !== RECEIPT_TYPE) throw bad('這個檔案不是驗票回執。請選擇檔名開頭為 nutc-vote-receipt 的檔案。');
    if (r.v !== RECEIPT_VERSION) throw bad(`這份回執的版本（v${r.v}）這個頁面看不懂，請重新整理後再試一次。`);
    if (typeof r.m_hex !== 'string' || !/^[0-9a-f]{64}$/.test(r.m_hex)) throw bad('回執裡的選票識別碼損壞了，請改用投票網站「我的回執」重新下載。');
    if (r.round !== null && r.round !== undefined && !(Number.isInteger(r.round) && r.round > 0)) throw bad('回執裡的選舉場次資訊損壞了，請改用投票網站「我的回執」重新下載。');
    return r;
  }

  function parseTyped(text) {
    const body = text.trim().replace(/^0x/i, '');
    if (!body) throw new InputError('mhex', '請先貼上選票識別碼。');
    if (/[^0-9a-fA-F]/.test(body)) throw new InputError('mhex', '選票識別碼只會有 0–9 和 a–f，裡面有其他字元，請檢查是否多複製了空白或文字。');
    if (body.length !== 64) throw new InputError('mhex', `選票識別碼是 64 位，您輸入了 ${body.length} 位，請檢查是否少複製或多複製。`);
    return body.toLowerCase();
  }

  async function verifyFile(file) {
    if (file.size > MAX_RECEIPT_BYTES) throw new InputError('file', '這個檔案太大，不是驗票回執。請選擇投票完成時下載的 .json 檔。');
    const receipt = parseReceipt(await file.text());
    openVerdict(`回執檔：${file.name}`);
    begin('list');
    step('回執格式與版本正確');
    return verifyReceipt(receipt, false);
  }

  function verifyTyped(text) {
    const m = parseTyped(text);
    openVerdict('手動輸入的選票識別碼');
    begin('list');
    step('選票識別碼格式正確');
    return verifyReceipt({ m_hex: m, round: null }, true);
  }

  const REPORT = '請保留回執檔，並把這個畫面截圖交給選務人員。';

  async function verifyReceipt(receipt, typed) {
    begin('sign');
    let resp;
    try { resp = await fetch('/api/signed_bundle', { cache: 'no-store' }); }
    catch (_) { throw new Outcome('offline', '連不上公告板，無法取得開票結果。', '請確認網路連線後再試一次。'); }
    if (resp.status === 404) throw new Outcome('pending', '計票中心還沒公告這一場的結果。', '投票截止並完成開票後，再回來驗證一次。您的回執會一直有效。');
    const sb = await resp.json();
    if (sb.status !== 'success') throw new Outcome('offline', sb.message || '公告板暫時沒有提供 CC 簽章的結果包。', '請稍後再試一次。');
    let bundle;
    try {
      bundle = await verifySignedBundle(sb, caCertUrl, t => step(t));
    } catch (e) {
      if (/無法從投票網站取得/.test(e.message)) throw new Outcome('offline', e.message, '請確認網路連線後再試一次。');
      throw new Outcome('mismatch', e.message, REPORT + '這代表公告內容和計票中心的簽章對不起來，不是您操作錯誤。');
    }
    done('sign');

    begin('list');
    if (receipt.round && bundle.deadline && receipt.round !== bundle.deadline) {
      throw new Outcome('round',
        `這份回執屬於截止時間 ${fmtTime(receipt.round)} 的選舉，公告板目前公告的是截止時間 ${fmtTime(bundle.deadline)} 的選舉。`,
        '請等您投票的那一場公告後再驗證；如果您確定是同一場，請通報選務人員。');
    }
    step(receipt.round ? '回執的選舉場次與公告一致'
      : typed ? `本次公告的選舉截止時間：${fmtTime(bundle.deadline)}`
      : '舊版回執沒有場次資訊，略過場次檢查');

    const list = bundle.valid_m_hex_list || [];
    const index = list.indexOf(receipt.m_hex);
    if (index < 0) {
      throw typed
        ? new Outcome('typo', `這次公告的 ${list.length} 張合法選票裡，沒有您輸入的識別碼。`,
            '最常見的原因是貼錯或少貼了幾位，請到投票網站「我的回執」複製完整的識別碼再試一次。確定無誤仍找不到，請通報選務人員。')
        : new Outcome('notfound', `這次公告的 ${list.length} 張合法選票裡，沒有這張回執的選票。`,
            REPORT + '回執可以證明您投過這張票。');
    }
    step(`在 ${list.length} 張合法選票中找到您的票`);
    done('list');

    begin('root');
    const layers = await buildLayersLocal(list);
    if (layers[layers.length - 1][0] !== bundle.root_official) {
      throw new Outcome('mismatch', '用公告的名單重算出的 Merkle Root，和 CC 簽章的不一樣。', REPORT + '這代表公告資料有誤，不是您操作錯誤。');
    }
    const proof = proofFromLayers(layers, index);
    if (!(await verifyProofLocally(receipt.m_hex, proof, bundle.root_official))) {
      throw new Outcome('mismatch', '從您的票往上算，算不出 CC 簽章的 Merkle Root。', REPORT + '這代表公告資料有誤，不是您操作錯誤。');
    }
    step(`驗證路徑（${proof.length} 層）算出的樹根與 CC 簽章相符`);
    done('root');

    return { index, total: list.length, show: () => showPosition(receipt, layers, index, proof, bundle.root_official) };
  }

  const VERDICTS = {
    ok:       { tone: 'ok',   icon: () => ICON_CHECK, title: '您的票已被計入' },
    pending:  { tone: 'info', icon: () => ICON_CLOCK, title: '還沒開票' },
    round:    { tone: 'warn', icon: () => ICON_ALERT, title: '這份回執屬於另一場選舉' },
    notfound: { tone: 'err',  icon: () => ICON_X,     title: '名單裡找不到這張票' },
    typo:     { tone: 'warn', icon: () => ICON_ALERT, title: '找不到這個識別碼' },
    mismatch: { tone: 'err',  icon: () => ICON_X,     title: '公告資料不一致' },
    offline:  { tone: 'warn', icon: () => ICON_ALERT, title: '暫時無法完成驗證' },
  };

  function clearFieldErrors() {
    for (const id of ['fileErr', 'mhexErr']) { $(id).classList.add('hidden'); $(id).textContent = ''; }
    $('mhexInput').removeAttribute('aria-invalid');
  }
  function showFieldError(err) {
    const box = $(err.field === 'file' ? 'fileErr' : 'mhexErr');
    box.innerHTML = ICON_ALERT;
    box.append(document.createTextNode(err.message));
    box.classList.remove('hidden');
    if (err.field === 'mhex') { $('mhexInput').setAttribute('aria-invalid', 'true'); $('mhexInput').focus(); }
  }

  function openVerdict(source) {
    const v = $('verdict');
    v.classList.remove('hidden');
    v.dataset.tone = 'info';
    $('verdictIcon').innerHTML = '<span class="spin"></span>';
    $('verdictTitle').textContent = '驗證中…';
    $('verdictSub').textContent = source;
    $('verdictDetail').textContent = '';
    $('verdictNext').classList.add('hidden');
    for (const g of GROUPS) {
      setCheck(g, 'wait');
      const d = $('chk-' + g).querySelector('details');
      d.open = false;
      d.querySelector('.steps').textContent = '';
    }
  }

  function closeVerdict(kind, sub, detail, next) {
    const conf = VERDICTS[kind];
    const v = $('verdict');
    v.dataset.tone = conf.tone;
    $('verdictIcon').innerHTML = conf.icon();
    $('verdictTitle').textContent = conf.title;
    if (sub) $('verdictSub').textContent = sub;
    $('verdictDetail').textContent = detail;
    const nx = $('verdictNext');
    nx.textContent = '';
    if (next) {
      const s = document.createElement('strong');
      s.textContent = '接下來';
      nx.append(s, document.createTextNode(next));
    }
    nx.classList.toggle('hidden', !next);
    v.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
    $('verdictTitle').focus({ preventScroll: true });
  }

  async function run(task) {
    clearFieldErrors();
    $('resultInfo').classList.add('hidden');
    $('treeSection').classList.add('hidden');
    try {
      const r = await task();
      closeVerdict('ok', `${r.total} 張合法選票中的第 ${r.index + 1} 張`,
        '三項檢查都在您的裝置上完成，沒有採用公告板伺服器的判斷。', '');
      r.show();
    } catch (err) {
      if (err instanceof InputError) {
        $('verdict').classList.add('hidden');
        showFieldError(err);
        return;
      }
      const kind = err instanceof Outcome ? err.kind : 'offline';
      if (current) {
        step(err.message, true);
        setCheck(current, 'fail');
        let after = false;
        for (const g of GROUPS) {
          if (g === current) { after = true; continue; }
          if (after && $('chk-' + g).dataset.state !== 'ok') setCheck(g, 'skip');
        }
        $('chk-' + current).querySelector('details').open = true;
      }
      closeVerdict(kind, '', err.message, err instanceof Outcome ? err.next : '請稍後再試一次。');
    } finally {
      current = null;
    }
  }

  $('receiptFile').addEventListener('change', e => {
    const file = e.target.files[0];
    e.target.value = '';
    if (file) run(() => verifyFile(file));
  });
  const runTyped = () => run(() => verifyTyped($('mhexInput').value));
  $('mhexBtn').addEventListener('click', runTyped);
  $('mhexInput').addEventListener('keydown', e => { if (e.key === 'Enter') runTyped(); });
  $('mhexInput').addEventListener('input', () => { $('mhexErr').classList.add('hidden'); $('mhexInput').removeAttribute('aria-invalid'); });
})();
</script>
</body>
</html>"""


# ── 路由 ──────────────────────────────────────────────────

@app.route('/')
def dashboard():
    published_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'published'")
    published = published_row is not None and published_row['value'] == '1'

    merkle_root = None
    tally = {}
    votes = []
    valid_count = 0
    tallied_at = None

    if published:
        root_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'merkle_root'")
        merkle_root = root_row['value'] if root_row else ""
        tally_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'tally_json'")
        tally = json.loads(tally_row['value']) if tally_row else {}
        # v2.0 修正：不再選取 vote 欄位，公告板 dashboard 不應逐票展示投票
        # 內容與 m_hex 的對應（規格書 §19.5）。 <3
        # 首頁只列前 50 筆（票數上萬時整頁會非常大）；完整清單見 /api/results
        votes = db.fetchall("SELECT id, m_hex FROM published_votes ORDER BY id LIMIT 50")
        valid_count = db.count("published_votes")
        tallied_at_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'tallied_at'")
        tallied_at = int(tallied_at_row['value']) if tallied_at_row else None

    return render_template_string(
        _DASHBOARD_HTML,
        published=published,
        merkle_root=merkle_root,
        tally=tally,
        votes=votes,
        valid_count=valid_count,
        tallied_at=tallied_at,
    )


@app.route('/verify', methods=['GET'])
def verify_page():
    """已停用的伺服器端查票頁：一律導向 /receipt，不讀取、不回顯查詢參數。"""
    return redirect('/receipt', code=302)


@app.route('/receipt', methods=['GET'])
def receipt_page():
    """驗證選票頁：回執檔或手動輸入的 m_hex 只在瀏覽器裡使用，驗證全程在本機完成。"""
    return render_template_string(
        _RECEIPT_HTML, ca_cert_url=CA_CERT_URL_FOR_BROWSER, viz_max_leaves=VIZ_MAX_LEAVES,
        icon_check=_ICON_CHECK, icon_x=_ICON_X, icon_alert=_ICON_ALERT, icon_clock=_ICON_CLOCK,
    )


@app.route('/api/admin/reset', methods=['POST'])
def api_admin_reset():
    """
    [POST] 重置公告板狀態（新一輪前使用）。

    背景：admin_tool 的 /api/new_round 原本只重置 TA 與 CA，完全沒有
    清掉 BB 這裡的 published 旗標——/api/publish 一開始就檢查
    bb_state.published=='1'，是的話直接以 ALREADY_PUBLISHED 拒絕新結
    果，導致新一輪投票開票後，BB 永遠停留在上一輪的結果，直到有人手動
    進容器清空資料庫。這裡補上對應的重置端點，清空已公告狀態與選票清
    單，讓下一輪能重新接受公告。

    BB 本身不要求 mTLS 用戶端憑證（要接受一般瀏覽器公開連線），這裡改
    用 Admin Bearer Token 單獨保護這個端點，比照 CA 的 /api/admin/*
    端點模式。 <3
    """
    if not check_admin_token():
        return jsonify(admin_auth_error()), 401

    vote_count = db.count("published_votes")
    db.execute("DELETE FROM published_votes")
    db.execute("DELETE FROM bb_state")

    print(f"[BB] 公告板狀態已重置（清除 {vote_count} 筆已公告選票）。")
    return jsonify({"status": "success", "deleted_votes": vote_count}), 200


@app.route('/api/publish', methods=['POST'])
def api_publish():
    """
    [POST] 接收 CC 推送的計票結果（v2.0 Sprint 2：含簽章驗證）
    
    Body: {
        "result_bundle": {
            "root_official": str,
            "tally": dict,
            "valid_m_hex_list": [str],   # v2.0 修正：只給 m_hex 清單，不含 vote 對應 <3
            "merkle_leaf_count": int,
            "tallied_at": int
        },
        "signature": str (Base64),
        "cert_pem": str
    }
    
    驗證流程：
      1. 驗證 CC 憑證是否由 CA 簽發
      2. 驗證 CC 對 result_bundle 的 RSA-PSS 簽章
      3. 檢查是否已公告（防止覆蓋）
      4. 儲存結果
    """
    data = request.get_json()
    if not data or 'result_bundle' not in data or 'signature' not in data or 'cert_pem' not in data:
        return jsonify({
            "status": "error",
            "code": "MISSING_FIELDS",
            "message": "缺少必要欄位（需要 result_bundle, signature, cert_pem）"
        }), 400

    result_bundle = data['result_bundle']
    signature_b64 = data['signature']
    cert_pem = data['cert_pem']

    # 檢查是否已公告（防止覆蓋）
    published_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'published'")
    if published_row and published_row['value'] == '1':
        return jsonify({
            "status": "error",
            "code": "ALREADY_PUBLISHED",
            "message": "結果已公告，不可覆蓋"
        }), 403

    # 步驟 1：驗證 CC 憑證是否由 CA 簽發
    global _ca_cert_pem, _ca_cert
    if not _ca_cert:
        try:
            _ca_cert_pem = load_or_fetch_ca_cert(KEYS_DIR, CA_URL)
            _ca_cert = x509.load_pem_x509_certificate(_ca_cert_pem.encode('utf-8'))
            print("[BB] CA 憑證補載入成功")
        except Exception as ex:
            print(f"[BB] 補載入 CA 憑證失敗：{ex}")
    if not _ca_cert:
        return jsonify({
            "status": "error",
            "code": "CA_CERT_UNAVAILABLE",
            "message": "BB 無法取得 CA 憑證，無法驗證 CC 憑證"
        }), 500

    # v4.0 修正：改用共用的 verify_cert_chain_and_cn()（見
    # shared/key_manager.py）——原本這裡手刻的驗證只檢查簽章鏈與 Subject
    # CN，沒有檢查憑證有效期限，跟其他服務（ta_server 的 release_key、
    # cc_server 對 TA/TPA）的驗證強度不一致；改用共用函式後，順帶也補上
    # 了有效期限檢查，且往後這段邏輯只需要維護一份。 <3
    cc_cert = verify_cert_chain_and_cn(cert_pem, _ca_cert_pem, 'CC')
    if cc_cert is None:
        return jsonify({
            "status": "error",
            "code": "CERT_INVALID",
            "message": "CC 憑證驗證失敗：未由合法 CA 簽發、已過期，或 Subject CN 不是 CC",
        }), 403
    cc_public_key = cc_cert.public_key()
    print(f"[BB] CC 憑證驗證通過（Subject: {cc_cert.subject}）")

    # 步驟 2：驗證 CC 對 result_bundle 的 RSA-PSS 簽章
    try:
        # v2.0 修正：補上 separators=(',', ':') 做 canonical JSON（規格書
        # §18.6），須與 CC 端簽章時的序列化方式完全一致，否則驗章必定失敗。 <3
        bundle_json = json.dumps(result_bundle, sort_keys=True, ensure_ascii=False, separators=(',', ':'))  # <3
        bundle_bytes = bundle_json.encode('utf-8')
        signature = b64_to_bytes(signature_b64)
        
        if not verify_signature(bundle_bytes, signature, cc_public_key):
            return jsonify({
                "status": "error",
                "code": "SIGNATURE_INVALID",
                "message": "CC 簽章驗證失敗"
            }), 403
        
        print(f"[BB] CC 簽章驗證通過（簽章長度：{len(signature)} bytes）")
    except Exception as e:
        return jsonify({
            "status": "error",
            "code": "SIGNATURE_VERIFICATION_ERROR",
            "message": f"簽章驗證過程發生錯誤：{e}"
        }), 500

    # 步驟 3：解析並儲存結果
    # v2.0 修正：改讀 valid_m_hex_list（純 m_hex 清單），不再接受/儲存 vote
    # 與 m_hex 的一一對應，避免任何人從公告資料反推「哪個葉節點是哪一票」。 <3
    root_official      = result_bundle['root_official']
    tally              = result_bundle['tally']
    m_hex_list         = result_bundle.get('valid_m_hex_list', [])
    merkle_leaf_count  = result_bundle.get('merkle_leaf_count')
    tallied_at         = result_bundle.get('tallied_at', int(time.time()))

    # v2.0 修正：新增結構一致性檢查（規格書 §18.5.1 BUNDLE_INCONSISTENT）。
    # 只驗證簽章代表「CC 確實簽了這包資料」，並不代表資料本身內部自洽；
    # 這裡額外核對 merkle_leaf_count 與 m_hex 清單長度、tally 加總是否一致，
    # 防止 CC 端邏輯錯誤或惡意建構出自相矛盾的結果包被 BB 照單全收。 <3
    tally_sum = sum(tally.values()) if isinstance(tally, dict) else -1
    if merkle_leaf_count != len(m_hex_list) or tally_sum != len(m_hex_list):
        return jsonify({
            "status": "error",
            "code": "BUNDLE_INCONSISTENT",
            "message": (
                f"結果包內部不一致：merkle_leaf_count={merkle_leaf_count}, "
                f"len(valid_m_hex_list)={len(m_hex_list)}, sum(tally)={tally_sum}"
            ),
        }), 403  # <3

    # 清空舊資料
    db.execute("DELETE FROM published_votes")

    # 儲存合法選票的 m_hex（含葉節點雜湊），依 CC 送來的洗牌後順序原樣寫入
    for m_hex in m_hex_list:
        leaf_hash = sha256_hex(m_hex.encode('utf-8'))
        db.execute(
            "INSERT INTO published_votes (m_hex, leaf_hash) VALUES (?, ?)",
            (m_hex, leaf_hash),
        )

    # 儲存狀態
    # v2.0 修正：補存 cc_cert_pem，讓選民端 Phase 6 Step 6.2a 可以獨立驗證
    # 「簽章公鑰本身是否合法」，而不是單方面信任 BB 的驗證結果（規格書
    # §6.3 Step 6.1、§18.5.2；先前 BB 只存 cc_signature，沒存 cc_cert_pem）。 <3
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('published', '1')")
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('merkle_root', ?)", (root_official,))
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('tally_json', ?)", (json.dumps(tally),))
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('tallied_at', ?)", (str(tallied_at),))
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('cc_signature', ?)", (signature_b64,))
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('cc_cert_pem', ?)", (cert_pem,))  # <3
    # 原封不動保存 CC 簽章的那串 canonical JSON。以前只存了結果包裡的部分
    # 欄位（少了 deadline、cc_id），任何人都無法重組出被簽章的原文，公開的
    # cc_signature 等於沒人驗得了。瀏覽器直接對這串原文驗章，也不用擔心
    # JS 與 Python 的 JSON 序列化細節（中文、欄位排序）不一致。
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('signed_bundle', ?)", (bundle_json,))

    # 日誌使用人類可讀格式
    print(f"[BB] ✅ 結果已驗證並公告（Unix ts：{tallied_at}  →  {ts_to_human(tallied_at)}）")
    print(f"[BB] Root_official = {root_official[:20]}...")
    print(f"[BB] 合法選票數：{len(m_hex_list)}")  # <3
    
    return jsonify({
        "status": "success",
        "message": "結果已驗證並公告",
        "verified": True,
        "tallied_at": tallied_at
    }), 200


@app.route('/api/results', methods=['GET'])
def api_results():
    """[GET] 回傳計票結果與 Merkle Root（Unix timestamp）"""
    published_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'published'")
    if not published_row or published_row['value'] != '1':
        return jsonify({"status": "pending", "message": "尚未公告"}), 200

    root_row      = db.fetchone("SELECT value FROM bb_state WHERE key = 'merkle_root'")
    tally_row     = db.fetchone("SELECT value FROM bb_state WHERE key = 'tally_json'")
    tallied_at_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'tallied_at'")
    sig_row       = db.fetchone("SELECT value FROM bb_state WHERE key = 'cc_signature'")
    cc_cert_row   = db.fetchone("SELECT value FROM bb_state WHERE key = 'cc_cert_pem'")  # <3
    # v2.0 修正：只回傳 m_hex 清單，不再回傳 vote 與 m_hex 的一一對應
    # （規格書 §19.5，避免公開的結果反推出每一張選票對應誰投的內容）。 <3
    votes         = db.fetchall("SELECT m_hex FROM published_votes ORDER BY id")
    m_hex_list    = [v['m_hex'] for v in votes]  # <3
    tallied_at    = int(tallied_at_row['value']) if tallied_at_row else None

    return jsonify({
        "status":            "success",
        "merkle_root":       root_row['value'] if root_row else "",
        "tally":             json.loads(tally_row['value']) if tally_row else {},
        "valid_m_hex_list":  m_hex_list,  # <3 之前是 valid_votes（含 vote），現在只給 m_hex
        "merkle_leaf_count": len(m_hex_list),  # <3
        "cc_signature":      sig_row['value'] if sig_row else "",
        "cc_cert_pem":       cc_cert_row['value'] if cc_cert_row else "",  # <3 讓選民端可獨立驗證簽章公鑰身分鏈
        "tallied_at":        tallied_at,
        "tallied_at_str": ts_to_human(tallied_at) if tallied_at else None,
    }), 200


@app.route('/api/signed_bundle', methods=['GET'])
def api_signed_bundle():
    """[GET] 回傳 CC 簽章的結果包原文、簽章與 CC 憑證，供任何人獨立驗章。

    驗證方式：用 CA 根憑證驗證 cc_cert_pem（CN 必須是 CC），再用其公鑰以
    RSA-PSS（SHA-256、MGF1-SHA-256、salt 長度 = PSS.MAX_LENGTH）驗證
    signature 是否為 signed_bundle 這串 UTF-8 原文的簽章。
    """
    row = db.fetchone("SELECT value FROM bb_state WHERE key = 'signed_bundle'")
    if not row:
        return jsonify({"status": "error", "message": "尚未公告，或這次公告沒有保存簽章原文"}), 404
    sig_row  = db.fetchone("SELECT value FROM bb_state WHERE key = 'cc_signature'")
    cert_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'cc_cert_pem'")
    return jsonify({
        "status":        "success",
        "signed_bundle": row['value'],
        "signature":     sig_row['value'] if sig_row else "",
        "cc_cert_pem":   cert_row['value'] if cert_row else "",
    }), 200


# ── Config Hot-Reload 端點 ────────────────────────────────────
make_reload_endpoint(app)


# ============================================================
# 內部函式
# ============================================================

# 超過這個張數時 /receipt 不畫完整樹狀圖（手機畫不動），只列驗證路徑。
VIZ_MAX_LEAVES = 256


if __name__ == '__main__':
    # v4.0 新增：BB 的監聽埠除了 CC 推送結果，還要接受一般瀏覽器（經
    # Caddy）的公開連線——瀏覽器不會持有這套內部 PKI 的用戶端憑證，
    # 所以刻意不要求 CERT_REQUIRED（require_client_cert=False），對
    # CC 身分的驗證繼續由既有的應用層簽章＋Subject CN 核對負責，見
    # shared/tls_utils.py 的說明。
    _ca_cert_path = os.path.join(KEYS_DIR, "ca_cert.pem")
    _ssl_ctx = build_mtls_server_context(
        _tls_cert_path, _tls_key_path, _ca_cert_path, require_client_cert=False,
    )
    app.run(host='0.0.0.0', port=5004, debug=False, ssl_context=_ssl_ctx)
