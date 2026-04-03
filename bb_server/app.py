"""
bb_server/app.py  —  公告板 (BB)

公開展示計票結果的地方。CC 開票完成後會把結果推送過來，
包含 Merkle Root、各候選人得票數、以及所有合法選票的清單。

選民可以輸入自己的 m_hex 來驗證選票，頁面會顯示互動式的
Merkle Tree 圖，清楚標示從葉節點到根的驗證路徑。

端點：
  GET  /                          公告板首頁（計票結果）
  GET  /verify                    Merkle Proof 視覺化驗證頁
  POST /api/publish               接收 CC 推送的計票結果
  GET  /api/results               查詢計票結果與 Merkle Root
  GET  /api/merkle_proof/<m_hex>  取得指定選票的 Merkle Proof
  GET  /api/config                查看目前設定
  POST /api/config/reload         重新載入 config.json
"""

import os
import sys
import json
import time
import datetime

# 確保 shared/ 可被 import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template_string
import requests as http_requests

from shared.merkle_tree import MerkleTree
from shared.format_utils import sha256_hex, ts_to_human
from shared.db_utils import Database
from shared.config_loader import make_reload_endpoint

# ============================================================
# 常數設定
# ============================================================
SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(SERVICE_DIR, "bb.db")
CC_URL      = os.environ.get("CC_URL", "http://localhost:5003")

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
        vote        TEXT NOT NULL,
        m_hex       TEXT NOT NULL,
        leaf_hash   TEXT NOT NULL
    )
""")

print("[BB] 公告板初始化完成。")

# ============================================================
# Flask App
# ============================================================
app = Flask(__name__)


# ── Jinja2 自訂過濾器：Unix timestamp → 人類可讀 ──────────────
@app.template_filter('ts_to_str')
def ts_to_str(ts):
    """將 Unix timestamp 轉為 YYYY-MM-DD HH:MM:SS（僅用於 UI 顯示）"""
    try:
        return datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)


# ── HTML 模板：主公告板 ────────────────────────────────────────
_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BB 公告板</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <meta http-equiv="refresh" content="20">
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">
  <div class="max-w-5xl mx-auto px-4 py-10">

    <!-- Header -->
    <div class="flex items-center gap-4 mb-8">
            <div class="w-12 h-12 rounded-xl bg-rose-600 flex items-center justify-center text-2xl">📜</div>
      <div>
        <h1 class="text-2xl font-bold text-white">公告板 (BB)</h1>
        <p class="text-gray-400 text-sm">Bulletin Board</p>
      </div>
      <span class="ml-auto px-3 py-1 rounded-full text-xs font-semibold
        {% if published %}bg-green-900 text-green-300{% else %}bg-yellow-900 text-yellow-300{% endif %}">
        {% if published %}● 已公告{% else %}● 等待結果{% endif %}
      </span>
    </div>

    {% if published %}
    <!-- Tally Results -->
    <div class="bg-gray-900 rounded-2xl border border-gray-800 p-6 mb-6">
      <h2 class="font-semibold text-gray-200 mb-5 text-lg">最終計票結果</h2>
      {% if tally %}
      <div class="space-y-4">
        {% set total = valid_count %}
        {% for candidate, count in tally.items() %}
        <div>
          <div class="flex justify-between text-sm mb-1.5">
            <span class="font-mono text-indigo-300 font-semibold">{{ candidate }}</span>
            <span class="text-white font-bold">{{ count }} 票
              <span class="text-gray-400 font-normal text-xs ml-1">
                ({{ "%.1f"|format(count / total * 100) if total > 0 else 0 }}%)
              </span>
            </span>
          </div>
          <div class="w-full bg-gray-800 rounded-full h-3">
            <div class="bg-indigo-500 h-3 rounded-full transition-all"
              style="width: {{ (count / total * 100) | int if total > 0 else 0 }}%"></div>
          </div>
        </div>
        {% endfor %}
      </div>
      <div class="mt-5 pt-4 border-t border-gray-800 flex justify-between text-sm">
        <span class="text-gray-400">合計合法選票</span>
        <span class="font-bold text-white">{{ valid_count }} 票</span>
      </div>
      {% endif %}
    </div>

    <!-- Merkle Root（零信任加密資料）-->
    <div class="bg-gray-900 rounded-xl border border-indigo-800/50 p-5 mb-6">
      <div class="flex items-center gap-2 mb-2">
        <span class="text-indigo-400 text-sm font-semibold">Root_official</span>
        <span class="text-xs text-gray-500">Merkle Root</span>
      </div>
      <p class="font-mono text-sm text-indigo-300 break-all bg-gray-800 rounded-lg px-4 py-3">{{ merkle_root }}</p>
      {% if tallied_at %}
      <p class="text-xs text-gray-500 mt-2">
        公告時間：<span class="font-mono text-gray-400">{{ tallied_at | ts_to_str }}</span>
        <span class="text-gray-600 ml-2">（Unix ts：{{ tallied_at }}）</span>
      </p>
      {% endif %}
    </div>

    <!-- Verify Form -->
    <div class="bg-gray-900 rounded-xl border border-gray-800 p-5 mb-6">
      <h2 class="font-semibold text-gray-200 mb-3">驗證選票</h2>
      <form method="GET" action="/verify" class="flex gap-3">
        <input type="text" name="m_hex" placeholder="輸入您的 m_hex 值..."
          class="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-indigo-500">
        <button type="submit"
          class="px-5 py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-sm font-semibold transition">
          驗證 + 視覺化
        </button>
      </form>
    </div>

    <!-- Valid Votes Table -->
    <div class="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
        <h2 class="font-semibold text-gray-200">合法選票清單</h2>
        <span class="text-xs text-gray-500">每 20 秒自動更新</span>
      </div>
      {% if votes %}
      <table class="w-full text-sm">
        <thead class="bg-gray-800 text-gray-400 text-xs uppercase">
          <tr>
            <th class="px-6 py-3 text-left">#</th>
            <th class="px-6 py-3 text-left">投票內容</th>
            <th class="px-6 py-3 text-left">m_hex（前 24 字元）</th>
            <th class="px-6 py-3 text-left">葉節點 H(m)（前 24 字元）</th>
            <th class="px-6 py-3 text-left">操作</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-800">
          {% for v in votes %}
          <tr class="hover:bg-gray-800/50 transition">
            <td class="px-6 py-3 text-gray-500">{{ v.id }}</td>
            <td class="px-6 py-3 font-mono text-indigo-300">{{ v.vote }}</td>
            <td class="px-6 py-3 font-mono text-gray-400 text-xs">{{ v.m_hex[:24] }}...</td>
            <td class="px-6 py-3 font-mono text-gray-500 text-xs">{{ v.leaf_hash[:24] }}...</td>
            <td class="px-6 py-3">
              <a href="/verify?m_hex={{ v.m_hex }}"
                class="text-xs text-indigo-400 hover:text-indigo-300 underline">驗證</a>
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <div class="px-6 py-10 text-center text-gray-500">尚無合法選票</div>
      {% endif %}
    </div>

    {% else %}
    <!-- Not Published Yet -->
    <div class="bg-gray-900 rounded-2xl border border-gray-800 p-12 text-center">
      <h2 class="text-xl font-semibold text-gray-300 mb-2">等待計票結果</h2>
      <p class="text-gray-500 text-sm">計票中心（CC）尚未公告結果。</p>
    </div>
    {% endif %}

  </div>
</body>
</html>"""


# ── HTML 模板：視覺化 Merkle Proof 驗證頁 ─────────────────────
_VERIFY_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BB · Merkle Proof 視覺化驗證</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    /* ── Canvas 滾動容器 ── */
    #tree-scroll-wrap {
      overflow: auto;
      background: #030712;
      border-radius: 12px;
      cursor: grab;
      position: relative;
      max-height: 70vh;
    }
    #tree-scroll-wrap:active { cursor: grabbing; }
    #tree-canvas { display: block; }

    /* ── 節點資訊浮動面板 ── */
    #node-panel {
      display: none;
      position: fixed;
      z-index: 200;
      background: #111827;
      border: 1px solid #374151;
      border-radius: 10px;
      padding: 14px 16px;
      font-family: 'Courier New', monospace;
      font-size: 12px;
      color: #e5e7eb;
      box-shadow: 0 8px 32px rgba(0,0,0,0.7);
      max-width: 420px;
      pointer-events: none;
    }
    #node-panel .panel-title {
      font-size: 11px; font-weight: bold; margin-bottom: 6px;
    }
    #node-panel .panel-hash {
      word-break: break-all; color: #a5b4fc; font-size: 11px; line-height: 1.6;
    }
    #node-panel .panel-meta {
      color: #6b7280; font-size: 10px; margin-top: 6px;
    }

    /* ── 縮放控制 ── */
    #zoom-controls {
      display: flex; gap: 6px; align-items: center;
    }
    .zoom-btn {
      width: 30px; height: 30px; border-radius: 6px;
      background: #1f2937; border: 1px solid #374151;
      color: #9ca3af; font-size: 16px; cursor: pointer;
      display: flex; align-items: center; justify-content: center;
      transition: all 0.15s;
    }
    .zoom-btn:hover { background: #374151; color: #e5e7eb; }
    #zoom-label { font-size: 12px; color: #6b7280; min-width: 40px; text-align: center; }

    /* ── 圖例 ── */
    .legend-dot {
      width: 12px; height: 12px; border-radius: 3px; flex-shrink: 0;
    }
  </style>
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">
  <div class="max-w-6xl mx-auto px-4 py-10">

    <!-- Back -->
    <div class="flex items-center gap-3 mb-6">
      <a href="/" class="text-gray-400 hover:text-white text-sm">← 返回公告板</a>
    </div>

    <!-- Header -->
    <div class="flex items-center gap-4 mb-6">
      <div>
        <h1 class="text-2xl font-bold text-white">Merkle Proof 驗證</h1>
        <p class="text-gray-400 text-sm">Merkle Tree 視覺化</p>
      </div>
    </div>

    {% if result %}
    <!-- 驗證結果 -->
    <div class="bg-gray-900 rounded-xl border border-gray-800 p-6 mb-6">
      <div class="flex items-center gap-3 mb-5">
        {% if result.valid %}
        <div>
          <p class="font-bold text-green-400 text-lg">驗證通過</p>
          <p class="text-gray-400 text-sm">您的選票已包含在合法計票結果中</p>
        </div>
        {% else %}
        <div>
          <p class="font-bold text-red-400 text-lg">驗證失敗</p>
          <p class="text-gray-400 text-sm">{{ result.message }}</p>
        </div>
        {% endif %}
      </div>

      {% if result.valid %}
      <!-- 零信任加密資料展示（可折疊） -->
      <details class="mb-6">
        <summary class="cursor-pointer text-sm font-semibold text-gray-300 hover:text-white select-none py-2">
          展開查看詳細資訊
        </summary>
        <div class="grid grid-cols-1 gap-3 mt-3">

          <!-- m_hex -->
          <div class="bg-gray-800 rounded-lg p-4 border border-amber-800/40">
            <div class="flex items-center gap-2 mb-2">
              <span class="w-2 h-2 rounded-full bg-amber-400"></span>
              <p class="text-xs text-amber-400 font-semibold uppercase tracking-wide">m_hex（選票包雜湊值）</p>
              <span class="text-xs text-gray-600">— 驗證起點</span>
            </div>
            <p class="font-mono text-xs text-amber-300 break-all">{{ result.m_hex }}</p>
          </div>

          <!-- Leaf Hash H(m) -->
          <div class="bg-gray-800 rounded-lg p-4 border border-yellow-800/40">
            <div class="flex items-center gap-2 mb-2">
              <span class="w-2 h-2 rounded-full bg-yellow-400"></span>
              <p class="text-xs text-yellow-400 font-semibold uppercase tracking-wide">Leaf Hash = H(m_hex)</p>
              <span class="text-xs text-gray-600">— 葉節點，SHA-256(m_hex)</span>
            </div>
            <p class="font-mono text-xs text-yellow-300 break-all">{{ result.leaf_hash }}</p>
          </div>

          <!-- Sibling Array -->
          <div class="bg-gray-800 rounded-lg p-4 border border-emerald-800/40">
            <div class="flex items-center gap-2 mb-2">
              <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
              <p class="text-xs text-emerald-400 font-semibold uppercase tracking-wide">Sibling Array（Merkle Proof 路徑）</p>
              <span class="text-xs text-gray-600">— {{ result.proof | length }} 步驟，從葉到根</span>
            </div>
            {% for step in result.proof %}
            <div class="flex items-start gap-3 py-2 {% if not loop.last %}border-b border-gray-700{% endif %}">
              <span class="text-xs text-gray-500 shrink-0 w-16">步驟 {{ loop.index }}</span>
              <span class="px-2 py-0.5 rounded text-xs font-mono
                {% if step.position == 'right' %}bg-blue-900/50 text-blue-300{% else %}bg-purple-900/50 text-purple-300{% endif %}">
                {{ step.position }}
              </span>
              <span class="font-mono text-xs text-emerald-300 break-all">{{ step.sibling }}</span>
            </div>
            {% endfor %}
          </div>

          <!-- Root_official -->
          <div class="bg-gray-800 rounded-lg p-4 border border-pink-800/40">
            <div class="flex items-center gap-2 mb-2">
              <span class="w-2 h-2 rounded-full bg-pink-400"></span>
              <p class="text-xs text-pink-400 font-semibold uppercase tracking-wide">Root_official（Merkle Root）</p>
              <span class="text-xs text-gray-600">— 零信任驗證樹根，由 CC 公告</span>
            </div>
            <p class="font-mono text-xs text-pink-300 break-all">{{ result.root }}</p>
          </div>

        </div>
      </details>

      <!-- ── 平鋪式 Merkle Tree Canvas ── -->
      <div class="bg-gray-950 rounded-xl border border-gray-800 p-4">

        <!-- 工具列 -->
        <div class="flex flex-wrap items-center justify-between gap-3 mb-3">
          <h3 class="font-semibold text-gray-200 text-sm">Merkle Tree</h3>

          <!-- 圖例 -->
          <div class="flex flex-wrap items-center gap-3 text-xs">
            <span class="flex items-center gap-1.5">
              <span class="legend-dot" style="background:#451a03;border:1.5px solid #f59e0b;"></span>
              <span class="text-gray-400">目標葉節點</span>
            </span>
            <span class="flex items-center gap-1.5">
              <span class="legend-dot" style="background:#022c22;border:1.5px solid #10b981;"></span>
              <span class="text-gray-400">Sibling</span>
            </span>
            <span class="flex items-center gap-1.5">
              <span class="legend-dot" style="background:#1e1b4b;border:1.5px solid #6366f1;"></span>
              <span class="text-gray-400">Proof 路徑</span>
            </span>
            <span class="flex items-center gap-1.5">
              <span class="legend-dot" style="background:#4a044e;border:1.5px solid #ec4899;"></span>
              <span class="text-gray-400">Root</span>
            </span>
            <span class="flex items-center gap-1.5">
              <span class="legend-dot" style="background:#1f2937;border:1.5px solid #374151;"></span>
              <span class="text-gray-400">一般節點</span>
            </span>
          </div>

          <!-- 縮放控制 -->
          <div id="zoom-controls">
            <button class="zoom-btn" onclick="changeZoom(-0.15)" title="縮小">−</button>
            <span id="zoom-label">100%</span>
            <button class="zoom-btn" onclick="changeZoom(+0.15)" title="放大">+</button>
            <button class="zoom-btn" onclick="resetZoom()" title="重置" style="font-size:12px;width:auto;padding:0 8px;">重置</button>
            <button class="zoom-btn" onclick="fitTree()" title="自動縮放" style="font-size:12px;width:auto;padding:0 8px;">最適</button>
          </div>
        </div>

        <!-- Canvas 滾動容器 -->
        <div id="tree-scroll-wrap">
          <canvas id="tree-canvas"></canvas>
        </div>

        <p class="text-xs text-gray-600 mt-3 text-center">
          點擊節點查看完整雜湊 · 拖曳或滾動條滑動 · 使用縮放按鈕調整大小
        </p>
      </div>

      {% endif %}
    </div>
    {% endif %}

    <!-- Verify Form -->
    <div class="bg-gray-900 rounded-xl border border-gray-800 p-5">
      <h2 class="font-semibold text-gray-200 mb-3">輸入 m_hex 進行驗證</h2>
      <form method="GET" action="/verify" class="space-y-3">
        <input type="text" name="m_hex" value="{{ m_hex or '' }}" placeholder="輸入您的 m_hex 值..."
          class="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-indigo-500">
        <button type="submit"
          class="w-full py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-sm font-semibold transition">
          驗證 Merkle Tree
        </button>
      </form>
    </div>

  </div>

  <!-- 節點資訊浮動面板 -->
  <div id="node-panel">
    <div class="panel-title" id="panel-title"></div>
    <div class="panel-hash" id="panel-hash"></div>
    <div class="panel-meta" id="panel-meta"></div>
  </div>

  {% if result and result.valid %}
  <script>
  // ════════════════════════════════════════════════════════════
  //  平鋪式 Merkle Tree — Canvas 渲染引擎
  // ════════════════════════════════════════════════════════════
  const treeData = {{ tree_data | tojson }};

  // ── 佈局常數 ──────────────────────────────────────────────
  const NODE_W    = 130;   // 節點寬度
  const NODE_H    = 38;    // 節點高度
  const H_GAP     = 16;    // 同層節點水平間距
  const V_GAP     = 64;    // 層間垂直間距
  const PADDING_X = 40;    // 左右邊距
  const PADDING_Y = 40;    // 上下邊距
  const RADIUS    = 7;     // 節點圓角

  // ── 顏色主題 ──────────────────────────────────────────────
  const COLORS = {
    normal:  { bg: '#1f2937', border: '#374151', text: '#9ca3af', glow: null },
    target:  { bg: '#451a03', border: '#f59e0b', text: '#fcd34d', glow: 'rgba(245,158,11,0.45)' },
    sibling: { bg: '#022c22', border: '#10b981', text: '#6ee7b7', glow: 'rgba(16,185,129,0.35)' },
    path:    { bg: '#1e1b4b', border: '#6366f1', text: '#a5b4fc', glow: 'rgba(99,102,241,0.35)' },
    root:    { bg: '#4a044e', border: '#ec4899', text: '#f9a8d4', glow: 'rgba(236,72,153,0.55)' },
  };
  const EDGE_NORMAL = '#374151';
  const EDGE_PATH   = '#6366f1';

  // ── 狀態 ──────────────────────────────────────────────────
  let scale = 1.0;
  let nodePositions = [];   // [{x, y, w, h, hash, role, layerName, layerIdx, nodeIdx}]
  let canvasW = 0, canvasH = 0;

  const canvas  = document.getElementById('tree-canvas');
  const ctx     = canvas.getContext('2d');
  const wrap    = document.getElementById('tree-scroll-wrap');
  const panel   = document.getElementById('node-panel');

  // ── 工具函式 ──────────────────────────────────────────────
  function shortHash(h) {
    if (!h) return '—';
    return h.slice(0, 8) + '…' + h.slice(-6);
  }

  function getNodeRole(layerIdx, nodeIdx) {
    for (const p of treeData.proof_path) {
      if (p.layer === layerIdx && p.index === nodeIdx) return p.role;
    }
    return 'normal';
  }

  function isPathEdge(fromLayer, fromIdx, toLayer, toIdx) {
    // 判斷這條邊是否在 proof 路徑上
    const parentIdx = Math.floor(fromIdx / 2);
    if (parentIdx !== toIdx) return false;
    const fromRole = getNodeRole(fromLayer, fromIdx);
    const toRole   = getNodeRole(toLayer, toIdx);
    return (fromRole === 'target' || fromRole === 'path') &&
           (toRole   === 'path'   || toRole   === 'root');
  }

  // ── 計算佈局 ──────────────────────────────────────────────
  function computeLayout() {
    const layers = treeData.layers;
    const totalLayers = layers.length;
    // 最寬的層（葉節點層）決定畫布寬度
    const maxNodes = Math.max(...layers.map(l => l.length));
    const totalW = maxNodes * (NODE_W + H_GAP) - H_GAP + PADDING_X * 2;
    const totalH = totalLayers * (NODE_H + V_GAP) - V_GAP + PADDING_Y * 2;

    canvasW = totalW;
    canvasH = totalH;

    nodePositions = [];

    // 從葉節點（layer 0）在底部，Root 在頂部
    for (let li = 0; li < totalLayers; li++) {
      const layer = layers[li];
      const n = layer.length;
      // 這層的 y 座標（Root 在頂，葉在底）
      const layerY = PADDING_Y + (totalLayers - 1 - li) * (NODE_H + V_GAP);
      // 這層節點的總寬度
      const layerTotalW = n * (NODE_W + H_GAP) - H_GAP;
      const startX = (totalW - layerTotalW) / 2;

      const isRoot = li === totalLayers - 1;
      const isLeaf = li === 0;
      const layerName = isRoot ? 'Root' : isLeaf ? '葉節點層' : `第 ${li} 層`;

      for (let ni = 0; ni < n; ni++) {
        const hash = layer[ni];
        let role = getNodeRole(li, ni);
        if (isRoot) role = 'root';

        nodePositions.push({
          x: startX + ni * (NODE_W + H_GAP),
          y: layerY,
          w: NODE_W,
          h: NODE_H,
          hash,
          role,
          layerName,
          layerIdx: li,
          nodeIdx: ni,
        });
      }
    }
  }

  // ── 圓角矩形 ──────────────────────────────────────────────
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

  // ── 繪製 ──────────────────────────────────────────────────
  function draw() {
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

    // ── 1. 繪製連接線 ──
    for (let li = 0; li < totalLayers - 1; li++) {
      const childLayer  = layers[li];
      const parentLayer = layers[li + 1];

      // 找出這兩層的節點位置
      const childNodes  = nodePositions.filter(n => n.layerIdx === li);
      const parentNodes = nodePositions.filter(n => n.layerIdx === li + 1);

      for (let ci = 0; ci < childLayer.length; ci++) {
        const child  = childNodes[ci];
        const pi     = Math.floor(ci / 2);
        const parent = parentNodes[pi];
        if (!child || !parent) continue;

        const onPath = isPathEdge(li, ci, li + 1, pi);

        ctx.beginPath();
        ctx.moveTo(child.x + child.w / 2, child.y + child.h);
        // 貝茲曲線讓連線更美觀
        const midY = (child.y + child.h + parent.y) / 2;
        ctx.bezierCurveTo(
          child.x + child.w / 2, midY,
          parent.x + parent.w / 2, midY,
          parent.x + parent.w / 2, parent.y
        );
        ctx.strokeStyle = onPath ? EDGE_PATH : EDGE_NORMAL;
        ctx.lineWidth   = onPath ? 2.5 : 1.2;
        ctx.globalAlpha = onPath ? 1.0 : 0.45;
        ctx.stroke();
        ctx.globalAlpha = 1.0;
      }
    }

    // ── 2. 繪製節點 ──
    for (const node of nodePositions) {
      const c = COLORS[node.role] || COLORS.normal;
      const { x, y, w, h } = node;

      // 光暈
      if (c.glow) {
        ctx.save();
        ctx.shadowColor = c.glow;
        ctx.shadowBlur  = 14;
        roundRect(ctx, x, y, w, h, RADIUS);
        ctx.fillStyle = c.bg;
        ctx.fill();
        ctx.restore();
      }

      // 背景
      roundRect(ctx, x, y, w, h, RADIUS);
      ctx.fillStyle = c.bg;
      ctx.fill();

      // 邊框
      roundRect(ctx, x, y, w, h, RADIUS);
      ctx.strokeStyle = c.border;
      ctx.lineWidth   = node.role === 'normal' ? 1.2 : 2;
      ctx.stroke();

      // 文字（縮短雜湊）
      ctx.fillStyle  = c.text;
      ctx.font       = `${node.role === 'normal' ? 400 : 600} 11px 'Courier New', monospace`;
      ctx.textAlign  = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(shortHash(node.hash), x + w / 2, y + h / 2);
    }

    // ── 3. 繪製層標籤（左側） ──
    ctx.textAlign    = 'right';
    ctx.textBaseline = 'middle';
    ctx.font         = '10px sans-serif';
    ctx.fillStyle    = '#4b5563';

    const drawnLayers = new Set();
    for (const node of nodePositions) {
      if (!drawnLayers.has(node.layerIdx)) {
        drawnLayers.add(node.layerIdx);
        ctx.fillText(node.layerName, PADDING_X - 8, node.y + node.h / 2);
      }
    }
  }

  // ── 縮放 ──────────────────────────────────────────────────
  function changeZoom(delta) {
    scale = Math.min(3.0, Math.max(0.2, scale + delta));
    document.getElementById('zoom-label').textContent = Math.round(scale * 100) + '%';
    draw();
  }

  function resetZoom() {
    scale = 1.0;
    document.getElementById('zoom-label').textContent = '100%';
    draw();
  }

  function fitTree() {
    const wrapW = wrap.clientWidth  - 8;
    const wrapH = wrap.clientHeight - 8;
    const sx = wrapW / canvasW;
    const sy = wrapH / canvasH;
    scale = Math.min(sx, sy, 1.0);
    document.getElementById('zoom-label').textContent = Math.round(scale * 100) + '%';
    draw();
  }

  // ── 拖曳滑動 ──────────────────────────────────────────────
  let isDragging = false, dragStartX = 0, dragStartY = 0, scrollStartX = 0, scrollStartY = 0;

  wrap.addEventListener('mousedown', e => {
    isDragging  = true;
    dragStartX  = e.clientX;
    dragStartY  = e.clientY;
    scrollStartX = wrap.scrollLeft;
    scrollStartY = wrap.scrollTop;
    wrap.style.cursor = 'grabbing';
  });
  window.addEventListener('mousemove', e => {
    if (!isDragging) return;
    wrap.scrollLeft = scrollStartX - (e.clientX - dragStartX);
    wrap.scrollTop  = scrollStartY - (e.clientY - dragStartY);
  });
  window.addEventListener('mouseup', () => {
    isDragging = false;
    wrap.style.cursor = 'grab';
  });

  // 觸控滑動（手機）
  let touchStartX = 0, touchStartY = 0, touchScrollX = 0, touchScrollY = 0;
  wrap.addEventListener('touchstart', e => {
    touchStartX  = e.touches[0].clientX;
    touchStartY  = e.touches[0].clientY;
    touchScrollX = wrap.scrollLeft;
    touchScrollY = wrap.scrollTop;
  }, { passive: true });
  wrap.addEventListener('touchmove', e => {
    wrap.scrollLeft = touchScrollX - (e.touches[0].clientX - touchStartX);
    wrap.scrollTop  = touchScrollY - (e.touches[0].clientY - touchStartY);
  }, { passive: true });

  // ── 點擊節點顯示資訊 ──────────────────────────────────────
  canvas.addEventListener('click', e => {
    const rect  = canvas.getBoundingClientRect();
    const dpr   = window.devicePixelRatio || 1;
    // 換算回邏輯座標
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
        target:  '目標葉節點',
        sibling: 'Sibling 節點',
        path:    'Proof 路徑節點',
        root:    'Root_official',
        normal:  '一般節點',
      };
      document.getElementById('panel-title').textContent = roleLabels[hit.role] || '節點';
      document.getElementById('panel-hash').textContent  = hit.hash;
      document.getElementById('panel-meta').textContent  =
        `層：${hit.layerName}　索引：${hit.nodeIdx}`;

      // 定位面板（避免超出視窗）
      const px = Math.min(e.clientX + 12, window.innerWidth  - 440);
      const py = Math.min(e.clientY + 12, window.innerHeight - 120);
      panel.style.left    = px + 'px';
      panel.style.top     = py + 'px';
      panel.style.display = 'block';
    } else {
      panel.style.display = 'none';
    }
  });

  // 點擊其他地方關閉面板
  document.addEventListener('click', e => {
    if (!canvas.contains(e.target)) panel.style.display = 'none';
  });

  // ── 初始化 ────────────────────────────────────────────────
  function init() {
    computeLayout();
    fitTree();   // 預設自動縮放以適合容器
  }

  document.addEventListener('DOMContentLoaded', init);
  window.addEventListener('resize', () => { fitTree(); });
  </script>
  {% endif %}
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
        votes = db.fetchall("SELECT id, vote, m_hex, leaf_hash FROM published_votes ORDER BY id")
        valid_count = len(votes)
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
    """
    選票驗證頁面（含視覺化 Merkle Tree）。
    回傳：驗證結果 + 完整 tree_data（供 JS 渲染互動式 Merkle Tree）。
    """
    m_hex = request.args.get('m_hex', '').strip()
    result = None
    tree_data = None

    if m_hex:
        result = _verify_m_hex(m_hex)
        if result.get('valid'):
            tree_data = _build_tree_data(m_hex)

    return render_template_string(
        _VERIFY_HTML,
        m_hex=m_hex,
        result=result,
        tree_data=tree_data,
    )


@app.route('/api/publish', methods=['POST'])
def api_publish():
    """
    [POST] 接收 CC 推送的計票結果。
    Body: {
        "root_official": str,
        "tally": dict,
        "valid_votes": [{"vote": str, "m_hex": str}],
        "tallied_at": int  (Unix timestamp，可選)
    }
    """
    data = request.get_json()
    if not data or 'root_official' not in data or 'tally' not in data:
        return jsonify({"status": "error", "message": "缺少必要欄位"}), 400

    root_official = data['root_official']
    tally         = data['tally']
    valid_votes   = data.get('valid_votes', [])
    # Unix timestamp（後端標準）
    tallied_at    = data.get('tallied_at', int(time.time()))

    # 清空舊資料
    db.execute("DELETE FROM published_votes")

    # 儲存合法選票（含葉節點雜湊）
    for v in valid_votes:
        leaf_hash = sha256_hex(v['m_hex'].encode('utf-8'))
        db.execute(
            "INSERT INTO published_votes (vote, m_hex, leaf_hash) VALUES (?, ?, ?)",
            (v['vote'], v['m_hex'], leaf_hash),
        )

    # 儲存狀態
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('published', '1')")
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('merkle_root', ?)", (root_official,))
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('tally_json', ?)", (json.dumps(tally),))
    db.execute("INSERT OR REPLACE INTO bb_state (key, value) VALUES ('tallied_at', ?)", (str(tallied_at),))

    # 日誌使用人類可讀格式
    print(f"[BB] 結果已公告（Unix ts：{tallied_at}  →  {ts_to_human(tallied_at)}）。Root_official = {root_official[:20]}...")
    return jsonify({"status": "success", "message": "結果已公告"}), 200


@app.route('/api/results', methods=['GET'])
def api_results():
    """[GET] 回傳計票結果與 Merkle Root（Unix timestamp）"""
    published_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'published'")
    if not published_row or published_row['value'] != '1':
        return jsonify({"status": "pending", "message": "尚未公告"}), 200

    root_row      = db.fetchone("SELECT value FROM bb_state WHERE key = 'merkle_root'")
    tally_row     = db.fetchone("SELECT value FROM bb_state WHERE key = 'tally_json'")
    tallied_at_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'tallied_at'")
    votes         = db.fetchall("SELECT vote, m_hex FROM published_votes ORDER BY id")
    tallied_at    = int(tallied_at_row['value']) if tallied_at_row else None

    return jsonify({
        "status":       "success",
        "merkle_root":  root_row['value'] if root_row else "",
        "tally":        json.loads(tally_row['value']) if tally_row else {},
        "valid_votes":  votes,
        # Unix timestamp（後端標準）
        "tallied_at":   tallied_at,
        # 人類可讀（僅供 UI/日誌）
        "tallied_at_str": ts_to_human(tallied_at) if tallied_at else None,
    }), 200


@app.route('/api/merkle_proof/<path:m_hex>', methods=['GET'])
def api_merkle_proof(m_hex: str):
    """
    [GET] 提供指定 m_hex 的 Merkle Proof。
    規範：驗證起點為 H(m)，不使用選票明文。
    """
    result = _verify_m_hex(m_hex)
    if result['valid']:
        return jsonify({
            "status":        "success",
            "m_hex":         m_hex,
            "leaf_hash":     result['leaf_hash'],
            "merkle_proof":  result['proof'],
            "root_official": result['root'],
            # 零信任加密資料
            "sibling_array": [step['sibling'] for step in result['proof']],
        }), 200
    else:
        return jsonify({"status": "error", "message": result['message']}), 404


# ── Config Hot-Reload 端點 ────────────────────────────────────
make_reload_endpoint(app)


# ============================================================
# 內部函式
# ============================================================

def _verify_m_hex(m_hex: str) -> dict:
    """驗證 m_hex 是否在 Merkle Tree 中，回傳驗證結果 dict"""
    published_row = db.fetchone("SELECT value FROM bb_state WHERE key = 'published'")
    if not published_row or published_row['value'] != '1':
        return {"valid": False, "message": "結果尚未公告"}

    votes = db.fetchall("SELECT m_hex FROM published_votes ORDER BY id")
    m_hex_list = [v['m_hex'] for v in votes]

    if m_hex not in m_hex_list:
        return {"valid": False, "message": "找不到此 m_hex，可能選票無效或尚未計入"}

    index = m_hex_list.index(m_hex)
    tree  = MerkleTree(m_hex_list)
    proof = tree.get_proof(index)
    root  = tree.get_root()

    # 驗證 Merkle Proof
    is_valid = MerkleTree.verify_proof(m_hex, proof, root)

    if is_valid:
        return {
            "valid":     True,
            "m_hex":     m_hex,
            "leaf_hash": sha256_hex(m_hex.encode('utf-8')),
            "proof":     proof,
            "root":      root,
            "index":     index,
        }
    else:
        return {"valid": False, "message": "Merkle Proof 驗證失敗"}


def _build_tree_data(m_hex: str) -> dict:
    """
    建構供前端 JS 渲染的 Merkle Tree 資料結構。
    包含：
      - layers: 每層節點雜湊列表（從葉到根）
      - target_index: 目標葉節點索引
      - proof_path: 每個節點的角色（target/sibling/path/normal）
      - root: Root_official
    """
    votes = db.fetchall("SELECT m_hex FROM published_votes ORDER BY id")
    m_hex_list = [v['m_hex'] for v in votes]

    if m_hex not in m_hex_list:
        return None

    index = m_hex_list.index(m_hex)
    tree  = MerkleTree(m_hex_list)
    proof = tree.get_proof(index)
    root  = tree.get_root()

    # 建構 proof_path：標記每層每個節點的角色
    proof_path = []
    current_index = index

    # 葉節點層（layer 0）：目標節點
    proof_path.append({"layer": 0, "index": current_index, "role": "target"})

    for step_i, step in enumerate(proof):
        layer_idx = step_i  # 當前層索引（0 = 葉節點層）

        # Sibling 節點
        if step['position'] == 'right':
            sibling_index = current_index + 1
        else:
            sibling_index = current_index - 1

        proof_path.append({"layer": layer_idx, "index": sibling_index, "role": "sibling"})

        # 下一層的路徑節點
        next_index = current_index // 2
        proof_path.append({"layer": layer_idx + 1, "index": next_index, "role": "path"})
        current_index = next_index

    # Root 節點（最後一層）
    last_layer_idx = len(tree.tree) - 1
    proof_path.append({"layer": last_layer_idx, "index": 0, "role": "root"})

    # 建構 layers（每層節點的雜湊值，補齊奇數層）
    layers = []
    for layer in tree.tree:
        # 若奇數個節點，補齊最後一個（與 MerkleTree._build_tree 一致）
        if len(layer) % 2 == 1 and len(layer) > 1:
            layers.append(layer + [layer[-1]])
        else:
            layers.append(list(layer))

    return {
        "layers":       layers,
        "target_index": index,
        "proof_path":   proof_path,
        "root":         root,
        "m_hex":        m_hex,
        "leaf_hash":    sha256_hex(m_hex.encode('utf-8')),
    }


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=False)
