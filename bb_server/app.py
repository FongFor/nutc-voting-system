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
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            msblue: '#0078D4',
            msblueHover: '#0060A8',
            deepblack: '#050505',
            cardblack: '#111111'
          }
        }
      }
    }
  </script>
  <link href="https://fonts.googleapis.com/css2?family=Noto+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Noto Sans', sans-serif; }
  </style>
  <script>
    // 避免畫面閃爍的深色模式初始化
    if (localStorage.getItem('theme') === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    function toggleTheme() {
      if (document.documentElement.classList.contains('dark')) {
        document.documentElement.classList.remove('dark');
        localStorage.setItem('theme', 'light');
      } else {
        document.documentElement.classList.add('dark');
        localStorage.setItem('theme', 'dark');
      }
    }
  </script>
  <meta http-equiv="refresh" content="20">
</head>
<body class="bg-gray-50 dark:bg-deepblack text-gray-800 dark:text-gray-100 min-h-screen transition-colors duration-300">
  <div class="max-w-5xl mx-auto px-4 py-10">

    <div class="flex items-center gap-4 mb-8">
      <div class="w-12 h-12 rounded-xl bg-white/70 dark:bg-cardblack/80 backdrop-blur-md shadow-sm flex items-center justify-center border border-gray-200 dark:border-gray-800">
        <svg class="w-6 h-6 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
      </div>
      <div>
        <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">公告板 (BB)</h1>
        <p class="text-gray-500 dark:text-gray-400 text-sm">Bulletin Board</p>
      </div>
      
      <div class="ml-auto flex items-center gap-3">
        <span class="px-3 py-1.5 rounded-full text-xs font-medium border backdrop-blur-sm flex items-center
          {% if published %}bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border-green-200 dark:border-green-800/50{% else %}bg-yellow-50 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-400 border-yellow-200 dark:border-yellow-800/50{% endif %}">
          <span class="inline-block w-1.5 h-1.5 rounded-full mr-1.5 {% if published %}bg-green-500 shadow-[0_0_4px_#22c55e]{% else %}bg-yellow-500 shadow-[0_0_4px_#eab308]{% endif %}"></span>
          {% if published %}已公告{% else %}等待結果{% endif %}
        </span>

        <button onclick="toggleTheme()" class="p-2 rounded-lg bg-white/70 dark:bg-cardblack/80 border border-gray-200 dark:border-gray-800 shadow-sm hover:bg-gray-100 dark:hover:bg-gray-900 transition-colors text-gray-600 dark:text-gray-300 focus:outline-none focus:ring-2 focus:ring-msblue/50">
          <svg class="w-4 h-4 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
          <svg class="w-4 h-4 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
        </button>
      </div>
    </div>

    {% if published %}
    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-2xl border border-gray-200 dark:border-gray-800 shadow-md p-6 mb-6">
      <h2 class="font-medium text-gray-800 dark:text-gray-200 mb-5 text-sm uppercase tracking-wider flex items-center gap-2">
        <svg class="w-4 h-4 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path></svg>
        最終計票結果
      </h2>
      {% if tally %}
      <div class="space-y-4">
        {% set total = valid_count %}
        {% for candidate, count in tally.items() %}
        <div>
          <div class="flex justify-between text-sm mb-1.5">
            <span class="font-mono text-gray-700 dark:text-gray-300 font-medium">{{ candidate }}</span>
            <span class="text-gray-900 dark:text-white font-semibold">{{ count }} 票
              <span class="text-gray-500 dark:text-gray-500 font-normal text-xs ml-1">
                ({{ "%.1f"|format(count / total * 100) if total > 0 else 0 }}%)
              </span>
            </span>
          </div>
          <div class="w-full bg-gray-100 dark:bg-[#1a1a1a] rounded-full h-2 overflow-hidden">
            <div class="bg-msblue h-2 rounded-full transition-all duration-500 ease-out"
              style="width: {{ (count / total * 100) | int if total > 0 else 0 }}%"></div>
          </div>
        </div>
        {% endfor %}
      </div>
      <div class="mt-6 pt-4 border-t border-gray-100 dark:border-gray-800 flex justify-between items-center text-sm">
        <span class="text-gray-500 dark:text-gray-400">合計合法選票</span>
        <span class="font-semibold text-lg text-gray-900 dark:text-white">{{ valid_count }} <span class="text-xs font-normal text-gray-500">票</span></span>
      </div>
      {% endif %}
    </div>

    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-msblue/30 dark:border-msblue/40 shadow-md p-5 mb-6 relative overflow-hidden">
      <div class="absolute top-0 left-0 w-1.5 h-full bg-msblue"></div>
      <div class="flex items-center gap-2 mb-3">
        <svg class="w-4 h-4 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
        <span class="text-msblue dark:text-[#3399FF] text-sm font-semibold tracking-wide">Root_official</span>
        <span class="text-[11px] text-gray-400 dark:text-gray-500 border-l border-gray-200 dark:border-gray-700 pl-2">Merkle Root</span>
      </div>
      <p class="font-mono text-xs sm:text-sm text-gray-700 dark:text-gray-300 break-all bg-gray-50 dark:bg-[#0a0a0a] rounded-lg border border-gray-100 dark:border-gray-800/80 px-4 py-3 shadow-inner">{{ merkle_root }}</p>
      {% if tallied_at %}
      <div class="flex items-center gap-2 mt-3 text-xs text-gray-500 dark:text-gray-500">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        <span>公告時間：<span class="font-mono text-gray-600 dark:text-gray-400">{{ tallied_at | ts_to_str }}</span> <span class="opacity-50 ml-1">(Unix ts: {{ tallied_at }})</span></span>
      </div>
      {% endif %}
    </div>

    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-5 mb-6">
      <h2 class="font-medium text-gray-800 dark:text-gray-200 mb-4 text-sm flex items-center gap-2">
        <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
        驗證選票
      </h2>
      <form method="GET" action="/verify" class="flex flex-col sm:flex-row gap-3">
        <input type="text" name="m_hex" placeholder="輸入您的 m_hex 值..."
          class="flex-1 bg-gray-50 dark:bg-[#0a0a0a] border border-gray-300 dark:border-gray-700 rounded-lg px-4 py-2.5 text-sm text-gray-800 dark:text-gray-200 placeholder-gray-400 dark:placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-msblue/50 focus:border-msblue transition-all shadow-inner">
        <button type="submit"
          class="px-6 py-2.5 bg-msblue hover:bg-msblueHover text-white rounded-lg text-sm font-medium shadow-sm transition-colors flex items-center justify-center gap-2 whitespace-nowrap">
          <span>驗證 + 視覺化</span>
        </button>
      </form>
    </div>

    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-100 dark:border-gray-800/60 bg-gray-50/50 dark:bg-[#0a0a0a]/50 flex items-center justify-between">
        <h2 class="font-medium text-gray-800 dark:text-gray-200 text-sm">合法選票清單</h2>
        <span class="text-[11px] text-gray-500 dark:text-gray-500 flex items-center gap-1.5">
          <span class="relative flex h-2 w-2">
            <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-msblue opacity-40"></span>
            <span class="relative inline-flex rounded-full h-2 w-2 bg-msblue"></span>
          </span>
          自動更新
        </span>
      </div>
      {% if votes %}
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead class="bg-gray-50 dark:bg-[#0a0a0a] text-gray-500 dark:text-gray-500 text-xs uppercase tracking-wider">
            <tr>
              <th class="px-6 py-3.5 text-left font-medium">#</th>
              <th class="px-6 py-3.5 text-left font-medium">投票內容</th>
              <th class="px-6 py-3.5 text-left font-medium">m_hex（前 24 字元）</th>
              <th class="px-6 py-3.5 text-left font-medium">葉節點 H(m)</th>
              <th class="px-6 py-3.5 text-left font-medium text-right">操作</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100 dark:divide-gray-800/60">
            {% for v in votes %}
            <tr class="hover:bg-gray-50 dark:hover:bg-[#1a1a1a] transition-colors">
              <td class="px-6 py-4 text-gray-400 dark:text-gray-600 text-xs">{{ v.id }}</td>
              <td class="px-6 py-4 font-mono text-gray-800 dark:text-gray-300 font-medium">{{ v.vote }}</td>
              <td class="px-6 py-4 font-mono text-gray-500 dark:text-gray-500 text-xs">{{ v.m_hex[:24] }}...</td>
              <td class="px-6 py-4 font-mono text-gray-400 dark:text-gray-600 text-xs">{{ v.leaf_hash[:24] }}...</td>
              <td class="px-6 py-4 text-right">
                <a href="/verify?m_hex={{ v.m_hex }}"
                  class="inline-flex items-center text-xs font-medium text-msblue hover:text-msblueHover dark:text-[#3399FF] dark:hover:text-white transition-colors">
                  驗證 <svg class="w-3.5 h-3.5 ml-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                </a>
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% else %}
      <div class="px-6 py-14 text-center text-gray-500 dark:text-gray-600">
        <svg class="w-10 h-10 mx-auto text-gray-300 dark:text-gray-700 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
        <p class="text-sm">尚無合法選票</p>
      </div>
      {% endif %}
    </div>

    {% else %}
    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-2xl border border-gray-200 dark:border-gray-800 shadow-md p-16 text-center">
      <div class="w-16 h-16 bg-gray-50 dark:bg-[#1a1a1a] rounded-full flex items-center justify-center mx-auto mb-4 border border-gray-100 dark:border-gray-800">
        <svg class="w-8 h-8 text-gray-400 dark:text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
      </div>
      <h2 class="text-lg font-medium text-gray-800 dark:text-gray-200 mb-2">等待計票結果</h2>
      <p class="text-gray-500 dark:text-gray-500 text-sm">計票中心（CC）尚未公告結果。</p>
    </div>
    {% endif %}

  </div>
</body>
</html>"""

_VERIFY_HTML = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BB · Merkle Proof 視覺化驗證</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            msblue: '#0078D4',
            msblueHover: '#0060A8',
            deepblack: '#050505',
            cardblack: '#111111'
          }
        }
      }
    }
  </script>
  <link href="https://fonts.googleapis.com/css2?family=Noto+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Noto Sans', sans-serif; }
    
    /* ── Canvas 固定滾動容器 (overflow:hidden + 純拖曳，無捲軸) ── */
    #tree-scroll-wrap {
      overflow: hidden;
      background: rgba(31, 41, 55, 0.02);
      border-radius: 12px;
      cursor: grab;
      position: relative;
      /* 固定高度：不隨 canvas 縮放而改變，防止死亡迴圈 */
      width: 100%;
      height: 65vh;
      min-height: 450px;
      box-shadow: inset 0 2px 10px rgba(0,0,0,0.03);
    }
    .dark #tree-scroll-wrap { 
      background: rgba(10, 10, 10, 0.4); 
      box-shadow: inset 0 2px 15px rgba(0,0,0,0.3); 
    }
    #tree-scroll-wrap:active { cursor: grabbing; }
    
    /* Canvas 用絕對定位，由 JS 控制 left/top 實現拖曳與置中 */
    #tree-canvas { 
      display: block;
      position: absolute;
      top: 0;
      left: 0;
    }

    /* ── 節點資訊浮動面板 ── */
    #node-panel {
      display: none;
      position: fixed;
      z-index: 200;
      background: rgba(255, 255, 255, 0.95);
      backdrop-filter: blur(8px);
      border: 1px solid rgba(229, 231, 235, 1);
      border-radius: 10px;
      padding: 14px 16px;
      font-family: 'Courier New', monospace;
      font-size: 12px;
      color: #1f2937;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1);
      max-width: 420px;
      pointer-events: none;
    }
    .dark #node-panel {
      background: rgba(17, 17, 17, 0.95);
      border-color: rgba(51, 51, 51, 1);
      color: #e5e7eb;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
    }
    #node-panel .panel-title { font-size: 11px; font-weight: 600; margin-bottom: 6px; font-family: 'Noto Sans', sans-serif; }
    #node-panel .panel-hash { word-break: break-all; color: #0078D4; font-size: 11px; line-height: 1.6; }
    .dark #node-panel .panel-hash { color: #3399FF; }
    #node-panel .panel-meta { color: #6b7280; font-size: 10px; margin-top: 6px; font-family: 'Noto Sans', sans-serif; }
    .dark #node-panel .panel-meta { color: #9ca3af; }

    /* ── 縮放控制 ── */
    #zoom-controls { display: flex; gap: 6px; align-items: center; }
    .zoom-btn {
      width: 30px; height: 30px; border-radius: 6px;
      background: rgba(0, 0, 0, 0.03); border: 1px solid rgba(0, 0, 0, 0.1);
      color: #4b5563; font-size: 16px; cursor: pointer;
      display: flex; align-items: center; justify-content: center;
      transition: all 0.2s;
    }
    .dark .zoom-btn { background: rgba(255, 255, 255, 0.05); border-color: rgba(255, 255, 255, 0.1); color: #9ca3af; }
    .zoom-btn:hover { background: rgba(0, 120, 212, 0.1); color: #0078D4; border-color: #0078D4; }
    .dark .zoom-btn:hover { background: rgba(51, 153, 255, 0.1); color: #3399FF; border-color: #3399FF; }
    #zoom-label { font-size: 12px; font-weight: 500; min-width: 40px; text-align: center; color: #4B5563; }
    .dark #zoom-label { color: #9CA3AF; }

    /* ── 圖例 ── */
    .legend-dot { width: 10px; height: 10px; border-radius: 3px; flex-shrink: 0; }
  </style>
  <script>
    if (localStorage.getItem('theme') === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    function toggleTheme() {
      if (document.documentElement.classList.contains('dark')) {
        document.documentElement.classList.remove('dark');
        localStorage.setItem('theme', 'light');
      } else {
        document.documentElement.classList.add('dark');
        localStorage.setItem('theme', 'dark');
      }
      if(typeof draw === 'function') draw(); 
    }
  </script>
</head>
<body class="bg-gray-50 dark:bg-deepblack text-gray-800 dark:text-gray-100 min-h-screen transition-colors duration-300">
  <div class="max-w-6xl mx-auto px-4 py-10">

    <div class="flex items-center justify-between mb-8">
      <div class="flex items-center gap-4">
        <a href="/" class="p-2 -ml-2 rounded-lg text-gray-400 hover:text-msblue hover:bg-msblue/10 transition-colors" title="返回公告板">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path></svg>
        </a>
        <div class="w-10 h-10 rounded-xl bg-white/70 dark:bg-cardblack/80 shadow-sm flex items-center justify-center border border-gray-200 dark:border-gray-800">
          <svg class="w-5 h-5 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </div>
        <div>
          <h1 class="text-xl font-semibold text-gray-900 dark:text-white">Merkle Proof 驗證</h1>
          <p class="text-gray-500 dark:text-gray-500 text-xs mt-0.5">Merkle Tree 視覺化</p>
        </div>
      </div>
      
      <button onclick="toggleTheme()" class="p-2 rounded-lg bg-white/70 dark:bg-cardblack/80 border border-gray-200 dark:border-gray-800 shadow-sm hover:bg-gray-100 dark:hover:bg-gray-900 transition-colors text-gray-600 dark:text-gray-300 focus:outline-none focus:ring-2 focus:ring-msblue/50">
        <svg class="w-4 h-4 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
        <svg class="w-4 h-4 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
      </button>
    </div>

    {% if result %}
    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-2xl border border-gray-200 dark:border-gray-800 shadow-md p-6 mb-6">
      <div class="flex items-start gap-4 mb-5 p-4 rounded-xl {% if result.valid %}bg-green-50/80 dark:bg-green-900/10 border border-green-200 dark:border-green-900/50{% else %}bg-red-50/80 dark:bg-red-900/10 border border-red-200 dark:border-red-900/50{% endif %}">
        {% if result.valid %}
        <div class="mt-0.5">
           <svg class="w-5 h-5 text-green-600 dark:text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </div>
        <div>
          <p class="font-semibold text-green-800 dark:text-green-400 text-sm">驗證通過</p>
          <p class="text-green-600 dark:text-green-500/80 text-xs mt-1">您的選票已包含在合法計票結果中</p>
        </div>
        {% else %}
        <div class="mt-0.5">
           <svg class="w-5 h-5 text-red-600 dark:text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        </div>
        <div>
          <p class="font-semibold text-red-800 dark:text-red-400 text-sm">驗證失敗</p>
          <p class="text-red-600 dark:text-red-500/80 text-xs mt-1">{{ result.message }}</p>
        </div>
        {% endif %}
      </div>

      {% if result.valid %}
      <details class="mb-6 group">
        <summary class="cursor-pointer text-[13px] font-medium text-gray-500 dark:text-gray-400 hover:text-msblue dark:hover:text-white select-none py-2 flex items-center transition-colors">
          <svg class="w-3.5 h-3.5 mr-2 transform transition-transform group-open:rotate-90" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
          展開查看詳細雜湊資訊
        </summary>
        <div class="grid grid-cols-1 gap-3 mt-3 pl-5 border-l border-gray-100 dark:border-gray-800 ml-1">
          <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-lg p-3.5 border border-gray-200 dark:border-gray-800 shadow-sm relative overflow-hidden">
            <div class="absolute top-0 left-0 w-1 h-full bg-amber-500"></div>
            <div class="flex flex-col sm:flex-row sm:items-center gap-2 mb-2">
              <p class="text-[11px] text-gray-700 dark:text-gray-300 font-semibold tracking-wider">m_hex（選票包雜湊值）</p>
              <span class="text-[10px] text-gray-400 dark:text-gray-600">— 驗證起點</span>
            </div>
            <p class="font-mono text-[11px] text-gray-600 dark:text-gray-500 break-all">{{ result.m_hex }}</p>
          </div>
          <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-lg p-3.5 border border-gray-200 dark:border-gray-800 shadow-sm relative overflow-hidden">
            <div class="absolute top-0 left-0 w-1 h-full bg-emerald-500"></div>
            <div class="flex flex-col sm:flex-row sm:items-center gap-2 mb-3">
              <p class="text-[11px] text-gray-700 dark:text-gray-300 font-semibold tracking-wider">Sibling Array（Merkle Proof 路徑）</p>
              <span class="text-[10px] text-gray-400 dark:text-gray-600">— {{ result.proof | length }} 步驟，從葉到根</span>
            </div>
            <div class="space-y-1">
              {% for step in result.proof %}
              <div class="flex flex-col sm:flex-row sm:items-center gap-2 py-1.5 {% if not loop.last %}border-b border-gray-200/60 dark:border-gray-800/80{% endif %}">
                <div class="flex items-center gap-2 shrink-0 w-24">
                  <span class="text-[10px] font-medium text-gray-500">步驟 {{ loop.index }}</span>
                  <span class="px-1.5 py-0.5 rounded text-[10px] font-mono {% if step.position == 'right' %}bg-blue-100/50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400{% else %}bg-purple-100/50 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400{% endif %}">{{ step.position }}</span>
                </div>
                <span class="font-mono text-[11px] text-gray-600 dark:text-gray-500 break-all">{{ step.sibling }}</span>
              </div>
              {% endfor %}
            </div>
          </div>
          <div class="bg-gray-50/80 dark:bg-[#0a0a0a] rounded-lg p-3.5 border border-gray-200 dark:border-gray-800 shadow-sm relative overflow-hidden">
            <div class="absolute top-0 left-0 w-1 h-full bg-msblue"></div>
            <div class="flex flex-col sm:flex-row sm:items-center gap-2 mb-2">
              <p class="text-[11px] text-gray-700 dark:text-gray-300 font-semibold tracking-wider">Root_official（Merkle Root）</p>
              <span class="text-[10px] text-gray-400 dark:text-gray-600">— 零信任驗證樹根，由 CC 公告</span>
            </div>
            <p class="font-mono text-[11px] text-gray-600 dark:text-gray-500 break-all">{{ result.root }}</p>
          </div>
        </div>
      </details>

      <div class="bg-white/50 dark:bg-[#0a0a0a]/50 rounded-xl border border-gray-200 dark:border-gray-800/80 p-3 sm:p-5 shadow-inner">
        <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
          <h3 class="font-medium text-gray-800 dark:text-gray-200 text-sm flex items-center gap-2">
             <svg class="w-4 h-4 text-msblue" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4"></path></svg>
             視覺化樹狀圖
          </h3>
          <div class="flex flex-wrap items-center gap-3 text-[11px] bg-white dark:bg-cardblack px-3 py-1.5 rounded-md border border-gray-200 dark:border-gray-800 shadow-sm">
            <span class="flex items-center gap-1.5"><span class="legend-dot" style="background:#f59e0b;border:1.5px solid #d97706;"></span><span class="text-gray-700 dark:text-gray-300 font-semibold">目標節點</span></span>
            <span class="flex items-center gap-1.5"><span class="legend-dot" style="background:#10b981;border:1.5px solid #059669;"></span><span class="text-gray-700 dark:text-gray-300 font-semibold">Sibling</span></span>
            <span class="flex items-center gap-1.5"><span class="legend-dot" style="background:#6366f1;border:1.5px solid #4f46e5;"></span><span class="text-gray-700 dark:text-gray-300 font-semibold">驗證路徑</span></span>
            <span class="flex items-center gap-1.5"><span class="legend-dot" style="background:#0ea5e9;border:1.5px solid #0284c7;"></span><span class="text-gray-700 dark:text-gray-300 font-semibold">Root</span></span>
          </div>
          <div id="zoom-controls">
            <button type="button" class="zoom-btn" onclick="changeZoom(-0.15)" title="縮小"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 12H4"></path></svg></button>
            <span id="zoom-label">100%</span>
            <button type="button" class="zoom-btn" onclick="changeZoom(+0.15)" title="放大"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg></button>
            <div class="h-3.5 border-l border-gray-300 dark:border-gray-700 mx-1"></div>
            <button type="button" class="zoom-btn px-2 w-auto text-[11px]" onclick="resetZoom()" title="重置">1:1</button>
            <button type="button" class="zoom-btn px-2 w-auto text-[11px]" onclick="fitTree()" title="自動縮放">最適</button>
            <button type="button" class="zoom-btn px-2 w-auto text-[11px]" onclick="focusTarget()" title="對焦到目標節點" style="color:#f59e0b;border-color:#f59e0b;">⊙ 對焦</button>
          </div>
        </div>

        <div id="tree-scroll-wrap" class="border border-gray-200 dark:border-gray-800/80">
          <canvas id="tree-canvas"></canvas>
        </div>

        <p class="text-[11px] text-gray-500 dark:text-gray-600 mt-3 text-center flex items-center justify-center gap-1">
          <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
          點擊節點查看完整雜湊 · 滑鼠拖曳滑動 · 滾輪垂直滑動 · 按住 Shift 滾輪水平滑動
        </p>
      </div>
      {% endif %}
    </div>
    {% endif %}

    <div class="bg-white/70 dark:bg-cardblack/80 backdrop-blur-lg rounded-xl border border-gray-200 dark:border-gray-800 shadow-md p-6">
      <h2 class="font-medium text-gray-800 dark:text-gray-200 mb-4 text-[13px] uppercase tracking-wider">輸入 m_hex 進行另一次驗證</h2>
      <form method="GET" action="/verify" class="flex flex-col sm:flex-row gap-3">
        <input type="text" name="m_hex" value="{{ m_hex or '' }}" placeholder="輸入您的 m_hex 值..."
          class="flex-1 bg-gray-50 dark:bg-[#0a0a0a] border border-gray-300 dark:border-gray-700 rounded-lg px-4 py-2.5 text-sm text-gray-800 dark:text-gray-200 placeholder-gray-400 dark:placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-msblue/50 focus:border-msblue transition-all shadow-inner">
        <button type="submit"
          class="px-6 py-2.5 bg-msblue hover:bg-msblueHover text-white rounded-lg text-sm font-medium shadow-sm transition-colors flex items-center justify-center gap-2 whitespace-nowrap">
          重新驗證
        </button>
      </form>
    </div>
  </div>

  <div id="node-panel">
    <div class="panel-title" id="panel-title"></div>
    <div class="panel-hash" id="panel-hash"></div>
    <div class="panel-meta" id="panel-meta"></div>
  </div>

  {% if result and result.valid %}
  <script>
  // ════════════════════════════════════════════════════════════
  //  完美的金字塔佈局 — 自底向上精準尋跡 + Root 絕對置中演算法
  // ════════════════════════════════════════════════════════════
  const treeData = {{ tree_data | tojson }};

  const NODE_W    = 108;
  const NODE_H    = 34;
  const H_GAP     = 24;
  const V_GAP     = 72;   
  
  // Canvas 內部的固定 Padding（大面積留白，確保畫面宏大不貼邊）
  const PADDING_X  = 100;
  const PADDING_Y  = 100;
  // 層標籤區域寬度（左側保留給文字）
  const LABEL_W    = 80;
  const RADIUS     = 6;

  function getThemeColors() {
    const isDark = document.documentElement.classList.contains('dark');
    return {
      normal:  isDark ? { bg: '#1a1a1a', border: '#333333', text: '#9ca3af', glow: null } 
                      : { bg: '#ffffff', border: '#d1d5db', text: '#6b7280', glow: null },
      target:  isDark ? { bg: '#92400e', border: '#fcd34d', text: '#fff', glow: 'rgba(251,191,36,0.8)' }
                      : { bg: '#fef3c7', border: '#f59e0b', text: '#92400e', glow: 'rgba(245,158,11,0.6)' },
      sibling: isDark ? { bg: '#065f46', border: '#6ee7b7', text: '#fff', glow: 'rgba(52,211,153,0.8)' }
                      : { bg: '#ecfdf5', border: '#10b981', text: '#065f46', glow: 'rgba(16,185,129,0.6)' },
      path:    isDark ? { bg: '#3730a3', border: '#a5b4fc', text: '#fff', glow: 'rgba(129,140,248,0.8)' }
                      : { bg: '#eef2ff', border: '#6366f1', text: '#3730a3', glow: 'rgba(99,102,241,0.6)' },
      root:    isDark ? { bg: '#075985', border: '#7dd3fc', text: '#fff', glow: 'rgba(56,189,248,0.8)' }
                      : { bg: '#f0f9ff', border: '#0ea5e9', text: '#075985', glow: 'rgba(14,165,233,0.6)' },
      edgeNormal: isDark ? '#333333' : '#d1d5db',
      edgePath:   isDark ? '#818cf8' : '#6366f1',
      layerText:  isDark ? '#6b7280' : '#9ca3af'
    };
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
    canvasH = PADDING_Y * 2 + (totalLayers - 1) * (NODE_H + V_GAP) + NODE_H;

    nodePositions = [];
    const nodeMap = Array.from({length: totalLayers}, () => []);

    // ── 步驟 1：排列最底層的葉節點（從 X=0 開始，純相對座標）
    // 只排列「真實」的葉節點（trueChildCount[0] 個）
    const nRealLeaves = trueChildCount[0];
    for (let ni = 0; ni < nRealLeaves; ni++) {
      const hash = layers[0][ni];
      const role = getNodeRole(0, ni);
      const nodeX = ni * (NODE_W + H_GAP);
      const node = {
        x: nodeX,
        y: canvasH - PADDING_Y - NODE_H,
        w: NODE_W, h: NODE_H, hash, role,
        layerName: '葉節點層', layerIdx: 0, nodeIdx: ni,
      };
      nodePositions.push(node);
      nodeMap[0][ni] = node;
    }

    // ── 步驟 2：由下往上，父節點精準對齊「真實」子節點中央
    for (let li = 1; li < totalLayers; li++) {
      const nReal = trueChildCount[li];
      const isRoot = li === totalLayers - 1;
      const layerName = isRoot ? 'Root_official' : `第 ${li} 層`;
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

        const node = {
          x: nodeX, y: layerY,
          w: NODE_W, h: NODE_H, hash, role,
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

  // ── 對焦到目標節點（將目標葉節點置中於視窗）──
  function focusTarget() {
    const target = nodePositions.find(n => n.role === 'target');
    if (!target) return;
    const wrapW = wrap.clientWidth;
    const wrapH = wrap.clientHeight;
    // 目標節點中心在畫布上的座標（縮放後）
    const targetCX = (target.x + target.w / 2) * scale;
    const targetCY = (target.y + target.h / 2) * scale;
    // 讓目標節點中心對齊容器中心
    canvasLeft = Math.round(wrapW / 2 - targetCX);
    canvasTop  = Math.round(wrapH / 2 - targetCY);
    canvas.style.left = canvasLeft + 'px';
    canvas.style.top  = canvasTop  + 'px';
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

        const startX = child.x + child.w / 2;
        const startY = child.y;                   
        const endX   = parent.x + parent.w / 2;
        const endY   = parent.y + parent.h;       
        const midY   = startY - (startY - endY) / 2; 

        ctx.beginPath();
        ctx.moveTo(startX, startY);
        ctx.bezierCurveTo(startX, midY, endX, midY, endX, endY);
        
        ctx.strokeStyle = onPath ? colors.edgePath : colors.edgeNormal;
        // 路徑連線超級加粗，對比普通線條
        ctx.lineWidth   = onPath ? 4.0 : 1.2;
        ctx.globalAlpha = onPath ? 1.0 : 0.3;
        ctx.stroke();
        ctx.globalAlpha = 1.0;
      }
    }

    // ── 繪製高亮重點節點 ──
    for (const node of nodePositions) {
      const c = colors[node.role] || colors.normal;
      const { x, y, w, h } = node;

      if (c.glow) {
        ctx.save();
        ctx.shadowColor = c.glow;
        // 發光範圍擴大，讓重點更醒目
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
      // 增強高亮節點的邊框粗細
      ctx.lineWidth   = node.role !== 'normal' ? 3.0 : 1.5;
      ctx.stroke();

      ctx.fillStyle  = c.text;
      ctx.font       = `${node.role === 'normal' ? 400 : 700} 11px 'Courier New', monospace`;
      ctx.textAlign  = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(shortHash(node.hash), x + w / 2, y + h / 2);
    }

    // ── 繪製層標籤 ──
    ctx.textAlign    = 'right';
    ctx.textBaseline = 'middle';
    ctx.font         = '11px "Noto Sans", sans-serif';
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

  // 避免縮放死循環，設立上下限（最小 0.15，最大 1.2）
  function changeZoom(delta) {
    scale = Math.max(0.15, Math.min(scale + delta, 1.2));
    document.getElementById('zoom-label').textContent = Math.round(scale * 100) + '%';
    draw();
    _centerCanvas();
  }

  function resetZoom() {
    scale = 1.0;
    document.getElementById('zoom-label').textContent = '100%';
    draw();
    _centerCanvas();
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

  // 最適化：計算最適比例，然後置中
  function fitTree() {
    const wrapW = wrap.clientWidth;
    const wrapH = wrap.clientHeight;
    const sx = wrapW / canvasW;
    const sy = wrapH / canvasH;
    scale = Math.max(0.15, Math.min(sx, sy, 1.2));
    document.getElementById('zoom-label').textContent = Math.round(scale * 100) + '%';
    draw();
    _centerCanvas();
  }

  // ── 滾輪縮放（以滑鼠位置為中心縮放）──
  wrap.addEventListener('wheel', e => {
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
    scale = Math.max(0.15, Math.min(scale + delta, 1.2));

    if (scale === oldScale) return;
    document.getElementById('zoom-label').textContent = Math.round(scale * 100) + '%';
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

  let touchStartX = 0, touchStartY = 0, canvasTouchLeft = 0, canvasTouchTop = 0;
  wrap.addEventListener('touchstart', e => {
    touchStartX    = e.touches[0].clientX;
    touchStartY    = e.touches[0].clientY;
    canvasTouchLeft = canvasLeft;
    canvasTouchTop  = canvasTop;
  }, { passive: true });
  wrap.addEventListener('touchmove', e => {
    canvasLeft = canvasTouchLeft + (e.touches[0].clientX - touchStartX);
    canvasTop  = canvasTouchTop  + (e.touches[0].clientY - touchStartY);
    canvas.style.left = canvasLeft + 'px';
    canvas.style.top  = canvasTop  + 'px';
  }, { passive: true });

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
        target:  '目標葉節點',
        sibling: 'Sibling 節點',
        path:    'Proof 路徑節點',
        root:    'Root_official',
        normal:  '一般節點',
      };
      document.getElementById('panel-title').textContent = roleLabels[hit.role] || '節點';
      document.getElementById('panel-hash').textContent  = hit.hash;
      document.getElementById('panel-meta').textContent  =
        `層級：${hit.layerName}　索引：${hit.nodeIdx}`;

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

  function init() {
    computeLayout();
    // 初始以 1:1 比例繪製，然後對焦到目標節點
    scale = 1.0;
    document.getElementById('zoom-label').textContent = '100%';
    draw();
    focusTarget();
  }

  // DOMContentLoaded 時初始化；若已載入完成則直接執行
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
  
  // 視窗變形時，自動重新計算最適比例
  window.addEventListener('resize', () => { fitTree(); });

  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
    if (!localStorage.getItem('theme')) {
      if (e.matches) document.documentElement.classList.add('dark');
      else document.documentElement.classList.remove('dark');
      draw();
    }
  });
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
