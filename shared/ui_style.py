"""
shared/ui_style.py — 全系統共用的網頁樣式

所有服務的網頁（選民端、公告板、Admin、各服務儀表板）共用這一份 CSS，
取代原本從 cdn.tailwindcss.com 載入的 Tailwind 與 Google Fonts：

  - 投票頁在瀏覽器裡加密選票，同一個頁面若執行第三方 CDN 的 JS，等於把
    選票加密交給對方——CDN 被入侵就能竄改選票。改為完全自帶，不載入任何
    外部資源。
  - 不用字型 CDN，改用系統內建的繁體中文字型，也不會向第三方洩漏瀏覽紀錄。

用法（在模板字串中串接）：
    from shared.ui_style import UI_HEAD
    _PAGE = \"\"\"<!DOCTYPE html><html lang="zh-TW"><head>
      <meta charset="UTF-8"><title>...</title>\"\"\" + UI_HEAD + \"\"\"
    </head>...\"\"\"

深色模式：<html> 加上 class="dark" 即切換；預設跟隨系統設定，
使用者按下切換按鈕（呼叫 toggleTheme()）後記在 localStorage。
"""

UI_CSS = """
:root {
  --bg: #f6f5f1;
  --surface: #ffffff;
  --surface-2: #f0eee8;
  --border: #d9d5cc;
  --border-strong: #b5afa2;
  --text: #1c1b19;
  --muted: #5d5a53;
  --accent: #1f4e79;
  --accent-hover: #163a5c;
  --accent-soft: #e8eef5;
  --on-accent: #ffffff;
  --ok: #1d6b3a;       --ok-soft: #e7f2ea;
  --err: #a8261b;      --err-soft: #fbeae8;
  --warn: #875800;     --warn-soft: #fbf1dc;
  --focus: #f2b705;
  --radius: 6px;
  --font: -apple-system, BlinkMacSystemFont, "PingFang TC", "Noto Sans TC", "Microsoft JhengHei", "Segoe UI", system-ui, sans-serif;
  --mono: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace;
  color-scheme: light;
}
html.dark {
  --bg: #151513;
  --surface: #1e1d1b;
  --surface-2: #272623;
  --border: #36342f;
  --border-strong: #4d4a43;
  --text: #ecebe7;
  --muted: #a6a299;
  --accent: #8db5df;
  --accent-hover: #abc9ea;
  --accent-soft: #1f2a36;
  --on-accent: #0f2236;
  --ok: #72cf91;       --ok-soft: #18291e;
  --err: #f28b81;      --err-soft: #341c1a;
  --warn: #e4b558;     --warn-soft: #2f2615;
  color-scheme: dark;
}

*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }
body {
  margin: 0; min-height: 100vh;
  background: var(--bg); color: var(--text);
  font-family: var(--font); font-size: 16px; line-height: 1.6;
  overflow-wrap: break-word;
}
img, svg, canvas { max-width: 100%; }
h1, h2, h3 { line-height: 1.3; margin: 0; letter-spacing: -0.01em; }
h1 { font-size: 1.6rem; font-weight: 700; }
h2 { font-size: 1.2rem; font-weight: 700; }
h3 { font-size: 1rem; font-weight: 700; }
p { margin: 0; }
a { color: var(--accent); text-underline-offset: 3px; }
a:hover { color: var(--accent-hover); }
code, .mono { font-family: var(--mono); font-size: 0.92em; }
:focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }
button, input, select, textarea { font: inherit; color: inherit; }
hr { border: 0; border-top: 1px solid var(--border); margin: 20px 0; }

/* ── 版面 ─────────────────────────────────────── */
.container { width: 100%; max-width: 720px; margin: 0 auto; padding: 0 16px; }
.container-wide { width: 100%; max-width: 1160px; margin: 0 auto; padding: 0 16px; }
main { padding: 28px 0 48px; }
.stack > :not(:first-child) { margin-top: 16px; }
.stack-sm > :not(:first-child) { margin-top: 8px; }
.stack-lg > :not(:first-child) { margin-top: 28px; }
.row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 12px; }
.row-between { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px 12px; }
.grid { display: grid; gap: 16px; grid-template-columns: minmax(0, 1fr); }
.grid-4 { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }  /* 數字卡片：手機上也兩欄 */
@media (min-width: 640px) {
  .grid-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .grid-4 { gap: 16px; }
}
@media (min-width: 960px) {
  .grid-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .grid-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
  .grid-main-side { grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); }
}
.ml-auto { margin-left: auto; }
.text-center { text-align: center; }
.w-full { width: 100%; }

/* ── 頁首 ─────────────────────────────────────── */
.topbar { background: var(--surface); border-bottom: 1px solid var(--border); border-top: 4px solid var(--accent); }
.topbar-inner { display: flex; align-items: center; gap: 12px; min-height: 60px; padding-top: 8px; padding-bottom: 8px; flex-wrap: wrap; }
.brand { display: flex; flex-direction: column; min-width: 0; margin-right: auto; text-decoration: none; color: var(--text); }
.brand-name { font-weight: 700; font-size: 1.05rem; }
.brand-sub { font-size: 0.8rem; color: var(--muted); }
.topbar-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }

/* ── 文字 ─────────────────────────────────────── */
.eyebrow { font-size: 0.8rem; font-weight: 600; color: var(--muted); letter-spacing: 0.02em; }
.lead { color: var(--muted); font-size: 0.98rem; }
.muted { color: var(--muted); }
.small { font-size: 0.875rem; }
.xsmall { font-size: 0.8rem; }
.strong { font-weight: 700; }

/* ── 卡片 ─────────────────────────────────────── */
.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 20px; }
@media (min-width: 640px) { .card { padding: 24px; } }
.card-flush { padding: 0; overflow: hidden; }
.card-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px 12px;
             padding: 14px 20px; border-bottom: 1px solid var(--border); }
.card-body { padding: 20px; }
.section-title { font-size: 1rem; font-weight: 700; }

/* ── 表單 ─────────────────────────────────────── */
.field { display: block; }
.field > label, .label { display: block; font-weight: 600; font-size: 0.92rem; margin-bottom: 6px; }
.hint { display: block; color: var(--muted); font-size: 0.85rem; margin-top: 4px; }
.input, textarea.input, select.input {
  display: block; width: 100%; min-height: 48px; padding: 10px 12px;
  font-size: 16px;  /* 小於 16px 時 iOS 會在聚焦時自動放大頁面 */
  background: var(--surface); color: var(--text);
  border: 1px solid var(--border-strong); border-radius: var(--radius);
}
.input:focus { outline: 3px solid var(--focus); outline-offset: 0; border-color: var(--text); }
.input::placeholder { color: var(--muted); opacity: 0.8; }
textarea.input { min-height: 120px; resize: vertical; }

/* ── 按鈕 ─────────────────────────────────────── */
.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 8px;
  min-height: 44px; padding: 10px 18px; border-radius: var(--radius);
  border: 1px solid var(--border-strong); background: var(--surface); color: var(--text);
  font-weight: 600; font-size: 0.95rem; line-height: 1.2; text-decoration: none; cursor: pointer;
  -webkit-tap-highlight-color: transparent;
}
.btn:hover { background: var(--surface-2); color: var(--text); }
.btn:disabled, .btn[aria-disabled="true"] { opacity: 0.5; cursor: not-allowed; }
.btn-primary { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }
.btn-primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); color: var(--on-accent); }
.btn-primary:disabled:hover { background: var(--accent); }
.btn-danger { color: var(--err); border-color: currentColor; background: var(--surface); }
.btn-danger:hover { background: var(--err-soft); color: var(--err); }
.btn-ok { background: var(--ok); border-color: var(--ok); color: var(--surface); }
.btn-ok:hover { opacity: 0.9; background: var(--ok); color: var(--surface); }
.btn-sm { min-height: 36px; padding: 6px 12px; font-size: 0.875rem; }
.btn-block { display: flex; width: 100%; }
.btn-link { background: none; border: 0; padding: 0; min-height: 0; color: var(--accent); text-decoration: underline; font-weight: 600; cursor: pointer; }
.theme-toggle { min-width: 44px; padding: 8px 10px; }
.theme-toggle .icon-sun { display: none; }
html.dark .theme-toggle .icon-sun { display: inline; }
html.dark .theme-toggle .icon-moon { display: none; }

/* ── 提示訊息 ─────────────────────────────────── */
.alert { border: 1px solid var(--border); border-left-width: 4px; border-radius: var(--radius);
         padding: 12px 14px; background: var(--surface); font-size: 0.95rem; }
.alert-title { font-weight: 700; margin-bottom: 2px; }
.alert-info { border-color: var(--accent); background: var(--accent-soft); }
.alert-ok   { border-color: var(--ok);     background: var(--ok-soft); }
.alert-err  { border-color: var(--err);    background: var(--err-soft); }
.alert-warn { border-color: var(--warn);   background: var(--warn-soft); }
.alert-ok .alert-title { color: var(--ok); }
.alert-err .alert-title { color: var(--err); }
.alert-warn .alert-title { color: var(--warn); }
.text-ok { color: var(--ok); } .text-err { color: var(--err); } .text-warn { color: var(--warn); } .text-accent { color: var(--accent); }

/* ── 標籤 ─────────────────────────────────────── */
.badge { display: inline-flex; align-items: center; gap: 6px; padding: 2px 10px; border-radius: 999px;
         font-size: 0.8rem; font-weight: 600; border: 1px solid var(--border-strong); color: var(--muted); background: var(--surface); white-space: nowrap; }
.badge::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
.badge-ok   { color: var(--ok);   border-color: currentColor; background: var(--ok-soft); }
.badge-err  { color: var(--err);  border-color: currentColor; background: var(--err-soft); }
.badge-warn { color: var(--warn); border-color: currentColor; background: var(--warn-soft); }
.badge-info { color: var(--accent); border-color: currentColor; background: var(--accent-soft); }

/* ── 數字統計 ─────────────────────────────────── */
.stat { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 14px 16px; min-width: 0; }
.stat-label { font-size: 0.85rem; color: var(--muted); }
.stat-value { font-size: 1.6rem; font-weight: 700; font-variant-numeric: tabular-nums; line-height: 1.25; overflow-wrap: anywhere; }

/* ── 表格 ─────────────────────────────────────── */
.table-wrap { width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; }
.table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
.table th, .table td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }
.table th { font-size: 0.8rem; font-weight: 700; color: var(--muted); background: var(--surface-2); white-space: nowrap; }
.table tbody tr:last-child td { border-bottom: 0; }
.table .num { text-align: right; font-variant-numeric: tabular-nums; }
.nowrap { white-space: nowrap; }
/* 欄位多的表格：手機上每一列改成一張小卡，欄名取自 td 的 data-label */
@media (max-width: 639px) {
  .table-stack thead { display: none; }
  .table-stack, .table-stack tbody, .table-stack tr, .table-stack td { display: block; width: 100%; }
  .table-stack tr { padding: 10px 16px; border-bottom: 1px solid var(--border); }
  .table-stack tbody tr:last-child { border-bottom: 0; }
  .table-stack td { display: flex; justify-content: space-between; align-items: center; gap: 12px;
                    padding: 5px 0; border: 0; text-align: right; }
  .table-stack td::before { content: attr(data-label); flex: none; color: var(--muted); font-size: 0.85rem; text-align: left; }
  .table-stack td[data-label=""]::before { content: none; }
  .table-stack .hide-sm { display: none; }
}

/* ── 雜湊值等長字串 ───────────────────────────── */
.hash { display: block; font-family: var(--mono); font-size: 0.85rem; line-height: 1.5;
        background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius);
        padding: 10px 12px; overflow-wrap: anywhere; word-break: break-all; color: var(--text); }
.hash-inline { font-family: var(--mono); font-size: 0.85em; overflow-wrap: anywhere; word-break: break-all; }

/* ── 得票長條 ─────────────────────────────────── */
.bar { height: 8px; background: var(--surface-2); border-radius: 999px; overflow: hidden; }
.bar > span { display: block; height: 100%; background: var(--accent); }

/* ── 候選人選項（投票頁） ───────────────────────── */
.choice {
  display: flex; align-items: center; gap: 14px; width: 100%; min-height: 60px; padding: 14px 16px;
  text-align: left; font-size: 1.05rem; font-weight: 600; cursor: pointer;
  background: var(--surface); color: var(--text);
  border: 1px solid var(--border-strong); border-radius: var(--radius);
  -webkit-tap-highlight-color: transparent;
}
.choice::before { content: ""; flex: none; width: 22px; height: 22px; border-radius: 50%;
                  border: 2px solid var(--border-strong); background: var(--surface); }
.choice:hover { border-color: var(--accent); }
.choice.is-selected { border: 2px solid var(--accent); padding: 13px 15px; background: var(--accent-soft); }
.choice.is-selected::before { border-color: var(--accent); background: var(--accent); box-shadow: inset 0 0 0 4px var(--surface); }
.choice-list > :not(:first-child) { margin-top: 10px; }

/* ── 步驟清單 ─────────────────────────────────── */
.steps { list-style: none; margin: 0; padding: 0; font-size: 0.9rem; }
.steps li { display: flex; gap: 10px; padding: 6px 0; border-bottom: 1px dashed var(--border); }
.steps li:last-child { border-bottom: 0; }
.steps .mark { flex: none; width: 1.2em; text-align: center; font-weight: 700; }
.step-ok .mark { color: var(--ok); } .step-err .mark { color: var(--err); } .step-run .mark { color: var(--accent); }
.step-err { color: var(--err); }
.numbered { margin: 0; padding-left: 1.4em; } .numbered li + li { margin-top: 6px; }

/* ── 定義清單（回執等） ─────────────────────────── */
.dl { margin: 0; }
.dl > div { padding: 12px 0; border-bottom: 1px solid var(--border); }
.dl > div:first-child { padding-top: 0; }
.dl > div:last-child { border-bottom: 0; padding-bottom: 0; }
.dl dt { font-size: 0.85rem; color: var(--muted); margin-bottom: 2px; }
.dl dd { margin: 0; font-weight: 600; overflow-wrap: anywhere; }

/* ── 頁尾 ─────────────────────────────────────── */
.footer { border-top: 1px solid var(--border); padding: 20px 0 32px; color: var(--muted); font-size: 0.85rem; }

/* ── 工具 ─────────────────────────────────────── */
.hidden { display: none !important; }
.is-disabled { opacity: 0.55; pointer-events: none; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); border: 0; }
.spin { display: inline-block; width: 16px; height: 16px; border: 2px solid currentColor; border-right-color: transparent;
        border-radius: 50%; animation: ui-spin 0.8s linear infinite; vertical-align: -3px; }
@keyframes ui-spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .spin { animation-duration: 2.4s; } }
details > summary { cursor: pointer; font-weight: 600; }
@media print {
  .no-print, .topbar-actions { display: none !important; }
  body { background: #fff; color: #000; }
  .card { border-color: #999; }
}
"""

# 深色模式：預設跟隨系統；使用者切換後記住選擇
THEME_SCRIPT = """<script>
(function () {
  var saved = null;
  try { saved = localStorage.getItem('theme'); } catch (e) {}
  if (saved === 'dark' || (saved === null && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    document.documentElement.classList.add('dark');
  }
})();
function toggleTheme() {
  var dark = document.documentElement.classList.toggle('dark');
  try { localStorage.setItem('theme', dark ? 'dark' : 'light'); } catch (e) {}
}
</script>"""

UI_HEAD = (
    '\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n'
    '  <meta name="color-scheme" content="light dark">\n'
    '  ' + THEME_SCRIPT + '\n'
    '  <style>' + UI_CSS + '</style>\n'
)

# 深色／淺色切換按鈕（放在頁首）
THEME_TOGGLE = (
    '<button type="button" class="btn btn-sm theme-toggle" onclick="toggleTheme()" aria-label="切換深色／淺色模式">'
    '<span class="icon-moon" aria-hidden="true">深色</span><span class="icon-sun" aria-hidden="true">淺色</span>'
    '</button>'
)
