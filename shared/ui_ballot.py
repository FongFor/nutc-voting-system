"""
shared/ui_ballot.py  —  對外兩站（投票網站、公告板）的視覺：計票紙

疊在 shared/ui_style.py 的 UI_CSS 之上：沿用同一套 class（card、btn、alert、
badge、steps…），只換掉色彩、線條與字重，再加上計票紙專用的元件。Admin 與
各服務儀表板不在範圍內，繼續只用 ui_style。

  - 底色暖白 #f6f5f1、海軍藍 #13253b 是指定色：海軍藍當墨水（字、頂欄、主要
    按鈕、正字筆畫）。
  - 朱紅只用在正字的最後一筆、計票紙的列線與錯誤。
  - 正字：一步一筆。zheng_svg() 給伺服器端樣板用，ZHENG_JS 給瀏覽器端用。
  - 不載入任何外部字型或資源（隱私：第三方不該在選民投票時收到連線）。
"""

import os

from shared.ui_style import UI_HEAD, THEME_TOGGLE  # noqa: F401  THEME_TOGGLE 給呼叫端一起匯入

# 標題字型：Noto Sans TC 固定字重 900、只含標題用到的字（約 19 KB），由各站自己提供，
# 不向外部字型服務請求。產生方式與授權見 shared/static/ballot-heading-900.LICENSE.txt。
_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
HEADING_FONT_PATH = "/assets/ballot-heading-900.woff2"


def register_ballot_assets(app):
    """在 Flask app 上掛出計票紙用的靜態檔（標題字型）。"""
    from flask import send_from_directory

    @app.route(HEADING_FONT_PATH)
    def _ballot_heading_font():
        resp = send_from_directory(_STATIC_DIR, "ballot-heading-900.woff2", mimetype="font/woff2", max_age=86400 * 30)
        return resp

BALLOT_CSS = """
@font-face {
  font-family: "Ballot Heading";
  src: url("/assets/ballot-heading-900.woff2") format("woff2");  /* 與 HEADING_FONT_PATH 相同 */
  font-weight: 900; font-style: normal; font-display: swap;
}
:root {
  --bg: #f6f5f1;
  --surface: #ffffff;
  --surface-2: #eceae3;
  --border: #d5d1c6;
  --border-strong: #8a8578;
  --text: #13253b;
  --muted: #4c5866;
  --accent: #13253b;
  --accent-hover: #0a1626;
  --accent-soft: #e2e7ee;
  --on-accent: #f6f5f1;
  --ok: #1f6b45;       --ok-soft: #e4f0e8;
  --err: #b3261e;      --err-soft: #f8e6e3;
  --warn: #8a5a00;     --warn-soft: #f7ecd6;
  --vermilion: #c8361f;
  --rule: rgba(200, 54, 31, 0.32);
  --shell: #13253b;
  --on-shell: #f6f5f1;
  --link: #1d4f91;
  --radius: 2px;
  --ink-line: 1.5px;
  --focus: #c8361f;
  --heading: "Ballot Heading", var(--font);
}
html.dark {
  --bg: #0d1724;
  --surface: #14223a;
  --surface-2: #1b2c47;
  --border: #2a3d5c;
  --border-strong: #5f7290;
  --text: #f6f5f1;
  --muted: #b2bccb;
  --accent: #f6f5f1;
  --accent-hover: #ffffff;
  --accent-soft: #22385a;
  --on-accent: #13253b;
  --ok: #76d39d;       --ok-soft: #15301f;
  --err: #ff8e84;      --err-soft: #3a1c1a;
  --warn: #f0bd5a;     --warn-soft: #33270f;
  --vermilion: #ff7a5c;
  --rule: rgba(255, 122, 92, 0.30);
  --shell: #091220;
  --on-shell: #f6f5f1;
  --link: #9cc3f5;
  --focus: #ff7a5c;
}

::selection { background: var(--text); color: var(--bg); }
html { scrollbar-color: var(--border-strong) var(--bg); }
h1, .brand-name { font-family: var(--heading); }
body { font-feature-settings: "tnum" 0; }
a { color: var(--link); }
a:hover { color: var(--text); }
h1 { font-size: clamp(1.65rem, 1.4rem + 1vw, 2.1rem); font-weight: 900; letter-spacing: 0; }
h2 { font-weight: 800; }
.section-title { font-weight: 800; }
.lead { color: var(--muted); }

/* 頁首：海軍藍頂欄，下緣一條朱紅列線 */
.topbar { background: var(--shell); color: var(--on-shell); border-top: 0; border-bottom: 3px solid var(--vermilion); }
.brand, .brand:hover { color: var(--on-shell); }
.brand-name { font-weight: 900; letter-spacing: 0.02em; }
.brand-sub { color: rgba(246, 245, 241, 0.78); }
.topbar .btn { background: transparent; color: var(--on-shell); border-color: rgba(246, 245, 241, 0.55); }
.topbar .btn:hover { background: rgba(246, 245, 241, 0.12); color: var(--on-shell); }
.topbar .badge { background: transparent; color: var(--on-shell); border-color: rgba(246, 245, 241, 0.55); }

/* 卡片與表單：極小圓角、墨線 */
.card { border: var(--ink-line) solid var(--border-strong); }
.input { border: var(--ink-line) solid var(--border-strong); }
.input:focus { border-color: var(--text); }

.btn { border: var(--ink-line) solid var(--text); font-weight: 700; min-height: 48px; }
.btn-sm { min-height: 40px; }
.btn:hover { background: var(--surface-2); }
.btn-primary { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }
.btn-primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); color: var(--on-accent); }

/* 提示：整圈 1.5px 墨線，不用粗左邊框 */
.alert { border-width: var(--ink-line); border-left-width: var(--ink-line); }

/* 標籤：方角，點改成小方塊 */
.badge { border-radius: var(--radius); border-width: var(--ink-line); }
.badge::before { border-radius: 1px; width: 6px; height: 6px; }

/* 候選人：選票上的方格 */
.choice { border: var(--ink-line) solid var(--border-strong); }
.choice::before { border-radius: 2px; border: 2px solid var(--text); }
.choice:hover { border-color: var(--text); }
.choice.is-selected { border: 2px solid var(--text); background: var(--accent-soft); }
.choice.is-selected::before { background: var(--text); border-color: var(--text); box-shadow: inset 0 0 0 4px var(--surface); }

/* 計票紙：每一列落在一條朱紅列線上（列線是結構，不是底紋） */
.sheet { list-style: none; margin: 0; padding: 0; border-top: 2px solid var(--text); }
.sheet > li { display: grid; grid-template-columns: 2em minmax(0, 1fr) auto; align-items: center; gap: 4px 10px;
  min-height: 56px; padding: 8px 10px; border-bottom: 1px solid var(--rule); }
.sheet .no { font-size: 0.85rem; color: var(--muted); font-weight: 700; }

/* 正字：海軍藍筆畫、最後一筆朱紅；.draw 時逐筆畫出 */
.zheng { display: inline-block; flex: none; vertical-align: middle; }
.zheng path { fill: none; stroke: currentColor; stroke-width: 10; stroke-linecap: round; }
.zheng path.s5 { stroke: var(--vermilion); }
.zheng path.off { stroke: var(--border); }
.tally .zheng path.off { display: none; }
@media (prefers-reduced-motion: no-preference) {
  .zheng.draw path:not(.off) { stroke-dasharray: 100; stroke-dashoffset: 100; animation: zheng-stroke 260ms cubic-bezier(0.16, 1, 0.3, 1) forwards; }
  @keyframes zheng-stroke { to { stroke-dashoffset: 0; } }
}

.tally { display: inline-flex; flex-wrap: wrap; align-items: center; gap: 2px 3px; color: var(--text); }
.tally-more { font-size: 0.8rem; font-weight: 700; color: var(--muted); margin-left: 4px; }

/* 筆跡記號（狀態）：一筆＝通過、紅叉＝失敗、斜線＝略過、空格＝未檢查 */
.mark-box { width: 30px; height: 30px; display: inline-grid; place-items: center; }
.mark-box svg { width: 26px; height: 26px; }
.mark-box path { fill: none; stroke-linecap: round; stroke-width: 3.5; }
.mark-ok path { stroke: var(--text); }
.mark-fail path { stroke: var(--err); }
.mark-skip path { stroke: var(--border-strong); }
.mark-wait { border: var(--ink-line) dashed var(--border-strong); width: 22px; height: 22px; }
.mark-stroke svg { width: 28px; height: 28px; }
.mark-stroke .zheng path { stroke-width: 11; }
.mark-stroke .zheng path.ghost { stroke: var(--border); stroke-width: 6; }
"""

BALLOT_HEAD = UI_HEAD + '  <style>' + BALLOT_CSS + '</style>\n'

# 正字五筆（viewBox 0 0 100 100）：一、豎、短橫、左短豎、底橫
ZHENG_PATHS = (
    "M18 18 L82 17",
    "M50 18 L50 84",
    "M50 50 L78 50",
    "M25 50 L25 84",
    "M12 85 L88 84",
)


def zheng_svg(strokes: int = 5, size: int = 22, label: str = "") -> str:
    """伺服器端畫一個正字，畫出前 strokes 筆，其餘以淡色佔位。"""
    parts = []
    for i, d in enumerate(ZHENG_PATHS):
        cls = f"s{i + 1}" + ("" if i < strokes else " off")
        parts.append(f'<path class="{cls}" pathLength="100" d="{d}"/>')
    aria = f'role="img" aria-label="{label}"' if label else 'aria-hidden="true"'
    return (f'<svg class="zheng" width="{size}" height="{size}" viewBox="0 0 100 100" {aria} focusable="false">'
            + "".join(parts) + "</svg>")


def tally_marks(count: int, max_groups: int = 12, size: int = 40) -> str:
    """票數畫成正字：每 5 票一個正字。票數多時只畫 max_groups 個，其餘由旁邊的數字說明。"""
    full, rest = divmod(max(int(count), 0), 5)
    shown = min(full, max_groups)
    out = [zheng_svg(5, size) for _ in range(shown)]
    if rest and full <= max_groups:
        out.append(zheng_svg(rest, size))
    more = full - shown
    tail = f'<span class="tally-more">＋{more * 5}</span>' if more > 0 else ""
    return '<span class="tally" aria-hidden="true">' + "".join(out) + tail + "</span>"


# 瀏覽器端的正字：zhengSvg(筆數, 尺寸, 是否逐筆畫出)
ZHENG_JS = """
const ZHENG_PATHS = """ + repr(list(ZHENG_PATHS)).replace("'", '"') + """;
function zhengSvg(strokes, size, draw) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('class', 'zheng' + (draw ? ' draw' : ''));
  svg.setAttribute('viewBox', '0 0 100 100');
  svg.setAttribute('width', size); svg.setAttribute('height', size);
  svg.setAttribute('aria-hidden', 'true');
  ZHENG_PATHS.forEach((d, i) => {
    const p = document.createElementNS(ns, 'path');
    p.setAttribute('d', d);
    p.setAttribute('pathLength', '100');
    p.setAttribute('class', 's' + (i + 1) + (i < strokes ? '' : ' off'));
    svg.appendChild(p);
  });
  return svg;
}
// 第 i 筆（0–4）單獨畫在一個小格裡，位置與正字相同：五列的記號合起來就是一個正字
function zhengStrokeSvg(i, draw) {
  const ns = 'http://www.w3.org/2000/svg';
  const box = document.createElement('span');
  box.className = 'mark-box mark-stroke';
  box.setAttribute('aria-hidden', 'true');
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('class', 'zheng' + (draw ? ' draw' : ''));
  svg.setAttribute('viewBox', '0 0 100 100');
  ZHENG_PATHS.forEach((d, j) => {
    const p = document.createElementNS(ns, 'path');
    p.setAttribute('d', d);
    p.setAttribute('pathLength', '100');
    p.setAttribute('class', 's' + (j + 1) + (j === i ? '' : ' ghost'));
    svg.appendChild(p);
  });
  box.appendChild(svg);
  return box;
}
"""

# 狀態筆跡記號
MARK_OK   = '<span class="mark-box mark-ok" aria-hidden="true"><svg viewBox="0 0 26 26"><path d="M3 14 L23 12"/></svg></span>'
MARK_FAIL = '<span class="mark-box mark-fail" aria-hidden="true"><svg viewBox="0 0 26 26"><path d="M5 5 L21 21 M21 5 L5 21"/></svg></span>'
MARK_SKIP = '<span class="mark-box mark-skip" aria-hidden="true"><svg viewBox="0 0 26 26"><path d="M4 22 L22 4"/></svg></span>'
MARK_WAIT = '<span class="mark-box" aria-hidden="true"><span class="mark-wait"></span></span>'
