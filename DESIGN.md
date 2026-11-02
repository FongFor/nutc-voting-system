---
name: NUTC 線上投票
description: 對外兩站（投票網站、公告板）的視覺：開票所的計票紙，一步一筆正字。
colors:
  ballot-paper: "#f6f5f1"
  navy-ink: "#13253b"
  navy-ink-deep: "#0a1626"
  surface-white: "#ffffff"
  surface-sunk: "#eceae3"
  border-hairline: "#d5d1c6"
  border-ink: "#8a8578"
  muted-ink: "#4c5866"
  accent-soft: "#e2e7ee"
  vermilion: "#c8361f"
  rule-line: "rgba(200, 54, 31, 0.32)"
  ok-green: "#1f6b45"
  ok-soft: "#e4f0e8"
  err-red: "#b3261e"
  err-soft: "#f8e6e3"
  warn-ochre: "#8a5a00"
  warn-soft: "#f7ecd6"
  link-blue: "#1d4f91"
  night-bg: "#0d1724"
  night-surface: "#14223a"
  night-surface-sunk: "#1b2c47"
  night-border-hairline: "#2a3d5c"
  night-border-ink: "#5f7290"
  night-muted: "#b2bccb"
  night-accent-soft: "#22385a"
  night-shell: "#091220"
  night-vermilion: "#ff7a5c"
  night-rule-line: "rgba(255, 122, 92, 0.30)"
  night-ok: "#76d39d"
  night-ok-soft: "#15301f"
  night-err: "#ff8e84"
  night-err-soft: "#3a1c1a"
  night-warn: "#f0bd5a"
  night-warn-soft: "#33270f"
  night-link: "#9cc3f5"
typography:
  verdict:
    fontFamily: "\"Ballot Heading\", -apple-system, BlinkMacSystemFont, \"PingFang TC\", \"Noto Sans TC\", \"Microsoft JhengHei\", \"Segoe UI\", system-ui, sans-serif"
    fontSize: "clamp(1.55rem, 1.3rem + 1.4vw, 2.1rem)"
    fontWeight: 900
    lineHeight: 1.2
  headline:
    fontFamily: "\"Ballot Heading\", -apple-system, BlinkMacSystemFont, \"PingFang TC\", \"Noto Sans TC\", \"Microsoft JhengHei\", \"Segoe UI\", system-ui, sans-serif"
    fontSize: "clamp(1.65rem, 1.4rem + 1vw, 2.1rem)"
    fontWeight: 900
    lineHeight: 1.3
    letterSpacing: "0"
  tally-numeral:
    fontFamily: "\"Ballot Heading\", -apple-system, BlinkMacSystemFont, \"PingFang TC\", \"Noto Sans TC\", \"Microsoft JhengHei\", \"Segoe UI\", system-ui, sans-serif"
    fontSize: "2.2rem"
    fontWeight: 900
    lineHeight: 1.1
    fontFeature: "\"tnum\" 1"
  title:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"PingFang TC\", \"Noto Sans TC\", \"Microsoft JhengHei\", \"Segoe UI\", system-ui, sans-serif"
    fontSize: "1.2rem"
    fontWeight: 800
    lineHeight: 1.3
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"PingFang TC\", \"Noto Sans TC\", \"Microsoft JhengHei\", \"Segoe UI\", system-ui, sans-serif"
    fontSize: "16px"
    fontWeight: 400
    lineHeight: 1.6
  label:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"PingFang TC\", \"Noto Sans TC\", \"Microsoft JhengHei\", \"Segoe UI\", system-ui, sans-serif"
    fontSize: "0.92rem"
    fontWeight: 600
    lineHeight: 1.6
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, \"Liberation Mono\", Menlo, monospace"
    fontSize: "0.85rem"
    fontWeight: 400
    lineHeight: 1.5
rounded:
  ink: "2px"
  mark: "1px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  base: "16px"
  card: "20px"
  card-wide: "24px"
  section: "28px"
  page-end: "48px"
components:
  topbar:
    backgroundColor: "{colors.navy-ink}"
    textColor: "{colors.ballot-paper}"
    height: "60px"
  topbar-night:
    backgroundColor: "{colors.night-shell}"
    textColor: "{colors.ballot-paper}"
  button-primary:
    backgroundColor: "{colors.navy-ink}"
    textColor: "{colors.ballot-paper}"
    rounded: "{rounded.ink}"
    padding: "10px 18px"
    height: "48px"
  button-primary-hover:
    backgroundColor: "{colors.navy-ink-deep}"
    textColor: "{colors.ballot-paper}"
  button-primary-night:
    backgroundColor: "{colors.ballot-paper}"
    textColor: "{colors.navy-ink}"
  button-secondary:
    backgroundColor: "{colors.surface-white}"
    textColor: "{colors.navy-ink}"
    rounded: "{rounded.ink}"
    padding: "10px 18px"
    height: "48px"
  button-secondary-hover:
    backgroundColor: "{colors.surface-sunk}"
    textColor: "{colors.navy-ink}"
  button-small:
    rounded: "{rounded.ink}"
    padding: "6px 12px"
    height: "40px"
  card:
    backgroundColor: "{colors.surface-white}"
    rounded: "{rounded.ink}"
    padding: "20px"
  input:
    backgroundColor: "{colors.surface-white}"
    textColor: "{colors.navy-ink}"
    rounded: "{rounded.ink}"
    padding: "10px 12px"
    height: "48px"
  badge:
    backgroundColor: "{colors.surface-white}"
    textColor: "{colors.muted-ink}"
    rounded: "{rounded.ink}"
    padding: "2px 10px"
  choice:
    backgroundColor: "{colors.surface-white}"
    textColor: "{colors.navy-ink}"
    rounded: "{rounded.ink}"
    padding: "14px 16px"
    height: "60px"
  choice-selected:
    backgroundColor: "{colors.accent-soft}"
    textColor: "{colors.navy-ink}"
  sheet-row:
    padding: "8px 10px"
    height: "56px"
  sheet-row-running:
    backgroundColor: "{colors.surface-white}"
  verdict-ok:
    backgroundColor: "{colors.ok-soft}"
    textColor: "{colors.ok-green}"
    rounded: "{rounded.ink}"
    padding: "20px"
  verdict-err:
    backgroundColor: "{colors.err-soft}"
    textColor: "{colors.err-red}"
    rounded: "{rounded.ink}"
    padding: "20px"
  verdict-zheng-box:
    backgroundColor: "{colors.surface-white}"
    textColor: "{colors.navy-ink}"
    size: "96px"
  vote-zheng-box:
    backgroundColor: "{colors.surface-white}"
    textColor: "{colors.navy-ink}"
    size: "64px"
  state-mark:
    size: "30px"
---

# Design System: NUTC 線上投票

## Overview

**Creative North Star: "開票所的計票紙"**

這套視覺借每個台灣選民都看過的開票所計票紙：暖白紙底、海軍藍墨水、朱紅列線，每完成一步就多畫一筆正字。選民不用讀說明，只要看正字畫到第幾筆，就知道自己完成到哪、票有沒有被收下、開票後有沒有被算進去。狀態全是手寫筆跡，不是圖示；版面是紙上的列，不是浮起的卡片堆。

範圍只有對外兩站：**投票網站（voter_client）與公告板（bb_server）**。這兩站載入 `shared/ui_style.py` 的基礎層，再疊上 `shared/ui_ballot.py` 的計票紙層（`BALLOT_HEAD`）。Admin 後台與各服務儀表板只用 `ui_style.py`，不屬於這個世界，也不要把計票紙的元件或配色帶過去。

密度適中、單手為先：內容欄寬 720px，按鈕最小高 48px，每一列計票紙最小高 56px。拒絕的方向（使用者確認）：白底藍按鈕、盾牌與打勾圖示的「公民科技」頁面，以及深色霓虹的加密貨幣風。

**Key Characteristics:**
- 暖白紙底 `ballot-paper` 與海軍藍墨水 `navy-ink` 是使用者指定色，兩站必用。
- 朱紅是筆，不是底色：正字最後一筆、計票紙列線、頂欄下緣、焦點框、「您的票」標記。
- 1.5px 墨線框、2px 極小圓角、字重 900 的標題。
- 正字逐筆：一步一筆，五步成一個「正」。
- 狀態用筆跡記號：空格、一筆、紅叉、斜線。
- 不載入任何外部資源，標題字型自帶。

## Colors

紙、墨、朱三色為主，綠、紅、黃褐只負責狀態；深色主題把紙與墨對調成「深海軍藍夜色底、暖白筆跡、亮朱紅」。

### Primary
- **海軍藍墨水 Navy Ink**（`navy-ink`）：淺色主題的文字、頂欄底、主要按鈕、正字筆畫、選中候選人的方格、計票紙頂端的 2px 粗線、Merkle 樹根。深色主題下墨水換成暖白 `ballot-paper`，海軍藍改當主要按鈕上的字。
- **深墨 Navy Ink Deep**（`navy-ink-deep`）：主要按鈕 hover。深色主題 hover 為純白 `surface-white`。

### Secondary
- **朱紅 Vermilion**（`vermilion`，深色 `night-vermilion`）：正字第五筆（`s5`）、頂欄下緣 3px 列線、鍵盤焦點框、樹狀圖與逐層說明中「您的票」那一格的外框、說明段落重點字的底線。
- **朱紅列線 Rule Line**（`rule-line`，深色 `night-rule-line`）：計票紙每一列下緣的 1px 線、流程步驟之間的連接線、區塊內的次分隔線。它是版面結構，每一列都落在一條線上。

### Tertiary（狀態）
- **墨綠 Ok Green**（`ok-green` / `ok-soft`；深色 `night-ok` / `night-ok-soft`）：「已被計入」的結論框、通過提示、樹狀圖的兄弟節點。
- **錯誤紅 Err Red**（`err-red` / `err-soft`；深色 `night-err` / `night-err-soft`）：失敗紅叉、錯誤結論、欄位錯誤訊息。比朱紅更深一階，與朱紅分開管理。
- **黃褐 Warn Ochre**（`warn-ochre` / `warn-soft`；深色 `night-warn` / `night-warn-soft`）：尚未開票、需要注意的結論。

### Neutral
- **暖白紙 Ballot Paper**（`ballot-paper`）：淺色頁面底色、頂欄與主要按鈕上的字；深色主題的文字與墨水色。
- **白紙面 Surface White**（`surface-white`）／**深色紙面**（`night-surface`）：卡片、輸入框、正字方框、正在進行的那一列。
- **凹紙面 Surface Sunk**（`surface-sunk` / `night-surface-sunk`）：次要按鈕 hover、雜湊值底。
- **淡線 Border Hairline**（`border-hairline` / `night-border-hairline`）：未畫的正字筆畫（佔位、ghost）、一般分隔線、未選中的樹狀圖連線。
- **墨線 Border Ink**（`border-ink` / `night-border-ink`）：卡片、輸入框、候選人選項的 1.5px 框，斜線「略過」記號，待檢查虛線框。
- **淡墨 Muted Ink**（`muted-ink` / `night-muted`）：導言、說明、計票紙列號、待執行列的文字。
- **淡藍底 Accent Soft**（`accent-soft` / `night-accent-soft`）：選中候選人的底、Merkle 路徑節點底。
- **連結藍 Link Blue**（`link-blue` / `night-link`）：文字連結與「技術細節」展開鈕；hover 變回墨水色。
- **夜色底 Night**（`night-bg`、`night-shell`）：深色主題的頁面底與頂欄底。

### Named Rules
**The Pinned Pair Rule.** `#13253b` 與 `#f6f5f1` 是使用者指定色，兩站在兩種主題中都必須出現（淺色：墨與紙；深色：頂欄字與筆跡）。不得替換成相近色。

**The Vermilion Is a Pen Rule.** 朱紅只畫線：筆畫、列線、外框、底線、焦點框。不拿來填大面積底色，也不拿來當按鈕底色。

**The Status Has Its Own Inks Rule.** 通過、錯誤、警示各用自己的 `ok`、`err`、`warn` 色組；錯誤紅與朱紅是兩個 token，不要互相替代。

## Typography

**Display Font:** Ballot Heading（自帶的 Noto Sans TC 900 子集，退回系統繁中字型）
**Body Font:** 系統繁中字型堆疊（PingFang TC、Noto Sans TC、Microsoft JhengHei…）
**Label/Mono Font:** 系統等寬字型，用於學號、OTP、雜湊值

**Character:** 粗黑到像麥克筆寫在計票紙上的標題，配上安靜的系統內文；粗細對比負責層級，不靠字級拉大。

### Hierarchy
- **Verdict**（900，`clamp(1.55rem, 1.3rem + 1.4vw, 2.1rem)`，1.2）：驗證結論「您的票已被計入」，顏色跟著結論語氣（綠／紅／黃褐）。
- **Headline**（900，`clamp(1.65rem, 1.4rem + 1vw, 2.1rem)`，1.3，字距 0）：每頁唯一的 h1，以及頂欄的「NUTC 線上投票」品名（900，字距 0.02em）。
- **Tally Numeral**（900，2.2rem，1.1，等寬數字）：開票結果的得票數。「第 4 張」這類行內數字用 900、1.6rem。
- **Title**（800，1.2rem，1.3）：h2、區塊標題、候選人名（1.05rem），用系統字型。
- **Body**（400，16px，1.6）：內文；說明段落限 62–65ch。
- **Label**（600，0.92rem）：欄位名稱；提示與次要資訊 0.85–0.875rem。
- **Mono**（0.85rem，1.5）：雜湊值、選票識別碼，可任意斷行。

### Named Rules
**The Subset Glyph Rule.** `ballot-heading-900.woff2` 只含兩站目前標題用到的字（約 19 KB）。只有 h1、品名、結論標題、得票數、投票進度標題使用 `--heading`。新增或改寫這些位置的文字時，必須用 fontTools 從 NotoSansTC-VF 重新產生子集（instancer wght=900 + subset，見 `shared/static/ballot-heading-900.LICENSE.txt`）；否則缺字會退回系統字型，同一行出現兩種字形。h2 以下不用標題字型。

**The No External Font Rule.** 字型一律由各站自己的 `/assets/` 路徑提供，不向任何字型服務請求。

## Layout

單欄紙張。內容欄 `max-width: 720px`、左右 16px；公告板的樹狀圖在 900px 以上放寬到 `min(1120px, 100vw - 32px)`。主區上 28px、下 48px。區塊間距 28px（`stack-lg`），區塊內 16px，緊密群組 8px。卡片內距 20px，640px 以上 24px。

計票紙是格線：每列三欄（列號 2em／內容／記號），最小高 56px、內距 8px 10px，列與列之間只有一條朱紅列線。開票結果每列兩欄（候選人＋正字／得票數），最小高 64px。斷點：640px（卡片內距、兩欄格）、860px（匿名說明的三步流程由直排轉橫排）、900px（樹狀圖放寬）。手機上主要動作要落在第一屏內。

## Elevation & Depth

紙是平的。深度靠墨線粗細與底色層次（紙底 → 白紙面 → 凹紙面）表達，卡片不帶陰影。唯一的陰影屬於狀態：計票紙上「正在執行」的那一列浮起，提醒視線停在這裡；完成後回到紙面。

### Shadow Vocabulary
- **進行列浮起**（`box-shadow: 0 6px 16px rgba(19, 37, 59, 0.14)`）：只給 `data-state="run"` 的計票紙列（投票進度、公告板五列檢查），同時底色換成白紙面。

### Named Rules
**The Flat Paper Rule.** 靜止時一切平貼紙面；陰影只表示「這一列正在進行」，同一時間最多一列。

## Shapes

方正、薄墨線。圓角統一 2px（`rounded.ink`），標籤前的小方塊 1px。框線用 1.5px 墨線（`--ink-line`）；強調框（選中選項、正字方框、計票紙頂線）用 2px 墨水色；頂欄下緣 3px 朱紅。圓形只出現在讀取中的轉圈；選票方格、標籤點、流程步驟點都是方的。提示框整圈 1.5px，不用粗左邊框。

## Components

### Buttons
紮實的墨水按鈕，像蓋章。
- **Shape:** 2px 圓角，1.5px 墨水色框，字重 700，最小高 48px（小按鈕 40px）。
- **Primary:** 海軍藍底、暖白字；深色主題反轉為暖白底、海軍藍字。
- **Hover / Focus:** 主要按鈕加深為 `navy-ink-deep`；次要按鈕底變 `surface-sunk`。焦點為 3px 朱紅外框、外距 2px；隱藏檔案輸入的焦點轉畫在對應的 label 按鈕上。
- **Secondary:** 白紙面、墨水色字與框。頂欄內的按鈕為透明底、暖白字、55% 暖白框，hover 加 12% 暖白底。切換按鈕（樹狀圖檢視）按下時反轉為墨底紙字。

### Chips（標籤）
- **Style:** 方角 2px、1.5px 框、0.8rem 600；前綴 6px 小方塊取代圓點。
- **State:** `ok`／`err`／`warn`／`info` 用各自的色與淡底；頂欄內為透明底暖白框。

### Cards / Containers
- **Corner Style:** 2px。
- **Background:** 白紙面（深色 `night-surface`）。
- **Shadow Strategy:** 無，見 Elevation & Depth。
- **Border:** 1.5px `border-ink`。
- **Internal Padding:** 20px，640px 以上 24px。可收合的卡片以 summary 右側文字「展開／收合」（連結藍）表示，不用三角形以外的圖示。

### Inputs / Fields
- **Style:** 白紙面、1.5px `border-ink`、2px 圓角、最小高 48px、字級 16px（避免 iOS 放大）。學號與 OTP 用等寬字。
- **Focus:** 框變墨水色，外加 3px 朱紅外框。
- **Error:** 欄位下方 `err` 色粗體訊息，前置內嵌 SVG 警示圖示。

### Navigation（頂欄）
海軍藍頂欄（深色 `night-shell`），下緣 3px 朱紅列線，最小高 60px。左側品名（Ballot Heading 900）＋副標（78% 暖白）；右側為返回連結按鈕與深淺色切換（文字「深色／淺色」，不用日月圖示）。

### 選票方格（候選人選項）
選票上的方格。最小高 60px、1.5px 墨線框；左側 22px 方格（2px 圓角、2px 墨框）。hover 框變墨水色；選中時 2px 墨框、`accent-soft` 底，方格填墨並留 4px 紙色內邊。

### 計票紙（Sheet）
有序列表，頂端 2px 墨水粗線，每列下緣一條朱紅列線；列號用國字「一、二、三…」（0.85rem 700 淡墨）。列狀態用 `data-state`：`wait` 文字淡墨、`run` 浮起、`ok` 畫筆、`fail` 文字轉紅、`skip` 淡墨。

### 正字（Signature）
五筆 SVG（viewBox 100×100，筆寬 10，圓頭）：一、豎、短橫、左短豎、底橫。前四筆墨水色，第五筆朱紅；未畫的筆以 `border-hairline` 佔位（在開票結果的正字串裡直接隱藏）。
- **計票：** 每 5 票一個正字，最多畫 12 個，超過的以「＋N」淡墨小字補述，旁邊一定附上阿拉伯數字。正字串是 `aria-hidden`，數字才是可讀內容。
- **進度：** 投票網站 64px 方框、公告板結論 96px 方框（白紙面、2px 墨框），完成幾步就畫幾筆。
- **一步一筆：** 計票紙每列完成時，右側的小格（28px，筆寬 11）只畫出這一列對應的那一筆，其餘四筆以 6px 淡線提示位置；五列的記號合起來就是一個正字。伺服器端用 `zheng_svg()`／`tally_marks()`，瀏覽器端用 `zhengSvg()`／`zhengStrokeSvg()`。

### 筆跡記號（State Marks）
30px 格、26px SVG、筆寬 3.5、圓頭：
- **通過：** 一筆微斜的橫線，墨水色（在計票紙檢查列中由該列的正字一筆取代）。
- **失敗：** 紅叉，`err` 色。
- **略過：** 一條斜線，`border-ink`。
- **未檢查：** 22px 空格，1.5px `border-ink` 虛線框。

### 結論框（Verdict）
1.5px 結論色框、結論色淡底、2px 圓角、內距 20／24px。左側 96px 正字方框，右側 Verdict 標題與「第 N 張，共 M 張」；下方為計票紙檢查列與主要動作。

### 動態
- 正字逐筆畫出：每筆 `260ms cubic-bezier(0.16, 1, 0.3, 1)`，以 stroke-dashoffset 從 100 畫到 0。只在 `prefers-reduced-motion: no-preference` 時播放，否則直接顯示完成的筆畫。
- 計票紙列的底色與浮起：`180ms ease`。
- 捲動到結論或樹狀圖：一般為 smooth，偏好減少動態時為瞬間跳轉。

## Do's and Don'ts

### Do:
- **Do** 讓兩站在兩種主題都出現 `#13253b` 與 `#f6f5f1`（The Pinned Pair Rule）。
- **Do** 用正字表示進度與票數：一步一筆、5 票一字，旁邊附上數字。
- **Do** 狀態用筆跡記號（空格、一筆、紅叉、斜線），並以文字或 `aria-label` 說出狀態。
- **Do** 讓計票紙每一列對齊一條朱紅列線（`rule-line`）；列線就是分隔線。
- **Do** 框線用 1.5px 墨線、圓角 2px、主要動作最小高 48px。
- **Do** 焦點一律 3px 朱紅外框（`--focus`），淺深兩色都清楚可見。
- **Do** 新增標題文字時重新產生 Ballot Heading 子集（The Subset Glyph Rule）。
- **Do** 所有動態都有 `prefers-reduced-motion` 對應。
- **Do** 字型、圖示、腳本全部自帶；圖示一律內嵌 SVG。

### Don't:
- **Don't** 載入任何外部字型、CDN、腳本或圖片；選民投票時第三方不該收到連線。
- **Don't** 把計票紙層（`BALLOT_HEAD`、正字、筆跡記號、海軍藍頂欄）用到 Admin 或各服務儀表板。
- **Don't** 用盾牌、勾勾徽章或白底藍按鈕的「公民科技」樣式，也不要深色霓虹的加密貨幣風。
- **Don't** 用朱紅填大面積底色或當按鈕底色（The Vermilion Is a Pen Rule）。
- **Don't** 給卡片加陰影；陰影只屬於正在進行的那一列（The Flat Paper Rule）。
- **Don't** 用粗左邊框的提示框、圓點標籤或圓形選票方格。
- **Don't** 在標題位置使用子集外的字而不重新產生字型。
