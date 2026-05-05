# NUTC Voting System — 系統架構技術規範書 v2.0

> 隱私保護式電子投票系統 · 完整協定規範與實作指引

---

## 文件資訊

| 欄位 | 內容 |
| --- | --- |
| 文件名稱 | NUTC Voting System 系統架構技術規範書 |
| 版本 | v2.0 |
| 適用對象 | 系統設計者、實作者、評審委員、AI 助手 |
| 文件目的 | 作為系統實作、稽核、防禦設計與資安攻擊測試之唯一權威來源（Single Source of Truth） |
| 撰寫風格 | 同時兼顧人類可讀性與 AI 可讀性：每章節含「概述」「形式化定義」「實作對照」三層 |

## 修訂歷史

| 版本 | 變更摘要 |
| --- | --- |
| v1.0 | 初版，定義 6 階段流程：系統初始化、身分驗證、盲簽章選票、時間解密、計票與 Merkle Tree 建構、使用者驗證 |
| v2.0 | **重大修訂**：新增威脅模型章節；新增 Phase 0「選民註冊階段」；新增「投票授權票（Voting Token）」機制；新增「CC 結果簽章 → BB 驗章」流程；統一密碼學原語規範（RSA-OAEP / RSA-PSS / RSA-FDH-Blind / AES-256-GCM）；強化 Merkle Tree 防止二次原像攻擊；強化匿名性（提交順序洗牌）；新增 SN 去重；新增完整 API 與 Schema 規格；新增安全性論證；新增攻擊驗證計畫 |

## 文件閱讀指引

- **Reviewer / 老師**：建議閱讀「第一部分：總論」+「第六部分：安全性分析」即可掌握全貌。
- **實作者**：應從「第三部分：密碼學基礎」開始，逐章對應「第五部分：介面規格」。
- **資安攻擊測試者**：直接閱讀「第 25 章：攻擊驗證計畫」。
- **AI 助手**：所有形式化定義、欄位、API 與資料庫 schema 皆有結構化標記，可直接作為 code generation 之依據。

---

## 目錄

**第一部分：總論**
1. [系統概述](#1-系統概述)
2. [設計目標與原則](#2-設計目標與原則)
3. [威脅模型（Threat Model）](#3-威脅模型threat-model)
4. [安全目標](#4-安全目標)

**第二部分：系統架構**

5. [角色定義與信任模型](#5-角色定義與信任模型)
6. [系統架構與資料流](#6-系統架構與資料流)
7. [服務通訊矩陣](#7-服務通訊矩陣)

**第三部分：密碼學基礎**

8. [符號定義表](#8-符號定義表)
9. [密碼學原語選用](#9-密碼學原語選用)
10. [金鑰規格與生命週期](#10-金鑰規格與生命週期)

**第四部分：協定流程（七階段）**

11. [Phase 0：選民註冊階段](#phase-0選民註冊階段)
12. [Phase 1：系統初始化與金鑰生成階段](#phase-1系統初始化與金鑰生成階段)
13. [Phase 2：身分驗證階段](#phase-2身分驗證階段)
14. [Phase 3：盲簽章選票階段](#phase-3盲簽章選票階段)
15. [Phase 4：時間解密階段](#phase-4時間解密階段)
16. [Phase 5：計票與 Merkle Tree 建構階段](#phase-5計票與-merkle-tree-建構階段)
17. [Phase 6：使用者驗證階段](#phase-6使用者驗證階段)

**第五部分：介面規格**

18. [RESTful API 規格](#18-restful-api-規格)
19. [資料模型（Database Schema）](#19-資料模型database-schema)
20. [訊息封包格式（JSON Schema）](#20-訊息封包格式json-schema)

**第六部分：安全性分析**

21. [安全性論證](#21-安全性論證)
22. [已知限制與未來工作](#22-已知限制與未來工作)

**第七部分：實作與部署**

23. [容器化部署架構](#23-容器化部署架構)
24. [設定檔規範](#24-設定檔規範)
25. [攻擊驗證計畫](#25-攻擊驗證計畫)

**附錄**

- [附錄 A：完整訊息流程圖](#附錄-a完整訊息流程圖)
- [附錄 B：錯誤代碼表](#附錄-b錯誤代碼表)
- [附錄 C：v1.0 → v2.0 變更對照](#附錄-cv10--v20-變更對照)
- [附錄 D：名詞與縮寫對照表](#附錄-d名詞與縮寫對照表)

---

# 第一部分：總論

## 1. 系統概述

### 1.1 系統定位

本系統為一具備**隱私保護**、**可驗證性**、**抗單點作惡**之分散式電子投票系統。透過密碼學原語（盲簽章、數位信封、時間解鎖加密、Merkle Tree）與多角色職責分離設計，使系統能在不揭露選民投票內容的前提下，提供：

- **匿名性（Anonymity）**：第三方機構無法得知任一選民的投票內容。
- **完整性（Integrity）**：選票一經提交不可被竄改。
- **可驗證性（Verifiability）**：每位選民可獨立驗證自己的選票確實被正確計入。
- **時序強制（Time-locked Tallying）**：投票截止前任何人均無法解讀選票內容。

### 1.2 與 v1.0 的本質差異

v1.0 將「角色拆分為 Docker 容器」視為系統重點；v2.0 認知到**容器拆分僅是部署層的隔離**，真正的安全來自於**協定層的密碼學保證**與**威脅模型驅動的端點存取控制**。v2.0 因此補強：

1. 新增 **Phase 0 選民註冊**：建立合法選民白名單，CA 不再為任意 entity_id 簽發憑證。
2. 新增 **Voting Token 授權票**：將 Phase 2 認證與 Phase 3 盲簽章嚴格綁定，防止「認證一次、無限取簽」的一人多票攻擊。
3. 新增 **CC 對開票結果之數位簽章**：BB 不再無條件接受 publish 請求，須驗證來源為合法 CC。
4. 新增 **TA 對 CC 之請求方驗證**：SK_TA 不再公開可取，必須由具備 Cert_CC 的請求方索取。
5. 升級密碼學原語：盲簽章採 RSA-FDH-Blind、對稱加密採 AES-256-GCM（AEAD）、Merkle Tree 採 domain-separated hashing。
6. 新增 **CC 端 SN 去重表**與**選票順序洗牌**：徹底斷絕「提交順序 → 投票人」的關聯。

---

## 2. 設計目標與原則

### 2.1 功能性目標

| 編號 | 目標 | 說明 |
| --- | --- | --- |
| F-1 | 一人一票 | 每位合法選民僅能投出一張有效選票 |
| F-2 | 開放透明開票 | 開票結果應可由任何人複驗 |
| F-3 | 截止強制 | 投票截止後拒絕新選票 |
| F-4 | 個別可驗證 | 選民可確認自己的票被計入 |
| F-5 | 全域可驗證 | 任何人可驗證 (合法選票集合 → Merkle Root → 計票結果) 之一致性 |

### 2.2 非功能性目標

| 編號 | 目標 | 說明 |
| --- | --- | --- |
| N-1 | 角色職責分離 | 任一單一角色作惡均無法破壞系統 |
| N-2 | 可部署性 | 以 Docker Compose 一鍵啟動 |
| N-3 | 可觀測性 | 各服務皆有 dashboard 與審計日誌 |
| N-4 | 可重置性 | 提供 reset 工具供測試重複執行 |
| N-5 | 設定熱重載 | 修改 config.json 不需重啟容器 |

### 2.3 設計原則

1. **最小權限原則（Principle of Least Privilege）**：每個服務僅能存取其職責所需的最少資料。
2. **零信任預設（Zero Trust by Default）**：所有跨服務請求一律要求認證，包括同一 Docker network 內。
3. **公開可驗證優於信任（Verifiability over Trust）**：所有重要狀態變更皆留下可第三方驗證之證據。
4. **失敗安全（Fail-Secure）**：任何驗證失敗時，預設拒絕而非放行。
5. **顯式優於隱式（Explicit over Implicit）**：協定中所有欄位、所有時序假設、所有信任假設均書面化。

---

## 3. 威脅模型（Threat Model）

> 本章為 v2.0 新增。明確界定攻擊者能力，是後續所有安全設計的依據。

### 3.1 攻擊者類型

| 代號 | 名稱 | 能力 |
| --- | --- | --- |
| A1 | **網路被動攻擊者** | 可竊聽所有公開頻道（容器間通訊、HTTPS 流量），但無法竄改 |
| A2 | **網路主動攻擊者** | 可竊聽、丟棄、篡改、重送任何訊息（中間人） |
| A3 | **惡意選民** | 持有合法選民憑證，但企圖：投多票、否認自己的票、嫁禍他人、洩露他人投票 |
| A4 | **腐敗的 TPA** | 試圖將選民身分與其投票內容關聯起來 |
| A5 | **腐敗的 CC** | 試圖在開票時偷改選票或加入幽靈票 |
| A6 | **腐敗的 BB** | 試圖公告錯誤的開票結果 |
| A7 | **腐敗的 TA** | 試圖在投票截止前提早洩漏 SK_TA |
| A8 | **外部攻擊者** | 不持有任何合法憑證，企圖：偽冒選民、灌爆服務、偽造結果 |

### 3.2 信任假設

系統不假設任何單一角色完全可信。各角色信任等級：

| 角色 | 信任等級 | 假設 |
| --- | --- | --- |
| **CA** | 半可信（Semi-trusted） | 在 Phase 0 選民註冊時誠實核發憑證；Phase 1 後，CA 可離線 |
| **TPA** | 半可信但好奇（Honest-but-Curious） | 會誠實執行協定，但會試圖學習選民的投票內容 |
| **TA** | 半可信 | 會誠實在截止時間到達後才釋出 SK_TA，但對請求方需驗證身分 |
| **CC** | 半可信 | 會誠實計票，但須對結果簽章以接受公開驗證 |
| **BB** | 不可信（Untrusted） | 假設 BB 可能被破壞或篡改；任何資訊在 BB 上必須由原始發布者簽章 |
| **Voter** | 完全不可信 | 任何選民均可能企圖作惡 |

### 3.3 不在防護範圍內的威脅（Out of Scope）

下列威脅本系統**不負責防護**，須以系統外手段（社會層、實體層、IT 治理）處理：

- **OOS-1 強制投票（Coercion）**：他人在選民身旁強迫其投特定候選人。完整防禦需 Receipt-Free 機制（如 JCJ/Civitas 協定），超出本系統範疇。
- **OOS-2 選民客戶端被植入木馬**：假設 voter_client 容器運行於可信主機。
- **OOS-3 多角色合謀**：本系統設計可抵抗單一角色作惡；多角色合謀（例如 TPA + CC 串通）非本版本目標。
- **OOS-4 量子計算攻擊**：本系統使用 RSA-2048，不抗量子。Post-Quantum 升級為未來工作。
- **OOS-5 阻斷服務（DDoS）**：應由前置基礎設施（WAF、CDN、限流）處理。本協定僅提供基本應用層 rate limiting。

---

## 4. 安全目標

對應威脅模型，本系統承諾以下可形式化驗證之安全目標：

### 4.1 機密性（Confidentiality）

- **C-1 投票內容機密性**：在投票截止前，除選民本人外，無人能得知任一選票之 Vote 明文。形式化：對任意攻擊者 A2、A4，在 Phase 4 開始前對 Vote 之預測機率不超過 `1/|Candidates| + negl(λ)`。
- **C-2 選民—選票不可關聯**：在 Phase 4 開始後，雖 Vote 明文公開，但 TPA/CC/BB 任一單獨無法將特定 Vote 對應到特定 Voter。

### 4.2 完整性（Integrity）

- **I-1 選票不可篡改**：任何攻擊者無法修改一張已合法簽章之選票而仍通過 CC 驗證。
- **I-2 計票結果不可篡改**：任何攻擊者無法在 BB 上發布偽造的開票結果而被選民驗證通過。
- **I-3 一人一票**：合法選民最多投出一張有效選票，惡意選民無法取得多張盲簽章。

### 4.3 可用性（Availability）

- **A-1 截止時間強制**：超過 `T_DL` 的選票一律拒收。
- **A-2 開票完整性**：合法選票均納入計票，不被遺漏。

### 4.4 可驗證性（Verifiability）

- **V-1 個別可驗證（Individual Verifiability）**：合法選民可驗證自己的選票確實被納入 Merkle Tree。
- **V-2 全域可驗證（Universal Verifiability）**：任何第三方可驗證：(a) BB 上的 Merkle Root 由合法 CC 簽章；(b) 公告之合法選票數與 Tally 統計值一致。
- **V-3 結果不可否認（Non-repudiation of Results）**：CC 簽章後即不可否認其開票結果。

### 4.5 隱私性（Privacy）

- **P-1 投票匿名性**：TPA 在盲簽章階段無法得知 Voter 投了誰。
- **P-2 提交順序匿名性**：CC 公布之選票順序與選民提交順序不相關（透過洗牌實現）。

---

# 第二部分：系統架構

## 5. 角色定義與信任模型

### 5.1 角色清單

| 簡稱 | 全名 | 職責 | 持有金鑰 | 信任等級 |
| --- | --- | --- | --- | --- |
| **CA** | Certificate Authority<br>憑證授權中心 | 為合法實體核發 X.509 憑證；維護選民註冊白名單 | `(SK_CA, PK_CA)` | 半可信，Phase 1 後可離線 |
| **TPA** | Third-Party Agency<br>第三方機構 | 選民身分驗證；發放 Voting Token；對盲化選票簽章 | `(SK_TPA, PK_TPA)` | 半可信，好奇 |
| **TA** | Time Authority<br>時間授權中心 | 維護投票截止時間；截止後僅向已認證 CC 釋放 SK_TA | `(SK_TA, PK_TA)` | 半可信 |
| **CC** | Counting Center<br>計票中心 | 接收選票封包；解封；驗證；計票；建構 Merkle Tree；對結果簽章 | `(SK_CC, PK_CC)` | 半可信 |
| **BB** | Bulletin Board<br>公告板 | 公開展示經 CC 簽章之開票結果；提供 Merkle Proof 查詢介面 | 無自有金鑰 | 不可信，僅作為公開儲存 |
| **Voter** | 選民 | 取得身分驗證；產生選票；包封；提交；事後驗證 | `(SK_Voter, PK_Voter)` | 完全不可信 |

### 5.2 角色職責分離原則

| 原則 | 描述 |
| --- | --- |
| **CA 不知投票內容** | CA 完成 Phase 0、Phase 1 後即可離線；不參與後續流程 |
| **TPA 知道誰投但不知投誰** | 透過盲簽章機制，TPA 看到的是盲化值 `m'`，無法還原 `Vote` |
| **CC 知道投誰但不知是誰投的** | CC 解開信封後看到 `Vote`，但選票經盲簽章保證無法關聯到 Voter |
| **TA 既不知是誰也不知投誰** | TA 僅持有時間鎖定金鑰；其私鑰直到截止後才釋放 |
| **BB 僅儲存與展示** | BB 不參與任何協定計算；所有內容均經原始發布者簽章 |

### 5.3 多角色合謀分析

雖然多角色合謀防禦在 OOS-3 已標記為超出範圍，但設計上仍考慮以下抗合謀特性：

| 合謀組合 | 後果 |
| --- | --- |
| TPA + CC | 可解匿名（TPA 知道 m'，CC 知道 m → Vote）。**緩解措施**：要求二者由不同組織營運 |
| TPA + TA | 無法解匿（仍需 CC 的 SK_CC 開信封）|
| CC + TA | 可在截止前解票（CC 提早拿到 SK_TA）。**緩解措施**：TA 強制檢查時間 |
| CC + BB | 可發布錯誤結果（但因 CC 必須簽章，篡改後選民可偵測）|
| TPA + 任意 Voter | 無新增能力（Voter 本就知自己的票）|

---

## 6. 系統架構與資料流

### 6.1 高階架構圖

```
                        ┌───────────────────┐
                        │       CA          │
                        │  選民註冊白名單     │
                        │  X.509 憑證簽發    │
                        └─────────┬─────────┘
                                  │ Phase 0,1
                ┌─────────────────┼─────────────────┐
                │                 │                 │
                ▼                 ▼                 ▼
        ┌─────────────┐    ┌─────────────┐  ┌─────────────┐
        │     TPA     │    │     TA      │  │     CC      │
        │  雙向認證    │    │  時間鎖管理  │  │  選票收集    │
        │  Token 簽發  │    │  SK_TA 釋放 │  │  解封驗證    │
        │  盲簽章      │    │             │  │  Merkle 建構 │
        └──────┬──────┘    └──────┬──────┘  └──────┬──────┘
               │ Phase 2,3        │ Phase 4         │ Phase 5
               │                  │ ◄───────────────┤
               │                  ▼                 │
               │          ┌─────────────┐           │
               └──────────►   Voter     │           │
                  Phase 2 │   Client    │           │
                  Phase 3 │             │           │
                          └──────┬──────┘           │
                                 │ Phase 3          │
                                 └───────┬──────────┘
                                         │
                                         ▼
                                  ┌─────────────┐
                                  │     BB      │
                                  │  結果公告    │
                                  │  Merkle 驗證 │
                                  └─────────────┘
                                         ▲
                                         │ Phase 6
                                         │
                                       Voter
                                       (驗證自己的票)
```

### 6.2 階段—角色責任矩陣

| 階段 | CA | TPA | TA | CC | BB | Voter |
| --- | --- | --- | --- | --- | --- | --- |
| **Phase 0** 選民註冊 | ★主導 | - | - | - | - | ●參與 |
| **Phase 1** 系統初始化 | ★主導 | ●參與 | ●參與 | ●參與 | ●參與 | - |
| **Phase 2** 身分驗證 | ◌備援 | ★主導 | - | - | - | ●參與 |
| **Phase 3** 盲簽章選票 | - | ★主導 | - | ●接收 | - | ★主導 |
| **Phase 4** 時間解密 | - | - | ★主導 | ●接收 | - | - |
| **Phase 5** 計票與 Merkle | - | ◌備援 | ◌結束 | ★主導 | ●接收 | - |
| **Phase 6** 使用者驗證 | - | - | - | ◌備援 | ★主導 | ★主導 |

★ = 主導者；● = 參與者；◌ = 背景或備援；`-` = 不參與

---

## 7. 服務通訊矩陣

### 7.1 通訊方向與認證需求

| 來源 → 目的 | 用途 | 認證方式 | 加密 |
| --- | --- | --- | --- |
| Voter → CA | 申請憑證（Phase 0/1） | Pre-shared OTP + PoP 簽章 | TLS |
| TPA/TA/CC → CA | 申請憑證（Phase 1） | 啟動腳本內的 PoP 簽章 | TLS |
| Voter → TPA | `/api/auth`（Phase 2） | Voter 簽章封包 + Cert | TLS |
| Voter → TPA | `/api/blind_sign`（Phase 3） | Voting Token + Cert | TLS |
| Voter → CC | `/api/receive_envelope`（Phase 3） | Voting Token Hash（鏈接但不揭示） | TLS |
| CC → TA | `/api/release_key`（Phase 4） | CC 簽章請求 + Cert_CC | TLS |
| CC → BB | `/api/publish`（Phase 5） | CC 簽章結果包 + Cert_CC | TLS |
| Voter → BB | `/api/merkle_proof/<m_hex>`（Phase 6） | 公開（無需認證） | TLS |
| Voter → BB | `/api/results`（Phase 6） | 公開（無需認證） | TLS |
| 任何人 → CA | `/api/ca_cert`（讀取根憑證） | 公開 | TLS |
| 任何人 → BB | dashboard 瀏覽 | 公開 | TLS |

### 7.2 內部 vs 外部端點

每個服務需明確區分：

- **公開端點（Public）**：無需認證，任何人可呼叫。例：`/api/ca_cert`、`/api/results`、`/api/public_key`
- **認證端點（Authenticated）**：必須帶有效認證憑證/Token。例：`/api/auth`、`/api/blind_sign`、`/api/receive_envelope`、`/api/release_key`、`/api/publish`
- **內部端點（Internal）**：僅 Docker 內部網路可達，且額外有 IP 白名單。例：`/api/config/reload`

### 7.3 端點存取控制速查表

| 端點 | 公開 | 認證需求 | 寫入限制 |
| --- | --- | --- | --- |
| `CA /api/ca_cert` | ✅ | - | 僅讀 |
| `CA /api/issue_cert` | ❌ | OTP + PoP | 限白名單實體 |
| `TPA /api/public_key` | ✅ | - | 僅讀 |
| `TPA /api/auth` | ❌ | Voter 簽章 + Cert | 1 次/Voter |
| `TPA /api/blind_sign` | ❌ | Voting Token | 1 次/Token |
| `TA /api/public_key` | ✅ | - | 僅讀 |
| `TA /api/deadline` | ✅ | - | 僅讀 |
| `TA /api/release_key` | ❌ | CC 簽章請求 + Cert_CC | 截止後可重複呼叫 |
| `CC /api/public_key` | ✅ | - | 僅讀 |
| `CC /api/receive_envelope` | ❌ | Token Binding Hash | 截止前可呼叫 |
| `CC /api/tally` | ❌ | 內部 IP + 簽章 | 僅 1 次成功 |
| `CC /api/results` | ✅ | - | 僅讀 |
| `BB /api/results` | ✅ | - | 僅讀 |
| `BB /api/publish` | ❌ | CC 簽章結果包 | 僅 1 次成功（不可覆蓋）|
| `BB /api/merkle_proof/<m_hex>` | ✅ | - | 僅讀 |

---

# 第三部分：密碼學基礎

## 8. 符號定義表

> 本表為 v2.0 統一規範。**所有後續章節、API、code 均必須遵守此符號表**。
> v1.0 中存在的混淆（如 `SI_Voter` 同時被當作雜湊與簽章）一律消除。

### 8.1 實體與識別碼

| 符號 | 型別 | 定義 |
| --- | --- | --- |
| `Voter` | Entity | 選民，系統的主要使用者 |
| `TPA` | Entity | 第三方機構（Third-party Agency） |
| `TA` | Entity | 時間授權中心（Time Authority） |
| `CC` | Entity | 計票中心（Counting Center） |
| `BB` | Entity | 公告板（Bulletin Board） |
| `CA` | Entity | 憑證授權中心（Certificate Authority） |
| `ID_x` | string | 實體 `x` 的唯一識別碼，例如 `VOTER_001`、`TPA`、`CC` |

### 8.2 金鑰與憑證

| 符號 | 型別 | 定義 |
| --- | --- | --- |
| `(SK_x, PK_x)` | RSA-2048 keypair | 實體 `x` 的私/公鑰對；`x ∈ {CA, TPA, TA, CC, Voter}` |
| `Cert_x` | X.509 PEM | 由 CA 對 PK_x 核發的數位憑證 |
| `e_TPA, n_TPA` | bigint | TPA 公鑰拆解後的指數與模數，用於盲簽章運算 |
| `d_TPA` | bigint | TPA 私鑰指數，僅 TPA 持有 |

### 8.3 雜湊與簽章原語

| 符號 | 型別 | 定義 |
| --- | --- | --- |
| `H(·)` | function | SHA-256 雜湊函數，輸出 256-bit |
| `H_leaf(·)` | function | Merkle Tree 葉節點專用雜湊：`H_leaf(x) = H(0x00 ‖ x)` |
| `H_node(·,·)` | function | Merkle Tree 中間節點專用雜湊：`H_node(L, R) = H(0x01 ‖ L ‖ R)` |
| `FDH(·)` | function | Full-Domain Hash，輸出長度等於 RSA 模數位元數（見 §9.5） |
| `Sig_x(m)` | bytes | 實體 `x` 對訊息 `m` 之 RSA-PSS 數位簽章 |
| `Verify_x(m, σ)` | bool | 用 `PK_x` 驗證 `σ` 是否為 `m` 之合法 PSS 簽章 |
| `Enc_PK(m)` | bytes | RSA-OAEP 公鑰加密 |
| `Dec_SK(c)` | bytes | RSA-OAEP 私鑰解密 |
| `AEnc_k(IV, AAD, m)` | (c, tag) | AES-256-GCM 認證加密；輸出密文 c 與 16-byte 驗證碼 tag |
| `ADec_k(IV, AAD, c, tag)` | m or ⊥ | AES-256-GCM 解密；驗證失敗則回傳 ⊥ |

### 8.4 盲簽章相關

| 符號 | 型別 | 定義 |
| --- | --- | --- |
| `m` | 256-bit hash | 選票包雜湊值（見 §14） |
| `μ` | bigint mod n | `μ = FDH(m)`，將 m 擴展至模數空間 |
| `r` | bigint mod n | 盲化因子，與 n 互質之隨機數 |
| `m'` | bigint mod n | 盲化後訊息：`m' = μ · r^e mod n` |
| `S` | bigint mod n | TPA 對 `m'` 的盲簽章：`S = (m')^d mod n` |
| `S'` | bigint mod n | 去盲化後的合法簽章：`S' = S · r⁻¹ mod n` |

### 8.5 訊息與封包

| 符號 | 型別 | 定義 |
| --- | --- | --- |
| `T_x` | int (Unix ts) | 實體 `x` 發送訊息當下的時間戳 |
| `T_now` | int (Unix ts) | 接收端讀取訊息時的系統時間 |
| `ΔT` | int (秒) | 系統設計之時間誤差容許值 |
| `T_DL` | int (Unix ts) | 投票截止時間 |
| `N_x` | hex string | 實體 `x` 產生的隨機 nonce（v1.0 之 `si`，已改名以避免與簽章 `Sig` 混淆） |
| `Auth_x→y` | JSON object | x 發給 y 的認證封包 |
| `Token` | JSON object | 由 TPA 簽發、用於 Phase 3 盲簽章授權的一次性票（見 §14） |
| `SN` | string | 選票流水號，由 Voter 在本地端產生 |
| `Vote` | string | 候選人字串明文 |
| `P` | JSON object | 選票封包（Phase 3）：`P = {C_Data, IV, Tag, AAD, C_Key}` |
| `C_Data` | base64 bytes | AES-GCM 加密之選票資料密文 |
| `C_Key` | base64 bytes | RSA-OAEP 加密之 AES 金鑰 |
| `IV` | base64 bytes | AES-GCM 96-bit 隨機 nonce |
| `Tag` | base64 bytes | AES-GCM 128-bit 認證碼 |
| `AAD` | bytes | AES-GCM Additional Authenticated Data |

### 8.6 Merkle Tree 與驗證

| 符號 | 型別 | 定義 |
| --- | --- | --- |
| `Leaf_i` | hex string | 第 i 張合法選票之葉節點：`Leaf_i = H_leaf(m_i)` |
| `H_parent` | hex string | 中間節點：`H_parent = H_node(L, R)` |
| `Root_official` | hex string | 由 CC 計算並簽章發布之 Merkle Root |
| `Root_calculated` | hex string | 選民本地端依 Merkle Proof 推導之 Root |
| `Proof_i` | list | 第 i 張選票之 Merkle Proof，由 (sibling, position) 元組組成 |
| `Sig_CC(Bundle)` | bytes | CC 對開票結果包之 PSS 簽章 |

---

## 9. 密碼學原語選用

### 9.1 演算法總表

| 用途 | 演算法 | 參數 | 理由 |
| --- | --- | --- | --- |
| 公鑰加密 | RSA-OAEP | 2048-bit, MGF1+SHA256 | 標準、抗 IND-CCA2 |
| 數位簽章 | RSA-PSS | 2048-bit, MGF1+SHA256, salt 32 byte | 較 PKCS#1 v1.5 安全 |
| 盲簽章 | RSA-FDH-Blind | 2048-bit | 可證明安全；textbook RSA blind 不安全 |
| 對稱加密 | AES-256-GCM | key 256-bit, IV 96-bit, tag 128-bit | AEAD，提供機密性+完整性 |
| 雜湊 | SHA-256 | 輸出 256-bit | 標準、廣泛支持 |
| Merkle 雜湊 | SHA-256 + Domain Separator | 葉 `0x00`、中間 `0x01` 前綴 | 防 CVE-2012-2459 二次原像 |
| 隨機數 | `secrets` (CSPRNG) | - | 加密級隨機 |

### 9.2 不採用的演算法（與 v1.0 差異）

| v1.0 | v2.0 | 原因 |
| --- | --- | --- |
| AES-CFB | **AES-GCM** | CFB 無 MAC，無法防止位元翻轉 |
| Textbook RSA Blind | **RSA-FDH-Blind** | Textbook RSA 受存在性偽造攻擊 |
| Merkle Tree 末葉重複 | **Domain-separated leaf/node** | 防 CVE-2012-2459 |
| RSA PKCS#1 v1.5 簽章 | **RSA-PSS** | PSS 為現代標準 |

### 9.3 RSA-OAEP 規格

```
參數：
  key_size:      2048 bit
  mgf:           MGF1
  hash:          SHA-256
  label:         None
  最大可加密明文長度: 2048/8 - 2*32 - 2 = 190 byte

用途：
  - C_Key = E_PK_CC(k)  其中 k 為 32-byte AES 金鑰
  - inner_enc = E_PK_TA(H(ID‖SN‖Vote) ‖ Vote)  注意明文須 ≤ 190 byte
```

### 9.4 RSA-PSS 規格

```
參數：
  key_size:      2048 bit
  mgf:           MGF1+SHA-256
  salt_length:   32 byte (= MAX_LENGTH)
  hash:          SHA-256

用途：
  - 認證封包簽章（Phase 2）
  - Voting Token 簽章（Phase 2）
  - CC 對開票結果包之簽章（Phase 5）
  - CC 對 TA release_key 請求之簽章（Phase 4）
```

### 9.5 RSA-FDH-Blind 盲簽章規格

#### 9.5.1 Full-Domain Hash 構造

由於 SHA-256 僅輸出 256-bit，需擴展至接近模數 `n` 的位元長度（2048-bit）。本系統採用基於 MGF1 的 FDH：

```
FDH(m, n_bits):
    """
    將 m 擴展為近似均勻分布於 [0, n) 的整數。
    n_bits = bit_length(n)，例如 2048。
    """
    target_bytes = ceil(n_bits / 8)        # = 256 byte for 2048-bit n
    mask         = MGF1_SHA256(m, target_bytes)
    
    # 確保結果 < n：將最高 bit 清零（簡化版，可改用 reject sampling）
    mask[0] &= (0xFF >> ((8 * target_bytes) - n_bits + 1))
    
    return int_from_bytes(mask) mod n
```

#### 9.5.2 盲簽章流程

```
角色：Voter, TPA
共用參數：(e, n) = TPA 公鑰

Step 1 (Voter)：計算選票雜湊
    m = H( H(ID_Voter ‖ SN ‖ Vote) ‖ Vote )

Step 2 (Voter)：擴展為 FDH
    μ = FDH(m, bit_length(n))

Step 3 (Voter)：選擇盲化因子
    r ← {1, ..., n-1} 滿足 gcd(r, n) = 1

Step 4 (Voter)：盲化
    m' = (μ · r^e) mod n

Step 5 (Voter → TPA)：傳送 m' 與 Voting Token

Step 6 (TPA)：驗證 Token 有效後盲簽
    S = (m')^d mod n

Step 7 (TPA → Voter)：回傳 S

Step 8 (Voter)：去盲化
    r⁻¹ = modular_inverse(r, n)
    S'  = (S · r⁻¹) mod n

Step 9 (Voter)：自我驗證
    assert (S')^e mod n == μ

Step 10 (任何驗證者)：驗證盲簽章
    μ_check = FDH(m, bit_length(n))
    assert (S')^e mod n == μ_check
```

> **重要**：v1.0 的驗證式 `S'^e mod n == m` 在 v2.0 改為 `S'^e mod n == FDH(m)`。CC 與選民端均須據此調整。

### 9.6 AES-256-GCM 規格

```
參數：
  key_size:    256 bit
  IV size:     96 bit (12 byte)，每次必須重新隨機產生
  tag_size:    128 bit (16 byte)
  AAD:         可選之關聯資料

封裝：
  IV ← random(12 byte)
  AAD = "voting-system-v2|" ‖ ID_Voter ‖ SN
  (C_Data, Tag) = AES-GCM-Encrypt(k, IV, AAD, plaintext)

解封：
  plaintext_or_⊥ = AES-GCM-Decrypt(k, IV, AAD, C_Data, Tag)
  若 Tag 驗證失敗則回傳 ⊥（不可繼續解密）
```

> **AAD 之作用**：將 `ID_Voter ‖ SN` 綁進密文，攻擊者即使重放整個信封也會在 AAD 不匹配時失敗。

### 9.7 Merkle Tree 規格（Domain-Separated）

```
葉節點：
    Leaf_i = H( 0x00 ‖ m_i )           # m_i 為 hex string of 選票包雜湊

中間節點：
    H_parent = H( 0x01 ‖ L ‖ R )       # L, R 為左右子節點 hash

奇數節點處理：
    當某層節點數為奇數時，最後一個節點直接「上提」(promote) 至下一層，
    而非複製。具體做法：
    
    function build_layer(nodes):
        result = []
        i = 0
        while i + 1 < len(nodes):
            result.append(H_node(nodes[i], nodes[i+1]))
            i += 2
        if i < len(nodes):
            result.append(nodes[i])    # 上提，不複製
        return result
```

> 此設計可同時防止：
> - **CVE-2012-2459** 二次原像攻擊（葉與中間節點 hash 不可能相同）
> - **末葉複製攻擊**（不再有 `H(L,L)` 之異常結構）

### 9.8 隨機數來源

所有隨機性皆使用作業系統 CSPRNG：

| 用途 | Python 介面 | 位元數 |
| --- | --- | --- |
| 盲化因子 r | `secrets.randbelow(n-2) + 2` | ≤ 2048 bit |
| AES 金鑰 k | `os.urandom(32)` | 256 bit |
| AES IV | `os.urandom(12)` | 96 bit |
| Voter Nonce N_Voter | `secrets.token_hex(16)` | 128 bit |
| Token ID | `secrets.token_hex(32)` | 256 bit |
| OTP（Phase 0 註冊） | `secrets.token_urlsafe(24)` | ≥ 144 bit |

---

## 10. 金鑰規格與生命週期

### 10.1 各角色金鑰

| 持有者 | 金鑰 | 用途 | 生命週期 | 儲存位置 |
| --- | --- | --- | --- | --- |
| CA | `SK_CA` | 簽章子實體憑證 | 系統運作期間 | `ca_keys` Docker volume，明文 PEM |
| CA | `PK_CA` | 公開信任根 | 系統運作期間 | 同上 |
| TPA | `SK_TPA` | 盲簽章 + 認證封包簽章 | 系統運作期間 | `tpa_keys` |
| TPA | `PK_TPA` | 選民盲化運算 | 系統運作期間 | 公開於 `/api/public_key` |
| TA | `SK_TA` | 選票內層解密 | 截止後釋放 | `ta_keys`，Phase 4 後傳輸至 CC |
| TA | `PK_TA` | 選民選票內層加密 | 系統運作期間 | 公開 |
| CC | `SK_CC` | 數位信封 C_Key 解密 + 結果簽章 + 對 TA 請求簽章 | 系統運作期間 | `cc_keys` |
| CC | `PK_CC` | 選民封裝會議金鑰 + BB 驗結果簽章 | 系統運作期間 | 公開 |
| Voter | `SK_Voter` | 認證封包簽章 + 盲化運算（用於 PoP） | 投票完成後可丟棄 | `voter{N}_keys`，明文 |
| Voter | `PK_Voter` | TPA 驗證 Voter 身分 | 同上 | 透過 Cert_Voter 公開 |

### 10.2 金鑰儲存安全要求

> **重要**：v2.0 仍以「教學/專題系統」為定位，金鑰以明文 PEM 儲存於 Docker volume。
> 進入正式部署需追加：
> - 私鑰使用 HSM（Hardware Security Module）
> - 或使用 OS keystore（Linux: kernel keyring）
> - 或最少：以 passphrase 加密 PEM
>
> 此項列為「未來工作」，見 §22。

### 10.3 金鑰生命週期狀態機

```
[未生成] ──啟動容器──► [已生成]
                          │
                          │ 向 CA 申請
                          ▼
                       [已認證] ──系統運作──► [使用中]
                                                │
                                                │ 系統重置 / reset.py
                                                ▼
                                            [已銷毀]
```

特別注意 **SK_TA**：

```
[已生成] ──系統運作──► [時間鎖定中] ──T_now ≥ T_DL──► [已釋放]
                                                       │
                                                       │ Phase 5 完成
                                                       ▼
                                                    [可丟棄]
```


---

# 第四部分：協定流程

> 本部分為協定核心。每個 Phase 採三層描述：
> 1. **目的與前置條件**（人類可讀）
> 2. **形式化步驟**（含數學式與訊息格式，AI 可直接生成 code）
> 3. **異常處理與安全備註**

---

## Phase 0：選民註冊階段

> **v2.0 新增階段**

### 0.1 目的

建立合法選民白名單，確保 CA 僅向已註冊之選民簽發憑證。徹底解決 v1.0 中「CA 對任意 entity_id 都簽發憑證」的根本性漏洞。

### 0.2 前置條件

- CA 服務已啟動且 SK_CA / PK_CA 已生成
- 系統管理員（Admin）持有可信通道，能向選民派發 OTP（One-Time Password）

### 0.3 參與者

- **Admin**（系統外角色）：負責產生 OTP 並透過可信通道派送（例：實體領取、加密 email）
- **CA**：維護 `voter_registry` 表
- **Voter**：以 OTP 完成註冊

### 0.4 形式化流程

```
─── Step 0.1：Admin 預先註冊選民身分 ───────────────────────
    對每位合法選民 i ∈ {1, ..., N}：
        OTP_i = secrets.token_urlsafe(24)
        Admin → CA: register(ID_Voter_i, OTP_hash_i)
        其中 OTP_hash_i = H(OTP_i)
        
    CA 內部寫入：
        voter_registry[ID_Voter_i] = {
            otp_hash:    OTP_hash_i,
            status:      'pending',
            registered_at: T_now,
        }
    
    Admin → Voter (out-of-band)：派送 OTP_i 與 ID_Voter_i

─── Step 0.2：Voter 本地端生成金鑰 ─────────────────────────
    (SK_Voter, PK_Voter) ← RSA-2048 keygen
    儲存於 voter{N}_keys volume

─── Step 0.3：Voter 向 CA 申請憑證（含 PoP） ──────────────
    challenge = "REGISTER|" ‖ ID_Voter ‖ T_Voter
    σ_pop     = Sig_Voter(challenge)
    
    Voter → CA: POST /api/issue_cert {
        entity_id:       ID_Voter,
        public_key:      PK_Voter (PEM),
        otp:             OTP_Voter,
        timestamp:       T_Voter,
        pop_signature:   σ_pop
    }

─── Step 0.4：CA 驗證並簽發 ────────────────────────────────
    1. 檢查 ID_Voter ∈ voter_registry
       否 → 回傳 403 ENTITY_NOT_REGISTERED
    
    2. 檢查 voter_registry[ID_Voter].status == 'pending'
       否 → 回傳 403 ALREADY_REGISTERED
    
    3. 檢查 H(OTP_Voter) == voter_registry[ID_Voter].otp_hash
       否 → 回傳 403 OTP_INVALID
    
    4. 檢查 |T_now - T_Voter| ≤ ΔT
       否 → 回傳 403 TIMESTAMP_OUT_OF_RANGE
    
    5. 重建 challenge 並驗證 PoP：
       challenge_check = "REGISTER|" ‖ ID_Voter ‖ T_Voter
       Verify_PK_Voter(challenge_check, σ_pop) == True
       否 → 回傳 403 POP_INVALID
    
    6. 簽發憑證：
       Cert_Voter = X.509{
           subject:   CN=ID_Voter,
           issuer:    CN=Voting CA,
           publicKey: PK_Voter,
           validity:  [T_now, T_now + 365 days],
           signature: Sig_CA(tbs_cert)
       }
    
    7. 標記為已註冊：
       voter_registry[ID_Voter].status = 'registered'
       voter_registry[ID_Voter].issued_cert_serial = Cert_Voter.serial
    
    8. 回傳 Cert_Voter

─── Step 0.5：服務帳號註冊（TPA / TA / CC） ────────────────
    對於系統服務（TPA、TA、CC），採以下流程：
    
    Admin 啟動容器時，於環境變數提供 SERVICE_REGISTRATION_TOKEN
    服務啟動腳本：
        1. 生成金鑰對
        2. 以 SERVICE_REGISTRATION_TOKEN 向 CA 註冊
        3. 流程同 Step 0.3-0.4
    
    每個 service token 使用一次後失效。
```

### 0.5 異常處理

| 錯誤碼 | 原因 | 處置 |
| --- | --- | --- |
| `ENTITY_NOT_REGISTERED` | ID 不在白名單 | 拒絕，記錄審計日誌 |
| `ALREADY_REGISTERED` | 該 ID 已領取過憑證 | 拒絕；若 Voter 遺失憑證需 Admin 重新派送 OTP |
| `OTP_INVALID` | OTP 不正確 | 拒絕；連續 3 次失敗鎖定該 ID 24 小時 |
| `TIMESTAMP_OUT_OF_RANGE` | 時間誤差超過 ΔT | 拒絕；提示 Voter 校時 |
| `POP_INVALID` | PoP 簽章驗證失敗 | 拒絕（攻擊者試圖用他人 PK 換取憑證）|

### 0.6 安全備註

| 編號 | 備註 |
| --- | --- |
| S-0.1 | OTP 必須以 H(OTP) 形式儲存，CA 資料庫被竊不洩露原 OTP |
| S-0.2 | OTP 過期時間建議 7 天；逾期需 Admin 重發 |
| S-0.3 | 同一 ID 僅可註冊一次；補發需 Admin 介入並產生審計記錄 |
| S-0.4 | challenge 中包含 timestamp 防止 PoP 簽章被重放 |
| S-0.5 | OTP 派送通道之安全性為「系統外」假設，須以實體投遞、加密郵件等方式確保 |

---

## Phase 1：系統初始化與金鑰生成階段

### 1.1 目的

建立系統信任基礎；分發各服務之 X.509 憑證；建立服務間互信。

### 1.2 前置條件

- Phase 0 已完成（CA 持有 voter_registry 與 service_registry）
- 各服務之 SERVICE_REGISTRATION_TOKEN 已透過 docker-compose 環境變數提供

### 1.3 各角色之金鑰用途總覽

| 角色 | 金鑰 | 用途說明 |
| --- | --- | --- |
| CA | SK_CA | 簽發其餘服務之憑證 |
| TPA | SK_TPA | (a) 對盲化訊息 m' 簽章；(b) 對 Voting Token 簽章；(c) Phase 2 認證封包簽章 |
| TPA | PK_TPA (即 e_TPA, n_TPA) | 選民執行盲化運算 |
| TA | SK_TA | 解密選票內層 E_PK_TA(...)；**截止後始釋放** |
| TA | PK_TA | 選民加密選票內容 |
| CC | SK_CC | (a) 解開信封外層 C_Key；(b) 對開票結果簽章；(c) 對 TA 索取私鑰請求簽章 |
| CC | PK_CC | 選民加密 AES 會議金鑰 k |
| Voter | SK_Voter | (a) Phase 2 認證封包簽章；(b) Phase 0 PoP；(c) 盲化運算（本地） |
| Voter | PK_Voter | TPA 驗證 Voter 身分 |

### 1.4 形式化流程

```
─── Step 1.1：CA 啟動 ──────────────────────────────────────
    若 ca_keys/ca_private_key.pem 不存在：
        (SK_CA, PK_CA) ← RSA-2048 keygen
        Cert_CA_self_signed = X509{...,  signature: Sig_CA(...)}
        儲存於 ca_keys/

─── Step 1.2：服務啟動順序 ─────────────────────────────────
    依序：CA → TPA → TA → CC → BB → Voters
    （docker-compose 透過 healthcheck + depends_on 強制此順序）

─── Step 1.3：每個服務 x ∈ {TPA, TA, CC} 執行 ─────────────
    a. 載入或生成 (SK_x, PK_x)
    b. 從 CA /api/ca_cert 下載 Cert_CA
    c. 以 SERVICE_REGISTRATION_TOKEN 申請 Cert_x
       （流程同 Phase 0 Step 0.3-0.4）
    d. 將 Cert_x、Cert_CA 儲存至本地 keys volume

─── Step 1.4：BB 啟動 ──────────────────────────────────────
    BB 不需金鑰對，但需下載 Cert_CA 與 Cert_CC：
    a. 從 CA /api/ca_cert 下載 Cert_CA
    b. 從 CC /api/cert 下載 Cert_CC
    c. 後續所有 publish 請求均以 Cert_CC 之公鑰驗證

─── Step 1.5：Voter 啟動 ──────────────────────────────────
    a. 載入或生成 (SK_Voter, PK_Voter)
    b. 若尚未持有 Cert_Voter，執行 Phase 0 Step 0.3
    c. 下載 Cert_CA、PK_TPA、PK_TA、PK_CC

─── Step 1.6：截止時間設定 ────────────────────────────────
    TA 啟動時讀取環境變數 VOTE_DURATION_SECONDS 或 config.json
    T_DL = T_start + duration
    將 T_DL 簽章後存入 TA 內部狀態
        T_DL_signed = (T_DL, Sig_TA(T_DL))
    任何查詢 deadline 之請求均回傳此簽章版本
```

### 1.5 安全備註

| 編號 | 備註 |
| --- | --- |
| S-1.1 | 所有金鑰生成必須使用 CSPRNG（Python `secrets` 或 `os.urandom`） |
| S-1.2 | CA 為信任根；CA 之 SK_CA 一旦洩漏整個系統信任崩潰 |
| S-1.3 | T_DL 一經 TA 簽章後不可變更，避免有人在投票期中途調整截止時間 |
| S-1.4 | docker-compose 之 depends_on 不應作為安全保證；服務啟動失敗時自身應回退至安全狀態 |

---

## Phase 2：身分驗證階段

### 2.1 目的

Voter 與 TPA 雙向認證，確認彼此身分；認證成功後 TPA 簽發**一次性 Voting Token**，作為 Phase 3 盲簽章之授權憑證。

### 2.2 前置條件

- Voter 持有 Cert_Voter 與 SK_Voter
- TPA 持有 Cert_TPA、SK_TPA、Cert_CA
- 當前時間 T_now < T_DL

### 2.3 認證封包格式（v2.0 統一）

```
Auth_Packet = {
    payload: {
        sender_id:    string,    // ID_Voter
        receiver_id:  string,    // "TPA"
        timestamp:    int,       // T_Voter（Unix ts）
        nonce:        string,    // N_Voter，128-bit hex（v1.0 之 si）
        cert_pem:     string,    // Cert_Voter PEM
    },
    signature: string,           // base64 of Sig_Voter(JSON_canonical(payload))
}
```

> **改名說明**：v1.0 的 `si` 在符號表中被定義為簽章雜湊，但程式碼中其實是 nonce。
> v2.0 一律改名為 `nonce`，符號為 `N_x`，以消除混淆。

### 2.4 形式化流程

```
─── Step 2.1：Voter → TPA 發送 Auth_Voter→TPA ─────────────
    payload = {
        sender_id:   ID_Voter,
        receiver_id: "TPA",
        timestamp:   T_Voter,
        nonce:       N_Voter,
        cert_pem:    Cert_Voter,
    }
    signature = Sig_Voter(JSON_canonical(payload))    // RSA-PSS
    
    POST TPA /api/auth { payload, signature }

─── Step 2.2：TPA 驗證 ────────────────────────────────────
    a. 截止時間：assert T_now ≤ T_DL；否則 403 DEADLINE_EXCEEDED
    
    b. 接收方 ID：assert payload.receiver_id == "TPA"
       否 → 403 RECEIVER_ID_MISMATCH
    
    c. 時間誤差（**雙向**檢查，v2.0 修正）：
       assert |T_now - payload.timestamp| ≤ ΔT
       否 → 403 TIMESTAMP_OUT_OF_RANGE
    
    d. 防重放：assert payload.nonce ∉ used_nonces
       否 → 403 NONCE_REPLAY
    
    e. 防重複投票：assert payload.sender_id ∉ voted_users
       否 → 403 ALREADY_VOTED
    
    f. 驗證憑證：
       assert verify_cert_with_ca(payload.cert_pem, Cert_CA) == True
       否 → 403 CERT_INVALID
    
    g. 從 cert_pem 取得 PK_Voter
    
    h. 驗證簽章：
       Verify_PK_Voter(JSON_canonical(payload), signature) == True
       否 → 403 SIGNATURE_INVALID

─── Step 2.3：TPA 簽發 Voting Token ───────────────────────
    Token_payload = {
        token_id:    secrets.token_hex(32),        // 256-bit
        voter_id:    ID_Voter,
        issued_at:   T_now,
        expires_at:  min(T_DL, T_now + 600),       // 10 分鐘 或 截止前
        nonce_bind:  N_Voter,                       // 綁定本次認證 nonce
    }
    Token_signature = Sig_TPA(JSON_canonical(Token_payload))
    
    Voting_Token = {
        payload:   Token_payload,
        signature: base64(Token_signature),
    }
    
    寫入 issued_tokens 表：
        issued_tokens[token_id] = {voter_id, issued_at, used: false}
    
    寫入 used_nonces：
        used_nonces[N_Voter] = (sender_id=ID_Voter, used_at=T_now)
    
    寫入 voted_users：
        voted_users[ID_Voter] = T_now

─── Step 2.4：TPA → Voter 回應 Auth_TPA→Voter + Token ────
    response_payload = {
        sender_id:    "TPA",
        receiver_id:  ID_Voter,
        timestamp:    T_TPA,
        nonce:        N_TPA,
        nonce_echo:   N_Voter,             // 回應 Voter 的 nonce 以建立關聯
        cert_pem:     Cert_TPA,
    }
    response_signature = Sig_TPA(JSON_canonical(response_payload))
    
    回傳 {
        status:        "success",
        response_packet: { payload: response_payload, signature: response_signature },
        voting_token:    Voting_Token,
    }

─── Step 2.5：Voter 驗證 TPA 回應 ─────────────────────────
    a. 接收方 ID：assert response_payload.receiver_id == ID_Voter
    b. 時間誤差：assert |T_now - response_payload.timestamp| ≤ ΔT
    c. nonce_echo：assert response_payload.nonce_echo == N_Voter（**新增，建立雙向關聯**）
    d. 驗證 Cert_TPA：assert verify_cert_with_ca(Cert_TPA, Cert_CA) == True
    e. 驗證簽章：Verify_PK_TPA(JSON_canonical(response_payload), response_signature) == True
    f. 驗證 Voting Token：
       Verify_PK_TPA(JSON_canonical(Token.payload), Token.signature) == True
       且 Token.payload.voter_id == ID_Voter
       且 Token.payload.nonce_bind == N_Voter
    g. 儲存 Voting_Token 至本地，準備 Phase 3 使用
```

### 2.5 異常處理

| 錯誤碼 | HTTP | 原因 |
| --- | --- | --- |
| `DEADLINE_EXCEEDED` | 403 | 投票時段已過 |
| `RECEIVER_ID_MISMATCH` | 403 | 封包目的地非 TPA |
| `TIMESTAMP_OUT_OF_RANGE` | 403 | 時間偏差超過 ΔT |
| `NONCE_REPLAY` | 403 | nonce 已被使用過 |
| `ALREADY_VOTED` | 403 | 該選民已完成投票 |
| `CERT_INVALID` | 403 | Voter 憑證未由 CA 簽發或已過期 |
| `SIGNATURE_INVALID` | 403 | Voter 簽章驗證失敗 |

### 2.6 安全備註

| 編號 | 備註 |
| --- | --- |
| S-2.1 | 時間誤差採**雙向**檢查（`|T_now - T_Voter| ≤ ΔT`），抵抗未來時戳攻擊 |
| S-2.2 | nonce_bind 將 Token 與當次認證 nonce 綁定，防止 Token 被獨立轉移 |
| S-2.3 | nonce_echo 機制使 Voter 能確認 TPA 的回應確實是針對本次請求 |
| S-2.4 | Token 有效期為 `min(T_DL, T_now + 600)`，確保 (a) 不超過截止時間，(b) 即使 Token 洩漏也僅有 10 分鐘可用 |
| S-2.5 | Token 的 token_id 為 256-bit，碰撞機率可忽略 |
| S-2.6 | 同一 ID_Voter 的 Token 僅能簽發一次（透過 voted_users 鎖定）|

---

## Phase 3：盲簽章選票階段

### 3.1 目的

Voter 在 TPA 不知投票內容的前提下取得對選票之合法簽章；隨後將選票封裝為數位信封並提交給 CC。

### 3.2 前置條件

- Voter 持有有效 Voting_Token（Phase 2 簽發）
- 當前時間 T_now < min(T_DL, Token.expires_at)

### 3.3 形式化流程：盲簽章

```
─── Step 3.1：Voter 計算選票雜湊 ──────────────────────────
    SN ← unique_serial(VOTER_ID, T_now)         // 例：SN{ts}{voter_suffix}
    Vote ∈ Candidates                             // 候選人字串
    
    inner_hash = H(ID_Voter ‖ "|" ‖ SN ‖ "|" ‖ Vote)
    m          = H(inner_hash ‖ "|" ‖ Vote)
    
    儲存本地：(SN, Vote, m) 作為事後驗證之憑證

─── Step 3.2：Voter 擴展為 FDH ────────────────────────────
    μ = FDH(m, bit_length(n_TPA))

─── Step 3.3：Voter 選擇盲化因子 ─────────────────────────
    重複：
        r ← secrets.randbelow(n_TPA - 2) + 2
        若 gcd(r, n_TPA) == 1，跳出迴圈

─── Step 3.4：Voter 盲化 ──────────────────────────────────
    m' = (μ · pow(r, e_TPA, n_TPA)) mod n_TPA

─── Step 3.5：Voter → TPA 請求盲簽章 ─────────────────────
    POST TPA /api/blind_sign {
        m_prime_hex:  hex(m'),
        voting_token: Voting_Token,
    }

─── Step 3.6：TPA 驗證 Token 與簽章 ───────────────────────
    a. 截止時間：assert T_now ≤ T_DL；否 → 403
    
    b. 驗證 Token 簽章：
       Verify_PK_TPA(JSON_canonical(Token.payload), Token.signature) == True
       否 → 403 TOKEN_SIGNATURE_INVALID
    
    c. 驗證 Token 是否過期：
       assert T_now ≤ Token.payload.expires_at
       否 → 403 TOKEN_EXPIRED
    
    d. 驗證 Token 未使用：
       token_id = Token.payload.token_id
       assert issued_tokens[token_id].used == false
       否 → 403 TOKEN_ALREADY_USED
    
    e. 標記為已使用（**原子操作**）：
       UPDATE issued_tokens SET used = true WHERE token_id = ?
    
    f. 執行盲簽章：
       S = pow(m', d_TPA, n_TPA)
       回傳 { status: "success", S_hex: hex(S) }

─── Step 3.7：Voter 去盲化並驗證 ─────────────────────────
    r_inv = pow(r, -1, n_TPA)
    S'    = (S · r_inv) mod n_TPA
    
    self_check：
        μ_recompute = FDH(m, bit_length(n_TPA))
        assert pow(S', e_TPA, n_TPA) == μ_recompute
        否 → 中止流程，視為 TPA 行為異常
```

### 3.4 形式化流程：數位信封封裝

```
─── Step 3.8：Voter 建構數位信封 ─────────────────────────
    
    內層（用 PK_TA 加密，截止後始可解開）：
        inner_plaintext = inner_hash ‖ "|" ‖ Vote
        inner_enc       = Enc_PK_TA(inner_plaintext)             // RSA-OAEP
    
    AES 明文（未加密前的中層內容）：
        aes_plaintext = base64(inner_enc) ‖ "|" ‖ hex(S') ‖ "|" ‖ hex(m)
    
    AES 加密（v2.0 改為 GCM）：
        k   = os.urandom(32)             // 256-bit AES key
        IV  = os.urandom(12)             // 96-bit nonce
        AAD = "voting-system-v2|" ‖ ID_Voter ‖ "|" ‖ SN
        (C_Data, Tag) = AES_GCM_Enc(k, IV, AAD, aes_plaintext)
    
    包封 AES 金鑰（用 PK_CC）：
        C_Key = Enc_PK_CC(k)             // RSA-OAEP
    
    最終信封：
        Envelope = {
            c_data:      base64(C_Data),
            iv:          base64(IV),
            tag:         base64(Tag),
            aad:         base64(AAD),
            c_key:       base64(C_Key),
            token_hash:  H(Token.payload.token_id),    // 用於 CC 端去重，但不揭露 token
        }

─── Step 3.9：Voter → CC 提交信封 ─────────────────────────
    POST CC /api/receive_envelope { Envelope }

─── Step 3.10：CC 處理信封 ────────────────────────────────
    a. 截止時間：assert T_now ≤ T_DL
    
    b. 防止 token 重複提交：
       assert Envelope.token_hash ∉ used_token_hashes
       否 → 403 TOKEN_HASH_REUSED
    
    c. 解開外層：
       k_decoded = base64_decode(Envelope.c_key)
       k         = Dec_SK_CC(k_decoded)              // RSA-OAEP
    
    d. 暫存（不解內容，等待 Phase 4）：
       INSERT INTO envelopes (c_data, iv, tag, aad, k, token_hash, received_at, status='pending')
       INSERT INTO used_token_hashes (token_hash, recorded_at)
    
    e. 回傳 { status: "success", message: "envelope received" }
```

### 3.5 異常處理

| 錯誤碼 | 階段 | 原因 |
| --- | --- | --- |
| `TOKEN_SIGNATURE_INVALID` | TPA | Token 簽章驗證失敗 |
| `TOKEN_EXPIRED` | TPA | Token 已超過 expires_at |
| `TOKEN_ALREADY_USED` | TPA | Token 已用於前次盲簽章 |
| `TOKEN_HASH_REUSED` | CC | 同一 Token 被嘗試提交多次信封 |
| `DEADLINE_EXCEEDED` | TPA / CC | 超過投票截止時間 |

### 3.6 安全備註

| 編號 | 備註 |
| --- | --- |
| S-3.1 | 盲簽章使用 FDH 而非 textbook RSA，抵抗存在性偽造 |
| S-3.2 | Voter 可自我驗證盲簽章合法性（Step 3.7 self_check），避免接受惡意 TPA 之偽簽 |
| S-3.3 | Token 使用後立即標記為 used，須以 atomic update 防 TOCTOU |
| S-3.4 | Token 與 Envelope 之關聯透過 `token_hash = H(token_id)` 達成；CC 不需也不應持有原始 token，僅需 hash 即可去重 |
| S-3.5 | AES-GCM 之 AAD 包含 ID_Voter 與 SN，攻擊者無法將密文搬移至他人 envelope |
| S-3.6 | C_Key 採 RSA-OAEP 而非 PKCS#1 v1.5，抗 Bleichenbacher 攻擊 |
| S-3.7 | SN 由 Voter 本地產生且包含時間戳，雖無法保證全域唯一，但配合 Token 一次性即足以防雙重投票 |

---

## Phase 4：時間解密階段

### 4.1 目的

投票截止後，TA 在驗證請求方為合法 CC 後釋放 SK_TA；CC 解密內層密文取得 Vote 明文，並驗證每張選票合法性。

### 4.2 前置條件

- 當前時間 T_now ≥ T_DL
- 所有 envelopes 已於 Phase 3 暫存於 CC

### 4.3 形式化流程

```
─── Step 4.1：CC 構造 SK_TA 索取請求 ──────────────────────
    request_payload = {
        requester_id: "CC",
        timestamp:    T_CC,
        nonce:        N_CC,
        purpose:      "tally",
    }
    request_signature = Sig_CC(JSON_canonical(request_payload))
    
    POST TA /api/release_key {
        payload:    request_payload,
        signature:  base64(request_signature),
        cert_pem:   Cert_CC,
    }

─── Step 4.2：TA 驗證請求方 ───────────────────────────────
    a. 截止時間：assert T_now ≥ T_DL
       否 → 403 NOT_YET_DEADLINE
    
    b. 時間誤差：assert |T_now - request_payload.timestamp| ≤ ΔT
       否 → 403 TIMESTAMP_OUT_OF_RANGE
    
    c. 驗證 Cert_CC：
       assert verify_cert_with_ca(Cert_CC, Cert_CA) == True
       且 Cert_CC.subject.CN == "CC"
       否 → 403 CERT_INVALID
    
    d. 驗證請求簽章：
       PK_CC = extract_pubkey(Cert_CC)
       Verify_PK_CC(JSON_canonical(request_payload), request_signature) == True
       否 → 403 SIGNATURE_INVALID
    
    e. 防重放：
       assert request_payload.nonce ∉ ta_used_nonces
       否 → 403 NONCE_REPLAY

─── Step 4.3：TA 釋放 SK_TA ───────────────────────────────
    記錄 release_log：
        INSERT INTO key_release_log (requester_id, requested_at, status='released')
    
    記錄 nonce：
        INSERT INTO ta_used_nonces (nonce, recorded_at)
    
    回傳 {
        status:           "released",
        private_key_pem:  SK_TA (PEM),
        d_hex:            hex(d_TA),
        n_hex:            hex(n_TA),
        released_at:      T_now,
    }

─── Step 4.4：CC 對每張暫存信封執行解密驗證 ────────────────
    取得 (e_TPA, n_TPA) 由 TPA /api/public_key
    
    for each envelope in pending_envelopes:
        
        # 4.4.1 解 AES-GCM
        plaintext_or_⊥ = AES_GCM_Dec(
            key = envelope.k,
            iv  = envelope.iv,
            aad = envelope.aad,
            ciphertext = envelope.c_data,
            tag = envelope.tag,
        )
        若為 ⊥ → 標記 status='invalid_aead'，continue
        
        # 4.4.2 解析 AES 明文
        parts = plaintext.split("|")
        inner_enc_b64 = parts[0]
        S_prime_hex   = parts[1]
        m_hex         = parts[2]
        
        # 4.4.3 解內層 RSA-OAEP
        inner_enc = base64_decode(inner_enc_b64)
        inner_plaintext = Dec_SK_TA(inner_enc)        // RSA-OAEP
        若解密失敗 → 標記 status='invalid_oaep'，continue
        
        # 4.4.4 解析內層
        (inner_hash, vote_content) = inner_plaintext.split("|")
        
        # 4.4.5 重算 m_check
        m_check = H(inner_hash ‖ "|" ‖ vote_content)
        assert m_check == m_hex
        否 → 標記 status='hash_mismatch'，continue
        
        # 4.4.6 驗證盲簽章（FDH 版本）
        μ_check = FDH(int(m_hex, 16), bit_length(n_TPA))
        assert pow(int(S_prime_hex, 16), e_TPA, n_TPA) == μ_check
        否 → 標記 status='blind_sig_invalid'，continue
        
        # 4.4.7 SN 去重檢查
        sn_extracted = extract_sn_from_inner_hash(envelope, inner_hash)
        # 註：由於 inner_hash 不直接揭露 SN，此項實作上以 m_hex 去重即可
        assert m_hex ∉ used_m_hex_set
        否 → 標記 status='m_duplicate'，continue
        used_m_hex_set.add(m_hex)
        
        # 4.4.8 標記為合法
        INSERT INTO valid_votes (vote=vote_content, m_hex)
        UPDATE envelopes SET status='verified' WHERE id=envelope.id
```

### 4.4 異常處理

| 錯誤碼 | 階段 | 原因 |
| --- | --- | --- |
| `NOT_YET_DEADLINE` | TA | 投票尚未截止 |
| `CERT_INVALID` | TA | 請求方憑證無效或不是 CC |
| `SIGNATURE_INVALID` | TA | 請求簽章驗證失敗 |
| `NONCE_REPLAY` | TA | release_key 請求 nonce 重放 |
| `invalid_aead` | CC | AES-GCM 認證碼驗證失敗（密文被竄改）|
| `invalid_oaep` | CC | RSA-OAEP 解密失敗 |
| `hash_mismatch` | CC | m 雜湊不一致 |
| `blind_sig_invalid` | CC | 盲簽章驗證失敗 |
| `m_duplicate` | CC | 同一 m 重複出現（重放選票）|

### 4.5 安全備註

| 編號 | 備註 |
| --- | --- |
| S-4.1 | TA 對請求方做完整身分驗證（憑證 + 簽章 + 時戳 + nonce），杜絕「任意人取金鑰」漏洞 |
| S-4.2 | 即使 SK_TA 在 release 後被洩漏，由於 Phase 3 之 envelopes 已被 CC 接收完畢，攻擊者無法觀察新選票 |
| S-4.3 | AES-GCM 認證失敗即拒絕該票，保證密文完整性 |
| S-4.4 | m_hex 去重保證即使 token 機制被繞過，重放選票也會被偵測 |
| S-4.5 | 所有失敗類型分別記錄，提供事後審計與攻擊偵測 |

---

## Phase 5：計票與 Merkle Tree 建構階段

### 5.1 目的

CC 對所有合法選票進行計數、構建 Merkle Tree、對結果簽章後推送至 BB；BB 驗證 CC 簽章後始公告。

### 5.2 形式化流程

```
─── Step 5.1：CC 取出合法選票 ─────────────────────────────
    valid_votes = SELECT vote, m_hex FROM valid_votes ORDER BY id

─── Step 5.2：選票順序洗牌（v2.0 新增）─────────────────────
    使用 CSPRNG 對 valid_votes 隨機洗牌：
        shuffled_votes = secure_shuffle(valid_votes)
    
    後續所有公告均以 shuffled_votes 之順序進行，
    斷絕「提交順序 → 投票人」之關聯。

─── Step 5.3：建構 Merkle Tree（domain-separated）──────────
    leaves = [H_leaf(v.m_hex) for v in shuffled_votes]
    
    layers = [leaves]
    while len(current_layer) > 1:
        next_layer = []
        i = 0
        while i + 1 < len(current_layer):
            next_layer.append(H_node(current_layer[i], current_layer[i+1]))
            i += 2
        if i < len(current_layer):
            next_layer.append(current_layer[i])    # 上提，不複製
        layers.append(next_layer)
        current_layer = next_layer
    
    Root_official = current_layer[0]    # 若 leaves 為空則為 ""

─── Step 5.4：計票統計 ────────────────────────────────────
    Tally = {}
    for v in shuffled_votes:
        Tally[v.vote] = Tally.get(v.vote, 0) + 1

─── Step 5.5：CC 簽章開票結果包 ───────────────────────────
    Result_Bundle = {
        root_official:   Root_official,
        tally:           Tally,
        valid_m_hex_list: [v.m_hex for v in shuffled_votes],   // 公開 m_hex 但不公開對應 vote
        merkle_leaf_count: len(shuffled_votes),
        deadline:        T_DL,
        tallied_at:      T_now,
        cc_id:           "CC",
    }
    
    bundle_hash = H(JSON_canonical(Result_Bundle))
    Sig_CC_Bundle = Sig_CC(bundle_hash)
    
    Signed_Result = {
        bundle:    Result_Bundle,
        signature: base64(Sig_CC_Bundle),
        cert_pem:  Cert_CC,
    }

─── Step 5.6：CC → BB 推送結果 ─────────────────────────────
    POST BB /api/publish { Signed_Result }

─── Step 5.7：BB 驗證並公告 ────────────────────────────────
    a. 檢查是否已公告（不可覆蓋）：
       assert NOT EXISTS published_state
       否 → 403 ALREADY_PUBLISHED
    
    b. 驗證 Cert_CC：
       assert verify_cert_with_ca(Signed_Result.cert_pem, Cert_CA) == True
       且 Cert_CC.subject.CN == "CC"
       否 → 403 CERT_INVALID
    
    c. 重算 bundle_hash 並驗證簽章：
       PK_CC = extract_pubkey(Signed_Result.cert_pem)
       bundle_hash_check = H(JSON_canonical(Signed_Result.bundle))
       Verify_PK_CC(bundle_hash_check, Signed_Result.signature) == True
       否 → 403 SIGNATURE_INVALID
    
    d. 結構性檢查：
       assert Signed_Result.bundle.merkle_leaf_count == 
              len(Signed_Result.bundle.valid_m_hex_list)
       assert sum(Signed_Result.bundle.tally.values()) == 
              Signed_Result.bundle.merkle_leaf_count
       否 → 403 BUNDLE_INCONSISTENT
    
    e. 寫入持久化儲存：
       INSERT INTO published_state (
           root_official, tally_json, valid_m_hex_list_json,
           cc_signature, cc_cert_pem, tallied_at, published_at
       )
       SET published = TRUE
    
    f. 回傳 { status: "success" }

─── Step 5.8：BB 公告內容 ────────────────────────────────
    /api/results 回傳：
    {
        root_official:    Root_official,
        tally:            Tally,
        valid_m_hex_list: [m_hex_1, m_hex_2, ...],   // 已洗牌
        merkle_leaf_count: N,
        cc_signature:     base64(...),
        cc_cert_pem:      Cert_CC,
        tallied_at:       T,
        published_at:     T',
    }
    
    注意：BB **不公開** vote 對 m_hex 的對應關係。
          選民僅能驗證自己的 m_hex 是否在列表中（透過 Merkle Proof）。
```

### 5.3 安全備註

| 編號 | 備註 |
| --- | --- |
| S-5.1 | 選票順序洗牌徹底斷絕「提交順序 ↔ 投票人」之關聯（強化 P-2 隱私目標）|
| S-5.2 | Merkle Tree 葉/節 domain separator 防止 CVE-2012-2459 |
| S-5.3 | CC 簽章使 BB 不可偽造結果；任何篡改皆會被選民驗證偵測 |
| S-5.4 | BB 結構性檢查（leaf_count == |list|，sum(tally) == leaf_count）防止 CC 提交不一致資料 |
| S-5.5 | BB 一旦公告即不可覆蓋，避免「先發布測試結果再覆蓋真結果」之混淆 |
| S-5.6 | BB **不公開** (vote, m_hex) 對應，僅公開 m_hex 列表與整體 tally；強化 P-1 機密性 |

---

## Phase 6：使用者驗證階段

### 6.1 目的

選民獨立驗證自己的選票被正確納入 Merkle Tree、且 Merkle Root 來源確實為合法 CC。

### 6.2 前置條件

- BB 已完成 Phase 5 公告
- 選民本地保存有 (SN, Vote, m)

### 6.3 形式化流程

```
─── Step 6.1：選民取得 BB 公告之 Result_Bundle ────────────
    GET BB /api/results
    取得：{ root_official, valid_m_hex_list, cc_signature, cc_cert_pem, ... }

─── Step 6.2：選民驗證 Result_Bundle 之 CC 簽章 ───────────
    a. 驗證 cc_cert_pem：
       assert verify_cert_with_ca(cc_cert_pem, Cert_CA) == True
       否 → 警示「BB 上的結果未由合法 CC 簽章」
    
    b. 重算 bundle_hash 並驗證 cc_signature：
       PK_CC = extract_pubkey(cc_cert_pem)
       bundle_hash = H(JSON_canonical(bundle部分))
       Verify_PK_CC(bundle_hash, cc_signature) == True
       否 → 警示「結果可能被篡改」

─── Step 6.3：選民查詢自己的 Merkle Proof ─────────────────
    GET BB /api/merkle_proof/<m_hex>
    
    若 BB 回傳 404：表示 m_hex 不在合法選票列表中
        → 警示「您的選票未被計入！」
    若 BB 回傳 200，取得：
        { m_hex, merkle_proof: [{sibling, position}, ...], root_official }

─── Step 6.4：選民本地端執行 Merkle Proof 驗證 ────────────
    current = H_leaf(m_hex)
    for step in merkle_proof:
        if step.position == "right":
            current = H_node(current, step.sibling)
        else:    # "left"
            current = H_node(step.sibling, current)
    
    Root_calculated = current

─── Step 6.5：與 BB 公告之 Root 比對 ──────────────────────
    if Root_calculated == root_official:
        ✅ 選票合法且已被計入
    else:
        ⚠️ 警示「選票驗證失敗，可能被竄改」
```

### 6.4 安全備註

| 編號 | 備註 |
| --- | --- |
| S-6.1 | 驗證起點為 H_leaf(m)（domain-separated），與 Merkle Tree 構造一致 |
| S-6.2 | 選民**先**驗證 CC 簽章再驗證 Merkle Proof，避免被假結果欺騙 |
| S-6.3 | 即使 BB 整體被攻陷，選民仍可透過 (cc_signature, root_official) 確認結果合法性 |
| S-6.4 | 選民驗證失敗時應公開（例如至 GitHub Issues），由社群檢視是否系統性問題 |

---

# 第五部分：介面規格

## 18. RESTful API 規格

> 本章為實作核心。所有端點以 JSON 通訊，HTTP 狀態碼遵循 RFC 7231。
> 錯誤回應統一格式為：
> ```json
> { "status": "error", "code": "ERROR_CODE", "message": "human readable" }
> ```

### 18.1 CA Server (port 5001)

#### 18.1.1 `GET /api/ca_cert`
- **公開**
- 回傳 CA 根憑證
- Response 200:
  ```json
  { "status": "success", "ca_certificate": "-----BEGIN CERTIFICATE-----..." }
  ```

#### 18.1.2 `POST /api/issue_cert`
- **認證**：OTP + PoP（v2.0 新增）
- Request:
  ```json
  {
    "entity_id":     "VOTER_001",
    "public_key":    "-----BEGIN PUBLIC KEY-----...",
    "otp":           "<base64url 24 chars>",
    "timestamp":     1730000000,
    "pop_signature": "<base64 of Sig_Voter('REGISTER|'+ID+'|'+timestamp)>"
  }
  ```
- Response 200:
  ```json
  { "status": "success", "certificate": "-----BEGIN CERTIFICATE-----..." }
  ```
- Response 403: `ENTITY_NOT_REGISTERED` / `ALREADY_REGISTERED` / `OTP_INVALID` / `TIMESTAMP_OUT_OF_RANGE` / `POP_INVALID`

#### 18.1.3 `POST /api/admin/register_voter` (內部)
- **認證**：Admin Bearer Token
- 用途：Admin 預先寫入 voter_registry
- Request:
  ```json
  {
    "voter_id":  "VOTER_001",
    "otp_hash":  "<hex of H(otp)>",
    "expires_at": 1730500000
  }
  ```

### 18.2 TPA Server (port 5000)

#### 18.2.1 `GET /api/public_key`
- **公開**
- Response 200:
  ```json
  {
    "status":         "success",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----...",
    "e":              "0x10001",
    "n":              "0x..."
  }
  ```

#### 18.2.2 `POST /api/auth`
- **認證**：Voter 簽章封包
- Request:
  ```json
  {
    "auth_packet": {
      "payload": {
        "sender_id":   "VOTER_001",
        "receiver_id": "TPA",
        "timestamp":   1730000000,
        "nonce":       "<32 hex chars>",
        "cert_pem":    "-----BEGIN CERTIFICATE-----..."
      },
      "signature": "<base64 RSA-PSS sig>"
    }
  }
  ```
- Response 200:
  ```json
  {
    "status": "success",
    "response_packet": {
      "payload": { ...含 nonce_echo... },
      "signature": "<base64>"
    },
    "voting_token": {
      "payload": {
        "token_id":   "<64 hex chars>",
        "voter_id":   "VOTER_001",
        "issued_at":  1730000000,
        "expires_at": 1730000600,
        "nonce_bind": "<32 hex chars>"
      },
      "signature": "<base64>"
    }
  }
  ```
- Response 403: 見 §2.5

#### 18.2.3 `POST /api/blind_sign`
- **認證**：Voting Token
- Request:
  ```json
  {
    "m_prime_hex": "0x...",
    "voting_token": {
      "payload":   { ... },
      "signature": "<base64>"
    }
  }
  ```
- Response 200:
  ```json
  { "status": "success", "S_hex": "0x..." }
  ```
- Response 403: `TOKEN_SIGNATURE_INVALID` / `TOKEN_EXPIRED` / `TOKEN_ALREADY_USED` / `DEADLINE_EXCEEDED`

#### 18.2.4 `GET /api/cert`
- **公開**
- 回傳 Cert_TPA（PEM）

### 18.3 TA Server (port 5002)

#### 18.3.1 `GET /api/public_key`
- **公開**
- 回傳 PK_TA PEM

#### 18.3.2 `GET /api/deadline`
- **公開**
- Response 200:
  ```json
  {
    "status":            "success",
    "deadline":          1730000600,
    "deadline_signature": "<base64 Sig_TA(deadline)>",
    "server_time":       1730000123,
    "remaining_seconds": 477,
    "is_expired":        false
  }
  ```

#### 18.3.3 `POST /api/release_key`
- **認證**：CC 簽章請求 + Cert_CC（v2.0 新增）
- Request:
  ```json
  {
    "payload": {
      "requester_id": "CC",
      "timestamp":    1730000700,
      "nonce":        "<32 hex chars>",
      "purpose":      "tally"
    },
    "signature": "<base64 Sig_CC(...)>",
    "cert_pem":  "-----BEGIN CERTIFICATE-----..."
  }
  ```
- Response 200:
  ```json
  {
    "status":          "released",
    "private_key_pem": "-----BEGIN PRIVATE KEY-----...",
    "d_hex":           "0x...",
    "n_hex":           "0x...",
    "released_at":     1730000700
  }
  ```
- Response 403: `NOT_YET_DEADLINE` / `CERT_INVALID` / `SIGNATURE_INVALID` / `NONCE_REPLAY`

### 18.4 CC Server (port 5003)

#### 18.4.1 `GET /api/public_key`
- **公開**

#### 18.4.2 `GET /api/cert`
- **公開**

#### 18.4.3 `POST /api/receive_envelope`
- **認證**：Token Hash 綁定
- Request:
  ```json
  {
    "c_data":     "<base64>",
    "iv":         "<base64>",
    "tag":        "<base64>",
    "aad":        "<base64>",
    "c_key":      "<base64>",
    "token_hash": "<64 hex chars>"
  }
  ```
- Response 200:
  ```json
  { "status": "success", "message": "envelope received" }
  ```
- Response 403: `DEADLINE_EXCEEDED` / `TOKEN_HASH_REUSED`

#### 18.4.4 `POST /api/tally`
- **認證**：內部 IP 白名單 + Admin 簽章
- 觸發 Phase 4 + Phase 5
- Response 200:
  ```json
  {
    "status":      "success",
    "valid_count": 42,
    "tally":       {"candidate_a": 30, "candidate_b": 12},
    "merkle_root": "<hex>"
  }
  ```

#### 18.4.5 `GET /api/results`
- **公開**
- 回傳 CC 內部之 Result_Bundle（含 cc_signature）

#### 18.4.6 `GET /api/merkle_proof/<int:index>`
- **公開**

### 18.5 BB Server (port 5004)

#### 18.5.1 `POST /api/publish`
- **認證**：CC 簽章結果包 + Cert_CC
- Request:
  ```json
  {
    "bundle": {
      "root_official":     "<hex>",
      "tally":             {"candidate_a": 30},
      "valid_m_hex_list":  ["0x...", "0x..."],
      "merkle_leaf_count": 42,
      "deadline":          1730000600,
      "tallied_at":        1730000700,
      "cc_id":             "CC"
    },
    "signature": "<base64 Sig_CC(...)>",
    "cert_pem":  "-----BEGIN CERTIFICATE-----..."
  }
  ```
- Response 200: `{ "status": "success" }`
- Response 403: `ALREADY_PUBLISHED` / `CERT_INVALID` / `SIGNATURE_INVALID` / `BUNDLE_INCONSISTENT`

#### 18.5.2 `GET /api/results`
- **公開**
- 回傳完整 Signed_Result 供選民驗證

#### 18.5.3 `GET /api/merkle_proof/<m_hex>`
- **公開**
- Response 200:
  ```json
  {
    "status":        "success",
    "m_hex":         "0x...",
    "leaf_hash":     "<hex>",
    "merkle_proof":  [{"sibling": "<hex>", "position": "left|right"}, ...],
    "root_official": "<hex>"
  }
  ```
- Response 404 if m_hex not found

### 18.6 通用約定

| 項目 | 規範 |
| --- | --- |
| Content-Type | `application/json` |
| 字符編碼 | UTF-8 |
| 時間戳 | Unix timestamp (秒)，所有 API 一律使用 |
| 大整數 | hex string 帶 `0x` 前綴 |
| 二進位資料 | base64 (URL-safe 否，標準 base64) |
| Canonical JSON | `json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':'))` |

---

## 19. 資料模型（Database Schema）

> 各服務各自持有 SQLite 資料庫，路徑為 `<service_dir>/<service>.db`。

### 19.1 CA Database

```sql
-- 選民/服務白名單（v2.0 新增）
CREATE TABLE voter_registry (
    entity_id           TEXT PRIMARY KEY,
    otp_hash            TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('pending', 'registered', 'revoked')),
    registered_at       INTEGER NOT NULL,
    expires_at          INTEGER,
    issued_cert_serial  TEXT,
    issued_at           INTEGER,
    fail_count          INTEGER DEFAULT 0,
    locked_until        INTEGER
);

CREATE TABLE issued_certs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id         TEXT NOT NULL,
    cert_serial       TEXT NOT NULL UNIQUE,
    cert_pem          TEXT NOT NULL,
    issued_at         TEXT NOT NULL,
    revoked_at        TEXT
);

CREATE INDEX idx_issued_certs_entity ON issued_certs(entity_id);
```

### 19.2 TPA Database

```sql
-- 已用 nonce（防重放）
CREATE TABLE used_nonces (
    nonce       TEXT PRIMARY KEY,
    sender_id   TEXT NOT NULL,
    used_at     INTEGER NOT NULL
);

-- 已投票選民（防重複投票）
CREATE TABLE voted_users (
    sender_id   TEXT PRIMARY KEY,
    voted_at    INTEGER NOT NULL
);

-- Voting Token 簽發記錄（v2.0 新增）
CREATE TABLE issued_tokens (
    token_id    TEXT PRIMARY KEY,
    voter_id    TEXT NOT NULL UNIQUE,
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    used_at     INTEGER
);

CREATE INDEX idx_issued_tokens_voter ON issued_tokens(voter_id);

-- 認證日誌
CREATE TABLE auth_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id    TEXT NOT NULL,
    nonce        TEXT NOT NULL,
    status       TEXT NOT NULL,
    reason       TEXT,
    processed_at INTEGER NOT NULL
);

-- 盲簽章日誌
CREATE TABLE blind_sign_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id        TEXT NOT NULL,
    blinded_m_hex   TEXT NOT NULL,
    signed_b_m_hex  TEXT NOT NULL,
    created_at      INTEGER NOT NULL
);
```

### 19.3 TA Database

```sql
-- 私鑰釋放日誌
CREATE TABLE key_release_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_id  TEXT,
    requested_at  INTEGER NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('released', 'rejected')),
    reason        TEXT
);

-- 防重放（v2.0 新增）
CREATE TABLE ta_used_nonces (
    nonce        TEXT PRIMARY KEY,
    requester_id TEXT NOT NULL,
    used_at      INTEGER NOT NULL
);
```

### 19.4 CC Database

```sql
-- 已接收信封
CREATE TABLE envelopes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    c_data       TEXT NOT NULL,
    iv           TEXT NOT NULL,
    tag          TEXT NOT NULL,    -- v2.0 新增：AES-GCM auth tag
    aad          TEXT NOT NULL,    -- v2.0 新增：AES-GCM AAD
    k            TEXT NOT NULL,    -- 解開 C_Key 後的 AES key (base64)
    token_hash   TEXT NOT NULL,    -- v2.0 新增：與 token 綁定
    received_at  INTEGER NOT NULL,
    status       TEXT NOT NULL CHECK (status IN
                  ('pending', 'verified', 'invalid_aead', 'invalid_oaep',
                   'hash_mismatch', 'blind_sig_invalid', 'm_duplicate'))
);

CREATE INDEX idx_envelopes_status ON envelopes(status);

-- Token Hash 去重（v2.0 新增）
CREATE TABLE used_token_hashes (
    token_hash   TEXT PRIMARY KEY,
    recorded_at  INTEGER NOT NULL
);

-- 合法選票（已洗牌順序）
CREATE TABLE valid_votes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    vote         TEXT NOT NULL,
    m_hex        TEXT NOT NULL UNIQUE,    -- v2.0 強制 UNIQUE
    verified_at  INTEGER NOT NULL,
    shuffle_seq  INTEGER                  -- v2.0 新增：洗牌後順序
);

-- 計票狀態
CREATE TABLE tally_state (
    key   TEXT PRIMARY KEY,
    value TEXT
);
-- key 範例：'done', 'merkle_root', 'tally_json',
--           'cc_signature', 'tallied_at', 'tpa_e', 'tpa_n'
```

### 19.5 BB Database

```sql
-- 公告狀態（v2.0 強化：含 CC 簽章）
CREATE TABLE published_state (
    key   TEXT PRIMARY KEY,
    value TEXT
);
-- key 範例：'published', 'root_official', 'tally_json',
--           'valid_m_hex_list_json', 'merkle_leaf_count',
--           'cc_signature', 'cc_cert_pem', 'tallied_at', 'published_at'

-- 已公告之 m_hex 列表（依洗牌後順序）
CREATE TABLE published_m_hex_list (
    seq      INTEGER PRIMARY KEY,
    m_hex    TEXT NOT NULL UNIQUE,
    leaf_hash TEXT NOT NULL
);

CREATE INDEX idx_published_m_hex ON published_m_hex_list(m_hex);

-- 注意：v2.0 之 BB **不儲存** vote 對 m_hex 的對應關係，
--       僅儲存 m_hex 列表與整體 tally 統計
```

### 19.6 Voter Database

```sql
-- 本地投票記錄
CREATE TABLE vote_record (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    voter_id      TEXT NOT NULL,
    sn            TEXT NOT NULL,
    vote          TEXT NOT NULL,
    m_hex         TEXT NOT NULL,
    s_prime_hex   TEXT NOT NULL,
    voting_token  TEXT,                    -- v2.0 新增
    voted_at      INTEGER NOT NULL,
    status        TEXT NOT NULL
);

-- 投票流程日誌
CREATE TABLE vote_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    step      TEXT NOT NULL,
    message   TEXT,
    status    TEXT NOT NULL,
    logged_at INTEGER NOT NULL
);
```

---

## 20. 訊息封包格式（JSON Schema）

> 本節以 JSON Schema Draft 2020-12 描述關鍵訊息結構，可直接用於請求驗證。

### 20.1 Auth Packet (`Auth_x→y`)

```json
{
  "$id": "https://nutc-voting/schema/auth_packet.json",
  "type": "object",
  "required": ["payload", "signature"],
  "properties": {
    "payload": {
      "type": "object",
      "required": ["sender_id", "receiver_id", "timestamp", "nonce", "cert_pem"],
      "properties": {
        "sender_id":   { "type": "string", "pattern": "^[A-Z0-9_]+$" },
        "receiver_id": { "type": "string", "pattern": "^[A-Z0-9_]+$" },
        "timestamp":   { "type": "integer", "minimum": 0 },
        "nonce":       { "type": "string", "pattern": "^[0-9a-f]{32}$" },
        "nonce_echo":  { "type": "string", "pattern": "^[0-9a-f]{32}$" },
        "cert_pem":    { "type": "string", "pattern": "^-----BEGIN CERTIFICATE-----" }
      }
    },
    "signature": {
      "type": "string",
      "contentEncoding": "base64"
    }
  }
}
```

### 20.2 Voting Token

```json
{
  "$id": "https://nutc-voting/schema/voting_token.json",
  "type": "object",
  "required": ["payload", "signature"],
  "properties": {
    "payload": {
      "type": "object",
      "required": ["token_id", "voter_id", "issued_at", "expires_at", "nonce_bind"],
      "properties": {
        "token_id":   { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "voter_id":   { "type": "string" },
        "issued_at":  { "type": "integer" },
        "expires_at": { "type": "integer" },
        "nonce_bind": { "type": "string", "pattern": "^[0-9a-f]{32}$" }
      }
    },
    "signature": { "type": "string", "contentEncoding": "base64" }
  }
}
```

### 20.3 Envelope `P`

```json
{
  "$id": "https://nutc-voting/schema/envelope.json",
  "type": "object",
  "required": ["c_data", "iv", "tag", "aad", "c_key", "token_hash"],
  "properties": {
    "c_data":     { "type": "string", "contentEncoding": "base64" },
    "iv":         { "type": "string", "contentEncoding": "base64" },
    "tag":        { "type": "string", "contentEncoding": "base64" },
    "aad":        { "type": "string", "contentEncoding": "base64" },
    "c_key":      { "type": "string", "contentEncoding": "base64" },
    "token_hash": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
  }
}
```

### 20.4 Result Bundle (Phase 5 → BB)

```json
{
  "$id": "https://nutc-voting/schema/result_bundle.json",
  "type": "object",
  "required": ["bundle", "signature", "cert_pem"],
  "properties": {
    "bundle": {
      "type": "object",
      "required": ["root_official", "tally", "valid_m_hex_list",
                   "merkle_leaf_count", "deadline", "tallied_at", "cc_id"],
      "properties": {
        "root_official":     { "type": "string", "pattern": "^[0-9a-f]*$" },
        "tally":             { "type": "object", "additionalProperties": { "type": "integer" } },
        "valid_m_hex_list":  { "type": "array", "items": { "type": "string" } },
        "merkle_leaf_count": { "type": "integer", "minimum": 0 },
        "deadline":          { "type": "integer" },
        "tallied_at":        { "type": "integer" },
        "cc_id":             { "type": "string", "const": "CC" }
      }
    },
    "signature": { "type": "string", "contentEncoding": "base64" },
    "cert_pem":  { "type": "string" }
  }
}
```


---

# 第六部分：安全性分析

## 21. 安全性論證

> 本章對應第 4 章「安全目標」，逐項論證 v2.0 系統如何達成。

### 21.1 機密性 C-1：投票內容機密性

**目標**：在投票截止前，除選民本人外，無人能得知任一選票之 Vote 明文。

**論證**：

1. Voter 將 Vote 透過 `inner_plaintext = inner_hash || Vote` 用 RSA-OAEP（PK_TA）加密為 `inner_enc`。
2. `inner_enc` 又被 AES-256-GCM（金鑰 k）封裝為 `C_Data`。
3. `k` 又被 RSA-OAEP（PK_CC）封裝為 `C_Key`。
4. **截止前**，欲取得 Vote 必須同時持有 SK_CC 與 SK_TA。
5. SK_CC 僅 CC 持有，SK_TA 僅 TA 持有。
6. CC 不會主動洩漏 SK_CC（誠實假設 §3.2）。
7. **TA 在 T_now < T_DL 時拒絕釋放 SK_TA**（Phase 4 Step 4.2.a）。
8. 因此唯有 (CC + TA) 合謀且攻破 TA 時序限制，才能解票 → 在單一角色作惡威脅模型下不可行。

✅ C-1 達成。

### 21.2 機密性 C-2：選民—選票不可關聯

**目標**：截止後 Vote 公開，但 TPA/CC/BB 任一單獨無法將 Vote 對應到 Voter。

**論證**：

| 攻擊角色 | 知道的資訊 | 為何無法關聯 |
| --- | --- | --- |
| TPA | (ID_Voter, m', S) | m' 為盲化值；TPA 在計算上無法從 m' 反推 m，因 r 為均勻隨機（盲簽章不可關聯性 / unlinkability） |
| CC | (Vote, m_hex, m_hex 提交順序) | CC 不知 m 對應哪個 Voter；提交順序在 §5.2 經洗牌 |
| BB | (Vote, m_hex 列表) 但不對應 | BB 僅儲存洗牌後之 m_hex 列表與整體 tally，不揭露對應關係（§19.5）|

✅ C-2 達成。

### 21.3 完整性 I-1：選票不可篡改

**論證**：

1. 攻擊者欲修改一張合法選票需通過 CC 之四重驗證：
   - AES-GCM Tag 驗證（修改 C_Data 必致 Tag 失敗）
   - RSA-OAEP 解密驗證（修改 C_Key 必致解密失敗）
   - m hash 重算比對（修改內層 Vote 必致 m_check ≠ m_hex）
   - 盲簽章驗證（任何修改 m 必致 (S')^e ≠ FDH(m)）
2. AES-GCM 偽造 Tag 之機率 ≤ 2⁻¹²⁸。
3. RSA-OAEP 在 IND-CCA2 下安全。
4. 盲簽章基於 RSA-FDH 假設，偽造機率為 negl(λ)。

✅ I-1 達成。

### 21.4 完整性 I-2：計票結果不可篡改

**論證**：

1. CC 對 Result_Bundle 進行 RSA-PSS 簽章。
2. BB 在 Step 5.7 驗證 Cert_CC、bundle 簽章、結構性檢查。
3. 攻擊者欲改 BB 上之 root_official 或 tally：
   - 直接寫入 BB 資料庫 → 選民查 /api/results 時驗證 cc_signature 失敗
   - 重發 publish → BB 拒絕（ALREADY_PUBLISHED）
   - 偽造 CC 簽章 → 不持有 SK_CC，無法產生合法 PSS 簽章
4. 即使 BB 整體被攻陷，選民仍能透過驗證 cc_signature 偵測篡改。

✅ I-2 達成。

### 21.5 完整性 I-3：一人一票

**論證**：

| 防線 | 機制 | 對應威脅 |
| --- | --- | --- |
| 第一防線 | TPA voted_users 表，每 sender_id 僅可 auth 一次 | 重複認證 |
| 第二防線 | TPA issued_tokens 表，每 voter_id 僅可發一次 token | 多取 token |
| 第三防線 | TPA 驗證 token 並標記為 used，每 token 僅可換一次盲簽章 | 一票多簽（v1.0 之破口）|
| 第四防線 | CC used_token_hashes 表，每 token_hash 僅可提交一次信封 | 同 token 多次提交 |
| 第五防線 | CC m_hex UNIQUE 與去重，重放選票必被拒 | 信封重放 |
| 第六防線 | AES-GCM AAD 含 ID_Voter ‖ SN，跨 voter 移植封包必失敗 | 信封挪移 |

✅ I-3 達成（需任一防線生效即可，本系統為**深度防禦**）。

### 21.6 可驗證性 V-1：個別可驗證

**論證**：選民執行 Phase 6 流程：(a) 驗證 CC 簽章 → (b) 取 Merkle Proof → (c) 本地計算 Root → (d) 比對。任何環節失敗皆能被選民個別偵測。✅

### 21.7 可驗證性 V-2：全域可驗證

**論證**：任何第三方可執行：

1. 自 BB 取得 (root_official, valid_m_hex_list, tally, cc_signature, cc_cert_pem)
2. 驗證 cc_cert_pem 為 CA 簽發
3. 驗證 cc_signature 對 bundle 之合法性
4. 重建 Merkle Tree from valid_m_hex_list，比對 root_official
5. 比對 |valid_m_hex_list| == merkle_leaf_count == sum(tally.values)

✅ V-2 達成。

### 21.8 隱私性 P-1：投票匿名性

**論證**：基於 RSA-FDH-Blind 之**unlinkability** 性質（Chaum '82）：給定 (m', S) 與最後出現的 (m, S')，TPA 無法在多項式時間內判斷哪些 (m, S') 對應到自己處理過的 (m', S)，因 r 為均勻隨機。

✅ P-1 達成（基於 RSA 假設）。

### 21.9 隱私性 P-2：提交順序匿名性

**論證**：CC 在 §5.2 對 valid_votes 執行 secure_shuffle（基於 CSPRNG）。BB 公告之 m_hex 順序與 envelopes 接收順序無關。即使 ISP 級攻擊者監聽到「VOTER_001 在時刻 t 提交」，也無法從 BB 公開列表中辨識哪個 m_hex 屬於 VOTER_001。

✅ P-2 達成。

### 21.10 抗攻擊能力總表

| 攻擊類型 | 對應威脅模型 | v1.0 是否存在 | v2.0 防禦機制 |
| --- | --- | --- | --- |
| 假冒實體申請憑證 | A8 | ✗ 無防禦 | ✓ Phase 0 OTP + PoP |
| 認證後一票多簽 | A3 | ✗ 無防禦 | ✓ Voting Token 一次性 |
| 任意人取 SK_TA | A8 | ✗ 無防禦 | ✓ TA 對請求方驗證 |
| 偽造 BB 開票結果 | A6, A8 | ✗ 無防禦 | ✓ CC 簽章 + BB 驗章 |
| 重複公告覆蓋 | A6, A8 | ✗ 無防禦 | ✓ ALREADY_PUBLISHED 鎖 |
| 盲簽章存在性偽造 | A3 | ✗ textbook RSA | ✓ FDH 擴展 |
| AES-CFB 位元翻轉 | A2 | ✗ 無 MAC | ✓ AES-GCM AEAD |
| Merkle Tree CVE-2012-2459 | A6 | ✗ 末葉重複 | ✓ Domain separator + 上提 |
| 提交順序解匿 | A2, A4 | ✗ 順序保留 | ✓ secure_shuffle |
| 重放認證封包 | A2 | ✓ 已有 nonce | ✓ 保留 |
| 選票重放 | A2, A3 | ◎ 部分（無 SN 去重）| ✓ m_hex UNIQUE + token_hash 去重 |
| 信封挪移 | A2 | ✗ 無 AAD | ✓ AES-GCM AAD 綁定 |
| 未來時戳攻擊 | A2 | ✗ 單向檢查 | ✓ 雙向 \|T_now - T\| ≤ ΔT |

---

## 22. 已知限制與未來工作

### 22.1 已知限制

| 編號 | 限制 | 說明 |
| --- | --- | --- |
| L-1 | 單一信任根 | CA 為唯一信任點；CA 被攻破則全系統信任崩潰。緩解：分散 CA / 門檻簽章 |
| L-2 | 無 Receipt-Free | 選民可向第三方證明自己的投票（透過 SN, Vote, m）→ 不抗強制投票 |
| L-3 | 多角色合謀 | TPA + CC 合謀可解匿名；本版本僅承諾抗單一角色作惡 |
| L-4 | 不抗量子 | RSA-2048 在量子計算下不安全 |
| L-5 | 無法驗證選民資格之即時性 | Cert_Voter 一經簽發無 OCSP/CRL 查詢，吊銷需重發 CA |
| L-6 | OTP 派送通道為系統外假設 | OTP 之安全性依賴 Admin 之派送機制 |
| L-7 | 私鑰明文儲存於 Docker volume | 應升級為加密儲存或 HSM |

### 22.2 未來工作（v3.0 候選議題）

1. **門檻盲簽章（Threshold Blind Signature）**：將 SK_TPA 分散至 t-of-n 個 TPA 節點
2. **Mix-Net 替代 secure_shuffle**：以可驗證 mix-net 強化匿名性與透明度
3. **零知識證明（ZKP）增強驗證**：CC 對「Tally 正確性」附 ZKP 證明
4. **OCSP / CRL**：CA 提供憑證吊銷狀態查詢
5. **加密私鑰儲存**：以 passphrase 或 HSM 保護 SK_x
6. **Post-Quantum 升級**：以 Kyber/Dilithium 取代 RSA
7. **Receipt-Free 機制**：採 JCJ/Civitas 等協定抗強制投票
8. **正式形式化驗證**：以 ProVerif / Tamarin 對協定進行符號驗證

---

# 第七部分：實作與部署

## 23. 容器化部署架構

### 23.1 容器清單

| 服務 | 映像 | 對外 Port | 內部 Port | Volume |
| --- | --- | --- | --- | --- |
| ca | nutc-voting | 5001 | 5001 | ca_keys |
| tpa | nutc-voting | 5000 | 5000 | tpa_keys |
| ta | nutc-voting | 5002 | 5002 | ta_keys |
| cc | nutc-voting | 5003 | 5003 | cc_keys |
| bb | nutc-voting | 5004 | 5004 | (無) |
| voter1...N | nutc-voting | 5005...5005+N-1 | 5005 | voter{i}_keys |

### 23.2 啟動順序與健康檢查

```
ca (healthy) → tpa, ta, cc 並行啟動 → bb → voter1..N
```

健康檢查要求：

| 服務 | endpoint | 期望回應 |
| --- | --- | --- |
| ca | `GET /api/ca_cert` | 200 |
| tpa | `GET /api/public_key` | 200 |
| ta | `GET /api/deadline` | 200 |
| cc | `GET /api/public_key` | 200 |
| bb | `GET /api/results` | 200 |

### 23.3 環境變數規範

| 變數 | 適用 | 用途 |
| --- | --- | --- |
| `PYTHONPATH=/app` | 全部 | 共用模組 import |
| `TZ=Asia/Taipei` | 全部 | 容器時區 |
| `CA_URL` | 非 ca 服務 | CA 端點 |
| `TPA_URL`, `TA_URL`, `CC_URL`, `BB_URL` | 各服務間參考 | RPC 端點 |
| `VOTER_ID` | voter | 選民識別碼 |
| `VOTE_DURATION_SECONDS` | ta | 投票時長（秒） |
| `DELTA_T` | tpa, ta | 時間誤差容忍（秒） |
| `SERVICE_REGISTRATION_TOKEN` | tpa, ta, cc | Phase 0/1 服務註冊用 |
| `ADMIN_API_TOKEN` | ca, cc | 內部管理 API |

### 23.4 網路拓撲

- 預設 Docker bridge network `voting_net`
- 對外僅曝露各 service port（5000-5007）
- 內部端點（如 `CC /api/tally`）建議綁定至 `127.0.0.1` 並透過 `docker exec` 執行

---

## 24. 設定檔規範

`config.json` 結構：

```json
{
  "candidates": ["候選人 A", "候選人 B", "候選人 C"],
  "voters": [
    { "id": "VOTER_001", "port": 5005 },
    { "id": "VOTER_002", "port": 5006 }
  ],
  "services": {
    "ca":  { "host": "ca",  "port": 5001, "local_port": 5001 },
    "tpa": { "host": "tpa", "port": 5000, "local_port": 5000 },
    "ta":  { "host": "ta",  "port": 5002, "local_port": 5002 },
    "cc":  { "host": "cc",  "port": 5003, "local_port": 5003 },
    "bb":  { "host": "bb",  "port": 5004, "local_port": 5004 }
  },
  "timing": {
    "vote_duration_seconds": 300,
    "delta_t_seconds":       300,
    "token_lifetime_seconds": 600,
    "service_startup_wait":   5,
    "health_check_retries":   15,
    "health_check_interval":  3
  },
  "crypto": {
    "rsa_key_size":  2048,
    "aes_key_size":  256,
    "aes_iv_size":   12,
    "aes_tag_size":  16,
    "fdh_target_bits": 2048
  },
  "security": {
    "max_otp_attempts":     3,
    "otp_lockout_seconds":  86400,
    "merkle_domain_leaf":   "0x00",
    "merkle_domain_node":   "0x01"
  }
}
```

熱重載：所有服務以 mtime 偵測 config.json 變更；安全關鍵參數（如 `crypto.*`）建議標記為**啟動時鎖定**，不接受 hot reload。

---

## 25. 攻擊驗證計畫

> 為強化專題之資安主題深度，建議實作以下攻擊腳本主動驗證系統防禦能力。

### 25.1 攻擊腳本總表

| 編號 | 腳本名稱 | 攻擊目標 | 預期結果（v2.0）|
| --- | --- | --- | --- |
| AT-01 | `attack_unauth_cert.py` | 嘗試以未註冊 ID 取得 CA 憑證 | 403 ENTITY_NOT_REGISTERED |
| AT-02 | `attack_double_vote.py` | 一個 Voter 認證後嘗試取得多個盲簽章 | 第二次 403 TOKEN_ALREADY_USED |
| AT-03 | `attack_steal_sk_ta.py` | 任意人嘗試從 TA 取得私鑰 | 403 CERT_INVALID 或 SIGNATURE_INVALID |
| AT-04 | `attack_fake_publish.py` | 攻擊者偽造 publish 至 BB | 403 SIGNATURE_INVALID |
| AT-05 | `attack_textbook_rsa.py` | 利用 RSA 乘法同態偽造盲簽章 | CC 驗證失敗（FDH 不滿足）|
| AT-06 | `attack_replay_envelope.py` | 重放他人合法 envelope | 403 TOKEN_HASH_REUSED |
| AT-07 | `attack_aes_bitflip.py` | 對 AES-CFB 位元翻轉（驗證 v2.0 GCM 防禦） | 解密 invalid_aead |
| AT-08 | `attack_merkle_collision.py` | 嘗試 CVE-2012-2459 二次原像 | Merkle Proof 驗證失敗 |
| AT-09 | `attack_future_timestamp.py` | 偽造未來時戳之認證封包 | 403 TIMESTAMP_OUT_OF_RANGE |
| AT-10 | `attack_envelope_swap.py` | 將自己的 c_data 與他人 c_key 拼接 | 403 invalid_aead（AAD 不符）|

### 25.2 攻擊腳本撰寫框架

```python
# attack_<name>.py 共用結構
import requests
from typing import Tuple

class AttackTest:
    name: str
    description: str
    expected_error_code: str
    
    def setup(self) -> None:
        """準備攻擊環境（如取得合法憑證）"""
        ...
    
    def execute(self) -> Tuple[int, dict]:
        """執行攻擊；回傳 (HTTP status, response body)"""
        ...
    
    def assert_defense(self, status: int, body: dict) -> bool:
        """驗證系統正確抵擋"""
        return status == 403 and body.get("code") == self.expected_error_code
    
    def run(self):
        self.setup()
        status, body = self.execute()
        if self.assert_defense(status, body):
            print(f"✅ {self.name}: 系統成功抵禦")
        else:
            print(f"❌ {self.name}: 系統未能抵禦！")
            print(f"   預期 403 + {self.expected_error_code}")
            print(f"   實際 {status} + {body}")
```

### 25.3 整合測試

`run_all_attacks.py`：

```bash
$ python run_all_attacks.py
✅ AT-01: 系統成功抵禦未註冊憑證申請
✅ AT-02: 系統成功抵禦一票多簽
✅ AT-03: 系統成功抵禦私鑰任意取得
...
總計：10/10 攻擊均被正確抵禦
```

---

# 附錄

## 附錄 A：完整訊息流程圖

### A.1 主流程序列圖

```
Voter      CA      TPA       TA      CC       BB
  │         │       │        │       │        │
  │ Phase 0：選民註冊（OTP + PoP）   │        │
  │────────►│       │        │       │        │
  │◄──Cert──│       │        │       │        │
  │         │       │        │       │        │
  │ Phase 1：服務啟動（並行）        │        │
  │         │◄──get cert──────────────┴────────┤
  │         │                                  │
  │ Phase 2：身分驗證              │        │
  │─Auth──────────►│        │       │        │
  │◄─AuthResp+Token│        │       │        │
  │         │       │        │       │        │
  │ Phase 3：盲簽章選票             │        │
  │─m', Token─────►│        │       │        │
  │◄──S─────────── │        │       │        │
  │  (本地去盲化、自我驗證)         │        │
  │─Envelope──────────────────────►│        │
  │◄──ack───────────────────────── │        │
  │         │       │        │       │        │
  │         │       │   Phase 4：時間解密     │
  │         │       │        │ ◄──req(sig)── │
  │         │       │        │ ──SK_TA────►  │
  │         │       │        │       │        │
  │         │       │ Phase 5：計票 + 簽章 + 公告
  │         │       │        │       │ ──pub─►│
  │         │       │        │       │ ◄ack── │
  │         │       │        │       │        │
  │ Phase 6：使用者驗證             │        │
  │──get_proof(m_hex)──────────────────────►│
  │◄──proof + cc_sig─────────────────────── │
  │  (本地驗證)                              │
```

## 附錄 B：錯誤代碼表

| 代碼 | HTTP | 來源 | 說明 |
| --- | --- | --- | --- |
| `ENTITY_NOT_REGISTERED` | 403 | CA | 未註冊之 entity_id |
| `ALREADY_REGISTERED` | 403 | CA | 已領取過憑證 |
| `OTP_INVALID` | 403 | CA | OTP 不正確 |
| `POP_INVALID` | 403 | CA | PoP 簽章驗證失敗 |
| `TIMESTAMP_OUT_OF_RANGE` | 403 | All | 時間誤差超過 ΔT |
| `RECEIVER_ID_MISMATCH` | 403 | TPA | 封包目的地 ID 不符 |
| `NONCE_REPLAY` | 403 | TPA, TA | nonce 已使用過 |
| `ALREADY_VOTED` | 403 | TPA | 該選民已完成認證 |
| `CERT_INVALID` | 403 | All | 憑證未由 CA 簽發、過期或被吊銷 |
| `SIGNATURE_INVALID` | 403 | All | 數位簽章驗證失敗 |
| `DEADLINE_EXCEEDED` | 403 | TPA, CC | 投票時段已過 |
| `TOKEN_SIGNATURE_INVALID` | 403 | TPA | Voting Token 簽章無效 |
| `TOKEN_EXPIRED` | 403 | TPA | Token 過期 |
| `TOKEN_ALREADY_USED` | 403 | TPA | Token 已使用 |
| `TOKEN_HASH_REUSED` | 403 | CC | 相同 token_hash 重複提交 |
| `NOT_YET_DEADLINE` | 403 | TA | 投票尚未截止 |
| `ALREADY_PUBLISHED` | 403 | BB | 結果已公告，不可覆蓋 |
| `BUNDLE_INCONSISTENT` | 403 | BB | Result Bundle 結構不一致 |

## 附錄 C：v1.0 → v2.0 變更對照

| 章節 | v1.0 | v2.0 | 變更類型 |
| --- | --- | --- | --- |
| 階段數 | 6 階段 | 7 階段（新增 Phase 0） | 新增 |
| CA 憑證簽發 | 無身分驗證 | OTP + PoP + 白名單 | 重大強化 |
| 認證封包 nonce 名稱 | `si`（與簽章 SI 衝突） | `nonce`（符號 N_x） | 命名修正 |
| 時間誤差檢查 | 單向 `T_now - T > ΔT` | 雙向 `\|T_now - T\| > ΔT` | 修正 |
| 盲簽章 → 選票提交綁定 | client 自律 | Voting Token + token_hash | 重大強化 |
| 盲簽章演算法 | textbook RSA | RSA-FDH-Blind | 密碼學升級 |
| AES 模式 | CFB（無 MAC） | GCM（AEAD）+ AAD | 密碼學升級 |
| TA 私鑰釋放 | 公開可取 | CC 簽章請求 + Cert | 重大強化 |
| BB publish | 無認證 + 可覆蓋 | CC 簽章 + 鎖定 | 重大強化 |
| Merkle Tree | 末葉重複 | Domain separator + 上提 | 密碼學升級 |
| BB 公告內容 | (vote, m_hex) 對 | 僅 m_hex 列表 + tally | 隱私強化 |
| 提交順序 | 保留 | secure_shuffle | 隱私強化 |
| 選票去重 | 無 | m_hex UNIQUE + token_hash 去重 | 完整性強化 |
| 文件章節 | 無 Threat Model | 完整威脅模型章節 | 新增 |
| 文件章節 | 無安全性論證 | 第六部分完整論證 | 新增 |

## 附錄 D：名詞與縮寫對照表

| 縮寫 | 全文 | 中文 |
| --- | --- | --- |
| AAD | Additional Authenticated Data | 附加驗證資料 |
| AEAD | Authenticated Encryption with Associated Data | 含關聯資料之認證加密 |
| BB | Bulletin Board | 公告板 |
| CA | Certificate Authority | 憑證授權中心 |
| CC | Counting Center | 計票中心 |
| CSPRNG | Cryptographically Secure PRNG | 加密級偽隨機數產生器 |
| FDH | Full-Domain Hash | 全域雜湊 |
| GCM | Galois/Counter Mode | Galois/計數器模式 |
| HSM | Hardware Security Module | 硬體安全模組 |
| MGF | Mask Generation Function | 遮罩產生函數 |
| OAEP | Optimal Asymmetric Encryption Padding | 最佳非對稱加密填充 |
| OTP | One-Time Password | 一次性密碼 |
| PoP | Proof of Possession | 持有權證明 |
| PSS | Probabilistic Signature Scheme | 機率性簽章方案 |
| SN | Serial Number | 流水號 |
| TA | Time Authority | 時間授權中心 |
| TPA | Third-Party Agency | 第三方機構 |
| ZKP | Zero-Knowledge Proof | 零知識證明 |

---

## 文件結尾

本規範書 v2.0 為 NUTC Voting System 之**唯一權威來源**。實作、稽核、攻擊測試均應以此為據。任何與本文件不一致的程式行為，應優先視為實作 bug 並修正。

**下一步建議實作順序**：

1. **Sprint 1（Phase 0 + Token 機制）**：實作 voter_registry、OTP/PoP 流程、Voting Token 簽發與驗證
2. **Sprint 2（CC/BB 信任鏈）**：CC 對結果簽章、BB 驗章、TA 對請求方驗證
3. **Sprint 3（密碼學升級）**：AES-GCM、FDH-Blind、Merkle domain separator、選票洗牌
4. **Sprint 4（攻擊驗證）**：撰寫 §25.1 之 10 個攻擊腳本

每個 Sprint 完成後對照本規範書相應章節進行回歸測試。

---

*— 本文件結尾 —*
