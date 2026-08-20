# NUTC Voting System — 現行系統架構與規格落差報告

> 本文件目的：以**目前程式碼的實際行為**為準，重新描述系統架構，並標示每一處與
> `voting_architecture_v2.md`（以下稱「v2.0 規格書」）不相符的地方。
> 同時對照原始研究計畫書《基於盲簽章技術之隱私保護線上投票系統0203.docx》
> （以下稱「研究計畫書」）所描述的概念架構，指出程式碼已經超出計畫書描述範圍之處。
>
> 標記說明：
> - ✅ 與 v2.0 規格書一致
> - ⚠️ 與 v2.0 規格書不完全一致（欄位命名 / 結構差異，功能通常仍可運作）
> - ❌ v2.0 規格書要求但程式碼尚未實作 / 尚未修復
> - 🆕 v2.0 規格書明訂、但研究計畫書完全未提及的新增機制

---

## 0. 三份文件的關係

```
研究計畫書（docx）           voting_architecture_v2.md         目前程式碼（本文件描述對象）
─────────────────           ──────────────────────────         ──────────────────────────
六階段協定                    七階段協定（新增 Phase 0）           七階段協定（含 Phase 0）
5 個角色（不含 CA）           6 個角色（CA 為半可信角色）           6 個角色 + CA
Textbook RSA 盲簽章           RSA-FDH-Blind                      RSA-FDH-Blind
未指定對稱加密模式             AES-256-GCM（AEAD）                 AES-256-GCM（AEAD）
Merkle：H(m) / H(L‖R)         Domain-separated（0x00/0x01 前綴）  Domain-separated
無 Voting Token 機制           Voting Token（綁定 Phase2→Phase3）  Voting Token（本次已補完整鏈路）
CC 公告完整 (vote, m_hex)      BB 僅公告 valid_m_hex_list          BB 僅公告 valid_m_hex_list（本次修復）
無選票去重機制描述             SN/m_hex 去重                       m_hex UNIQUE 去重（本次修復）
無洗牌機制描述                 secure shuffle                     shuffle 已持久化（本次修復）
```

研究計畫書是**概念驗證層級**的學術提案，對應到 v1.0～v2.0 規格書修訂歷史中「v1.0」
的安全等級（見 v2.0 規格書修訂歷史表）。程式碼實際實作的是 v2.0 規格書的協定，
且在本次工作階段（見 §4）修補了數個 v2.0 規格書已經要求、但先前程式碼尚未落實
的項目。

---

## 1. 研究計畫書 vs 程式碼：結構性不相符列表

以下項目是**研究計畫書的「主要結構」與目前程式碼直接矛盾或缺漏**的地方，供撰寫
論文/報告時對照修訂：

| # | 研究計畫書描述 | 程式碼實際行為 | 差異說明 |
|---|---|---|---|
| 1 | 系統由「**五個**獨立實體」組成：Voter、TPA、TA、CC、BB（計畫書 §研究方法本文明確排除 CA） | 系統實際由 **CA + TPA + TA + CC + BB + Voter 六個服務**組成，CA 是獨立的 Flask 容器（`ca_server/`），負責選民白名單與憑證核發 | 計畫書的符號定義表雖然列了 CA，但方法論段落的角色清單卻漏掉它，論文口徑本身不一致；程式碼把 CA 當成一個完整的第一等公民角色 |
| 2 | 協定流程「共**六個階段**」：系統初始化、身分驗證、盲簽章選票、時間解密、計票與 Merkle Tree、使用者驗證 | 程式碼多一個 **Phase 0 選民註冊階段**（CA 白名單 + OTP + PoP 簽章核發憑證），共**七個階段** | 計畫書完全沒有描述「誰可以拿到憑證」這件事，等於預設任何人都能取得合法身分；程式碼用 OTP + 白名單解決這個漏洞 |
| 3 | 身分驗證階段未提及任何一次性「投票授權票」機制，TPA 認證成功後直接進入盲簽章階段 | 程式碼在 Phase 2 認證成功後核發 **Voting Token**（一次性、10 分鐘效期），Phase 3 `/api/blind_sign` **強制**要求附上此 Token 才會簽章（本次工作階段修復：先前 Token 是可選的，等同無效） | 沒有 Token 機制時，「認證一次、無限次取盲簽章」的一人多票攻擊在計畫書描述的協定下無法被阻擋 |
| 4 | 盲簽章數學式：`m' = m·rᵉ mod n`、`S = (m')ᵈ mod n`（直接對雜湊值 m 盲化，即 textbook RSA blind signature） | 程式碼先以 **FDH（Full-Domain Hash，MGF1-SHA256）** 將 m 擴展為 `μ = FDH(m, bit_length(n))`，再盲化 `m' = μ·rᵉ mod n` | Textbook RSA 盲簽章存在存在性偽造攻擊（existential forgery），v2.0 規格書已明文將其列為「不採用」之演算法；計畫書的公式若照字面實作會重現此漏洞 |
| 5 | 數位信封只描述「對稱加密 `Cdata = Ek(m)`」，未指定加密模式，也未描述完整性驗證機制 | 程式碼採用 **AES-256-GCM**（AEAD），並以 `AAD = "voting-system-v2\|ID_Voter\|SN"` 綁定身分與流水號，解密時驗證 Tag 失敗即拒絕 | 若照計畫書字面實作（如 AES-CBC/CFB），密文可被位元翻轉竄改而不被發現；程式碼的 GCM Tag 驗證正是為了防止這點（測試套件 AT-07/AT-10 專門驗證此防線） |
| 6 | Merkle Tree 公式：葉節點 `Leafᵢ = H(mⱼ)`，父節點 `Hparent = H(Hleft \|\| Hright)`，兩者用同一個雜湊函數、無前綴區分 | 程式碼採 **domain-separated hashing**：葉節點 `H(0x00‖m)`、中間節點 `H(0x01‖L‖R)`（`shared/merkle_tree.py`） | 計畫書的公式正是 **CVE-2012-2459 二次原像攻擊**的典型脆弱結構（攻擊者可用一個中間節點的雜湊值偽造成另一棵樹的葉節點）；程式碼的前綴設計專門防禦此漏洞（測試套件 AT-08 驗證） |
| 7 | 「CC 將最終計票結果、Root_official**與有效選票列表**公布至 BB」，未區分列表內容是否含投票內容 | 程式碼只公布 **`valid_m_hex_list`**（純 m_hex 清單）與 `tally`（候選人加總），**不**公布逐票的 vote↔m_hex 對應（本次工作階段修復：先前確實有公布對應關係，已依 v2.0 規格書 §19.5 修正） | 若逐票公布 vote 內容，任何人只要知道某位選民的 `(ID, SN)` 就能在候選人集合內窮舉比對，反推出他投給誰；只公布 m_hex 清單可以降低此風險面 |
| 8 | 未提及選票流水號（SN）或選票雜湊（m）的重複使用防禦機制 | 程式碼在 CC 端以 `valid_votes.m_hex UNIQUE` 索引 + `used_token_hashes.token_hash UNIQUE` 索引做**雙重去重**（本次工作階段修復：先前完全沒有 m_hex 去重，token_hash 去重也因欄位可為空而形同虛設） | 沒有去重機制時，同一張已簽章選票理論上能重複提交並被重複計票 |
| 9 | 計票階段未提及提交順序與選票內容的關聯性處理 | 程式碼在 `_do_tally()` 內對合法選票做 **Fisher-Yates 洗牌**（CSPRNG）後才建構 Merkle Tree，並將洗牌後順序持久化為 `shuffle_seq`（本次工作階段修復：先前洗牌結果只留在記憶體，CC 自己的 `/api/merkle_proof` 卻用未洗牌順序重建樹，導致驗證對不上） | 若不洗牌，選票在 CC 資料庫的插入順序（=提交時間順序）與 Merkle Tree 的葉節點順序一致，可能被用來推測「誰先投票、投了什麼」 |

---

## 2. 系統角色（現況：7 個）

| 角色 | 研究計畫書是否提及 | v2.0 規格書 | 程式碼現況 |
|---|---|---|---|
| CA（憑證授權中心） | 僅存在於符號表，方法論正文未列入「五實體」 | ✅ 半可信角色，主導 Phase 0/1 | ✅ 獨立服務 `ca_server/`，維護 `voter_registry` 白名單 |
| TPA（第三方機構） | ✅ | ✅ | ✅ |
| TA（時間授權中心） | ✅ | ✅ | ✅ |
| CC（計票中心） | ✅ | ✅ | ✅ |
| BB（公告板） | ✅ | ✅ | ✅ |
| Voter（選民） | ✅ | ✅ | ✅ |
| Admin（系統外角色，OTP 派發） | ❌ 未提及 | ✅ Phase 0 定義 | ✅ 獨立工具 `admin_tool/`（Web UI + API） |

---

## 3. 七階段協定：現況逐項對照

### Phase 0：選民註冊（研究計畫書完全未描述此階段）

| 項目 | 狀態 | 說明 |
|---|---|---|
| OTP 產生與零知識儲存（`H(OTP)`） | ✅ | `ca_server/app.py`、`admin_tool/app.py` |
| PoP（Proof of Possession）簽章驗證 | ✅ | Voter 需簽署 `REGISTER\|ID\|timestamp` |
| 白名單檢查（`ENTITY_NOT_REGISTERED`） | ✅ | |
| OTP 連續 3 次失敗鎖定 24 小時 | ❌ | 規格書 §0.5 要求，`voter_registry` 表缺 `fail_count`/`locked_until` 欄位，尚未實作 |
| OTP 7 天過期 | ❌ | `voter_registry` 缺 `expires_at` 檢查邏輯（API 有收欄位，但核發時未驗證是否逾期）|
| 服務憑證（TPA/TA/CC/BB）核發用 `SERVICE_REGISTRATION_TOKEN` 一次性驗證 | ❌ | 規格書 §0.5 Step 0.5、§1.4 Step 1.3 要求；程式碼目前只檢查 `entity_id` 是否在硬編碼的 `_SERVICE_IDS` 集合中，任何人知道服務 ID 字串即可換發憑證 |
| Admin 管理端點（`/api/admin/*`）認證 | ❌ | 規格書 §18.1.3 要求 Admin Bearer Token；程式碼三個管理端點目前無任何驗證 |
| 憑證撤銷（revocation） | ❌ | 規格書允許 `status='revoked'`，但無對應撤銷端點與 CHECK 約束 |

### Phase 1：系統初始化與金鑰生成

| 項目 | 狀態 |
|---|---|
| 各服務 RSA-2048 金鑰自行生成 | ✅ |
| 服務間憑證下載與信任鏈建立 | ✅ |
| T_DL 由 TA 簽章後不可變更 | ✅ |

### Phase 2：身分驗證

| 項目 | 狀態 | 說明 |
|---|---|---|
| `auth_component.py` 認證封包（nonce / nonce_echo / 雙向 ΔT） | ✅ | **本次工作階段修復**：此檔案原本是未解決的 Git merge conflict，v1.0（`si`）與 v2.0（`nonce`）兩版並存導致整個模組是語法錯誤、TPA/TA/CC 完全無法啟動；已保留 v2.0 版本 |
| TPA 驗證 Voter 憑證時的 CA 簽章鏈驗證 | ✅ | **本次工作階段修復**：原本固定傳 `ca_public_key=None`，CA 鏈驗證形同虛設；CA 憑證不可用時也未 fail-closed，已修正為強制拒絕 |
| Voting Token 簽發（`token_id` / `expires_at` / `nonce_bind`） | ✅ | |
| Token 簽章序列化使用 canonical JSON（`separators=(',', ':')`） | ⚠️ | 規格書 §18.6 要求；TPA 簽發 Token 時用的是 `json.dumps(..., sort_keys=True, ensure_ascii=False)`，**缺少 `separators` 參數**。TPA 自簽自驗雖能自洽，但外部稽核工具若照規格重建 canonical JSON 會驗章失敗 |
| `/api/auth` 錯誤回應皆含 `code` 欄位 | ⚠️ | 部分分支（重放、重複投票、憑證錯誤）目前直接回傳字串訊息，未附 `code`，與規格書 §18 通用錯誤格式不完全一致 |

### Phase 3：盲簽章選票

| 項目 | 狀態 | 說明 |
|---|---|---|
| RSA-FDH-Blind（MGF1-SHA256 擴展） | ✅ | |
| `/api/blind_sign` 強制要求 Voting Token | ✅ | **本次工作階段修復**：原本 Token 可選（缺 Token 只印警告照樣簽），等同可跳過 Phase 2 直接取簽 |
| Token 「未使用→標記已使用」為原子操作 | ✅ | **本次工作階段修復**：原本是先 `SELECT` 再 `UPDATE` 兩步，存在 TOCTOU 競態；已改為 `UPDATE ... WHERE used = 0` 並用 rowcount 判斷 |
| voter_client 實際傳遞 Voting Token 給 `/api/blind_sign` | ✅ | **本次工作階段修復**：瀏覽器端原本拿到 Token 卻從未使用 |
| 數位信封 `token_hash = H(token_id)` 正確計算並送出 | ✅ | **本次工作階段修復**：原本 voter_client 端寫死空字串，CC 端去重形同虛設 |
| CC 端 `token_hash` 去重為必要欄位 + 原子化（UNIQUE + IntegrityError） | ✅ | **本次工作階段修復** |
| 數位信封欄位（`c_data/iv/tag/aad/c_key/token_hash`）符合 Schema | ✅ | |

### Phase 4：時間解密

| 項目 | 狀態 | 說明 |
|---|---|---|
| TA 僅在截止後釋放 `SK_TA` | ✅ | |
| TA 驗證請求方持有合法簽章封包 | ✅ | |
| TA 核對請求方**憑證本身的 Subject CN** 是否為 `"CC"` | ✅ | **本次工作階段修復**：原本只信任請求 payload 自報的 `sender_id=="CC"` 字串，任何持有合法 CA 憑證的人（例如一般選民）都能自稱 CC 騙取 `SK_TA`；規格書 §4.2c / S-4.1 明訂此為 v2.0 新增重點防禦，先前未真正落實 |
| `/api/release_key` 請求／回應欄位結構符合規格書 §18.3.3 | ⚠️ | 規格書要求 `payload`/`signature`/`cert_pem` 為頂層欄位且含 `purpose:"tally"`；程式碼目前包在 `{"auth": {...}}` 內，且無 `purpose` 欄位與對應驗證 |
| nonce 缺漏時的防重放檢查 | ⚠️ | `ta_server/app.py` 目前 `if nonce:` 為真值判斷，nonce 為空字串時會整段跳過重放偵測 |

### Phase 5：計票與 Merkle Tree 建構

| 項目 | 狀態 | 說明 |
|---|---|---|
| CC 對每張選票驗證盲簽章合法性（`S'ᵉ mod n == FDH(m)`） | ✅ | |
| CC 端 m_hex 去重（防重放同一張已簽章選票） | ✅ | **本次工作階段修復**：原本完全沒有此檢查 |
| Secure shuffle 並持久化排序，`/api/merkle_proof`、`/api/results` 與正式簽章的 root 使用同一份順序 | ✅ | **本次工作階段修復**：原本洗牌結果只存在記憶體，CC 自己的驗證端點會用未洗牌順序重建樹，跟已簽章推送給 BB 的 `root_official` 對不上 |
| Domain-separated Merkle Tree（防 CVE-2012-2459） | ✅ | |
| CC 對結果簽章（RSA-PSS） | ✅ | |
| 推送給 BB 的結果包只含 `valid_m_hex_list`，不含 vote↔m_hex 對應 | ✅ | **本次工作階段修復**：對應規格書 §19.5「BB 不儲存 vote 對 m_hex 的對應關係」 |
| `result_bundle` 含 `deadline`、`cc_id` 欄位（供 BB 做結構一致性檢查） | ❌ | 規格書 §18.5.1 / §20.4 要求，程式碼尚未加入這兩個欄位 |
| bundle 簽章原文使用 canonical JSON（`separators=(',', ':')`） | ⚠️ | CC/BB 雙方目前用 `json.dumps(..., sort_keys=True, ensure_ascii=False)`（無 separators），雙方自洽但不符規格書 §18.6 |
| `/api/tally` 端點存取控制（內部 IP 白名單 + 簽章） | ❌ | 規格書 §18.4.4 要求；目前任何人皆可呼叫觸發開票 |

### Phase 6：使用者驗證

| 項目 | 狀態 | 說明 |
|---|---|---|
| BB `/api/publish` 驗證憑證由 CA 簽發 | ✅ | |
| BB `/api/publish` 核對憑證 **Subject CN** 是否為 `"CC"` | ✅ | **本次工作階段修復**：原本只驗證憑證合法性，未驗證是否真的核發給 CC，任何合法選民的憑證都能冒充 CC 發布結果 |
| BB `/api/publish` 防止覆蓋（`ALREADY_PUBLISHED`） | ✅ | |
| BB 儲存並回傳 `cc_cert_pem`（供選民驗證簽章公鑰身分鏈） | ❌ | 規格書 §6.3 Step 6.1、§18.5.2 要求；BB 目前只存 `cc_signature`，不存 `cc_cert_pem`，選民端 Phase 6 Step 6.2a 的憑證鏈驗證無法獨立完成，只能單方面信任 BB |
| BB 公告結構一致性檢查（`merkle_leaf_count == len(valid_m_hex_list) == sum(tally)`，即 `BUNDLE_INCONSISTENT`） | ❌ | 規格書 §18.5.1 明列此錯誤碼，目前未實作對應檢查 |
| BB `/api/results`、`/api/merkle_proof` 不洩漏 vote↔m_hex 對應 | ✅ | **本次工作階段修復** |
| Merkle Proof 驗證（選民端重建 Root 並比對） | ✅ | |

---

## 4. 本次工作階段（Session）已修復項目彙總

依修復順序：

1. `shared/auth_component.py`：移除未解決的 Git merge conflict，保留 v2.0（`nonce`）版本
2. `tpa_server/app.py`：`/api/auth` 改為 fail-closed，CA 憑證不可用時拒絕請求，並真正傳入 CA 公鑰驗證憑證鏈
3. `ta_server/app.py`：`/api/release_key` 增加憑證 Subject CN 核對，防止冒充 CC 騙取 `SK_TA`
4. `bb_server/app.py`：`/api/publish` 增加憑證 Subject CN 核對，防止冒充 CC 發布結果
5. Voting Token 全鏈路：`tpa_server`（強制要求 + 原子化標記已使用）、`voter_client`（實際傳遞 Token 並計算 `token_hash`）、`cc_server`（`token_hash` 必要欄位 + 原子化去重）
6. `cc_server/app.py`：m_hex 去重（UNIQUE 索引 + IntegrityError）、洗牌順序持久化（`shuffle_seq`）、`/api/results` 與 `/api/merkle_proof` 改用洗牌後順序排序
7. `cc_server/app.py` / `bb_server/app.py`：推送與公告的結果只含 `valid_m_hex_list`，移除 vote↔m_hex 一一對應（同步更新 `test/test_comprehensive.py` 的對應斷言）
8. `.dockerignore`：避免本地散落的 `.db`/`keys/` 檔案污染 Docker build context

**驗證方式**：`docker compose up --build` 啟動全部 7 個服務 + `PYTHONIOENCODING=utf-8 python test/test_comprehensive.py --voters 5 --verbose`，51 項測試（含 §25 全部 10 項攻擊驗證）全數通過。

---

## 5. 尚未修復的規格落差（依服務彙總，供後續工作階段參考）

| 服務 | 項目 | 對應規格 |
|---|---|---|
| CA | `SERVICE_REGISTRATION_TOKEN` 一次性驗證未實作（服務憑證核發只靠硬編碼白名單） | §0.5 Step 0.5、§1.4 Step 1.3 |
| CA | Admin 管理端點無認證 | §18.1.3 |
| CA | OTP 鎖定（3 次失敗/24hr）、OTP 7 天過期未實作 | §0.5、§0.6 S-0.2 |
| CA | 憑證撤銷機制未實作 | §19.1 |
| TPA | Token 簽章 canonical JSON 缺 `separators` | §18.6 |
| TPA | `/api/auth` 部分錯誤回應缺 `code` 欄位 | §18 通用錯誤格式 |
| TA | `/api/release_key` 欄位結構與 `purpose` 驗證未對齊規格 | §18.3.3 |
| TA | nonce 為空字串時跳過防重放檢查 | §4.2e |
| CC/BB | `result_bundle` 缺 `deadline`、`cc_id` 欄位 | §18.5.1、§20.4 |
| CC/BB | bundle 簽章原文缺 canonical JSON `separators` | §18.6 |
| CC | `/api/tally` 無存取控制 | §18.4.4 |
| BB | 不儲存 `cc_cert_pem`，選民無法獨立驗證簽章公鑰身分鏈 | §6.3、§18.5.2 |
| BB | 未實作 `BUNDLE_INCONSISTENT` 結構一致性檢查 | §18.5.1 |
| 全域 | 多處資料庫欄位命名與規格書 Schema 不完全一致（如 `si`/`nonce`、`voter_id`/`entity_id`） | §19 |

---

## 附錄：與研究計畫書的建議調整方向

若研究計畫書後續要修訂以反映實際系統（例如準備口試或期末報告），建議至少更新：

1. 角色清單補上 CA，並新增 Phase 0（選民註冊）說明
2. 盲簽章章節補充 FDH 擴展步驟，說明其防禦「存在性偽造攻擊」的必要性
3. 數位信封章節明確指定 AES-256-GCM 並說明 AAD 的角色（防重放/防篡改）
4. Merkle Tree 章節補充 domain-separated hashing 設計，說明其防禦 CVE-2012-2459 的原理
5. 新增「投票授權票（Voting Token）」小節，說明其如何防止一人多票
6. 計票階段補充「選票洗牌」與「僅公告 m_hex 清單」兩項隱私保護設計，並說明其與可驗證性（V-2）之間的取捨
