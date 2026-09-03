# NUTC Voting System — 系統架構文件 v3.0

> 本文件取代先前的「現行系統架構與規格落差報告」版本，改以 **v3.0** 命名，
> 因為程式碼在本輪修復後，已經把 `voting_architecture_v2.md`（以下稱「v2.0
> 規格書」）原本要求、但長期未落實的安全機制全部補齊，實作內容已超出 v2.0
> 規格書草創時的範圍。
>
> 本文件目的：
> 1. 以**目前程式碼的實際行為**為準，列出系統的**完整功能清單**（不只是落差，
>    而是全部功能）。
> 2. 逐項標示每個功能與《基於盲簽章技術之隱私保護線上投票系統0203.docx》
>    （以下稱「研究計畫書」）所描述內容的**相異之處**。
> 3. 記錄本次（v3.0）新增/修復的項目，並列出仍屬於未來工作範疇的項目。
>
> 標記說明：
> - 🆕 **v3 新增**：v2.0 規格書已要求、但直到 v3.0 才真正實作的機制
> - 🔧 **v3 修復**：v2.0 規格書要求、程式碼曾經有但實作錯誤／形同虛設，v3.0 修正
> - ✅ **既有且正確**：v2.0 規格書要求、程式碼原本就正確實作
> - 📄 **計畫書未提及**：研究計畫書完全沒有描述這項機制（不代表計畫書錯誤，
>   只是概念層級的提案本來就比正式規格粗略）
> - ⚠️ **與計畫書描述矛盾**：研究計畫書有描述，但寫法與實際安全作法不同
>   （若照計畫書字面實作會有安全疑慮）

---

## 0. 三份文件的關係與版本沿革

```
研究計畫書（docx，2026 提案）      v2.0 規格書（voting_architecture_v2.md）      v3.0 程式碼（本文件）
──────────────────────────      ─────────────────────────────────────      ─────────────────────
六階段協定                        七階段協定（新增 Phase 0）                    七階段協定（完整實作）
5 個角色（不含 CA）                6 個角色（CA 半可信）                        6 個角色 + CA + Admin 工具
Textbook RSA 盲簽章                RSA-FDH-Blind                              RSA-FDH-Blind
未指定對稱加密模式                  AES-256-GCM（AEAD）                         AES-256-GCM（AEAD）
Merkle：H(m) / H(L‖R)             Domain-separated（0x00/0x01 前綴）          Domain-separated
無 Voting Token 機制               Voting Token（規格已定義）                   Voting Token（v3 才真正串通全鏈路）
無服務憑證防偽機制                  SERVICE_REGISTRATION_TOKEN（規格已定義）     🆕 v3 才實作
無 Admin 端點保護機制               Admin Bearer Token（規格已定義）             🆕 v3 才實作
無 OTP 濫用防禦                    OTP 鎖定 + 過期（規格已定義）                🆕 v3 才實作
無憑證撤銷機制                     憑證撤銷（規格已定義）                        🆕 v3 才實作
CC 公告完整 (vote, m_hex)          BB 僅公告 valid_m_hex_list                  ✅ v3 已對齊
無選票去重機制描述                  SN/m_hex 去重                              ✅ v3 已對齊（含 UNIQUE 約束）
無洗牌機制描述                     secure shuffle                             ✅ v3 已對齊（含持久化）
```

**版本判讀**：研究計畫書是概念驗證層級的學術提案，安全等級大致對應 v2.0
規格書修訂歷史中的「v1.0」；v2.0 規格書訂出了完整目標，但過去很長一段時間
程式碼落後於規格書；v3.0 是「目標與實作完全對齊，並修正過程中發現的額外
bug（如憑證效期寫死 30 天）」之後的現況文件。

---

## 1. 系統角色（7 個）

| 角色 | 說明 | 研究計畫書是否提及 |
|---|---|---|
| **CA**（憑證授權中心） | 維護選民白名單、核發/撤銷 X.509 憑證、管理服務帳號一次性註冊權杖 | 僅存在於符號表，方法論正文的「五實體」清單未列入 |
| **TPA**（第三方機構） | 選民身分驗證、簽發 Voting Token、盲簽章 | ✅ |
| **TA**（時間授權中心） | 維護投票截止時間、截止後有條件釋放 `SK_TA` | ✅ |
| **CC**（計票中心） | 接收信封、解封驗證、去重、洗牌、建構 Merkle Tree、簽章結果、推送 BB | ✅ |
| **BB**（公告板） | 驗證並公告 CC 簽章結果、提供 Merkle Proof 查詢 | ✅ |
| **Voter**（選民） | 身分驗證、產生選票、盲化、包封、提交、事後驗證 | ✅ |
| **Admin**（系統外角色 / `admin_tool`） | OTP 派發、選民名冊管理、選舉啟動/重置、憑證撤銷操作 | ❌ 完全未提及 |

---

## 2. 完整端點清單（依服務）

### CA（port 5001）

| 端點 | 方法 | 認證 | 說明 |
|---|---|---|---|
| `/` | GET | 公開 | Dashboard |
| `/api/ca_cert` | GET | 公開 | 取得 CA 根憑證 |
| `/api/issue_cert` | POST | 選民：OTP+PoP；服務：`registration_token` | 核發憑證 |
| `/api/admin/register_voter` | POST | 🆕 Admin Bearer Token | 預先登記選民、派發 OTP |
| `/api/admin/voter_registry` | GET | 🆕 Admin Bearer Token | 選民名冊查詢 |
| `/api/admin/reset_voter_registry` | POST | 🆕 Admin Bearer Token | 清空選民名冊 |
| `/api/admin/revoke_cert` | POST | 🆕 Admin Bearer Token | 🆕 撤銷選民憑證 |
| `/api/revocation_list` | GET | 公開 | 🆕 公開撤銷清單（簡化版 CRL） |
| `/api/voter_status` | GET | 公開 | 選民端查詢自己的註冊狀態（供偵測重置用，刻意保持公開） |

### TPA（port 5000）

| 端點 | 方法 | 認證 | 說明 |
|---|---|---|---|
| `/` | GET | 公開 | Dashboard |
| `/api/public_key` | GET | 公開 | 取得 `(e, n)` |
| `/api/auth` | POST | Voter 簽章 + Cert | Phase 2 雙向認證、核發 Voting Token |
| `/api/blind_sign` | POST | Voting Token（🔧 強制） | Phase 3 盲簽章 |
| `/api/config/reload` | POST | 內部 | 熱重載 config.json |

### TA（port 5002）

| 端點 | 方法 | 認證 | 說明 |
|---|---|---|---|
| `/` | GET | 公開 | Dashboard |
| `/api/public_key` | GET | 公開 | 取得 `PK_TA` |
| `/api/deadline` | GET | 公開 | 查詢截止時間與選舉狀態 |
| `/api/release_key` | POST | 🔧 CC 簽章請求 + Cert_CC（欄位結構已對齊規格書 §18.3.3） | 截止後釋放 `SK_TA` |
| `/api/start_election` | POST | 內部（Admin 呼叫） | standby → running |
| `/api/admin/reset_election` | POST | 內部（Admin 呼叫） | 重置為 standby |
| `/api/config/reload` | POST | 內部 | 熱重載 |

### CC（port 5003）

| 端點 | 方法 | 認證 | 說明 |
|---|---|---|---|
| `/` | GET | 公開 | Dashboard（內部可見逐票 vote+m_hex，CC 本就知道投票內容） |
| `/ui/tally` | POST | 🆕 內部 IP 白名單 | Dashboard 開票按鈕 |
| `/api/public_key` | GET | 公開 | 取得 `PK_CC` |
| `/api/receive_envelope` | POST | 🔧 `token_hash` 必要且原子去重 | Phase 3 信封提交 |
| `/api/tally` | POST | 🆕 內部 IP 白名單 + Admin Bearer Token | 觸發開票 |
| `/api/results` | GET | 公開 | 🔧 只回傳 `valid_m_hex_list` + `tally`（不含逐票 vote 對應） |
| `/api/merkle_proof/<index>` | GET | 公開 | 🔧 依洗牌後 `shuffle_seq` 排序建樹 |
| `/api/config/reload` | POST | 內部 | 熱重載 |

### BB（port 5004）

| 端點 | 方法 | 認證 | 說明 |
|---|---|---|---|
| `/` | GET | 公開 | Dashboard（🔧 已移除逐票投票內容欄位） |
| `/verify` | GET | 公開 | Merkle Proof 視覺化驗證頁 |
| `/api/publish` | POST | 🔧 CC 簽章 + Cert_CC + Subject CN 核對 + 🆕 `BUNDLE_INCONSISTENT` 結構檢查 | CC 推送結果 |
| `/api/results` | GET | 公開 | 🔧 只回傳 `valid_m_hex_list`；🆕 附上 `cc_cert_pem` |
| `/api/merkle_proof/<m_hex>` | GET | 公開 | 依 m_hex 查詢 Proof |
| `/api/config/reload` | POST | 內部 | 熱重載 |

---

## 3. 完整功能清單（依協定階段）

### Phase 0：選民註冊

| 功能 | 狀態 | 與研究計畫書比較 |
|---|---|---|
| Admin 產生 OTP，僅以 `H(OTP)` 存入 CA（零知識模式） | ✅ | 📄 計畫書完全未描述選民註冊/白名單流程 |
| Voter 產生 RSA-2048 金鑰對 | ✅ | ✅ 一致（計畫書「系統初始化」有描述金鑰生成，但未區分這是選民自行生成） |
| PoP（Proof of Possession）簽章驗證 `REGISTER\|ID\|timestamp` | ✅ | 📄 未提及 |
| 白名單檢查（`ENTITY_NOT_REGISTERED`） | ✅ | 📄 未提及 —— 若照計畫書字面實作，任何人自稱一個 ID 就能取得合法憑證 |
| OTP 連續 3 次失敗鎖定 24 小時 | 🆕 | 📄 未提及 |
| OTP 7 天過期 | 🆕 | 📄 未提及 |
| 服務憑證（TPA/TA/CC）`SERVICE_REGISTRATION_TOKEN` 一次性驗證 | 🆕 | 📄 未提及 |
| 憑證撤銷（`/api/admin/revoke_cert`）+ 公開撤銷清單 | 🆕 | 📄 未提及 |
| Admin 管理端點 Bearer Token 保護 | 🆕 | 📄 「Admin」角色本身在計畫書中不存在 |

### Phase 1：系統初始化與金鑰生成

| 功能 | 狀態 | 與研究計畫書比較 |
|---|---|---|
| 各服務 RSA-2048 金鑰自行生成 | ✅ | ✅ 一致 |
| 服務間憑證下載與信任鏈建立 | ✅ | 📄 計畫書未描述憑證機制，僅籠統提及金鑰用途 |
| 憑證效期 365 天 | 🔧 | 📄 未提及（此為本輪修復：原本程式碼寫死 30 天，與規格書不符，已修正） |
| `T_DL` 由 TA 簽章後不可變更 | ✅ | 📄 未提及簽章保護，只說 TA「透過生成時間金鑰確保機密性」 |

### Phase 2：身分驗證

| 功能 | 狀態 | 與研究計畫書比較 |
|---|---|---|
| 認證封包欄位：`sender_id/receiver_id/timestamp/nonce/cert_pem` | ✅ | ⚠️ 計畫書用 `SIVoter = H(IDVoter‖IDTPA‖TVoter)` 單一雜湊值代表認證要素，沒有獨立的 nonce 欄位，且未區分「認證雜湊」與「數位簽章」（v1.0 遺留的命名混淆，v2.0 規格書已明確消除） |
| 雙向時間誤差檢查 `\|T_now − T\| ≤ ΔT` | ✅ | ✅ 概念一致（計畫書步驟 2、7 皆有描述時間誤差檢查） |
| `nonce_echo` 機制（回應封包關聯本次請求） | ✅ | 📄 未提及 |
| CA 憑證鏈驗證，且 fail-closed（🔧 CA 憑證不可用時直接拒絕，而非降級放行） | 🔧 | 📄 未提及憑證鏈驗證細節，僅說「TPA 使用 CA 的公鑰驗證憑證的合法性」 |
| Voting Token 核發（`token_id/voter_id/issued_at/expires_at/nonce_bind`） | ✅ | 📄 **完全未提及**——這是計畫書與實作最大的落差之一 |
| Token 簽章使用 canonical JSON（`separators=(',', ':')`） | 🆕 | 📄 未提及 |
| `/api/auth` 統一錯誤碼（`RECEIVER_ID_MISMATCH`/`TIMESTAMP_OUT_OF_RANGE`/`NONCE_REPLAY`/`ALREADY_VOTED`/`CERT_INVALID`/`SIGNATURE_INVALID` 等） | 🆕 | 📄 未提及 |
| 防重放（nonce 已使用檢查）、防重複投票（`voted_users`） | ✅ | ✅ 計畫書有「TPA 檢查是否與自身 ID 相符」等步驟，但未提及去重表設計 |

### Phase 3：盲簽章選票

| 功能 | 狀態 | 與研究計畫書比較 |
|---|---|---|
| 選票雜湊 `m = H(H(ID‖SN‖Vote)‖Vote)` | ✅ | ✅ 公式一致 |
| **FDH（Full-Domain Hash）擴展** `μ = FDH(m, bit_length(n))` 後才盲化 | ✅ | ⚠️ **矛盾**：計畫書直接對 `m` 盲化（`m' = m·rᵉ mod n`），這是 textbook RSA 盲簽章，存在存在性偽造攻擊；程式碼採用 FDH-Blind，是安全上必要的修正，不是可有可無的「額外功能」 |
| 盲化、TPA 盲簽章、去盲化、自我驗證四步驟 | ✅ | ✅ 概念一致（多一道 FDH 擴展） |
| `/api/blind_sign` **強制**要求 Voting Token 才簽章 | 🔧 | 📄 未提及 Token 機制，若照計畫書字面實作，認證與取簽完全脫鉤，等同「認證一次、無限取簽」 |
| Token 使用狀態原子化更新（`UPDATE ... WHERE used=0`，防 TOCTOU 併發重複使用） | 🔧 | 📄 未提及 |
| 數位信封：內層 `Enc_PK_TA(inner_hash‖Vote)`，外層 AES-256-GCM + RSA-OAEP 包裹金鑰 | ✅ | ⚠️ 計畫書只寫 `Cdata = Ek(m)`，未指定加密模式；若照字面用非 AEAD 模式（如 CBC/CFB），密文可被竄改而不被察覺 |
| `AAD = "voting-system-v2\|ID_Voter\|SN"` 綁定身分與流水號 | ✅ | 📄 未提及 AAD 概念 |
| `token_hash = H(token_id)` 正確計算並放入信封 | 🔧 | 📄 未提及 |
| CC 端 `token_hash` 去重：必要欄位 + `UNIQUE` 約束原子化 | 🔧 | 📄 未提及去重機制 |

### Phase 4：時間解密

| 功能 | 狀態 | 與研究計畫書比較 |
|---|---|---|
| TA 僅在 `T_now ≥ T_DL` 後釋放 `SK_TA` | ✅ | ✅ 概念一致 |
| `/api/release_key` 採規格書 §18.3.3 結構：頂層 `payload/signature/cert_pem`，`payload` 含 `requester_id/timestamp/nonce/purpose` | 🔧 | 📄 未提及請求方身分驗證機制，計畫書僅說「TA 釋出私密金鑰 SK_TA 給 CC」，未描述如何確認請求方真的是 CC |
| 核對請求方**憑證 Subject CN** 是否為 `"CC"`（而非只信任自報欄位） | 🔧 | 📄 未提及 —— 這是防止「任何合法選民自稱 CC 騙取 `SK_TA`」的關鍵防線 |
| `purpose` 欄位限定 `"tally"`，nonce 必要且防重放 | 🆕 | 📄 未提及 |
| CC 解密驗證：`H(H(ID‖SN‖Vote)‖Vote)` 與 `m` 比對 | ✅ | ✅ 公式一致 |

### Phase 5：計票與 Merkle Tree 建構

| 功能 | 狀態 | 與研究計畫書比較 |
|---|---|---|
| CC 驗證每張選票之盲簽章合法性 | ✅ | ✅ 概念一致 |
| **m_hex 去重**（`valid_votes.m_hex UNIQUE` + `IntegrityError` 原子擋下） | 🔧 | 📄 未提及重複選票防禦 |
| **Secure shuffle**（Fisher-Yates + CSPRNG）並持久化為 `shuffle_seq` | 🔧 | 📄 完全未提及——計畫書步驟直接說「CC 將最終計票結果、Root 與有效選票列表公布至 BB」，暗示按原始順序處理 |
| **Domain-separated Merkle Tree**（葉 `H(0x00‖m)`、節點 `H(0x01‖L‖R)`） | ✅ | ⚠️ **矛盾**：計畫書公式 `Leafᵢ = H(mⱼ)`、`Hparent = H(HLeft‖HRight)` 沒有前綴區分，是 **CVE-2012-2459 二次原像攻擊**的典型脆弱結構 |
| CC 對結果 RSA-PSS 簽章 | ✅ | 📄 未提及簽章保護開票結果 |
| 推送 BB 只含 `valid_m_hex_list`（不含 vote 對應）+ `merkle_leaf_count` + `deadline` + `cc_id` | 🔧🆕 | ⚠️ 計畫書描述會公布「有效選票列表」，字面上暗示含票值，與 v3.0 的隱私設計原則相反 |
| Bundle 簽章使用 canonical JSON | 🆕 | 📄 未提及 |
| `/api/tally` 內部 IP 白名單 + Admin Bearer Token | 🆕 | 📄 「開票」動作在計畫書中沒有存取控制概念 |

### Phase 6：使用者驗證

| 功能 | 狀態 | 與研究計畫書比較 |
|---|---|---|
| BB 驗證 CC 憑證由 CA 簽發 | ✅ | ✅ 概念一致 |
| BB 額外核對憑證 **Subject CN** 是否為 `"CC"` | 🔧 | 📄 未提及——沒有此檢查時，任何合法選民的憑證都能冒充 CC 發布結果 |
| BB 防止結果被覆蓋（`ALREADY_PUBLISHED`） | ✅ | 📄 未提及 |
| BB **儲存 `cc_cert_pem`**，供選民獨立驗證簽章公鑰身分鏈 | 🆕 | 📄 未提及 |
| BB **`BUNDLE_INCONSISTENT`** 結構一致性檢查（`merkle_leaf_count == len(valid_m_hex_list) == sum(tally)`） | 🆕 | 📄 未提及 |
| Merkle Proof 生成與驗證（`Rootcalculated` vs `Rootofficial`） | ✅ | ✅ 公式與流程一致，含視覺化驗證頁面（計畫書未提及視覺化） |

---

## 4. 與研究計畫書結構性不相符的總結（供論文修訂參考）

| # | 研究計畫書 | 目前程式碼 |
|---|---|---|
| 1 | 系統由「五個」獨立實體組成，不含 CA | 六個服務 + CA 獨立角色，另有 Admin 系統外工具 |
| 2 | 協定共「六個階段」 | 七個階段（多 Phase 0 選民註冊） |
| 3 | 無 Voting Token，認證後可無限次取盲簽章 | Voting Token 強制、一次性、10 分鐘效期、原子化消費 |
| 4 | Textbook RSA 盲簽章（`m' = m·rᵉ mod n`） | RSA-FDH-Blind（先做 Full-Domain Hash 擴展） |
| 5 | 未指定對稱加密模式 | AES-256-GCM（AEAD）+ AAD 綁定身分 |
| 6 | Merkle Tree 無 domain separator，易受二次原像攻擊 | Domain-separated hashing（0x00/0x01 前綴） |
| 7 | 「有效選票列表」公布方式未區分是否含票值 | 只公布 m_hex 清單，不公布 vote 對應 |
| 8 | 無選票去重、無洗牌機制描述 | m_hex/token_hash 雙重去重 + 持久化洗牌 |
| 9 | 無服務身分驗證機制描述（憑證核發、TA 釋放私鑰皆未談身分冒充防禦） | SERVICE_REGISTRATION_TOKEN、Subject CN 核對、Admin Bearer Token 等多層防冒充機制 |
| 10 | 無 OTP 濫用防禦、無憑證撤銷 | OTP 鎖定/過期、憑證撤銷 + 公開撤銷清單 |

---

## 5. 與 v2.0 規格書的殘餘落差（非 bug，屬範疇外）

以下項目 v2.0 規格書本身列為**未來工作**（§22.2），v3.0 不處理，且與研究計畫書無關：

- 門檻盲簽章（Threshold Blind Signature）
- Mix-Net 取代 secure shuffle
- 零知識證明強化 Tally 正確性驗證
- OCSP/CRL **即時**撤銷查詢（v3.0 已有撤銷清單資料模型與人工撤銷動作，但尚未把「查詢撤銷清單」接進每一次憑證驗證流程——即時撤銷生效機制列為未來工作）
- Post-Quantum 密碼學升級
- Receipt-Free 機制（抗強制投票）
- 正式形式化驗證（ProVerif / Tamarin）

以下為次要、非安全性的程式碼一致性事項，可視情況處理：
- 部分資料庫欄位命名沿用 v1.0（如 `si` vs `nonce`）
- CC 內部 dashboard 顯示逐票 vote+m_hex（此為 CC 角色本就持有的資訊，非對外洩漏，予以保留）

---

## 附錄：建議的研究計畫書修訂方向

1. 角色清單補上 CA，並新增 Phase 0（選民註冊：OTP + PoP + 白名單）說明
2. 盲簽章章節補充 FDH 擴展步驟，說明其防禦「存在性偽造攻擊」的必要性
3. 數位信封章節明確指定 AES-256-GCM，並說明 AAD 防重放/防篡改的角色
4. Merkle Tree 章節補充 domain-separated hashing 設計，說明其防禦 CVE-2012-2459 的原理
5. 新增「投票授權票（Voting Token）」小節，說明其如何防止一人多票
6. 計票階段補充「選票洗牌」與「僅公告 m_hex 清單」兩項隱私保護設計
7. 新增「服務身分驗證」小節：服務憑證一次性註冊權杖、TA/BB 對請求方憑證 Subject CN 的核對，說明其如何防止角色冒充
8. 新增「系統維運」小節：OTP 生命週期管理（鎖定/過期）、憑證撤銷機制、Admin 角色與其存取控制
