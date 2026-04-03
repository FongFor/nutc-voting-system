# NUTC Voting System

## 系統架構

各服務以 Docker 容器方式運行，透過 Docker 內部網路互相溝通：


| 服務      | Port      | 說明                                                        |
| --------- | --------- | ----------------------------------------------------------- |
| **CA**    | 5001      | 憑證授權中心，整個系統的信任根，負責簽發各服務的 X.509 憑證 |
| **TPA**   | 5000      | 第三方認證機構，處理選民身分驗證和盲簽章，不知道選民投給誰  |
| **TA**    | 5002      | 時間授權中心，管理投票時間窗口，截止後才釋放 SK_TA 給 CC    |
| **CC**    | 5003      | 計票中心，收集加密選票，截止後解密驗證並建立 Merkle Tree    |
| **BB**    | 5004      | 公告板，公開展示計票結果，提供互動式 Merkle Proof 驗證      |
| **Voter** | 5005-5007 | 選民端 Web UI，每個選民一個容器                             |

---

## 投票流程

```
Phase 1  CA 啟動，各服務向 CA 申請憑證
Phase 2  選民向 TPA 雙向認證（含 CA 憑證鏈驗證）
Phase 3  選民盲化選票 → TPA 盲簽章 → 打包數位信封 → 送至 CC
Phase 4  等待投票截止（TA 管理倒數計時）
Phase 5  CC 向 TA 取得 SK_TA → 解密驗證選票 → 建 Merkle Tree → 推送至 BB
Phase 6  BB 公告結果，選民可用 m_hex 驗證選票是否被計入
```

### 安全機制

- **匿名性**：盲簽章讓 TPA 無法得知選民投給誰
- **防重放**：每個認證封包含 nonce (si)，用過即作廢
- **防重複投票**：TPA 記錄已投票的選民 ID
- **截止強制執行**：截止後 TPA 和 CC 拒絕所有新請求（HTTP 403）
- **可驗證性**：Merkle Tree 讓每位選民可以獨立驗證自己的選票

## 開始

每次測試都要reset一遍比較好

### 環境需求

- Docker Desktop（建議 4.x 以上）
- Python 3.10+（用於執行測試腳本）
- 套件詳見`requirements.txt`

### 啟動系統

```bash
docker compose up --build
```

等待所有服務健康檢查通過（約 30-60 秒）就OK。

### 執行測試

```bash
# 標準 E2E 測試（3 位預設選民）
python e2e_test.py

# 多人並發模擬（預設 50 人）
python simulate_voters.py

# 自選人數
python simulate_voters.py -n 20
python simulate_voters.py -n 100

# 更多選項
python simulate_voters.py --help
```

### 重置系統

```bash
python reset.py
docker compose down -v
docker compose up --build
```

## 設定檔

所有業務參數都在 `config.json`，修改後不需要重啟容器。

```json
{
  "candidates": ["候選人A", "候選人B", "候選人C"],
  "timing": {
    "vote_duration_seconds": 120,
    "delta_t_seconds": 300
  }
}
```

**修改候選人**：直接編輯 `config.json` 的 `candidates` ，存檔後即生效。

**修改投票時長**：調整 `vote_duration_seconds`，下次重置後套用。

## Web UI


| 服務             | 網址                  | 說明                         |
| ---------------- | --------------------- | ---------------------------- |
| 選民端 VOTER_001 | http://localhost:5005 | 投票頁面                     |
| 選民端 VOTER_002 | http://localhost:5006 | 投票頁面                     |
| 選民端 VOTER_003 | http://localhost:5007 | 投票頁面                     |
| TPA 儀表板       | http://localhost:5000 | 認證記錄監控                 |
| TA 倒數計時      | http://localhost:5002 | 投票截止倒數                 |
| CC 儀表板        | http://localhost:5003 | 信封收集與開票狀況           |
| BB 公告板        | http://localhost:5004 | 計票結果與 Merkle Proof 驗證 |

---

## Merkle Proof 驗證

投票完成後，頁面會顯示你的 `m_hex`（選票識別碼）。

1. 開票後前往 BB 公告板：http://localhost:5004/verify
2. 輸入你的 `m_hex`
3. 頁面會顯示互動式 Merkle Tree，標示從你的選票到根節點的完整路徑
4. 可以看到 `m_hex`、`sibling` 陣列、`Root_official` 等資訊

也可以直接呼叫 API：

```bash
curl http://localhost:5004/api/merkle_proof/<你的m_hex>
```

## API 參考

### CA (5001)


| 方法 | 路徑             | 說明           |
| ---- | ---------------- | -------------- |
| GET  | /api/ca_cert     | 取得 CA 根憑證 |
| POST | /api/issue_cert  | 申請憑證       |
| POST | /api/verify_cert | 驗證憑證       |

### TPA (5000)


| 方法 | 路徑               | 說明                     |
| ---- | ------------------ | ------------------------ |
| GET  | /api/public_key    | 取得 TPA 公鑰（含 e, n） |
| POST | /api/auth          | 選民身分認證             |
| POST | /api/blind_sign    | 盲簽章                   |
| GET  | /api/config        | 查看目前設定             |
| POST | /api/config/reload | 重新載入 config.json     |

### TA (5002)


| 方法 | 路徑               | 說明                           |
| ---- | ------------------ | ------------------------------ |
| GET  | /api/public_key    | 取得 TA 公鑰                   |
| GET  | /api/deadline      | 查詢截止時間（Unix timestamp） |
| POST | /api/release_key   | 釋放 SK_TA（截止後才放行）     |
| GET  | /api/config        | 查看目前設定                   |
| POST | /api/config/reload | 重新載入 config.json           |

### CC (5003)


| 方法 | 路徑                  | 說明                 |
| ---- | --------------------- | -------------------- |
| GET  | /api/public_key       | 取得 CC 公鑰         |
| POST | /api/receive_envelope | 接收數位信封         |
| POST | /api/tally            | 觸發開票             |
| GET  | /api/results          | 查詢計票結果         |
| GET  | /api/config           | 查看目前設定         |
| POST | /api/config/reload    | 重新載入 config.json |

### BB (5004)


| 方法 | 路徑                        | 說明                        |
| ---- | --------------------------- | --------------------------- |
| POST | /api/publish                | 接收 CC 推送的計票結果      |
| GET  | /api/results                | 查詢計票結果與 Merkle Root  |
| GET  | /api/merkle_proof/\<m_hex\> | 取得指定選票的 Merkle Proof |
| GET  | /api/config                 | 查看目前設定                |
| POST | /api/config/reload          | 重新載入 config.json        |

---

## 模擬腳本

### simulate_voters.py

```bash
python simulate_voters.py              # 預設 50 人
python simulate_voters.py -n 10        # 10 人
python simulate_voters.py -n 100       # 100 人
python simulate_voters.py -n 50 --random      # 隨機分配候選人
python simulate_voters.py -n 50 --workers 20  # 20 個並發執行緒
python simulate_voters.py -n 50 --skip-wait   # 跳過等待截止
python simulate_voters.py -n 50 --verbose     # 顯示詳細步驟
```

輸出包含各候選人得票長條圖、模擬端預期分佈 vs CC 實際計票結果對比、Merkle Proof 驗證統計。

### e2e_test.py

```bash
python e2e_test.py                     # 測試所有選民
python e2e_test.py --voter VOTER_001   # 只測試指定選民
python e2e_test.py --skip-wait         # 跳過等待截止
python e2e_test.py --verbose           # 顯示詳細 HTTP 回應
```

## 專案結構

```
nutc-voting-system/
├── config.json              # 中心化設定檔（候選人、時間、服務位址）
├── docker-compose.yml       # 容器編排
├── Dockerfile               # 共用映像檔
├── requirements.txt         # Python 套件
├── ca_server/app.py         # 憑證授權中心
├── tpa_server/app.py        # 第三方認證機構
├── ta_server/app.py         # 時間授權中心
├── cc_server/app.py         # 計票中心
├── bb_server/app.py         # 公告板
├── voter_client/app.py      # 選民端
├── shared/
│   ├── config_loader.py     # 設定檔載入器（熱重載）
│   ├── auth_component.py    # 認證封包工具
│   ├── crypto_utils.py      # 數位信封加解密
│   ├── format_utils.py      # 格式轉換（含時區處理）
│   ├── key_manager.py       # 金鑰管理
│   ├── merkle_tree.py       # Merkle Tree
│   └── db_utils.py          # SQLite 工具
├── e2e_test.py              # 端到端測試
├── simulate_voters.py       # 多人投票模擬
└── reset.py                 # 重置腳本
```

## 疑難雜症

**Q：啟動後投票頁面顯示「服務尚未就緒」？**

各服務需要時間初始化金鑰和憑證，通常等 30-60 秒後重新整理即可。也可以觀察 `docker compose logs` 確認各服務是否正常啟動。

**Q：投票失敗，顯示「認證封包已過期」？**

這是時鐘偏差問題。`e2e_test.py` 和 `simulate_voters.py` 都有內建時鐘同步機制，會自動補償。如果手動呼叫 API，確認本機時間與容器時間差距在 `delta_t_seconds`（預設 300 秒）以內。

**Q：想修改候選人？**

直接編輯 `config.json` 的 `candidates` 陣列，存檔後即生效，不需要重啟容器。

**Q：想延長投票時間？**

修改 `config.json` 的 `timing.vote_duration_seconds`，然後執行 `python reset.py` 重置後重新啟動。

**Q：如何強制重新載入設定？**

```bash
curl -X POST http://localhost:5000/api/config/reload
curl -X POST http://localhost:5002/api/config/reload
curl -X POST http://localhost:5003/api/config/reload
```

## 細節

**時間處理**：後端和 API 一律用 Unix timestamp（整數秒），顯示給前端的時間用 `ts_to_human()` 轉換，預設 UTC+8。時區由 `DISPLAY_TIMEZONE_OFFSET` 環境變數控制，不依賴容器系統時區。

**Config **：`shared/config_loader.py` 的 `_HotReloadConfig` 每次存取時會檢查 `config.json` 的 mtime，有變化就自動重新載入，整個過程 thread-safe。

**截止時間強制執行**：TPA 和 CC 都有 Deadline Middleware，截止後的 `/api/auth`、`/api/blind_sign`、`/api/receive_envelope` 請求會直接回傳 HTTP 403，`code: DEADLINE_EXCEEDED`。voter前端也有倒數計時，截止後送出按鈕會被禁用。
