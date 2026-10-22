# cvehub 維護清單

## 定期

| 頻率 | 工作 | 怎麼做 | 確認 |
|---|---|---|---|
| 每天或每週 | 更新漏洞資料（兩份一起） | 下載 `https://security-metadata.canonical.com/osv/osv-all.tar.xz` 與 `.../vex/vex-all.tar.xz`，放到 `data/inbox/`、`data/vex-inbox/` 或用網頁上傳 | 「資料匯入」頁兩份最新一筆都是 `ok`、使用中＝是；VEX「無法辨識」是 0；`/healthz` 沒有 `*_stale` |
| 每天 | 看健康狀態 | 監控 `/healthz` 是否 200 | 503 時依 README 第 8 節處理 |
| 每月 | 抽查 Landscape 套件清單是否完整 | 挑 2–3 台主機，用 `ubuntu_cve_report.py --dpkg` 跑一次，和 cvehub 的結果比較 | CVE 清單相同 |
| 每季 | 重建 image（取得 Python、套件的安全更新） | 在能上網的機器重新存一份基礎 image 帶進來 `docker load`，再用目前版本的 zip 跑 `scripts/upgrade.sh`（README 10.3） | 腳本最後「已更新」；網頁正常；`/healthz` 200 |
| 每季 | 備份 | 複製 `data/cvehub.sqlite3`（建議先 `docker compose stop`，或用 `sqlite3 ... ".backup"`）、`.env`、`config/` 到別台機器 | 備份檔能用 sqlite3 開啟 |
| 每季 | 檢查例外 | 「例外」頁看有沒有快到期或已過期的項目 | 過期的例外處理掉或延長 |
| 每季 | 檢查帳號 | 「帳號管理」頁：離職或調動的人停用、看稽核紀錄有沒有異常登入失敗 | 只剩需要的帳號 |
| 每年 | 更新相依套件版本 | 調整 `requirements.txt` 的版本號 → 重建 → 跑測試 | 測試 `OK` |

## 事件觸發

### Landscape 升級後
1. 網頁按「立即同步」，或 `docker compose exec cvehub python -m cvehub.cli sync </dev/null`
2. ✅ 主機數、套件數和升級前差不多
3. ❌ 出現 `Landscape API GetComputers 失敗` 之類的錯誤：legacy API 可能有變動。Landscape 的呼叫都在 `cvehub/sources.py` 的 `Landscape` 類別，只需要改這裡（例如改用 REST API `/api/v2/computers`）

### 新的 Ubuntu 版本上線（約每兩年一次 LTS）
1. `.env` 的 `UBUNTU_RELEASES` 加上新版本，例如 `20.04,22.04,24.04,26.04`
2. 重新匯入 OSV 與 VEX（網頁上傳同一份檔案，或 `cli import-osv`／`cli import-vex`）；VEX 版本代號在 `cvehub/vex_import.py` 的 `CODENAMES`
3. ✅ 「資料匯入」頁新版本的筆數 > `OSV_MIN_ROWS_PER_RELEASE`
4. 找一台新版本的主機，確認 kernel 判斷正確：主機頁的「執行中 kernel」有值、kernel 套件名稱規則沒變（`cvehub/sync.py` 的 `KERNEL_ABI`、`KERNEL_NAME`）

### 舊的 Ubuntu 版本全部退役
`UBUNTU_RELEASES` 拿掉該版本 → 重新匯入，資料庫會變小。

### VEX 有「無法辨識」的說明
- Canonical 改了 VEX 說明文字的措辭；那些套件的狀態會顯示 Unknown（統計表多一欄）
- 「資料匯入」頁的訊息列出新句子；在 `cvehub/vex_import.py` 的 `classify()` 加上對應，跑測試後重新匯入

### OSV 匯入失敗（`last_osv_import_failed`）
- 「資料匯入」頁的訊息會說明原因；舊資料仍在使用，報表不受影響
- 「某版本的資料筆數不足」：先確認 `UBUNTU_RELEASES` 沒設錯；沒設錯的話，可能是 Canonical 改了 OSV 的版本名稱（例如 `Ubuntu:24.04:LTS`），要調整 `cvehub/osv_import.py` 的 `wanted_ecosystems()`

### Python 版本到期（3.12 於 2028-10 停止支援）
1. 照 README 步驟 3 準備並載入 `python:3.13-slim`
2. `.env` 改 `BASE_IMAGE=python:3.13-slim`
3. 用目前版本的 zip 跑 `scripts/upgrade.sh`（會重建、跑測試，失敗自動還原）

### 升級 cvehub 本身
1. 下載新版 zip，先看 `CHANGELOG.md` 的「升級注意」
2. `sudo bash scripts/upgrade.sh <新版 zip>`（README 第 10 節；自動備份、測試、失敗還原）
3. 腳本若列出「.env 沒有的新設定」：依 `.env.example` 的說明決定要不要補進 `.env`（不補就用預設值），補完 `docker compose up -d`
4. 確認網頁右上角版本與 `/healthz` 正常；有問題 `--rollback`
5. `backups/` 由腳本自動只保留最近 5 份

## 已知限制（處理前請先確認）
- Landscape 的套件資料有延遲（最慢約 45 分鐘）
- Landscape 24 的套件清單可能漏少數套件（所以要每月抽查）
- Ubuntu Pro／ESM 的判斷未經實測；第一次有 Pro 主機時，請用 `ubuntu_cve_report.py --dpkg` 對照
