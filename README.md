# cvehub：哪台主機受哪些 CVE 影響

Landscape（主機與已安裝套件）＋ kernel API（執行中的 kernel）＋ Canonical OSV（漏洞資料）＋ Canonical VEX（官方處理狀態）→ 網頁查詢、輸出報表（季報表）、歷史紀錄、CSV／Excel 報表。

兩份 Canonical 資料都要（一起下載、一起更新）：
- **OSV**（`osv-all.tar.xz`）：每個套件的**第一個修正版本**，用來判斷主機要不要更新。
- **VEX**（`vex-all.tar.xz`）：官方處理狀態（Needs evaluation、Vulnerable、work in progress、fix deferred、Ignored、Fixed、Not affected、Not in release）。VEX 的版本號是目前最新版，不能拿來判斷主機，所以兩份都要。

- 一個容器：Python 3.12 ＋ Flask ＋ SQLite（第三方套件只有 Flask、gunicorn、APScheduler，可從 Nexus 安裝）
- Landscape 24.04／26.04 皆可（只用 legacy API 的 `GetComputers`、`GetPackages`）
- 漏洞資料手動下載、放進來就自動匯入，**可離線使用**

## 1. 需求

| 項目 | 建議 |
|---|---|
| 主機 | 任一台有 Docker（或 Podman）的 Linux，能連到 Landscape 和 kernel API |
| 記憶體 | 1 GB 以上（實測匯入 OSV 時容器峰值約 210 MiB） |
| 磁碟 | 2 GB 以上（實測資料庫約 240 MB：20.04／22.04／24.04／26.04 四個版本；OSV 檔每份約 47 MB，預設保留 5 份） |
| 網路 | 容器 → Landscape（HTTPS）、kernel API；**不需要連外** |

## 2. 部署步驟

照順序做，每一步都有 ✅ 確認方式；沒有出現 ✅ 的結果就先不要往下做。以下以安裝到 `/opt/cvehub` 為例，指令都用有 sudo 權限的帳號執行。

### 步驟 1：確認 Docker
```bash
docker --version && docker compose version
```
✅ 兩個都印出版本（Docker 24 以上、Compose v2）。

### 步驟 2：取得程式
```bash
sudo git clone https://github.com/paradise1019/cvehub.git /opt/cvehub
cd /opt/cvehub
```
不能連 GitHub 的環境：在可上網的機器下載 ZIP（GitHub 頁面 Code → Download ZIP），複製過去解開到 `/opt/cvehub`。
✅ `ls /opt/cvehub` 看得到 `docker-compose.yml`、`.env.example`、`cvehub/`。

### 步驟 3：建立 image
```bash
cd /opt/cvehub
sudo docker compose build
```
- 內網要從 Nexus 抓 Python 套件：`sudo PIP_INDEX_URL=https://<nexus>/repository/<pypi-proxy>/simple docker compose build`
- 基礎 image 要從內部 registry 拿：加上 `--build-arg BASE_IMAGE=<registry>/python:3.12-slim`

✅ `sudo docker images cvehub` 看得到 `cvehub:0.5.1`（約 190 MB）。

### 步驟 4：準備設定檔與資料目錄
```bash
cd /opt/cvehub
sudo cp .env.example .env
sudo chmod 600 .env
sudo mkdir -p config data/inbox data/vex-inbox
sudo chown -R 10001 data            # 容器內以 UID 10001 執行
```
⚠️ `.env` 會放 Landscape 金鑰與密碼雜湊，**不要 commit、不要寄出**（`.gitignore` 已排除 `.env`、`data/`、`config/`）。

### 步驟 5：跑自動化測試
```bash
sudo docker compose run --rm --no-deps cvehub python -m unittest discover -s tests -t . </dev/null
```
✅ 最後一行是 `OK`（中間會印出幾段 `ValueError`，那是「錯誤檔案要被拒絕」的測試，正常）。

### 步驟 6：在 Landscape 產生唯讀的 API 金鑰
見第 3 節：建一個只能檢視電腦的帳號，用它產生 API 金鑰（Settings → API credentials）。
Landscape 是自簽憑證時，把 Landscape 伺服器上的 `/etc/ssl/certs/landscape_server_ca.crt` 複製到 `/opt/cvehub/config/`。
✅ `ls /opt/cvehub/config/landscape_server_ca.crt` 存在（使用公開憑證的 Landscape 可略過，並把 `.env` 的 `LANDSCAPE_CA_FILE=` 留空）。

### 步驟 7：編輯 `.env`
`sudo nano /opt/cvehub/.env`，至少要改這些（其他維持預設即可，每一項都有說明）：

| 設定 | 填什麼 |
|---|---|
| `LANDSCAPE_API_URI` | `https://<Landscape 主機名稱>/api/`（主機名稱要和憑證一致） |
| `LANDSCAPE_API_KEY`、`LANDSCAPE_API_SECRET` | 步驟 6 產生的金鑰 |
| `UBUNTU_RELEASES` | 主機有用到的版本，例如 `20.04,22.04,24.04` |
| `KERNEL_API_URL` 等 | 有 kernel API 就依第 4 節填寫；**沒有就把 `KERNEL_API_URL=` 留空**（改用「最新安裝的 kernel」推測） |
| `TZ` | 時區，例如 `Asia/Taipei` |
| `SCHEDULE_SYNC` | 自動同步時間（cron 格式），預設每天 06:00、18:00 |

### 步驟 8：設定網頁登入密碼
```bash
cd /opt/cvehub
sudo docker compose run --rm --no-deps cvehub python -m cvehub.cli hash-password
```
輸入兩次密碼（至少 12 個字元），把輸出的整串（`scrypt:...`）填到 `.env` 的 `WEB_AUTH_PASSWORD_HASH=`。
⚠️ 雜湊值裡有 `$`，在 `.env` 裡**每個 `$` 都要寫成 `$$`**（docker compose 會把 `$` 當成變數）。
✅ 下面這行印出 `2`：
```bash
sudo docker compose run --rm --no-deps cvehub sh -c 'echo "$WEB_AUTH_PASSWORD_HASH" | tr -cd "$" | wc -c'
```

### 步驟 9：決定 HTTP 或 HTTPS
帳號密碼用 Basic Auth 傳送，**正式環境請用 HTTPS**（第 7 節：放在反向代理後面，或容器直接提供 HTTPS）。只在測試網段試用時可以先用 HTTP。

### 步驟 10：啟動
```bash
cd /opt/cvehub
sudo docker compose up -d
sudo docker compose logs --tail 20
```
✅ log 有「排程啟動」；`sudo docker compose ps` 狀態變成 `healthy`（約 1 分鐘）。

### 步驟 11：匯入漏洞資料（OSV 與 VEX 兩份都要）
1. 在能上網的機器下載兩個檔案：
   - `https://security-metadata.canonical.com/osv/osv-all.tar.xz`（約 50 MB）
   - `https://security-metadata.canonical.com/vex/vex-all.tar.xz`（約 80 MB）
2. 複製到主機，放進放檔目錄：
   ```bash
   sudo cp osv-all.tar.xz /opt/cvehub/data/inbox/
   sudo cp vex-all.tar.xz /opt/cvehub/data/vex-inbox/
   sudo chown -R 10001 /opt/cvehub/data
   ```
   （也可以用網頁「資料匯入」頁上傳。）
3. 立即匯入並同步（不想等排程）：
   ```bash
   sudo docker compose exec cvehub python -m cvehub.cli sync </dev/null
   ```
   OSV 約 4 分鐘、VEX 約 4 分鐘，接著向 Landscape 取主機與套件。

✅ 指令最後印出「同步完成：主機 N、…」，N 是 Landscape 裡的主機數。

### 步驟 12：確認網頁
1. 瀏覽器開 `http(s)://<主機>:8080/`，用 `WEB_AUTH_USER`（預設 `admin`）和步驟 8 的密碼登入。
2. 逐頁確認：
   - 總覽：主機清單、每台的 CVE 數
   - 資料匯入：OSV、VEX 兩份最新一筆都是 `ok`、使用中＝是；VEX「無法辨識」是 0
   - 輸出報表：按「快速選擇」某一季，統計表有數字，「下載 Excel」能開啟
   - 受影響主機：列出 CVE 與主機
3. 健康檢查：
   ```bash
   curl -s http://127.0.0.1:8080/healthz          # HTTPS 時：curl -sk https://127.0.0.1:8080/healthz
   ```
✅ 回 `"status":"ok"`、`"problems":[]`。

### 步驟 13：接上日常維護
- 漏洞資料每天或每週更新一次（兩份一起），見 `MAINTENANCE.md`
- 把 `/healthz` 接到監控（第 8 節）
- 定期備份 `data/cvehub.sqlite3`、`.env`、`config/`（第 10 節）

## 3. Landscape API 帳號（建議最小權限）

cvehub 只需要讀取電腦與套件清單。請在 Landscape 建一個專用帳號，給它**只能檢視電腦**的角色，再用這個帳號產生 API 金鑰（Settings → Generate API credentials）。不要用管理員的金鑰。

## 4. kernel API

### 4.1 兩種呼叫方式（`KERNEL_API_MODE`）

| 模式 | cvehub 怎麼呼叫 | 適合 |
|---|---|---|
| `per-host`（建議） | 每台主機 GET 一次，URL 裡的 `{hostname}`、`{shortname}`、`{ip}` 會換成這台主機的值（自動 URL 編碼） | 你的 API 是「給主機、回版本」 |
| `bulk` | GET 一次 `KERNEL_API_URL`，回傳全部主機 | API 能一次列出全部 |

URL 可以直接用 IP，例如：
```
KERNEL_API_MODE=per-host
KERNEL_API_URL=http://10.0.0.5:8000/api/kernel/?hostname={hostname}&ip={ip}
```

### 4.2 回應格式

per-host 模式接受兩種：
- **JSON 物件**：
  ```json
  {"hostname": "web01.example.com", "kernel_release": "6.8.0-147-generic",
   "kernel_version": "Ubuntu 6.8.0-147.147-generic 6.8.12", "collected_at": "2026-10-17T13:00:00+08:00"}
  ```
- **純文字**：只有版本，例如 `6.8.0-147.147`。cvehub 會從 Landscape 的套件清單找出對應的 kernel 名稱。限制：該 kernel 套件必須還裝在主機上
- 查無資料回 **404**（畫面顯示「無資料」，改用最新安裝的 kernel 推測）

bulk 模式：清單、Django REST framework 分頁（`{"results": [...], "next": ...}`），或 `{主機: {...}}`。

| 欄位（名稱可在 .env 改） | 說明 |
|---|---|
| `kernel_version` | **建議提供**：`/proc/version_signature` 的內容，程式會取出 `6.8.0-147.147` |
| `kernel_release` | `uname -r`。只有這個也可以，程式會從 Landscape 套件清單查 `linux-image-<uname -r>` 的版本 |
| `collected_at` | 收集時間（ISO 8601）。超過 `KERNEL_API_MAX_AGE_HOURS` 視為過期，不採用 |
| `hostname` | bulk 模式用來對應主機 |

主機對應（`HOST_MATCH_KEY`）：`hostname`（完整名稱）、`shortname`（第一段）、`ip`（Landscape 回報的第一個 IPv4）。

認證：`KERNEL_API_AUTH=token`（送出 `Authorization: Token <...>`）、`bearer`、`basic` 或 `none`。

### 4.3 Django view（貼進你的專案）

`django-kernel-view/kernel_view.py`：只用 Django 內建功能，不需要 Django REST framework。
1. 放進你的某個 app，**只要改 `lookup_kernel(hostname, ip)`**：從你的資料回傳 kernel 資訊（檔案裡有範例）
2. `settings.py` 加 `CVEHUB_TOKEN`（和 cvehub 的 `KERNEL_API_TOKEN` 相同）、`CVEHUB_ALLOWED_IPS`（cvehub 主機 IP）
3. `urls.py` 加 `path("api/kernel/", kernel_version)`

已實測（Django 5.2）：用主機名稱、用 IP 查詢都正常；查無資料 404、token 錯誤 401、非 GET 405。

kernel API 查詢失敗（不是 404）時，沿用上一次取得的 kernel 資料並標示「查詢失敗」；執行中 kernel 的 CVE 不會因為查詢失敗而被標成已解決（0.3.1 修正）。

有 kernel 資料時，kernel CVE 以**執行中的 kernel** 判斷，處理方式為 `reboot`（修正版已安裝、重開機即可）或 `upgrade+reboot`。

## 5. 網頁

| 頁面 | 內容 |
|---|---|
| 總覽 | 各等級數量、OSV 資料日期（太舊會警告）、每台主機的 CVE 數與是否需要重開機、最近同步紀錄 |
| 受影響主機 | 給維運：以 CVE 為單位，看主機有幾台受影響。「待更新」＝已有修正版本、主機還沒更新；「尚無修正」＝主機有裝、官方還沒修正（待評估／受影響／修正中／延後修正／不修正）。每格只列 3 台主機（數百台時不會爆版），其餘點 CVE 頁；CSV 列全部；每頁 100 列 |
| 輸出報表 | 給主管：依 **CVE 公開日期**（可一鍵選季），列出 Ubuntu 官方對每個 CVE × 套件 × 版本（20.04／22.04／24.04）的處理狀態（繁體中文；滑鼠移到狀態上顯示官方英文名稱），**跟主機無關**。統計表＝等級 × 版本 × 狀態（以 CVE 計，多個套件取最需要注意的狀態）；明細可依狀態篩選、各欄排序、每頁 100 列；下載 Excel（統計、狀態說明、明細） |
| 明細 | 比對結果「主機 × 套件 × CVE」一行，只含已有修正版本的項目（官方還沒修正的看受影響主機）；可篩選主機、CVE、套件、等級、狀態、未解決／已解決（主機×CVE 彙總：`/findings?view=summary`） |
| 主機頁、CVE 頁 | 單一主機的所有 CVE；單一 CVE：每台主機的狀態（待更新／尚無修正／已修正／不受影響）與官方狀態表 |
| 例外 | 風險接受：主機（可用 `*`）＋ CVE（可用 `*`）＋原因＋到期日；不刪資料，只在畫面與報表上標示 |
| 資料匯入 | 上傳 osv-all.tar.xz、vex-all.tar.xz，兩份的匯入紀錄（sha256、檔案日期、VEX 無法辨識的說明數） |

每個清單都有「匯出 CSV」（含 BOM，Excel 直接開中文不亂碼）。JSON API：`/api/findings`、`/api/status`。

## 6. 指令列

```bash
docker compose exec cvehub python -m cvehub.cli sync </dev/null         # 立即同步
docker compose exec cvehub python -m cvehub.cli import-osv /data/inbox/osv-all.tar.xz </dev/null
docker compose exec cvehub python -m cvehub.cli report </dev/null       # 重新輸出報表
```
（`</dev/null`：在腳本裡呼叫時避免 `docker compose exec` 吃掉後面的輸入。）
同步／匯入同時只會有一個在執行（網頁按鈕、排程、指令列共用一把鎖）。

## 7. HTTPS

二擇一：

**A. 放在既有的反向代理後面（建議）**：容器維持 HTTP、只對代理開放，憑證由代理處理。nginx 範例：
```nginx
server {
    listen 443 ssl;
    server_name cvehub.example.com;
    ssl_certificate     /etc/ssl/cvehub.crt;
    ssl_certificate_key /etc/ssl/cvehub.key;
    client_max_body_size 200m;                 # 網頁上傳 OSV 檔（約 50 MB）
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;           # 必要：CSRF 檢查比對 Origin 和 Host
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
    }
}
```
這時 `docker-compose.yml` 的 ports 改成 `"127.0.0.1:8080:8080"`，只讓本機的代理連。

**B. 容器直接提供 HTTPS**：把憑證和私鑰放到 `config/`（私鑰擁有者 UID 10001、權限 600），`.env` 設定：
```
WEB_TLS_CERT=/config/tls.crt
WEB_TLS_KEY=/config/tls.key
```
重建容器後只接受 HTTPS（已實測：HTTPS 200、HTTP 不再接受）。

## 8. 監控（/healthz）

`GET /healthz` **不需要登入**，只回健康狀態，不含任何主機或 CVE 資料：
```json
{"status": "ok", "problems": [], "osv_file_date": "2026-10-17T13:09:58",
 "last_successful_sync": "2026-10-17T17:29:53", "version": "0.3.1"}
```
- 正常回 **200**；有問題回 **503**，`problems` 會列出原因：

| problems | 意思 | 怎麼處理 |
|---|---|---|
| `no_osv_data` | 還沒有漏洞資料 | 上傳 osv-all.tar.xz |
| `osv_data_stale` | OSV 檔超過 `OSV_STALE_WARN_DAYS` 天 | 下載新檔 |
| `last_osv_import_failed` | 最近一次匯入失敗（舊資料仍在使用） | 看「資料匯入」頁的訊息 |
| `vex_data_stale` / `last_vex_import_failed` | 有匯入 VEX 時才檢查：檔案太舊／最近一次匯入失敗 | 同 OSV |
| `kernel_api_error` | 有主機的 kernel API 查詢失敗（逾時、403、500…），沿用上次的 kernel 資料 | 看 `docker compose logs` 的「kernel API 查詢 … 失敗」，檢查 token、來源 IP 限制、對方服務 |
| `never_synced` / `sync_too_old` | 從沒同步成功／超過 `HEALTH_MAX_SYNC_AGE_HOURS` 小時沒成功 | 看 `docker compose logs`，通常是 Landscape 連不上或金鑰失效 |
| `last_sync_failed` | 最近一次同步失敗 | 同上 |

接到現有監控（Prometheus blackbox、Zabbix、Nagios 等）：HTTP 檢查 `/healthz` 回 200 即可。

## 9. 自動化測試

修改程式或升級版本後，先跑測試：
```bash
docker compose build
docker compose run --rm --no-deps cvehub python -m unittest discover -s tests -t . </dev/null
```
✅ 最後一行是 `OK`（目前 51 個測試，約 8 秒；不需要網路、Landscape 或真的 OSV／VEX 檔）。
過程中會印出一段 `ValueError: 檔案中沒有任何 24.04 的資料`，那是「錯誤檔案應該被拒絕」的測試，正常。

涵蓋：Debian 版本比較、OSV 匯入（撤回的 CVE、其他版本、惡意路徑、缺版本時保留舊資料、放檔目錄）、比對（已修／未修／部分修、Pro 才有的修正、舊 kernel、執行中 kernel 的 reboot／upgrade+reboot、kernel 名稱不在 OSV 時的推回）、歷史（新增→解決→再出現）、例外、kernel API（JSON／純文字／404／URL 編碼／主機對應）、網頁（登入、CSRF、XSS、/healthz、CSV）。

## 10. 備份與升級

- 要備份的只有 `data/cvehub.sqlite3`（歷史與例外）和 `.env`、`config/`
- 定期維護請見 `MAINTENANCE.md`
- 升級：替換程式目錄 → `docker compose build && docker compose up -d`；資料表會自動建立或升級
- ⚠️ 新版可能有新的設定項目：升級後和新的 `.env.example` 比對，把缺少的項目補進 `.env`（缺少時使用預設值，例如 `KERNEL_API_MODE` 預設是 `bulk`）

## 11. 限制

- Landscape 的套件清單是 client 定期回報的：client 每 30 分鐘檢查一次套件、每 15 分鐘和伺服器交換一次，**主機升級後最慢約 45 分鐘才會反映在 cvehub**（剛升級完馬上看會看到舊資料）
- Landscape 24 的套件清單可能漏少數套件（實測 692 個裡少 12 個），可偶爾用 `ubuntu_cve_report.py --dpkg` 抽查
- 服務沒重啟（記憶體裡還是舊函式庫）不在範圍內；需要時可用 `collect_running.py`
- PPA、第三方套件沒有 OSV 資料；Livepatch 已修補的 kernel CVE 仍會列出
- Ubuntu Pro／ESM 的判斷有實作但 lab 沒有 Pro 主機，**未實測**
- 網頁登入只有一組 basic auth 帳號；如需多人、AD／LDAP，建議放在既有的反向代理後面處理

## 12. 實測紀錄（lab，2026-10-17）

| 項目 | 結果 |
|---|---|
| OSV 匯入 | 42,504 個 CVE、223 萬筆 affected，約 4 分鐘；容器記憶體峰值 206 MiB；資料庫 241 MB |
| 放檔目錄自動匯入 | ✅ 排程偵測到新檔 → 匯入 → 同步 → 輸出報表 |
| c1（26.04）openssl 降版 | ✅ 38 個 CVE，處理方式 `upgrade`（與 `ubuntu_cve_report.py` 結果相同） |
| c2 kernel API 回報執行中 6.8.0-139 | ✅ 1,299 個 kernel CVE，處理方式 `reboot`（6.8.0-147 已安裝） |
| kernel 資料 3 天前（過期） | ✅ 標示 stale，不採用 |
| 修好後 | ✅ c2 改跑 7.0.0-38 後，1,299 個 kernel CVE 標示 `resolved_at`，`first_seen` 保留 |
| c2（24.04）openssl 降版 | ✅ 43 個 CVE（與 `ubuntu_cve_report.py` 相同） |
| 例外 | ✅ 標示原因與到期日，可隱藏 |
| kernel API per-host（Django view，用主機名稱／IP） | ✅ 都正確取得執行中 kernel |
| kernel API 純文字回應 | ✅ |
| 匯入檢查（每個版本筆數） | ✅ 20.04＝633,560、22.04＝871,999、24.04＝485,910、26.04＝90,790 |
| /healthz、HTTPS | ✅ 正常 200；容器直接提供 HTTPS 時只接受 HTTPS |
| 自動化測試 | ✅ 27 個全部通過 |
| 登入、CSRF、XSS | ✅ 未登入／錯誤密碼 401；跨站 POST 403；輸入的 HTML 被轉成純文字 |
