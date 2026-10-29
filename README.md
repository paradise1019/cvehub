# cvehub：哪台主機受哪些 CVE 影響

Landscape（主機與已安裝套件）＋ kernel API（執行中的 kernel）＋ Canonical OSV（漏洞資料）＋ Canonical VEX（官方處理狀態）→ 網頁查詢、輸出報表（季報表）、歷史紀錄、CSV／Excel 報表。

兩份 Canonical 資料都要（一起下載、一起更新）：
- **OSV**（`osv-all.tar.xz`）：每個套件的**第一個修正版本**，用來判斷主機要不要更新。
- **VEX**（`vex-all.tar.xz`）：官方處理狀態（Needs evaluation、Vulnerable、work in progress、fix deferred、Ignored、Fixed、Not affected、Not in release）。VEX 的版本號是目前最新版，不能拿來判斷主機，所以兩份都要。

- 一個容器：Python 3.12 ＋ Flask ＋ SQLite（第三方套件只有 Flask、gunicorn、APScheduler，可從 Nexus 安裝）
- Landscape 24.04／26.04 皆可（只用 legacy API 的 `GetComputers`、`GetPackages`）
- 漏洞資料手動下載、放進來就自動匯入，**可離線使用**

> **cvetrack**（[`cvetrack/`](cvetrack/README.md)）：同樣的比對規則，做成可以裝進既有 Django 專案的 app，另外追蹤每次匯入／同步的**變化**（新公告、釋出修正、已修補、已移除、已重開機…）並對應**變更單號**。cvehub 本身不受影響，兩者各自獨立部署。

## 1. 需求

| 項目 | 建議 |
|---|---|
| 主機 | 任一台有 Docker（或 Podman）的 Linux，能連到 Landscape 和 kernel API |
| 記憶體 | 1 GB 以上（實測匯入 OSV 時容器峰值約 210 MiB） |
| 磁碟 | 2 GB 以上（實測資料庫約 240 MB：20.04／22.04／24.04／26.04 四個版本；OSV 檔每份約 47 MB，預設保留 5 份） |
| 網路 | 容器 → Landscape（HTTPS）、kernel API；**不需要連外** |

## 2. 部署步驟

照順序做，每一步都有 ✅ 確認方式；沒有出現 ✅ 的結果就先不要往下做。以下以安裝到 `/opt/cvehub`、zip 放在 `/tmp` 為例，指令都用有 sudo 權限的帳號執行。
主機**不需要能 `docker pull`、不需要連外**：基礎 image 由別台機器準備好帶進來，Python 套件從內部 Nexus 安裝。

### 步驟 1：確認 Docker
```bash
sudo docker --version && sudo docker compose version
```
✅ 兩個都印出版本（Docker 24 以上、Compose v2）。

### 步驟 2：解開程式
從 GitHub 下載 zip（Code → Download ZIP，或 Tags 裡某個版本的 Source code (zip)），放到 `/tmp`：
```bash
cd /tmp && python3 -m zipfile -e /tmp/cvehub-main.zip /tmp/cvehub-src
sudo mkdir -p /opt/cvehub
sudo cp -a /tmp/cvehub-src/*/. /opt/cvehub/
cd /opt/cvehub
```
✅ `ls /opt/cvehub` 看得到 `docker-compose.yml`、`.env.example`、`cvehub/`、`scripts/`。

### 步驟 3：準備基礎 image（主機不能 docker pull 時）
在**一台能上網、有 Docker 的機器**（同樣是 x86_64）：
```bash
docker pull python:3.12-slim
docker save python:3.12-slim | gzip > python-3.12-slim.tar.gz
sha256sum python-3.12-slim.tar.gz        # 記下來，帶進去後核對
```
把檔案帶到 cvehub 主機的 `/tmp`，然後：
```bash
sha256sum /tmp/python-3.12-slim.tar.gz   # 和上面一致
sudo docker load -i /tmp/python-3.12-slim.tar.gz
```
✅ `sudo docker image inspect python:3.12-slim >/dev/null && echo OK` 印出 `OK`。
（內部 registry 有這個 image 時，也可以 load 那一份，並在 `.env` 的 `BASE_IMAGE=` 寫它的完整名稱，例如 `nexus.example.com:8443/python:3.12-slim`。）

### 步驟 4：準備設定檔與資料目錄，填建置設定
```bash
cd /opt/cvehub
sudo cp .env.example .env
sudo chmod 600 .env
sudo mkdir -p config data/inbox data/vex-inbox
sudo chown -R 10001 data            # 容器內以 UID 10001 執行
sudo nano .env                      # 先改最上面的「0. 建置」
```

| 設定 | 填什麼 |
|---|---|
| `BASE_IMAGE` | 步驟 3 載入的 image 名稱（預設 `python:3.12-slim`） |
| `PIP_INDEX_URL` | Nexus 的 PyPI proxy，例：`https://nexus.example.com/repository/pypi-proxy/simple` |
| `PIP_TRUSTED_HOST` | Nexus 是自簽憑證時填它的主機名稱（例：`nexus.example.com`）；公開憑證留空 |
| `BUILD_HTTP_PROXY` 等 | 建置時連 Nexus 要經過 proxy 才填，一般留空 |

⚠️ `.env` 之後會放 Landscape 金鑰，**不要 commit、不要寄出**（`.gitignore` 已排除 `.env`、`data/`、`config/`）。

### 步驟 5：建立 image
```bash
cd /opt/cvehub
sudo docker compose build
```
過程中會看到 `Looking in indexes: <你的 Nexus>`，表示套件從 Nexus 安裝。
✅ 最後是 `Built`；`sudo docker images cvehub` 看得到新版本（約 190 MB）。
❌ `pull access denied`／`failed to resolve source metadata`：基礎 image 沒載入或名稱和 `BASE_IMAGE` 不同，回到步驟 3。
❌ `Could not find a version that satisfies the requirement`／SSL 錯誤：檢查 `PIP_INDEX_URL`、`PIP_TRUSTED_HOST`，以及 Nexus 的 PyPI proxy 能不能抓到 `requirements.txt` 裡的套件。

### 步驟 6：跑自動化測試
```bash
sudo docker compose run --rm --no-deps cvehub python -m unittest discover -s tests -t . </dev/null
```
✅ 最後一行是 `OK`（中間會印出幾段 `ValueError`、匯入紀錄，那是測試內容，正常）。

### 步驟 7：在 Landscape 產生唯讀的 API 金鑰
見第 3 節：建一個只能檢視電腦的帳號，用它產生 API 金鑰（Settings → API credentials）。
Landscape 是自簽憑證時，把 Landscape 伺服器上的 `/etc/ssl/certs/landscape_server_ca.crt` 複製到 `/opt/cvehub/config/`。
✅ `ls /opt/cvehub/config/landscape_server_ca.crt` 存在（使用公開憑證的 Landscape 可略過，並把 `.env` 的 `LANDSCAPE_CA_FILE=` 留空）。

### 步驟 8：編輯 `.env`
`sudo nano /opt/cvehub/.env`，除了步驟 4 的建置設定，至少還要改這些（其他維持預設即可，每一項都有說明）：

| 設定 | 填什麼 |
|---|---|
| `LANDSCAPE_API_URI` | `https://<Landscape 主機名稱>/api/`（主機名稱要和憑證一致） |
| `LANDSCAPE_API_KEY`、`LANDSCAPE_API_SECRET` | 步驟 7 產生的金鑰 |
| `UBUNTU_RELEASES` | 主機有用到的版本，例如 `20.04,22.04,24.04` |
| `KERNEL_API_URL` 等 | 有 kernel API 就依第 4 節填寫；**沒有就把 `KERNEL_API_URL=` 留空**（改用「最新安裝的 kernel」推測） |
| `TZ` | 時區，例如 `Asia/Taipei` |
| `SCHEDULE_SYNC` | 自動同步時間（cron 格式），預設每天 06:00、18:00 |

### 步驟 9：建立第一個管理員帳號
```bash
cd /opt/cvehub
sudo docker compose run --rm --no-deps cvehub python -m cvehub.cli user-add admin admin
```
（第一個 `admin` 是帳號名稱，可以自己取；第二個 `admin` 是角色。）輸入兩次密碼（至少 12 個字元）。
✅ 印出「已新增 admin（管理）」；`sudo docker compose run --rm --no-deps cvehub python -m cvehub.cli user-list` 看得到這個帳號。
其他人的帳號登入後在「帳號管理」頁建立（見第 5.1 節）。

### 步驟 10：決定 HTTP 或 HTTPS
登入時密碼會經過網路傳送，**正式環境請用 HTTPS**（第 7 節：放在反向代理後面，或容器直接提供 HTTPS）。只在測試網段試用時可以先用 HTTP。

### 步驟 11：啟動
```bash
cd /opt/cvehub
sudo docker compose up -d
sudo docker compose logs --tail 20
```
✅ log 有「排程啟動」；`sudo docker compose ps` 狀態變成 `healthy`（約 1 分鐘）。

### 步驟 12：匯入漏洞資料（OSV 與 VEX 兩份都要）
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

### 步驟 13：確認網頁
1. 瀏覽器開 `http(s)://<主機>:8080/`，用步驟 9 建立的帳號登入。
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

### 步驟 14：接上日常維護
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
| 輸出報表 | 給主管：依 **CVE 公開日期**（可一鍵選季），**跟主機無關**，「已修正」以**報表期末日**判斷（修正的 USN 在期末前發布才算）。最上方是**主管摘要**：一句話結論、數字卡（critical＋high）、版本 × 等級矩陣（尚未解決／適用，和上一期比較）、要做的事（kernel 升級版本、一般套件更新、官方未修正追蹤）。下方依序是統計（版本 → 等級 → kernel／其他套件）、Kernel 修補版本（附評鑑單文字）、可展開的狀態明細、CVE 明細（篩選、排序、每頁 100 列）。Excel 依序：主管摘要、統計、狀態明細、Kernel 修補版本、Kernel 明細、狀態說明、明細 |
| 明細 | 比對結果「主機 × 套件 × CVE」一行，只含已有修正版本的項目（官方還沒修正的看受影響主機）；可篩選主機、CVE、套件、等級、狀態、未解決／已解決（主機×CVE 彙總：`/findings?view=summary`） |
| 主機頁、CVE 頁 | 單一主機的所有 CVE；單一 CVE：每台主機的狀態（待更新／尚無修正／已修正／不受影響）與官方狀態表 |
| 例外 | 風險接受：主機（可用 `*`）＋ CVE（可用 `*`）＋原因＋到期日；不刪資料，只在畫面與報表上標示 |
| 資料匯入 | 上傳 osv-all.tar.xz、vex-all.tar.xz，兩份的匯入紀錄（sha256、檔案日期、VEX 無法辨識的說明數） |

### 5.1 帳號與權限

| 角色 | 可以做的事 |
|---|---|
| 檢視 | 看所有頁面、下載 Excel／CSV、變更自己的密碼 |
| 管理 | 另外可以上傳 OSV／VEX、新增／刪除例外、立即同步、帳號管理 |

- 帳號管理（右上角「帳號管理」，只有管理員看得到）：新增帳號、重設密碼、變更角色、停用；下方是稽核紀錄（登入、帳號變更、上傳、例外、同步）。
- 密碼至少 12 個字元，只存雜湊值。連續輸錯 5 次鎖 15 分鐘（管理員重設密碼可解除）。閒置 60 分鐘自動登出（`WEB_SESSION_IDLE_MINUTES`）。
- 改密碼、改角色、停用後，該帳號原本的登入立即失效。至少會保留一個啟用中的管理員。
- 忘記密碼、管理員都進不去時，在主機上用指令重設：`sudo docker compose exec cvehub python -m cvehub.cli user-passwd admin`
- 腳本呼叫 `/api/findings`、`/api/status` 用 Basic Auth（任何啟用中的帳號，建議另建一個「檢視」帳號給腳本用）。

每個清單都有「匯出 CSV」（含 BOM，Excel 直接開中文不亂碼）。JSON API：`/api/findings`、`/api/status`（Basic Auth，見 5.1）。

## 6. 指令列

```bash
docker compose exec cvehub python -m cvehub.cli sync </dev/null         # 立即同步
docker compose exec cvehub python -m cvehub.cli import-osv /data/inbox/osv-all.tar.xz </dev/null
docker compose exec cvehub python -m cvehub.cli report </dev/null       # 重新輸出報表
docker compose exec cvehub python -m cvehub.cli user-list </dev/null    # 列出帳號
docker compose exec cvehub python -m cvehub.cli user-add <帳號> viewer  # 新增帳號（互動輸入密碼；角色 viewer 或 admin）
docker compose exec cvehub python -m cvehub.cli user-passwd <帳號>      # 重設密碼（也會解除鎖定）
docker compose exec cvehub python -m cvehub.cli user-role <帳號> admin
docker compose exec cvehub python -m cvehub.cli user-disable <帳號>     # user-enable 重新啟用
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
✅ 最後一行是 `OK`（目前 64 個測試，約 9 秒；不需要網路、Landscape 或真的 OSV／VEX 檔）。
過程中會印出一段 `ValueError: 檔案中沒有任何 24.04 的資料`，那是「錯誤檔案應該被拒絕」的測試，正常。

涵蓋：Debian 版本比較、OSV 匯入（撤回的 CVE、其他版本、惡意路徑、缺版本時保留舊資料、放檔目錄）、比對（已修／未修／部分修、Pro 才有的修正、舊 kernel、執行中 kernel 的 reboot／upgrade+reboot、kernel 名稱不在 OSV 時的推回）、歷史（新增→解決→再出現）、例外、kernel API（JSON／純文字／404／URL 編碼／主機對應）、網頁（登入、CSRF、XSS、/healthz、CSV）。

## 10. 更新與回復

### 10.1 取得新版
- 有網路：GitHub 頁面右側「Releases／Tags」選版本 → 下載 **Source code (zip)**，或直接下載
  `https://github.com/paradise1019/cvehub/archive/refs/tags/v<版本>.zip`（例：`v0.6.0.zip`）
- 只想拿最新開發版：Code → Download ZIP（`main` 分支）
- 先看 `CHANGELOG.md` 的「升級注意」

### 10.2 用更新腳本（建議）
把 zip 複製到主機（例如 `/tmp/cvehub-0.6.0.zip`），然後：
```bash
cd /opt/cvehub
sudo bash scripts/upgrade.sh /tmp/cvehub-0.6.0.zip
```
換好程式後，腳本會用和建置相同的 compose 設定確認基礎 image（`BASE_IMAGE`）在本機；沒有的話試著 `docker pull`，主機不能連外而拉不到時就自動還原程式並提示（容器不會動到）。換程式到測試完成之間（步驟 2–3）失敗、按 Ctrl-C 或 SSH 斷線，都會自動還原程式；開始停機後（步驟 4–6）SSH 斷線不會中止腳本，會繼續把新版啟動完成；這段按 Ctrl-C 或失敗則會印出回復指令。
腳本會顯示「目前版本 → 新版本」與更新說明，確認後依序：
1. 備份程式與設定到 `backups/<時間>-<舊版本>/code.tgz`
2. 替換程式檔（**`.env`、`data/`、`config/`、`docker-compose.override.yml` 不會動**）
3. 建立新版 image、跑自動化測試——**失敗就自動還原程式，舊版容器照常運作，不會停機**
4. 停止容器、備份資料庫到同一個備份目錄
5. 啟動新版（資料庫結構與資料格式會自動升級）
6. 等容器 healthy，印出 `/healthz`

✅ 最後印出「已更新到 x.y.z」與回復指令。到網頁右上角確認版本號。
每次更新／回復的過程也會記在 `backups/upgrade.log`（SSH 斷線後可以用它確認結果）；同時只能有一個更新或回復在執行。

**第一次從 0.5.x 更新**（舊版還沒有 `scripts/`）：用新版裡的腳本，並指定安裝目錄：
```bash
mkdir /tmp/cvehub-new && cd /tmp/cvehub-new && python3 -m zipfile -e /tmp/cvehub-0.6.0.zip .
sudo CVEHUB_DIR=/opt/cvehub bash /tmp/cvehub-new/*/scripts/upgrade.sh /tmp/cvehub-0.6.0.zip
```

### 10.3 更新基礎 image（Python 安全更新，建議每季一次）
照步驟 3 在能上網的機器重新 `docker pull python:3.12-slim` → `docker save`，帶進主機 `docker load`（同名會取代舊的），然後用目前版本的 zip 再跑一次更新腳本：
```bash
sudo bash /opt/cvehub/scripts/upgrade.sh /tmp/cvehub-main.zip
```
腳本會用新的基礎 image 重建、測試、再啟動；版本號不變也可以這樣做。

### 10.4 回復
```bash
cd /opt/cvehub
ls backups/                                         # 找到更新前的備份，例：20261022-093000-0.5.1
sudo bash scripts/upgrade.sh --rollback backups/20261022-093000-0.5.1
```
程式與資料庫都回到更新前（更新後的同步結果會在下次同步重新產生；`.env`、`config/` 不會被還原）。

### 10.5 備份
- 定期複製 `data/cvehub.sqlite3`（建議先 `docker compose stop`，或用 `sqlite3 ... ".backup"`）、`.env`、`config/` 到別台機器
- `backups/` 每次更新會多一份（含資料庫），腳本自動只保留最近 5 份（`sudo CVEHUB_KEEP_BACKUPS=10 bash scripts/upgrade.sh …` 可改）

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
