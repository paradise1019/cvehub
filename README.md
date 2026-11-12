# cvehub：哪台主機受哪些 CVE 影響

把「每台主機裝了哪些套件」和 Canonical 的漏洞資料比對，告訴你哪台主機要更新什麼、要不要重開機，並產生給主管看的報表。

```
主機清單 CSV（Ansible 收集）──┐
                              ├─→ cvehub（一個容器）─→ 網頁、Excel 報表
OSV＋VEX（Canonical 漏洞資料）─┘
```

- **主機清單**：每台主機的 Ubuntu 版本與已安裝套件，用附的 Ansible playbook 收集（也可以改接 Landscape，見附錄 F）。
- **OSV**（`osv-all.tar.xz`，約 55 MB）：每個套件的第一個修正版本，用來判斷主機要不要更新。
- **VEX**（`vex-all.tar.xz`，約 80 MB）：官方處理狀態（Needs evaluation、Vulnerable、Not affected…），給報表用。
- 一個容器（Python 3.12＋Flask＋SQLite），**不需要連外**；漏洞資料用瀏覽器下載後從網頁上傳。

## 1. 需求

| 項目 | 需求 |
|---|---|
| 主機 | x86_64 Linux，有 Docker 24 以上與 Compose v2（`sudo apt install docker.io docker-compose-v2`）、python3 |
| 記憶體／磁碟 | 1 GB 以上／2 GB 以上（四個 Ubuntu 版本的資料庫約 250 MB） |
| 基礎 image | `python:3.12-slim`：主機能 `docker pull` 就自動抓；不能的話先 `docker load`（步驟 1） |
| Python 套件 | 建置時從 PyPI 或內部 Nexus 安裝（Flask、gunicorn、APScheduler、openpyxl，共約 12 MB） |
| 帶進去的檔案 | 程式 zip 約 120 KB；不能 pull 時另加基礎 image 約 45 MB；完全離線時改帶離線安裝包約 50 MB（見「完全離線」） |

建好的 image 約 190 MB（基礎 image 占大部分）。

## 2. 安裝

### 步驟 1：準備基礎 image（主機不能 docker pull 時才需要）
在能上網的電腦：
```bash
docker pull python:3.12-slim
docker save python:3.12-slim | gzip > python-3.12-slim.tar.gz
```
帶到主機後：
```bash
sudo docker load -i python-3.12-slim.tar.gz
```
✅ `sudo docker image inspect python:3.12-slim >/dev/null && echo OK` 印出 `OK`。
內部 registry 有這個 image 時，也可以 load 那一份，安裝時「基礎 image」填它的完整名稱。

### 步驟 2：執行 install.sh
把程式 zip（GitHub「Code → Download ZIP」下載的 `cvehub-main.zip`）放到主機的 `/tmp`：
```bash
rm -rf /tmp/cvehub-src && python3 -m zipfile -e /tmp/cvehub-main.zip /tmp/cvehub-src
sudo bash /tmp/cvehub-src/*/install.sh
```
腳本會問幾個問題（直接按 Enter 用預設值）：

| 問題 | 預設 | 說明 |
|---|---|---|
| 主機來源 | `file` | `file`＝匯入主機清單；`landscape`＝接 Landscape（會再問網址與金鑰） |
| Ubuntu 版本 | `20.04,22.04,24.04` | 你的主機有用到的版本 |
| 時區 | `Asia/Taipei` | |
| 網頁的 port | `8080` | 被其他程式佔用、或是瀏覽器會拒絕連線的 port（例如 10080、6000；Chrome 顯示 `ERR_UNSAFE_PORT`）時會請你換一個；只給本機反向代理連時填 `127.0.0.1:8080` |
| 網站標示 | 空白 | 同一台主機裝兩套時用來分辨，例 `測試`（見下方「同一台裝第二套」）；只有一套就留空 |
| 基礎 image | `python:3.12-slim` | 步驟 1 載入的名稱 |
| Python 套件來源 | `https://pypi.org/simple` | 內部 Nexus 填它的 PyPI proxy，例 `https://nexus.example.com/repository/pypi-proxy/simple` |
| 自簽憑證的主機名稱 | 空白 | Nexus 是自簽憑證才填，例 `nexus.example.com` |
| 管理員帳號 | `admin` | 接著輸入兩次密碼（至少 12 個字元） |

接著自動完成：複製程式到 `/opt/cvehub`、寫 `.env`（權限 600）、建 image、跑自動化測試、建管理員、啟動。
✅ 最後印出「cvehub x.y.z 已安裝並啟動」和網址。

- 安裝到別的目錄：`sudo CVEHUB_DIR=/srv/cvehub bash …/install.sh`
- 不詢問、全用預設值：加 `-y`（管理員之後再建，指令會印出來）；要指定值時用環境變數，例 `sudo WEB_HOST_PORT=8081 bash …/install.sh -y`（只在全新安裝時有效）
- 之後要換 port：改 `.env` 的 `WEB_HOST_PORT`，`cd /opt/cvehub && sudo docker compose up -d`（不要改 `docker-compose.yml`，更新時會被換掉）
- ❌ 拿不到基礎 image：回到步驟 1。❌ 建置失敗：檢查 Nexus 網址、自簽憑證主機名稱（`sudo nano /opt/cvehub/.env`），修正後重新執行 `sudo bash /opt/cvehub/install.sh`（會沿用 `.env` 接著做，不會再問）。

### 完全離線（沒有 Python 套件來源、也不能 docker pull）
主機只能用傳檔案的方式時，用離線安裝包：程式、Python 套件、基礎 image 都在一個檔案裡，安裝與更新都不連網路。

在能上網（或連得到 Nexus）、有 Docker 的機器，把 `cvehub-main.zip` 放到 `/tmp`，解開後產生安裝包：
```bash
rm -rf /tmp/cvehub-src && python3 -m zipfile -e /tmp/cvehub-main.zip /tmp/cvehub-src
sudo bash /tmp/cvehub-src/*/scripts/make-offline.sh /tmp/out
```
✅ 產生 `/tmp/out/cvehub-<版本>-offline.tar.gz`（約 50 MB）。要從 Nexus 下載套件時加 `PIP_INDEX_URL=…`；基礎 image 不是 `python:3.12-slim` 時加 `BASE_IMAGE=…`。

把這個檔案傳到主機後，解開到自己的目錄（安裝包目錄的擁有者要是自己或 root、別人不能寫入，否則 install.sh 不會從那裡載入 image）：
```bash
mkdir -p ~/cvehub-install && tar -xzf cvehub-<版本>-offline.tar.gz -C ~/cvehub-install
(cd ~/cvehub-install/cvehub-<版本>-offline && sha256sum -c --quiet SHA256SUMS)       # 沒有輸出＝檔案完整
sudo bash ~/cvehub-install/cvehub-<版本>-offline/cvehub-<版本>/install.sh
```
基礎 image 會自動 `docker load`（先檢查 SHA256SUMS、架構、image 名稱），不會問套件來源，其他問題和步驟 2 相同。
更新也一樣：新版的離線安裝包解開後執行裡面的 install.sh（6.1）。安裝或更新中途失敗時，也是重新執行安裝包裡的 install.sh。
- `.env` 的 `BASE_IMAGE` 要和安裝包裡的相同（`base-image.txt`），不同時不會自動載入
- 安裝包要在和主機相同架構（一般是 x86_64／amd64）的機器上產生
- 換基礎 image（例如每季的 Python 安全更新）：重新產生安裝包（會先 `docker pull` 最新的），再跑一次 install.sh；安裝包裡的 image 一律重新載入

### 同一台裝第二套（例如放測試資料）
正式資料和測試資料要分開時，在同一台主機另裝一套：兩套的資料庫、帳號、設定各自獨立，測試資料不會出現在正式那套的總覽、報表與歷史裡，不要了整套刪掉即可。
```bash
sudo CVEHUB_DIR=/opt/cvehub-test bash /tmp/cvehub-src/*/install.sh
```
（離線安裝包一樣在前面加 `CVEHUB_DIR=…`。）問題的回答：
- **網頁的 port**：和第一套不同，例 `8081`。瀏覽器登入用的 cookie 會自動依 port 分開，兩套可以同時登入
- **網站標示**：例 `測試`。每一頁最上方會有一條色帶、瀏覽器分頁標題前面加【測試】，上傳檔案前看得出是哪一套（顏色用 `.env` 的 `SITE_COLOR` 改；之後要改標示：改 `.env` 的 `SITE_LABEL`，再 `sudo docker compose up -d`）。正式那套也可以標，例 `正式` 配 `SITE_COLOR=green`

要注意：
- **安裝目錄的最後一段不能和第一套相同**（`/opt/cvehub` 與 `/srv/cvehub` 都是 `cvehub`）：Docker 會把兩套當成同一套、互相重建或停止對方的容器。install.sh 與更新時都會檢查，相同就停下（目前沒有做任何變更），請換目錄名稱，例 `/opt/cvehub-test`
- 每一套各用自己的 image（`.env` 的 `CVEHUB_IMAGE`，依安裝目錄自動決定，例 `/opt/cvehub-test` 是 `cvehub-test`），重新建置或更新失敗還原時不會改到另一套。0.9.8 以前另外裝的第二套，更新到這一版時會自動設定（預設目錄 `/opt/cvehub` 那套維持 `cvehub`）
- 兩套各自更新（各跑一次 install.sh，`CVEHUB_DIR` 指定目錄），回復也是各自的 `backups/`
- 兩套的排程預設時間相同，OSV／VEX 匯入（各約 3–5 分鐘）會同時吃 CPU 與磁碟：把測試那套的 `SCHEDULE_SYNC` 錯開（例 `30 6,18 * * *`）。開了自動下載（`CVE_DATA_DOWNLOAD`）的話只在一套開，另一套用手動上傳，不必下載兩次
- 磁碟：每套各有一份資料庫與 OSV／VEX 保存檔（各約數百 MB）

## 3. 開始使用

瀏覽器開 `http://<主機>:<port>/`（安裝結束時印出的網址），用管理員登入。

### 3.1 匯入漏洞資料（OSV、VEX 兩份一起）
1. 在能上網的電腦下載：
   - https://security-metadata.canonical.com/osv/osv-all.tar.xz
   - https://security-metadata.canonical.com/vex/vex-all.tar.xz
2. 網頁「資料匯入」→ 分別上傳。各約 3–5 分鐘，完成後自動重新比對。

✅「資料匯入」頁兩份最新一筆都是 `ok`、使用中＝是。

**自動下載**（主機連得到外網或 proxy 時）：`.env` 設 `CVE_DATA_DOWNLOAD=on`，再 `cd /opt/cvehub && sudo docker compose up -d`。
之後依 `SCHEDULE_CVE_DATA_DOWNLOAD`（預設每 6 小時）檢查 Canonical 的兩份檔案，有更新才下載（沒更新時只問一次、不傳檔案），下載完自動匯入、重新比對。
- 要經過 proxy：`DOWNLOAD_PROXY=http://proxy.example.com:3128`（只有下載用，不影響 Landscape／kernel API）；proxy 會攔截 HTTPS 時，把它的 CA 放到 `config/`，設 `DOWNLOAD_CA_FILE=/config/proxy-ca.crt`
- 「資料匯入」頁顯示每份的上次檢查、結果與 Canonical 的檔案日期；管理員可按「立即檢查並下載」；指令：`sudo docker compose exec cvehub python -m cvehub.cli download`
- 超過 `DOWNLOAD_ALERT_HOURS`（預設 48）小時沒有成功檢查，`/healthz` 會回報 `cve_download_failing`
- Canonical 沒有提供檢查碼或簽章：靠 HTTPS 憑證驗證，下載後先檢查大小與 xz／tar 格式，匯入時再檢查內容（每個版本的筆數下限）；不合格的不會取代使用中的資料
- 完全離線的主機不要開，照上面的方式上傳

### 3.2 匯入主機清單
1. 把 `ansible/collect-hosts.yml`（zip 裡就有）複製到 Ansible 控制端，收集（只讀取，不需要 sudo、不改任何東西）：
   ```bash
   ansible-playbook -i <inventory> collect-hosts.yml -e cvehub_hosts=<群組> -e cvehub_out=/tmp/cvehub-hosts.csv
   ```
   ✅ 最後印出「主機 N／N」與「沒收到：無」。沒指定 `cvehub_out` 時輸出到家目錄 `cvehub-hosts-<日期時間>.csv`。
2. 網頁「資料匯入」→「上傳主機清單 CSV」。

✅ 匯入紀錄是 `ok`，總覽列出這些主機。檔案有錯時整份不匯入，訊息會列出錯誤與列號。
沒有 Ansible 的做法、CSV 欄位見第 4 節。

### 3.3 看結果

| 頁面 | 給誰 | 內容 |
|---|---|---|
| 歷年弱點 | 所有人 | Canonical 收錄的全部 CVE，依年份分頁籤；可搜尋編號、描述、套件，依版本、等級、整體狀態篩選；資料還沒收錄的 CVE 會說明原因 |
| 總覽 | 所有人 | 各等級數量、資料日期、每台主機的 CVE 數與是否要重開機；主機清單可依名稱／IP、Ubuntu 版本、需重開機篩選，點欄位名稱排序，每頁 50 或 100 台 |
| 受影響主機 | 維運 | 以 CVE 為單位：「待更新」（已有修正、主機還沒更新）、「尚無修正」，以及受影響的主機 |
| 輸出報表 | 主管 | 依 CVE 公開日期（可一鍵選季）：主管摘要、統計、Kernel 修補版本、明細；可下載 Excel |
| 明細 | 維運 | 主機 × 套件 × CVE，可篩選；每個清單都能匯出 CSV |
| 主機頁／CVE 頁 | | 單一主機的所有 CVE；單一 CVE 在每台主機的狀態 |
| 例外 | 管理 | 風險接受：主機＋CVE（都可用 `*`）＋原因＋到期日 |
| 資料匯入 | 管理 | 上傳 OSV、VEX、主機清單與匯入紀錄 |

## 4. 主機清單格式

UTF-8 的 CSV（Excel 存的有 BOM 也可以），第一列是欄位名稱、順序不限，之後**一列一個套件**；主機層級的欄位每列重複。

```
hostname,ip,release,pro,kernel_release,kernel_version,collected_at,package,version
web01,10.0.0.21,22.04,no,6.8.0-49-generic,6.8.0-49.49~22.04.1,2026-11-02T01:00:00Z,openssl,3.0.2-0ubuntu1.18
web01,10.0.0.21,22.04,no,6.8.0-49-generic,6.8.0-49.49~22.04.1,2026-11-02T01:00:00Z,libssl3:amd64,3.0.2-0ubuntu1.18
```

| 欄位 | 必要 | 內容 |
|---|---|---|
| `hostname` | ✅ | 主機名稱（不分大小寫） |
| `release` | ✅ | Ubuntu 版本，例 `22.04`（`Ubuntu 22.04.5 LTS` 也可以）；要在安裝時填的版本裡 |
| `package` | ✅ | **binary** 套件名稱（dpkg 看到的名稱；`:amd64` 會自動去掉） |
| `version` | ✅ | 完整版本，**含 epoch**，例 `1:9.6p1-3ubuntu13.5` |
| `pro` | | `yes`／`no`；空白＝依版本有沒有 `+esm` 推測 |
| `kernel_release` | | 執行中 kernel：`uname -r` |
| `kernel_version` | | 執行中 kernel 版本：`/proc/version_signature` 整行或其中的 `6.8.0-49.49~22.04.1` |
| `collected_at` | | 收集時間（ISO 8601） |
| `ip` | | 只用來顯示（總覽、主機頁）；`collect-hosts.yml` 預設填 Ansible 用 SSH 實際連進這台主機的位址（其他連線方式用 `hostname -I` 的第一個；多張網卡時請直接設 `cvehub_ip`），可用 `-e cvehub_ip=…` 或 host_vars 指定。沒有這一欄、空白或 `N/A` 時清掉原本的 IP；格式不對時保留原本的 IP（匯入紀錄會註明），其他照常匯入 |

- 只列**已安裝**的套件（dpkg 狀態第二個字元是 `i`；只剩設定檔的 `rc` 不列）。
- 沒給 kernel 欄位時，用「最新安裝的 kernel」判斷；有給時，kernel 的 CVE 依執行中 kernel 判斷，並分出「重開機即可」與「要升級再重開」。
- 一個檔案可以有很多台主機；每台各自產生的檔案可以直接串起來，各段的欄位順序不同也可以。
- 檔案裡沒有的主機保留上次的資料。若每次都上傳全部主機、希望沒列出的自動停用，`.env` 設 `HOSTS_FILE_MODE=replace`。
- 和 Landscape 同步過的同名主機會接續原本的歷史（反過來切換到 Landscape 也是）。名稱預設只比第一段、不分大小寫（`.env` 的 `HOST_MATCH_KEY=shortname`）：`web01` 和 `web01.example.com` 是同一台。
- 主機名稱是識別主機的依據，**兩台機器同名（例如兩個機房都有 `web01`）一定要先改成不同的名稱**：用 Ansible 時在 host_vars 設 `cvehub_hostname`（例 `web01-tpe`）；手動收集時把下面指令裡的 `$(hostname)` 換成自訂名稱。
- 每一列欄位名稱代表新的一段（一次收集；playbook 與手動指令都是每台主機一段）。**同一個主機名稱出現在兩段裡就整份不匯入**——兩台同名，或同一台新舊兩次收集的檔案串在一起，都會擋下。
- 同一段裡，同一台主機的 Ubuntu 版本、Pro、kernel、IP、收集時間要一致；寫法不同但意思相同的不算不一致（例如 `22.04` 和 `Ubuntu 22.04.5 LTS`、`yes` 和 `true`、`…Z` 和 `…+00:00`）。拿掉標題列再把新舊檔接在一起時，靠收集時間不同擋下。

**沒有 Ansible 時**，在每台主機執行，把輸出存成 `.csv`：
```bash
. /etc/os-release
echo "hostname,ip,release,pro,kernel_release,kernel_version,collected_at,package,version"
dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${Version}\n' \
  | awk -F'\t' -v p="$(hostname),$(hostname -I | awk '{print $1}'),$VERSION_ID,,$(uname -r),$(awk '{print $2}' /proc/version_signature),$(date -u +%FT%TZ)" 'substr($1,2,1)=="i" {print p "," $2 "," $3}'
```

除了網頁上傳，也可以把檔案放到 `/opt/cvehub/data/hosts-inbox/`（cvehub 啟動時建立，每 30 分鐘檢查），或用指令 `import-hosts`（附錄 E）。這個目錄請不要自己用 root 建立：容器以 UID 10001 執行，對目錄沒有寫入權就無法把處理完的檔案移到 `hosts-archive/`，同步會一直失敗。

## 5. 日常維護

| 頻率 | 工作 | 怎麼做 |
|---|---|---|
| 每天或每週 | 更新主機清單 | 重跑 `collect-hosts.yml` → 上傳 |
| 每週 | 更新漏洞資料（兩份一起） | 下載 OSV、VEX → 上傳（3.1） |
| 每天 | 看健康狀態 | 監控 `/healthz` 是否 200（附錄 D） |
| 每季 | 備份 | 複製 `/opt/cvehub/data/cvehub.sqlite3`、`.env`、`config/` 到別台（6.3） |
| 每季 | 更新基礎 image（Python 安全更新） | 重新 `docker save`／`docker load` 基礎 image，再跑一次 install.sh（6.1） |
| 每季 | 檢查例外與帳號 | 「例外」頁處理快到期的；「帳號管理」停用不需要的帳號 |

## 6. 更新、回復、備份

### 6.1 更新
新版 zip 一樣用 install.sh，它發現已經安裝過就自動改成更新（新版的 `cvehub-main.zip` 放到 `/tmp`；先刪掉上次解開的目錄，避免混到舊檔）：
```bash
rm -rf /tmp/cvehub-new && python3 -m zipfile -e /tmp/cvehub-main.zip /tmp/cvehub-new
sudo bash /tmp/cvehub-new/*/install.sh
```
流程：顯示版本與更新說明 → 備份程式與設定 → 換程式 → 建 image、跑測試（**失敗自動還原，舊版照常運作**）→ 停機約 1 分鐘、備份資料庫 → 啟動新版 → 健康檢查。
`.env`、`data/`、`config/` 不會動；新版多出的設定會列出來，沒補就用預設值。
完全離線的主機：解開新版的離線安裝包，執行裡面的 install.sh（見「2. 安裝」的「完全離線」），不必另外準備基礎 image 與套件。
同一個版本重跑也可以（例如換了新的基礎 image 要重建）。過程記在 `/opt/cvehub/backups/upgrade.log`。

### 6.2 回復
```bash
cd /opt/cvehub
ls backups/                                           # 例：20261102-093000-0.8.1
sudo bash scripts/upgrade.sh --rollback backups/20261102-093000-0.8.1
```
程式與資料庫回到那份備份的狀態（`.env`、`config/`、`docker-compose.override.yml` 不還原）；備份之後新增或修改的帳號、例外規則、稽核紀錄也會回到當時，確認前會顯示備份時間。
還原前，目前的資料庫會先另存到 `backups/<時間>-pre-rollback/cvehub.sqlite3`。選錯備份要拿回來時：`sudo docker compose stop`，把它複製成 `data/cvehub.sqlite3`（先刪掉旁邊的 `-wal`、`-shm`），`sudo chown 10001 data/cvehub.sqlite3`，再 `sudo docker compose up -d`。
`backups/` 自動只留最近 5 份（含這種另存的）。

### 6.3 備份
定期把 `data/cvehub.sqlite3`、`.env`、`config/` 複製到別台機器。資料庫備份不用停機：
```bash
cd /opt/cvehub && sudo docker compose exec -T cvehub python -c "import sqlite3; sqlite3.connect('/data/cvehub.sqlite3').backup(sqlite3.connect('/data/backup.sqlite3'))"
```
（備份檔在 `data/backup.sqlite3`。）

---

## 附錄 A：設定（.env）

所有設定與說明都在 `/opt/cvehub/.env`（範本 `.env.example`）。最上面「A」是安裝時填的，B 是主機清單，C、D 只有接 Landscape 才用，其他通常不用改。
改完：`cd /opt/cvehub && sudo docker compose up -d`；改了「A」裡建置相關的項目要加 `--build`。

`HISTORY_KEEP_DAYS`（預設 365 天）是已解決比對結果的保留天數，也適用於這些紀錄：稽核紀錄、同步紀錄、主機清單匯入紀錄、失敗的 OSV／VEX 匯入紀錄。每次同步成功時刪除過期的；成功的 OSV／VEX 匯入紀錄（放檔目錄靠它判斷檔案匯入過了，舊檔再放回去也不會蓋掉較新的資料）、最新一筆匯入、最近 5 筆與最後一次成功的同步紀錄一律保留。

## 附錄 B：帳號與權限

| 角色 | 可以做的事 |
|---|---|
| 檢視 | 看所有頁面、下載 Excel／CSV、改自己的密碼 |
| 管理 | 另外可以上傳資料、管理例外、立即同步、帳號管理 |

- 帳號在右上角「帳號管理」建立；下方是稽核紀錄（登入、帳號變更、上傳、例外、同步）。
- 密碼至少 12 個字元。連續輸錯 5 次鎖 15 分鐘；閒置 60 分鐘自動登出。至少保留一個啟用中的管理員。
- 忘記密碼：`cd /opt/cvehub && sudo docker compose exec cvehub python -m cvehub.cli user-passwd admin`
- 腳本呼叫 `/api/findings`、`/api/status` 用 Basic Auth（建議另建一個「檢視」帳號）。

## 附錄 C：HTTPS

登入密碼會經過網路，正式使用請用 HTTPS，二擇一：

**放在既有的反向代理後面（建議）**：`.env` 設 `WEB_HOST_PORT=127.0.0.1:8080`（只讓本機的代理連）、`WEB_COOKIE_SECURE=true`，`sudo docker compose up -d`。nginx 範例：
```nginx
server {
    listen 443 ssl;
    server_name cvehub.example.com;
    ssl_certificate     /etc/ssl/cvehub.crt;
    ssl_certificate_key /etc/ssl/cvehub.key;
    client_max_body_size 200m;                 # 上傳 OSV／VEX
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;           # 必要：CSRF 檢查比對 Origin 和 Host
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
    }
}
```

**容器直接提供 HTTPS**：憑證與私鑰放 `config/`（私鑰擁有者 UID 10001、權限 600），`.env` 設 `WEB_TLS_CERT=/config/tls.crt`、`WEB_TLS_KEY=/config/tls.key`，`sudo docker compose up -d`。

## 附錄 D：監控（/healthz）

`GET /healthz` 不需要登入、不含主機或 CVE 資料。正常回 **200**；有問題回 **503**，`problems` 列出原因：

| problems | 意思 | 處理 |
|---|---|---|
| `no_osv_data` | 還沒有漏洞資料 | 上傳 OSV |
| `osv_data_stale`／`vex_data_stale` | 檔案超過 7 天（`OSV_STALE_WARN_DAYS`） | 下載新檔上傳 |
| `last_osv_import_failed`／`last_vex_import_failed` | 最近一次匯入失敗（舊資料仍在使用） | 看「資料匯入」頁的訊息 |
| `never_synced`／`sync_too_old`／`last_sync_failed` | 比對從沒成功／太久沒成功／最近失敗 | `sudo docker compose logs --tail 50` |
| `kernel_api_error` | （接 kernel API 時）查詢失敗，沿用上次的資料 | 檢查 token、對方服務 |

清單匯入模式下，排程仍會每天重新比對兩次（`SCHEDULE_SYNC`），沒上傳新清單不會造成 `sync_too_old`。

## 附錄 E：指令列

在 `/opt/cvehub` 執行：
```bash
sudo docker compose exec cvehub python -m cvehub.cli sync </dev/null          # 立即重新比對（先匯入放檔目錄裡的新檔）
sudo docker compose exec cvehub python -m cvehub.cli import-hosts /data/hosts.csv </dev/null   # 匯入後重新比對；檔案要放在 data/ 底下
sudo docker compose exec cvehub python -m cvehub.cli import-osv /data/osv-all.tar.xz </dev/null
sudo docker compose exec cvehub python -m cvehub.cli import-vex /data/vex-all.tar.xz </dev/null
sudo docker compose exec cvehub python -m cvehub.cli period 2026-07-01 2026-09-30 medium </dev/null   # 輸出報表 Excel 到 data/reports
sudo docker compose exec cvehub python -m cvehub.cli user-list </dev/null
sudo docker compose exec cvehub python -m cvehub.cli user-add <帳號> viewer     # 或 admin；互動輸入密碼
sudo docker compose exec cvehub python -m cvehub.cli user-passwd <帳號>         # 重設密碼（也會解除鎖定）
sudo docker compose exec cvehub python -m cvehub.cli user-disable <帳號>        # user-enable 重新啟用
```
同步與匯入同時只會有一個在執行（網頁、排程、指令列共用一把鎖）。

## 附錄 F：接 Landscape 與 kernel API

`.env` 設 `HOST_SOURCE=landscape`，填「C. Landscape API」，`sudo docker compose up -d`。cvehub 依 `SCHEDULE_SYNC` 從 Landscape 取得電腦與已安裝套件（legacy API `GetComputers`、`GetPackages`，24.04／26.04 皆可）。
- 金鑰請用只能檢視電腦的專用帳號產生（Settings → API credentials）；自簽憑證把 Landscape 伺服器上的 `/etc/ssl/certs/landscape_server_ca.crt` 放到 `config/`。
- Landscape 的套件清單由 client 定期回報，主機升級後最慢約 45 分鐘才反映。

**kernel API**（選用）：提供每台主機執行中的 kernel，讓 kernel CVE 依執行中版本判斷。填「D. kernel API」：
- `per-host`（建議）：每台主機 GET 一次，URL 裡的 `{hostname}`、`{shortname}`、`{ip}` 會換成這台的值，例 `http://10.0.0.5:8000/api/kernel/?hostname={hostname}`。
- `bulk`：GET 一次回傳全部主機（清單、DRF 分頁或 `{主機: {...}}`）。
- 回應：JSON `{"hostname": "...", "kernel_release": "6.8.0-147-generic", "kernel_version": "Ubuntu 6.8.0-147.147-generic 6.8.12", "collected_at": "2026-10-17T13:00:00+08:00"}`，或純文字版本 `6.8.0-147.147`；查無資料回 404。
- `django-kernel-view/kernel_view.py`：可貼進既有 Django 專案的範例 view（只要改 `lookup_kernel()`）；`mock-kernel-api/` 是測試用的假 API。
- 查詢失敗時沿用上次的 kernel 資料，不會把執行中 kernel 的 CVE 誤標成已解決。

## 附錄 G：自動化測試

install.sh 和更新都會自動跑。手動：
```bash
cd /opt/cvehub && sudo docker compose run --rm --no-deps -T cvehub python -m unittest discover -s tests -t . </dev/null
```
✅ 最後一行 `OK`（中間印出的 `ValueError` 是「錯誤檔案應該被拒絕」的測試，正常）。

## 附錄 H：狀況處理

| 狀況 | 處理 |
|---|---|
| 登入一直顯示「表單已過期，請重新整理頁面」 | 0.9.2 已修正最常見的原因（瀏覽器自己要的 `/favicon.ico` 換掉了登入頁的 token），請先更新。仍出現時看原因：`cd /opt/cvehub && sudo docker compose logs | grep CSRF`——「沒有送出 cookie」＝瀏覽器沒存或不送（HTTP 連線卻設 `WEB_COOKIE_SECURE=true`／`WEB_TLS_CERT`、瀏覽器政策封鎖 cookie、同主機名稱的其他網站有同名 cookie：用 `.env` 的 `WEB_COOKIE_NAME` 換名稱）；「cookie 無法使用」＝重新安裝換了金鑰，重新整理登入頁即可；「不一致」＝頁面是舊的（中間的代理快取），重新整理再登入 |
| 主機清單匯入失敗 | 「資料匯入」頁列出錯誤與列號；常見：缺 `release`、版本不在安裝時填的清單、同一台主機的 `release` 前後不一致 |
| OSV 匯入「某版本的資料筆數不足」 | 先確認 `UBUNTU_RELEASES` 沒設錯；沒錯的話可能是 Canonical 改了版本名稱（`cvehub/osv_import.py` 的 `wanted_ecosystems()`） |
| VEX「無法辨識」不是 0 | Canonical 改了說明文字；在 `cvehub/vex_import.py` 的 `classify()` 加對應，跑測試後重新匯入 |
| 新的 Ubuntu 版本上線 | `.env` 的 `UBUNTU_RELEASES` 加上新版本 → `sudo docker compose up -d` → 重新上傳 OSV 與 VEX |
| 舊版本全部退役 | `UBUNTU_RELEASES` 拿掉 → 重新上傳，資料庫會變小 |
| 安裝或更新時顯示「另一套 cvehub 使用相同的 Docker 專案名稱」 | 兩套安裝目錄的最後一段相同（見 2.「同一台裝第二套」）。新安裝：換目錄名稱；已經裝好的：到其中一套的目錄 `sudo docker compose down`，在它的 `.env` 加 `COMPOSE_PROJECT_NAME=cvehub-test`（別的名稱）後 `sudo docker compose up -d`，再到另一套的目錄 `sudo docker compose up -d`，用 `sudo docker ps` 確認兩套各有自己的容器後再更新（兩套共用專案名稱時主機上只會有一個容器，所以要先 down）。訊息裡的目錄已經不用、只剩容器時，刪掉那個容器即可（`sudo docker ps -a` 看 NAMES） |
| 更新時顯示「另一套 cvehub 也使用 image …」 | 兩套的 `.env` 設了相同的 `CVEHUB_IMAGE`：把其中一套改成別的名稱再更新 |
| Python 3.12 停止支援（2028-10） | 載入 `python:3.13-slim`，`.env` 改 `BASE_IMAGE`，再跑一次 install.sh |

## 附錄 I：限制

- 只看套件版本：服務沒重啟（記憶體裡還是舊函式庫）、Livepatch 已修補的 kernel 不在判斷範圍。
- PPA、第三方套件沒有 OSV 資料，不會列出。
- Ubuntu Pro／ESM 的判斷已實作，但沒有在真實 Pro 主機上驗證過。
- OSV／VEX 匯入期間（各約 3–5 分鐘）資料庫只能讀：上傳檔案沒問題（匯入完會接著處理），但登入、新增例外、帳號管理可能要等一下或失敗，等匯入完成再操作。

> 同一個 repo 的 `cvetrack/`：同樣的比對規則，做成可以裝進既有 Django 專案的 app，另外追蹤每次匯入的變化與變更單號。和 cvehub 各自獨立。
