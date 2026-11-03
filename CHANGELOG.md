# 更新說明

更新方式見 README「6. 更新、回復、備份」：解開新版 zip，`sudo bash <解開的目錄>/install.sh`。

## 0.9.1
- 網頁的主機 port 改成 `.env` 的 `WEB_HOST_PORT`（安裝時會問、會檢查是否被佔用；可寫 `127.0.0.1:8080`），不用再改 `docker-compose.yml`
- 更新時，舊版 `docker-compose.yml` 手動改過的 port（含指定 IP、長格式）會自動寫進 `.env` 的 `WEB_HOST_PORT`，不會變回 8080；`.env` 已經有 `WEB_HOST_PORT` 時以它為準；ports 有多筆、看不懂時，更新前就停下來請你先設定（不會做任何變更）
- 更新時不使用殼層的 `WEB_HOST_PORT`、`BASE_IMAGE`、`PIP_*`、`BUILD_*` 環境變數，一律以 `.env` 為準
- 修正：同一台主機還有別的網站（例如另一套 cvehub）時，登入一直顯示「表單已過期」。瀏覽器的 cookie 不分 port，同名 cookie 會互相蓋掉；主機 port 不是 8080 時 cookie 名稱改成 `cvehub_session_<port>`，也可以用 `WEB_COOKIE_NAME` 自訂（用 `docker-compose.override.yml` 改 port 時請設這個；換名稱後要重新登入一次）

## 0.9.0
- 新增主機清單匯入（`HOST_SOURCE=file`）：不接 Landscape，改用 CSV 提供主機、Ubuntu 版本、已安裝套件（選填 Pro、執行中 kernel）；網頁上傳、放檔目錄、`cvehub.cli import-hosts` 三種方式（README 3.1）
- 附 `ansible/collect-hosts.yml`：唯讀收集各主機的套件與 kernel，合併成一個 CSV
- 新增 `install.sh`：一支腳本處理安裝與更新（全新安裝會問幾個問題、寫 .env、建 image、跑測試、建管理員、啟動；已安裝則交給 `scripts/upgrade.sh`）
- 文件重寫：README 改成「安裝 → 開始使用 → 主機清單 → 日常維護 → 更新」，其他放附錄；`MAINTENANCE.md` 併入 README
- `.env.example` 重新排列：安裝時填的放最上面；新安裝預設 `HOST_SOURCE=file`、不接 kernel API
- OSV／VEX 匯入期間（單一交易，約數分鐘）上傳檔案不再回 500：稽核紀錄寫不進資料庫時改記在容器 log
- install.sh：安裝中途失敗後重跑會沿用 `.env` 接著做（`.install-incomplete` 標記，成功啟動後才刪；`.env` 全部寫完才改名，不會留下寫一半的設定）；從安裝目錄重跑更新時只打包程式（不含資料庫、`.env`），暫存檔用完刪除；`.env` 的值含 `$`、`#`、空白時自動加引號
- 主機清單：每個版本匯入時就檢查能否比較；任何錯誤都記成失敗並移出放檔目錄（檔名加 `failed-`），不會卡住之後的同步；還沒有 OSV 時上傳的清單也會先匯入；`cli import-hosts` 把檔案放進放檔目錄、照先後順序處理並回報這個檔案的結果（比對失敗時結束代碼非 0）
- 上傳的檔案先寫成 `.part` 再改名，同步途中不會讀到寫一半的檔案
- 執行中 kernel 的推算改為 Landscape 與清單匯入共用（`kernel.infer_running`）
- `collect-hosts.yml` 改成單一 play（可用 `--limit`）、連不上的主機略過並列出、暫存目錄一定刪除、預設輸出到家目錄
- 已安裝的 `.env` 沒有 `HOST_SOURCE` 時仍是 `landscape`，原有部署不受影響；資料庫自動新增 `host_import` 表

## 0.8.1（code review 修正）
- 主管摘要：期末後才釋出修正的 CVE 仍算「期末時尚未修正」，但不再列進「風險接受／持續追蹤」，改列「期末後才釋出修正（現在已可更新）」；數字卡與結論句另外標出數量
- 主管摘要：只有 Ubuntu Pro（ESM）才有的修正，從「一般套件更新（apt upgrade）」分開，列為「需要 Ubuntu Pro（ESM）的套件更新」；kernel 的修補版本只有 Pro 才有時，在要做的事、kernel 表、Excel 與說明句都標「（需要 Ubuntu Pro）」；同系列有部分 CVE 的修正來自 Pro 時，說明句另外註明
- 靠 Pro 修正時，修正版本與 USN 編號／日期改成同一個 USN 的：版本、USN、日期、是否來自 Pro 都取自同一個 USN（描述期末時是哪個修正）；20.04 由一般套件庫修正的不再標成 Pro
- 只選 critical 時，數字卡與 Excel 的標籤跟著顯示 critical（原本固定寫 critical＋high）
- 上一期的比較結果快取（換頁、排序、匯出不再每次重算上一期）；日期只接受 YYYY-MM-DD、限 2000～2100 年（太早的日期原本會 500；20261231 這種寫法原本會讓區間比較出錯）
- 登入失敗仍回同一句話，但稽核紀錄記下真正原因（密碼錯誤第幾次、何時鎖定、鎖定中仍在嘗試、帳號不存在或已停用）
- 更新腳本：備份程式時失敗或被中斷，會清掉做到一半的備份（code.tgz 先寫 .part 再改名），不會留下被截斷的備份給回復用

## 0.8.0
- 輸出報表最上方新增「主管摘要」（網頁與 Excel 第一頁）：一句話結論、數字卡（critical＋high：適用＝已有修正＋尚未修正＋不受影響）、版本 × 等級矩陣（尚未解決／適用，和上一期比較 ▲▼）、要做的事（每個版本的 kernel 升級版本、一般套件更新、官方未修正追蹤）
- 統計改成「版本 → 等級 → kernel／其他套件」，分母是「適用此版本」（扣掉版本無此套件與官方無紀錄）；原本的完整狀態細分移到「狀態明細」（網頁可展開、Excel 一頁）
- 上一期：區間是整季就比上一季，否則比前一段等長區間

## 0.7.1（code review 修正）
**升級注意**
- OSV 資料格式再更新一次（沒有日期的 USN 不再蓋掉有日期的）：更新後約 30 分鐘內自動重新匯入一次（約 5 分鐘），完成前畫面會提醒，期間產生的報表修正日期可能不完整。

- 20.04 的修正日期同時查一般套件庫與 Pro 的 USN（ESM 之前修正的不會再變成「日期不明」）；USN 沒有日期的列為「日期不明」，不再當成期末前已修正
- 未登入的 POST（例如上傳）不再先解析內容；登入表單限制大小
- 登入失敗一律回同一句話，不透露帳號是否存在或被鎖定
- 更新腳本：回復時優先使用本機既有的 image（不必連 Nexus）；換程式途中失敗會自動還原；`.env` 的 `BASE_IMAGE` 支援引號、註解、Windows 換行；`backups/` 不再送進 docker build
- 網頁加上「期末後修正」「已修正（日期不明）」的顏色

## 0.7.0
**升級注意**
- OSV 資料格式更新（加入 USN 修正日期）：更新後約 30 分鐘內會自動用保存的 OSV 檔重新匯入一次（約 5 分鐘），也可以按「立即同步」。完成前畫面上會提醒，輸出報表的修正日期暫時不完整。

**變更**
- 輸出報表的「已修正」改以**報表期末日**判斷：修正它的 USN 在期末前發布才算已修正；期末之後才發布的列為「期末後修正（日期）」，沒有 USN 的列為「已修正（日期不明）」。同一個區間任何時候產生，結果都一樣。
- 新增「Kernel 修補版本（截至期末）」：每個 Ubuntu 版本 × kernel 系列，期末前已修正的 kernel CVE 要升級到哪個版本（取最高的修正版本，附 CVE、USN、發布日），以及期末仍未修正、日期不明的數量；附可直接貼進風險評鑑單的文字。Excel 新增「Kernel 修補版本」「Kernel 明細」兩頁。

## 0.6.1
**升級注意**
- 建置設定移到 `.env` 最上面的「0. 建置」：`BASE_IMAGE`、`PIP_INDEX_URL`、`PIP_TRUSTED_HOST`、`BUILD_HTTP_PROXY` 等。原本用環境變數帶 `PIP_INDEX_URL` 的，請改寫進 `.env`。
- 主機不能 `docker pull` 時，基礎 image 要先 `docker load` 進來（README 步驟 3）；更新腳本會先檢查，沒有就停下、不改任何東西。

## 0.6.0
**升級注意**
- 登入改成網頁登入頁＋多帳號。第一次啟動時，`.env` 原本的 `WEB_AUTH_USER`／`WEB_AUTH_PASSWORD_HASH` 會自動轉成第一個「管理」帳號，**原本的帳號密碼照樣可以登入**。
- 腳本呼叫 `/api/*` 仍用 Basic Auth（任何啟用中的帳號）；網頁不再接受 Basic Auth。
- 放在 HTTPS 反向代理後面時，`.env` 加 `WEB_COOKIE_SECURE=true`。

**新功能**
- 帳號分「檢視」（看所有頁面、下載報表）與「管理」（上傳資料、例外、立即同步、帳號管理）
- 帳號管理頁（新增、重設密碼、變更角色、停用）、我的帳號（變更密碼）、稽核紀錄（登入、帳號變更、上傳、例外、同步）
- 連續輸錯 5 次鎖 15 分鐘；閒置 60 分鐘自動登出（`WEB_SESSION_IDLE_MINUTES`）；改密碼／改角色／停用後舊的登入立即失效
- 指令列：`user-add`、`user-passwd`、`user-role`、`user-disable`、`user-enable`、`user-list`
- 更新腳本 `scripts/upgrade.sh`：備份、換程式、測試、啟動、健康檢查；失敗自動還原，也可以 `--rollback`

## 0.5.1
- 狀態改繁體中文；「季報表」改名「輸出報表」；受影響主機每格只列 3 台；明細換頁
- 安全修正：Landscape 錯誤訊息遮掉 access key、kernel API 分頁只跟同一台主機、CSV／Excel 公式注入

## 0.5.0
- 匯入 Canonical VEX（官方處理狀態），輸出報表與受影響主機頁
