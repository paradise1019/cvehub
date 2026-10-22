# 更新說明

更新方式見 README「10. 更新與回復」：`sudo bash scripts/upgrade.sh <新版 zip>`。

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
