# cvetrack

Landscape 受管 Ubuntu 主機的 CVE 追蹤，做成可以裝進**既有 Django 專案**的 app。

- 比對：Canonical OSV（修正版本）× Landscape 回報的已安裝套件（＋選用的 kernel API 回報執行中 kernel），規則與 [cvehub](../README.md) 0.8 相同。
- **變化追蹤**：每次匯入／同步是一個 Run，和上一次比較，差異記成事件，並判斷原因（新公告、釋出修正、已修補、已移除、已重開機、公告修訂、新主機、主機移除…）。
- **變更單**：已修補／已移除／已重開機是人做的變更，要對應變更單號；可以事後批次補號，也可以先開單、由系統列出「建議對應」再由人確認。
- 帳號沿用原專案的 Django 帳號；權限用 Django 群組（之後接 LDAP 也不用改）。
- 資料庫：與原專案共用 SQLite（匯入分批、交易很短，不會長時間鎖住原專案）。

設計說明（事件與原因的判斷規則）見 [docs/DESIGN.md](docs/DESIGN.md)。

## 需求

- Python 3.10 以上、Django 5.2（LTS）、openpyxl
- Landscape（legacy API 的 access key／secret key）
- 磁碟：OSV＋VEX 匯入後資料庫約增加 300～600 MB（依 Ubuntu 版本數）

## 1. 安裝到既有的 Django 專案

以下假設原專案在 `/srv/myproject`、venv 在 `/srv/myproject/.venv`，用 gunicorn＋nginx 執行。

### 1-1 安裝套件

有網路：

```bash
/srv/myproject/.venv/bin/pip install "cvetrack @ git+https://github.com/paradise1019/cvehub@main#subdirectory=cvetrack"
```

沒有網路（離線）：在可以上網的機器下載 repo 的 zip，以及相依套件：

```bash
python3 -m pip download -d wheels "Django>=5.2,<6.0" "openpyxl>=3.1"
```

把 zip 和 `wheels/` 複製到主機後：

```bash
cd /tmp && python3 -m zipfile -e cvehub-main.zip /tmp/cvehub-src
/srv/myproject/.venv/bin/pip install --no-index --find-links /tmp/wheels /tmp/cvehub-src/cvehub-main/cvetrack
```

（有內部 PyPI 鏡像，例如 Nexus 的 pypi proxy 時，`pip install --index-url <鏡像網址> ...` 即可。）

✅ 確認：`/srv/myproject/.venv/bin/python -c "import cvetrack; print(cvetrack.__version__)"`

### 1-2 settings.py

```python
INSTALLED_APPS = [
    # ...原本的 app...
    "cvetrack",
]

# 共用 SQLite：WAL 讓讀寫可以同時進行，timeout 讓寫入互相等待而不是直接失敗
DATABASES["default"]["OPTIONS"] = {
    "init_command": "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;",
    "transaction_mode": "IMMEDIATE",
    "timeout": 30,
}

# 原專案沒有自己的登入頁時，用 Django Admin 的
LOGIN_URL = "/admin/login/"

CVETRACK = {
    "DATA_DIR": "/srv/myproject/cvetrack-data",      # 放檔目錄、保存的 OSV／VEX、鎖檔
    "UBUNTU_RELEASES": ["20.04", "22.04", "24.04"],
    "LANDSCAPE_API_URI": "https://landscape.example.com/api/",
    "LANDSCAPE_CA_FILE": "/etc/ssl/certs/landscape-ca.pem",   # 自簽憑證才需要
    # 金鑰不要寫在 settings.py：用環境變數 CVETRACK_LANDSCAPE_API_KEY、CVETRACK_LANDSCAPE_API_SECRET
}
```

### 1-3 urls.py

```python
from django.urls import include, path

urlpatterns = [
    # ...
    path("cvetrack/", include("cvetrack.urls")),
]
```

### 1-4 建立資料表、權限群組、靜態檔

```bash
cd /srv/myproject
.venv/bin/python manage.py migrate cvetrack
.venv/bin/python manage.py cvetrack_setup_groups
.venv/bin/python manage.py collectstatic --noinput
```

✅ 確認：`manage.py showmigrations cvetrack` 全部是 `[X]`；Django Admin 的「群組」有 `cvetrack-viewer`、`cvetrack-operator`、`cvetrack-admin`。

把使用者加進群組：

| 群組 | 可以做的事 |
|---|---|
| cvetrack-viewer | 查看所有頁面、匯出 |
| cvetrack-operator | ＋補單號、開變更單、在 Django Admin 管理變更單與例外 |
| cvetrack-admin | ＋上傳 OSV／VEX、立即同步、看稽核紀錄 |

之後改用 LDAP（django-auth-ldap）時，把 AD 群組對應到這三個群組即可。

### 1-5 排程

`cvetrack_tick` 每 5 分鐘執行一次：放檔目錄有新檔、網頁按了「立即同步」、或距離上次同步超過 `SYNC_EVERY_HOURS`（預設 12）才會做事，其他時候馬上結束。

`/etc/systemd/system/cvetrack-tick.service`：

```ini
[Unit]
Description=cvetrack tick

[Service]
Type=oneshot
User=myproject
WorkingDirectory=/srv/myproject
EnvironmentFile=/etc/myproject/cvetrack.env
ExecStart=/srv/myproject/.venv/bin/python manage.py cvetrack_tick
```

`/etc/systemd/system/cvetrack-tick.timer`：

```ini
[Unit]
Description=cvetrack tick every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

`/etc/myproject/cvetrack.env`（權限 600，擁有者 root；gunicorn 的 service 也要載入同一個檔）：

```
CVETRACK_LANDSCAPE_API_KEY=...
CVETRACK_LANDSCAPE_API_SECRET=...
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cvetrack-tick.timer
```

### 1-6 nginx

OSV 約 50 MB、VEX 約 80 MB，上傳要放寬：

```nginx
location /cvetrack/data/ {
    client_max_body_size 200m;
    proxy_read_timeout 300s;
    proxy_pass http://127.0.0.1:8000;
    # 其他 proxy_set_header 同原專案
}
```

## 2. 匯入資料與第一次同步

1. 下載（有網路的機器）：
   - `https://security-metadata.canonical.com/osv/osv-all.tar.xz`
   - `https://security-metadata.canonical.com/vex/vex-all.tar.xz`
2. 在「資料匯入」頁上傳，或直接複製到 `DATA_DIR/inbox/`。
3. 等排程（或手動）：`manage.py cvetrack_sync --trigger manual`
4. 第一次 Run 是「基準」：現有的弱點記成初始事件，之後的 Run 才會列出變化。

OSV／VEX 建議每週更新一次，兩份一起更新。

## 3. 日常操作

| 時機 | 做什麼 |
|---|---|
| 上傳新的 OSV 後 | 看「Run／差異」最新那次：新公告、釋出修正（現在可以修了）、公告修訂 |
| 修補主機前 | 開變更單（填預計主機與時間） |
| 修補完、同步後 | 變更單頁確認「建議對應」；或到「待補單號」篩選主機／日期後批次補號 |
| 每週 | 總覽的「待補單號超過 N 天」、「變更單過了預計時間卻沒有事件」 |

## 4. 設定（`settings.CVETRACK`）

| 名稱 | 預設 | 說明 |
|---|---|---|
| `DATA_DIR` | `BASE_DIR/cvetrack-data` | 放檔、保存、鎖檔 |
| `UBUNTU_RELEASES` | `["20.04","22.04","24.04"]` | 要比對的版本 |
| `HOST_SOURCE` | `landscape` | 或 JSON 檔路徑（測試、示範用） |
| `LANDSCAPE_API_URI`／`_KEY`／`_SECRET`／`_CA_FILE` | | 金鑰可用環境變數 `CVETRACK_LANDSCAPE_API_KEY` 等 |
| `LANDSCAPE_QUERY` | | 只同步符合的主機（有設定時，沒出現的主機不會被當成移除） |
| `KERNEL_API_URL`、`KERNEL_API_MODE`、`KERNEL_API_AUTH`… | | 執行中 kernel（同 cvehub） |
| `PRO_MODE` | `auto` | auto＝依 Landscape 回報的 Pro 狀態 |
| `INCLUDE_UNFIXED` | `False` | 是否列出官方尚無修正的弱點 |
| `SYNC_EVERY_HOURS` | `12` | 0＝只處理放檔與手動要求 |
| `TICKET_PATTERN` | 空白 | 單號格式（regex），例 `CHG-\d{4}-\d{4}` |
| `UNTICKETED_WARN_DAYS` | `7` | 超過幾天沒補單號就提醒 |
| `TICKET_SUGGEST_GRACE_HOURS` | `24` | 預計結束後多久內的修補仍列為建議對應 |
| `BASE_TEMPLATE` | `cvetrack/base.html` | 原專案有自己的 base 樣板時換掉（要有 `{% block content %}`） |

## 5. 升級

```bash
cd /srv/myproject
# 1. 備份資料庫（線上備份，服務不用停）
.venv/bin/python -c "import sqlite3; s=sqlite3.connect('db.sqlite3'); d=sqlite3.connect('db-before-cvetrack-upgrade.sqlite3'); s.backup(d)"
# 2. 停排程，避免升級途中同步
sudo systemctl stop cvetrack-tick.timer
# 3. 安裝新版（離線同 1-1）
.venv/bin/pip install --upgrade "cvetrack @ git+https://github.com/paradise1019/cvehub@v<版本>#subdirectory=cvetrack"
.venv/bin/python manage.py migrate cvetrack
.venv/bin/python manage.py collectstatic --noinput
sudo systemctl restart myproject-gunicorn
sudo systemctl start cvetrack-tick.timer
```

回復：裝回舊版、停服務、用備份的資料庫檔換回來、啟動。

## 6. 開發與測試

```bash
cd cvetrack
python3 -m venv .venv && .venv/bin/pip install -e ".[test]"
.venv/bin/python -m pytest
# 示範專案（只有 Django Admin，模擬既有專案）
cd demo && ../.venv/bin/python manage.py migrate && ../.venv/bin/python manage.py createsuperuser
CVETRACK_HOST_SOURCE=/path/to/hosts.json ../.venv/bin/python manage.py runserver
```

`tools/parity_hosts.py`、`tools/parity_compare.py`：用同一批主機與同一份 OSV，比對 cvehub 與 cvetrack 的結果是否完全相同。
