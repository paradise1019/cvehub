"""從環境變數讀取設定（見 .env.example）"""
import os


def _b(name, default=False):
    v = os.environ.get(name)
    return default if v is None or v == "" else v.strip().lower() in ("1", "true", "yes", "on")


def _i(name, default):
    v = os.environ.get(name)
    return default if v in (None, "") else int(v)


def _s(name, default=""):
    v = os.environ.get(name)
    return default if v is None else v.strip()


class Config:
    # 主機來源：landscape＝從 Landscape API 同步；file＝匯入主機清單 CSV（不呼叫 Landscape，見 host_import.py）
    HOST_SOURCE = _s("HOST_SOURCE", "landscape")
    HOSTS_INBOX_DIR = _s("HOSTS_INBOX_DIR", "/data/hosts-inbox")
    HOSTS_ARCHIVE_DIR = _s("HOSTS_ARCHIVE_DIR", "/data/hosts-archive")
    HOSTS_KEEP_FILES = _i("HOSTS_KEEP_FILES", 30)
    # merge＝清單裡沒有的主機保留上次資料；replace＝清單代表全部主機，沒有的停用
    HOSTS_FILE_MODE = _s("HOSTS_FILE_MODE", "merge")

    LANDSCAPE_API_URI = _s("LANDSCAPE_API_URI")
    LANDSCAPE_API_KEY = _s("LANDSCAPE_API_KEY")
    LANDSCAPE_API_SECRET = _s("LANDSCAPE_API_SECRET")
    LANDSCAPE_CA_FILE = _s("LANDSCAPE_CA_FILE")
    LANDSCAPE_QUERY = _s("LANDSCAPE_QUERY")
    LANDSCAPE_TIMEOUT = _i("LANDSCAPE_TIMEOUT", 300)
    LANDSCAPE_RETRIES = _i("LANDSCAPE_RETRIES", 3)
    # Landscape 回傳的電腦比啟用中的少超過這個百分比（或變成 0 台）時同步失敗、不停用主機；0＝只擋 0 台
    LANDSCAPE_MAX_DROP_PERCENT = _i("LANDSCAPE_MAX_DROP_PERCENT", 50)

    KERNEL_API_URL = _s("KERNEL_API_URL")
    # bulk：一次取得全部主機；per-host：每台主機查一次（URL 裡放 {hostname} {shortname} {ip}）
    KERNEL_API_MODE = _s("KERNEL_API_MODE", "bulk")
    KERNEL_API_AUTH = _s("KERNEL_API_AUTH", "none")
    KERNEL_API_TOKEN = _s("KERNEL_API_TOKEN")
    KERNEL_API_USER = _s("KERNEL_API_USER")
    KERNEL_API_PASSWORD = _s("KERNEL_API_PASSWORD")
    KERNEL_API_CA_FILE = _s("KERNEL_API_CA_FILE")
    KERNEL_API_TIMEOUT = _i("KERNEL_API_TIMEOUT", 60)
    KERNEL_API_FIELD_HOST = _s("KERNEL_API_FIELD_HOST", "hostname")
    KERNEL_API_FIELD_VERSION = _s("KERNEL_API_FIELD_VERSION", "kernel_version")
    KERNEL_API_FIELD_RELEASE = _s("KERNEL_API_FIELD_RELEASE", "kernel_release")
    KERNEL_API_FIELD_COLLECTED_AT = _s("KERNEL_API_FIELD_COLLECTED_AT", "collected_at")
    KERNEL_API_MAX_AGE_HOURS = _i("KERNEL_API_MAX_AGE_HOURS", 48)

    HOST_MATCH_KEY = _s("HOST_MATCH_KEY", "shortname")
    HOST_MATCH_CASE_INSENSITIVE = _b("HOST_MATCH_CASE_INSENSITIVE", True)

    OSV_INBOX_DIR = _s("OSV_INBOX_DIR", "/data/inbox")
    OSV_ARCHIVE_DIR = _s("OSV_ARCHIVE_DIR", "/data/osv-archive")
    OSV_KEEP_FILES = _i("OSV_KEEP_FILES", 5)
    VEX_INBOX_DIR = _s("VEX_INBOX_DIR", "/data/vex-inbox")
    VEX_ARCHIVE_DIR = _s("VEX_ARCHIVE_DIR", "/data/vex-archive")
    # 雲端／OEM kernel 變體預設不匯入 VEX（資料量大）；主機有用到時列出名稱，可用 *，例：linux-aws*,linux-azure
    VEX_KEEP_KERNEL_VARIANTS = [p.strip() for p in _s("VEX_KEEP_KERNEL_VARIANTS").split(",") if p.strip()]
    UBUNTU_RELEASES = [r.strip() for r in _s("UBUNTU_RELEASES", "20.04,22.04,24.04").split(",") if r.strip()]
    OSV_STALE_WARN_DAYS = _i("OSV_STALE_WARN_DAYS", 7)
    # 自動下載 OSV／VEX（download.py）：連得到外網或 proxy 才開；完全離線的主機照舊上傳
    CVE_DATA_DOWNLOAD = _b("CVE_DATA_DOWNLOAD", False)
    SCHEDULE_CVE_DATA_DOWNLOAD = _s("SCHEDULE_CVE_DATA_DOWNLOAD", "17 */6 * * *")
    OSV_DOWNLOAD_URL = _s("OSV_DOWNLOAD_URL", "https://security-metadata.canonical.com/osv/osv-all.tar.xz")
    VEX_DOWNLOAD_URL = _s("VEX_DOWNLOAD_URL", "https://security-metadata.canonical.com/vex/vex-all.tar.xz")
    DOWNLOAD_PROXY = _s("DOWNLOAD_PROXY")
    DOWNLOAD_CA_FILE = _s("DOWNLOAD_CA_FILE")
    DOWNLOAD_TIMEOUT = _i("DOWNLOAD_TIMEOUT", 60)
    DOWNLOAD_MAX_MB = _i("DOWNLOAD_MAX_MB", 500)
    DOWNLOAD_MAX_MINUTES = _i("DOWNLOAD_MAX_MINUTES", 30)
    DOWNLOAD_ALLOW_HTTP = _b("DOWNLOAD_ALLOW_HTTP", False)
    DOWNLOAD_ALERT_HOURS = _i("DOWNLOAD_ALERT_HOURS", 48)
    # 匯入檢查：每個 UBUNTU_RELEASES 版本至少要有這麼多筆 affected，否則判定檔案有問題、保留舊資料
    OSV_MIN_ROWS_PER_RELEASE = _i("OSV_MIN_ROWS_PER_RELEASE", 1000)

    PRO_MODE = _s("PRO_MODE", "auto")
    INCLUDE_UNFIXED = _b("INCLUDE_UNFIXED", False)
    MIN_PRIORITY = _s("MIN_PRIORITY", "low")
    CHECK_OLD_KERNELS = _b("CHECK_OLD_KERNELS", False)

    TZ = _s("TZ", "UTC")
    SCHEDULE_SYNC = _s("SCHEDULE_SYNC", "0 6,18 * * *")
    SCHEDULE_OSV_CHECK = _s("SCHEDULE_OSV_CHECK", "*/30 * * * *")

    DB_PATH = _s("DB_PATH", "/data/cvehub.sqlite3")
    REPORT_DIR = _s("REPORT_DIR", "/data/reports")
    REPORT_FORMATS = [f.strip() for f in _s("REPORT_FORMATS", "csv").split(",") if f.strip()]
    HISTORY_KEEP_DAYS = _i("HISTORY_KEEP_DAYS", 365)

    WEB_LISTEN = _s("WEB_LISTEN", "0.0.0.0")
    WEB_PORT = _i("WEB_PORT", 8080)                    # 容器內部的 port（健康檢查固定連 8080，不要改）
    WEB_HOST_PORT = _s("WEB_HOST_PORT", "8080")        # 主機上的 port（docker-compose.yml 使用；可寫 127.0.0.1:8080）
    # session cookie 名稱：瀏覽器的 cookie 不分 port，同一台主機有別的網站（例如另一套 cvehub）時會互相蓋掉
    # 留空＝主機 port 是 8080 時用 cvehub_session，否則 cvehub_session_<port>
    WEB_COOKIE_NAME = _s("WEB_COOKIE_NAME")
    WEB_AUTH_USER = _s("WEB_AUTH_USER", "admin")        # 舊版單一帳號：沒有任何帳號時自動轉成第一個管理員
    WEB_SECRET_KEY = _s("WEB_SECRET_KEY")              # session 簽章金鑰；留空＝自動產生在資料目錄（.secret_key）
    WEB_SESSION_IDLE_MINUTES = _i("WEB_SESSION_IDLE_MINUTES", 60)
    WEB_COOKIE_SECURE = _b("WEB_COOKIE_SECURE", False)  # 放在 HTTPS 反向代理後面時設 true（容器直接提供 HTTPS 時自動開啟）
    WEB_AUTH_PASSWORD_HASH = _s("WEB_AUTH_PASSWORD_HASH")
    WEB_BASE_PATH = _s("WEB_BASE_PATH").rstrip("/")
    LOG_LEVEL = _s("LOG_LEVEL", "info")
    # /healthz：超過幾小時沒有成功同步就回報異常
    HEALTH_MAX_SYNC_AGE_HOURS = _i("HEALTH_MAX_SYNC_AGE_HOURS", 26)
    # HTTPS（直接由容器提供；留空＝HTTP，建議放在反向代理後面）
    WEB_TLS_CERT = _s("WEB_TLS_CERT")
    WEB_TLS_KEY = _s("WEB_TLS_KEY")
    # 網站標示：同一台主機裝了兩套以上（例如正式、測試）時用來分辨；每一頁最上方與瀏覽器分頁標題顯示，留空＝不顯示
    SITE_LABEL = _s("SITE_LABEL")[:40]
    # 標示的顏色：red | orange | green | blue | purple | gray，或 #rrggbb；留空＝orange
    SITE_COLOR = _s("SITE_COLOR")


SITE_COLORS = {"red": "#cf222e", "orange": "#bc4c00", "green": "#1a7f37", "blue": "#0969da", "purple": "#8250df", "gray": "#57606a"}


def site_color():
    """SITE_COLOR 換成 CSS 色碼；名稱不認得、格式不對時用 orange（不讓設定值直接進 CSS）"""
    v = Config.SITE_COLOR.lower()
    if v in SITE_COLORS:
        return SITE_COLORS[v]
    return v if len(v) == 7 and v[0] == "#" and all(c in "0123456789abcdef" for c in v[1:]) else SITE_COLORS["orange"]


PRIO = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4, "": 5}
