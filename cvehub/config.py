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
    LANDSCAPE_API_URI = _s("LANDSCAPE_API_URI")
    LANDSCAPE_API_KEY = _s("LANDSCAPE_API_KEY")
    LANDSCAPE_API_SECRET = _s("LANDSCAPE_API_SECRET")
    LANDSCAPE_CA_FILE = _s("LANDSCAPE_CA_FILE")
    LANDSCAPE_QUERY = _s("LANDSCAPE_QUERY")
    LANDSCAPE_TIMEOUT = _i("LANDSCAPE_TIMEOUT", 300)
    LANDSCAPE_RETRIES = _i("LANDSCAPE_RETRIES", 3)

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
    WEB_PORT = _i("WEB_PORT", 8080)
    WEB_AUTH_USER = _s("WEB_AUTH_USER", "admin")
    WEB_AUTH_PASSWORD_HASH = _s("WEB_AUTH_PASSWORD_HASH")
    WEB_BASE_PATH = _s("WEB_BASE_PATH").rstrip("/")
    LOG_LEVEL = _s("LOG_LEVEL", "info")
    # /healthz：超過幾小時沒有成功同步就回報異常
    HEALTH_MAX_SYNC_AGE_HOURS = _i("HEALTH_MAX_SYNC_AGE_HOURS", 26)
    # HTTPS（直接由容器提供；留空＝HTTP，建議放在反向代理後面）
    WEB_TLS_CERT = _s("WEB_TLS_CERT")
    WEB_TLS_KEY = _s("WEB_TLS_KEY")


PRIO = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4, "": 5}
