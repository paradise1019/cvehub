"""cvetrack 設定：原專案 settings.py 的 CVETRACK = {...}；金鑰類設定也可以改用環境變數（CVETRACK_<名稱>）

用法：from cvetrack.conf import conf；conf.LANDSCAPE_API_URI
"""
import os

from django.conf import settings

DEFAULTS = {
    # Landscape legacy API
    "LANDSCAPE_API_URI": "",
    "LANDSCAPE_API_KEY": "",
    "LANDSCAPE_API_SECRET": "",
    "LANDSCAPE_CA_FILE": "",
    "LANDSCAPE_QUERY": "",
    "LANDSCAPE_TIMEOUT": 300,
    "LANDSCAPE_RETRIES": 3,
    # 主機來源：landscape，或 JSON 檔路徑（測試、示範、沒有 Landscape 時）
    "HOST_SOURCE": "landscape",
    # kernel API（選用）：bulk＝一次取得全部主機；per-host＝每台查一次（URL 裡放 {hostname} {shortname} {ip}）
    "KERNEL_API_URL": "",
    "KERNEL_API_MODE": "bulk",
    "KERNEL_API_AUTH": "none",          # none | token | bearer | basic
    "KERNEL_API_TOKEN": "",
    "KERNEL_API_USER": "",
    "KERNEL_API_PASSWORD": "",
    "KERNEL_API_CA_FILE": "",
    "KERNEL_API_TIMEOUT": 60,
    "KERNEL_API_FIELD_HOST": "hostname",
    "KERNEL_API_FIELD_VERSION": "kernel_version",
    "KERNEL_API_FIELD_RELEASE": "kernel_release",
    "KERNEL_API_FIELD_COLLECTED_AT": "collected_at",
    "KERNEL_API_MAX_AGE_HOURS": 48,
    "KERNEL_KEEP_DAYS": 7,               # kernel 資料過舊／查無資料時，沿用上一次可信值最多幾天
    "HOST_MATCH_KEY": "shortname",       # shortname | hostname | ip
    "HOST_MATCH_CASE_INSENSITIVE": True,
    # 資料檔
    "DATA_DIR": "",                      # 預設：BASE_DIR/cvetrack-data
    "UBUNTU_RELEASES": ["20.04", "22.04", "24.04"],
    "OSV_MIN_ROWS_PER_RELEASE": 1000,    # 每個版本至少要有這麼多筆 affected，否則判定檔案有問題
    "KEEP_FILES": 5,                     # 保存目錄留幾份 OSV／VEX 檔
    "VEX_KEEP_KERNEL_VARIANTS": [],      # 雲端／OEM kernel 變體預設不匯入 VEX；可列名稱（可用 *）
    "IMPORT_BATCH": 20000,               # 匯入每個交易寫幾筆（與原專案共用 SQLite，交易要短）
    # 比對
    "PRO_MODE": "auto",                  # auto | yes | no
    # 主機來源這次少了超過這個比例的主機（或回傳 0 台）時，Run 直接失敗、不把主機停用（避免 Landscape 異常時全部被當成移除）
    "RETIRE_MAX_FRACTION": 0.5,
    "INCLUDE_UNFIXED": False,
    "CHECK_OLD_KERNELS": False,
    # 排程（cvetrack_tick 每幾分鐘執行一次；距離上次成功同步超過這麼多小時就同步，0＝只處理放檔與手動要求）
    "SYNC_EVERY_HOURS": 12,
    "OSV_STALE_WARN_DAYS": 7,
    # 變更單
    "TICKET_PATTERN": "",                # 單號格式（regex），空白＝不限
    "UNTICKETED_WARN_DAYS": 7,
    "TICKET_SUGGEST_GRACE_HOURS": 24,    # 預計結束後多久內的修補事件仍列為建議對應
    "PAGE_SIZE": 100,
    # 畫面
    "BASE_TEMPLATE": "cvetrack/base.html",
}

ENV_KEYS = ("LANDSCAPE_API_URI", "LANDSCAPE_API_KEY", "LANDSCAPE_API_SECRET", "KERNEL_API_URL", "KERNEL_API_TOKEN",
            "KERNEL_API_USER", "KERNEL_API_PASSWORD")


class _Conf:
    def __getattr__(self, name):
        if name not in DEFAULTS:
            raise AttributeError(name)
        user = getattr(settings, "CVETRACK", {}) or {}
        if name in user:
            return user[name]
        if name in ENV_KEYS and os.environ.get("CVETRACK_" + name):
            return os.environ["CVETRACK_" + name]
        if name == "DATA_DIR":
            return os.path.join(str(getattr(settings, "BASE_DIR", ".")), "cvetrack-data")
        return DEFAULTS[name]

    def path(self, *parts):
        return os.path.join(self.DATA_DIR, *parts)


conf = _Conf()
