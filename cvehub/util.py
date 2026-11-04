"""低層共用小工具（sync、匯入、auth 都用；不 import 其他 cvehub 模組，避免循環 import）"""
import datetime
import hashlib
import re


def now():
    """現在的本地時間，ISO 8601 到秒（資料庫裡的時間欄位都用這個格式）"""
    return datetime.datetime.now().isoformat(timespec="seconds")


def sha256_file(path):
    """檔案的 sha256（分段讀，大檔案也不會一次讀進記憶體）"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def norm_release(r):
    """24.04、"Ubuntu 22.04.5 LTS" → 版本號"""
    m = re.search(r"(\d+\.\d+)", str(r or ""))
    return m.group(1) if m else ""


def parse_time(s, utc=False):
    """ISO 8601 → 本地時間（naive）；utc=True 時換成 UTC（沒帶時區的視為本地時間）。格式不對或超出範圍回傳 None"""
    try:
        t = datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        if utc:
            return t.astimezone(datetime.timezone.utc)
        return t.astimezone().replace(tzinfo=None) if t.tzinfo else t
    except (ValueError, OverflowError):
        return None
