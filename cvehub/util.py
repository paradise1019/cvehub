"""低層共用小工具（sync、匯入、auth 都用；不 import 其他 cvehub 模組，避免循環 import）"""
import datetime
import hashlib
import lzma
import re
import tarfile


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


# 匯入時「檔案內容有問題」的錯誤（格式、筆數不足、壞掉的壓縮檔、JSON 結構不對）：這種檔案移出放檔目錄（failed-），
# 不再重試，也不會擋住後面的檔案（自動下載會再抓新的）；資料庫忙、磁碟滿這類錯誤把檔案留在放檔目錄，下次再試
CONTENT_ERRORS = (ValueError, tarfile.TarError, lzma.LZMAError, EOFError, KeyError, TypeError, AttributeError, IndexError)
FAILED_KEEP = 3                     # 保存目錄裡 failed- 檔最多留幾份（另外算，不會擠掉正常的保存檔）


def prune_archive(archive, keep):
    """保存目錄：正常的檔案留最新 keep 份（0＝不刪），failed- 的留最新 FAILED_KEEP 份"""
    import glob
    import os
    files = sorted(glob.glob(os.path.join(archive, "*.tar.xz")), key=os.path.getmtime)
    good = [f for f in files if not os.path.basename(f).startswith("failed-")]
    bad = [f for f in files if os.path.basename(f).startswith("failed-")]
    for old in (good[:-keep] if keep > 0 else []) + bad[:-FAILED_KEEP]:
        os.remove(old)


def archive_name(path, failed=False):
    """放檔目錄的檔案移到保存目錄時的檔名：前面加日期（已有就不加）；內容有問題的再加 failed-"""
    import os
    name = os.path.basename(path)
    if not (len(name) > 9 and name[:8].isdigit() and name[8] == "-"):
        name = "%s-%s" % (datetime.date.today().strftime("%Y%m%d"), name)
    return ("failed-" + name) if failed else name
