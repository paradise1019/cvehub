"""自動下載 OSV／VEX（CVE_DATA_DOWNLOAD=on；連得到外網或 proxy 的主機才用，完全離線的主機照舊上傳）

  依 SCHEDULE_CVE_DATA_DOWNLOAD 檢查 Canonical 的 osv-all.tar.xz、vex-all.tar.xz：
  - 帶上次的 ETag／Last-Modified 詢問，沒有更新（304）就不下載；上次下載的那份沒有匯入成功、也不在放檔目錄時
    （匯入失敗、被清掉、資料庫還原過），不帶條件重新下載
  - 有更新：先寫成放檔目錄裡的 .<名稱>.part（放檔目錄只看 *.tar.xz，寫一半的不會被匯入），檢查大小
    （Content-Length、DOWNLOAD_MAX_MB、剩餘空間）、整體時間（DOWNLOAD_MAX_MINUTES）與 xz 檢查碼／tar 格式，
    再改名成不重複的 <種類>-all-download-<時間>.tar.xz（正在匯入的檔案不會被換掉）；之後的匯入與檢查和上傳的一樣
  - 內容和已匯入成功的完全相同（sha256）時不放進去
  - 只用 HTTPS（轉址到 http 也拒絕；DOWNLOAD_ALLOW_HTTP 只給內部鏡像用），憑證一律驗證
  - 同時只有一個下載（跨程序：網頁排程、按鈕、指令列）；狀態記在 data/download-state.json，網頁「資料匯入」頁顯示
  Canonical 沒有提供檢查碼或簽章：靠 HTTPS 與匯入時的內容檢查
"""
import contextlib
import datetime
import email.utils
import fcntl
import hashlib
import json
import logging
import lzma
import os
import shutil
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from .config import Config
from .util import now

log = logging.getLogger(__name__)

KINDS = {   # kind → (網址設定, 放檔目錄設定, 檔名, 匯入紀錄表)
    "osv": ("OSV_DOWNLOAD_URL", "OSV_INBOX_DIR", "osv-all.tar.xz", "osv_import"),
    "vex": ("VEX_DOWNLOAD_URL", "VEX_INBOX_DIR", "vex-all.tar.xz", "vex_import"),
}
CHUNK = 1024 * 1024
MIN_FREE = 1024 * 1024 * 1024        # 下載後放檔目錄所在的磁碟至少還要留 1 GB（資料庫、保存目錄、匯入時的暫存）
_read_error = None                   # 狀態檔讀不到／寫不進去（failing() 會回報；讀、寫各自在成功時清除）
_write_error = None
last_sha = {}                        # 這個程序最近下載的 sha256（kind → sha；指令列確認匯入時用，不依賴狀態檔）


def _data_dir():
    return os.path.dirname(os.path.abspath(Config.DB_PATH))


def state_path():
    return os.path.join(_data_dir(), "download-state.json")


def load_state():
    """{kind: {...}}；檔案不存在＝{}；讀不到或壞掉時記下錯誤（failing() 會回報）並回傳 {}"""
    global _read_error
    try:
        with open(state_path(), encoding="utf-8") as f:
            s = json.load(f)
        if not isinstance(s, dict):
            raise ValueError("格式不對")
        _read_error = None
        return s
    except FileNotFoundError:
        _read_error = None
        return {}
    except (OSError, ValueError) as e:
        _read_error = "讀不到下載狀態：%s" % e
        return {}


def _save_state(s):
    global _write_error
    p = state_path()
    try:
        with open(p + ".part", "w", encoding="utf-8") as f:
            json.dump(s, f, ensure_ascii=False, indent=1)
        os.replace(p + ".part", p)
        _write_error = None
    except OSError as e:
        _write_error = "無法寫入下載狀態：%s" % e
        log.warning(_write_error)


@contextlib.contextmanager
def _single():
    """跨程序：同時只有一個下載；已經有一個在跑時 yield False"""
    f = open(os.path.join(_data_dir(), ".cvehub-download.lock"), "a")
    try:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
    finally:
        f.close()


def _check_url(url):
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme != "https" and not (scheme == "http" and Config.DOWNLOAD_ALLOW_HTTP):
        raise ValueError("只能用 https 下載：%s" % url[:200])


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            _check_url(newurl)          # 轉址到 http、ftp、file 一律拒絕
        except ValueError:
            if fp is not None:
                fp.close()
            raise
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener():
    """只有 HTTP(S)（沒有 file、ftp），HTTPS 一律驗證憑證；DOWNLOAD_PROXY 有設時只有下載走它（不影響 Landscape／
    kernel API），沒設時照容器的 HTTPS_PROXY／NO_PROXY 環境變數"""
    ctx = ssl.create_default_context(cafile=Config.DOWNLOAD_CA_FILE or None)
    proxy = ({"http": Config.DOWNLOAD_PROXY, "https": Config.DOWNLOAD_PROXY} if Config.DOWNLOAD_PROXY else None)
    o = urllib.request.OpenerDirector()
    for h in (urllib.request.ProxyHandler(proxy), urllib.request.HTTPHandler(), urllib.request.HTTPSHandler(context=ctx),
              _Redirect(), urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor()):
        o.add_handler(h)
    return o


def _check_archive(path):
    """完整讀過一次 xz（驗證檢查碼），開頭要是 tar（ustar）；不合格丟 ValueError"""
    try:
        with lzma.open(path) as x:
            head = x.read(512)
            while x.read(CHUNK):
                pass
    except (lzma.LZMAError, EOFError, OSError) as e:
        raise ValueError("不是完整的 tar.xz：%s" % e)
    if len(head) < 512 or head[257:262] != b"ustar":
        raise ValueError("解開後不是 tar 檔")


def _imported(con, table, sha):
    return con.execute("SELECT 1 FROM %s WHERE sha256=? AND status='ok'" % table, (sha,)).fetchone() is not None


def _fetch(con, kind, opener):
    url_key, inbox_key, name, table = KINDS[kind]
    url = getattr(Config, url_key)
    inbox = getattr(Config, inbox_key)
    st = dict(load_state().get(kind) or {})
    if st.get("url") != url:                        # 換了網址：不沿用上次的 ETag
        st = {"url": url, "first_checked_at": st.get("first_checked_at") or st.get("checked_at")}
    st["first_checked_at"] = st.get("first_checked_at") or st.get("checked_at") or now()
    _check_url(url)
    os.makedirs(inbox, exist_ok=True)
    # 上次下載的那份還在放檔目錄、或已經匯入成功，才帶條件詢問；否則（匯入失敗、被清掉、資料庫還原過）不帶條件，
    # 沒更新也重新下載：設定改正或 Canonical 修正後自動恢復（壞掉的檔案會重複下載，/healthz 有匯入失敗的警告）
    dropped = bool(st.get("file")) and os.path.exists(os.path.join(inbox, st["file"]))
    conditional = bool(st.get("sha256")) and (dropped or _imported(con, table, st["sha256"]))
    headers = {"User-Agent": "cvehub"}
    if conditional and st.get("etag"):
        headers["If-None-Match"] = st["etag"]
    if conditional and st.get("last_modified"):
        headers["If-Modified-Since"] = st["last_modified"]
    max_bytes = Config.DOWNLOAD_MAX_MB * 1024 * 1024
    deadline = time.monotonic() + Config.DOWNLOAD_MAX_MINUTES * 60
    part = os.path.join(inbox, "." + name + ".part")
    try:
        try:
            r = opener.open(urllib.request.Request(url, headers=headers), timeout=Config.DOWNLOAD_TIMEOUT)
        except urllib.error.HTTPError as e:
            e.close()
            if e.code == 304:
                return st, ("same", "沒有更新")
            raise
        with r:
            length = r.headers.get("Content-Length")
            length = int(length) if length and length.isdigit() else None
            if length and length > max_bytes:
                raise ValueError("檔案 %d MB 超過 DOWNLOAD_MAX_MB（%d）" % (length // 2 ** 20, Config.DOWNLOAD_MAX_MB))
            need = (length or max_bytes) + MIN_FREE
            free = shutil.disk_usage(inbox).free
            if free < need:
                raise ValueError("磁碟空間不足：剩 %d MB，需要 %d MB（檔案＋保留 1 GB）" % (free // 2 ** 20, need // 2 ** 20))
            h, size = hashlib.sha256(), 0
            with open(part, "wb") as f:
                while True:
                    if time.monotonic() > deadline:
                        raise ValueError("超過 DOWNLOAD_MAX_MINUTES（%d 分鐘）還沒下載完" % Config.DOWNLOAD_MAX_MINUTES)
                    b = r.read1(CHUNK) if hasattr(r, "read1") else r.read(CHUNK)    # read1：每次最多等一次收資料，才能檢查時間上限
                    if not b:
                        break
                    size += len(b)
                    if size > max_bytes:
                        raise ValueError("檔案超過 DOWNLOAD_MAX_MB（%d）" % Config.DOWNLOAD_MAX_MB)
                    h.update(b)
                    f.write(b)
            if length is not None and size != length:
                raise ValueError("下載不完整（%d／%d bytes）" % (size, length))
            etag, last_mod = r.headers.get("ETag"), r.headers.get("Last-Modified")
        _check_archive(part)
        t = email.utils.parsedate_to_datetime(last_mod) if last_mod else None
        if t is not None:                           # 檔案日期用 Canonical 的（匯入紀錄的「檔案日期」、過期警告看它）
            os.utime(part, (t.timestamp(), t.timestamp()))
        sha = h.hexdigest()
        last_sha[kind] = sha
        st.update(etag=etag, last_modified=last_mod, sha256=sha, file=None)
        if _imported(con, table, sha):
            return st, ("same", "內容和已匯入的相同")
        fname = "%s-all-download-%s.tar.xz" % (kind, datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"))
        os.replace(part, os.path.join(inbox, fname))
        st["file"] = fname
        return st, ("new", "已下載 %.1f MB（%s），等匯入" % (size / 2 ** 20, last_mod or "日期不明"))
    finally:
        if os.path.exists(part):
            try:
                os.remove(part)
            except OSError:
                pass


def fetch(con, kind, opener=None):
    """檢查並下載一份（fetch_all 已經拿到 _single()）；回傳 (結果代碼, 說明)：new＝放進放檔目錄、same＝沒有更新、error＝失敗"""
    st = dict(load_state().get(kind) or {})
    try:
        st, result = _fetch(con, kind, opener or _opener())
    except Exception as e:
        result = ("error", str(e)[:300])
        log.warning("%s 下載失敗：%s", KINDS[kind][2], e)
        st["first_checked_at"] = st.get("first_checked_at") or st.get("checked_at") or now()
    st.update(checked_at=now(), result=result[0], message=result[1])
    if result[0] != "error":
        st["ok_at"] = st["checked_at"]
    state = load_state()                            # 重新讀再寫：不蓋掉另一份的狀態
    state[kind] = st
    _save_state(state)
    return result


def fetch_all(con, opener=None):
    """兩份都檢查；回傳 {kind: (結果, 說明)}；已經有一個在下載時（任何程序）回傳 None"""
    with _single() as ok:
        if not ok:
            return None
        out = {}
        for kind in KINDS:
            out[kind] = fetch(con, kind, opener)
            log.info("自動下載 %s：%s", KINDS[kind][2], out[kind][1])
        return out


def failing(state=None):
    """開啟自動下載時，超過 DOWNLOAD_ALERT_HOURS 小時沒有一次成功（下載或確認沒有更新）的檔案；狀態檔讀寫失敗＝全部"""
    if not Config.CVE_DATA_DOWNLOAD:
        return []
    state = load_state() if state is None else state
    if _read_error or _write_error:
        return list(KINDS)
    limit = datetime.datetime.now() - datetime.timedelta(hours=Config.DOWNLOAD_ALERT_HOURS)
    out = []
    for kind in KINDS:
        s = state.get(kind) or {}
        since = s.get("ok_at") or s.get("first_checked_at") or s.get("checked_at")   # 從來沒成功過：從第一次檢查起算
        if not since:
            continue                                # 還沒檢查過（剛開啟）
        try:
            if datetime.datetime.fromisoformat(since) >= limit:
                continue
        except ValueError:
            pass
        out.append(kind)
    return out
