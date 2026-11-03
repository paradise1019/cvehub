"""主機清單匯入（HOST_SOURCE=file）：不接 Landscape，改從 CSV 讀主機與已安裝套件

CSV 一列一個套件，第一列是欄位名稱（順序不限，多出來的欄位忽略）：
  必要：hostname, release, package, version
  選填：ip, pro, kernel_release, kernel_version, collected_at
主機層級的欄位（release、ip、pro、kernel_*、collected_at）每列重複；同一台主機各列的值不能互相矛盾（空白不算；
寫法不同但意思相同的視為相同，例如 22.04／Ubuntu 22.04.5 LTS；collected_at 原樣比對；ip 只用來顯示，格式不對只略過）。
同一個檔案可以有很多台主機；檔案中間再出現的標題列會改用新的欄位對應（每台主機各自產生的檔案可以直接串起來，欄位順序不同也可以）。
整個檔案驗證通過才匯入，有任何錯誤就整份不匯入、在資料匯入頁顯示錯誤。
"""
import csv
import datetime
import glob
import hashlib
import io
import ipaddress
import logging
import os
import re
import shutil

from .config import Config
from .kernel import SIG_VERSION, infer_running
from .util import norm_release, parse_time as _parse_time
from .vercmp import vercmp

log = logging.getLogger(__name__)

REQUIRED = ("hostname", "release", "package", "version")
HOST_FIELDS = ("release", "ip", "pro", "kernel_release", "kernel_version", "collected_at")
MAX_ERRORS = 20
HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
VERSION = re.compile(r"^[A-Za-z0-9.+~:-]+$")
KERNEL_RELEASE = re.compile(r"^\d+\.\d+\.\d+-\d+[a-z0-9.-]*$")
IP_PLACEHOLDERS = {"-", "?", "none", "null", "n/a", "na", "unknown"}     # 不是位址的佔位字：當成空白
PRO_VALUES = {"1": 1, "true": 1, "yes": 1, "y": 1, "0": 0, "false": 0, "no": 0, "n": 0}


class ImportError_(Exception):
    pass


def _same_form(f, val):
    """比對同一台主機各列是否一致前，先換成同一種寫法（格式不對的原樣留著，後面的檢查會報錯）"""
    if f == "release":
        return norm_release(val) or val                 # 22.04 ＝ Ubuntu 22.04.5 LTS
    if f == "pro":
        p = PRO_VALUES.get(val.lower())
        return val if p is None else ("yes" if p else "no")
    # collected_at 原樣比對：同一次收集各列是同一個字串；不同＝不同次收集（不做時區換算，避免日光節約等邊界問題）
    if f == "kernel_version":
        m = SIG_VERSION.search(val)                     # /proc/version_signature 整行 ＝ 其中的版本
        return m.group(1) if m else val
    return val


def parse(text):
    """解析 CSV 文字，回傳 {hostname: {"release","ip","pro","kernel_release","kernel_version","collected_at","packages"}}
    有錯誤時丟出 ImportError_（訊息列出前 MAX_ERRORS 個錯誤與列號）"""
    rd = csv.reader(io.StringIO(re.sub(r"(?m)^\ufeff", "", text)))    # 串接的 Excel 檔：每一段的第一行開頭都可能帶 BOM
    header = None
    errors = []
    hosts = {}

    def err(line, msg):
        if len(errors) < MAX_ERRORS:
            errors.append("第 %d 列：%s" % (line, msg))

    for row in rd:
        line = rd.line_num
        cells = [c.strip() for c in row]
        if not any(cells):
            continue
        low = [c.lower() for c in cells]
        if header is None or set(REQUIRED) <= set(low):
            # 第一列是欄位名稱；檔案中間再出現標題列（串接多個檔案，欄位順序可以不同）就改用新的對應
            if header is None:
                missing = [c for c in REQUIRED if c not in low]
                if missing:
                    raise ImportError_("缺少欄位：%s（第一列要是欄位名稱，必要欄位 %s）" % ("、".join(missing), ", ".join(REQUIRED)))
            header = low
            col = {name: header.index(name) for name in REQUIRED + HOST_FIELDS if name in header}
            continue
        v = {k: (cells[i] if i < len(cells) else "") for k, i in col.items()}
        hn, pkg, ver = v["hostname"], v["package"], v["version"]
        if not hn or not pkg or not ver:
            err(line, "hostname、package、version 不能空白")
            continue
        if not HOSTNAME.match(hn):
            err(line, "主機名稱格式不正確：%s" % hn[:80])
            continue
        pkg = pkg.split(":", 1)[0]      # libc6:amd64 → libc6
        if not PACKAGE.match(pkg):
            err(line, "套件名稱格式不正確：%s" % pkg[:80])
            continue
        try:
            if not VERSION.match(ver):
                raise ValueError
            vercmp(ver, "0")            # 比對時要能和修正版本比較，現在就先檢查
        except ValueError:
            err(line, "版本格式不正確：%s" % ver[:80])
            continue
        key = hn.lower()
        h = hosts.get(key)
        if h is None:
            h = hosts[key] = {"hostname": hn, "line": line, "packages": {}, "set_at": {}, "raw": {}, "conflict": False}
            for f in HOST_FIELDS:
                h[f] = ""
        for f in HOST_FIELDS:
            raw = v.get(f, "")
            if not raw or (f == "ip" and raw.lower() in IP_PLACEHOLDERS):
                continue
            if f == "ip":                                    # 只用來顯示：格式不對就略過，不影響整份匯入
                try:
                    val = str(ipaddress.ip_address(raw))     # 同一個位址的不同寫法（2001:DB8::1／2001:db8::1）視為相同
                except ValueError:
                    first = h.setdefault("ip_bad", (raw, line))
                    if first[0].lower() != raw.lower() and not h["conflict"]:   # 兩個不同的錯誤 IP：一樣可能是兩台同名
                        h["conflict"] = True
                        err(line, "主機 %s 的 ip 和第 %d 列不同（%s ≠ %s）：可能是兩台同名的機器（請改用不同的主機名稱），"
                            "或修正 ip" % (hn, first[1], raw[:40], first[0][:40]))
                    continue
            else:
                val = _same_form(f, raw)
            if h[f] and h[f] != val:
                # 同一台主機的欄位前後不同：多半是兩台同名的機器被串在一起，不能合併。每台只報一次，不佔滿錯誤清單
                if not h["conflict"]:
                    h["conflict"] = True
                    why = ("可能是同一台主機兩次收集的資料串在一起（請只保留最新的一份），或兩台同名的機器" if f == "collected_at"
                           else "可能是兩台同名的機器（請改用不同的主機名稱），或同一台的資料前後不一致")
                    err(line, "主機 %s 的 %s 和第 %d 列不同（%s ≠ %s）：%s" % (hn, f, h["set_at"][f], raw[:40], h["raw"][f][:40], why))
            elif not h[f]:
                h[f], h["set_at"][f], h["raw"][f] = val, line, raw
        old = h["packages"].get(pkg)
        if old is None or vercmp(ver, old) > 0:     # 多架構（amd64＋i386）同名套件取較新的版本
            h["packages"][pkg] = ver

    if header is None:
        raise ImportError_("檔案是空的")
    for h in hosts.values():
        line, hn = h["line"], h["hostname"]
        at = lambda f, h=h: h["set_at"].get(f, h["line"])                # 錯誤指向設定那個值的列
        if h["ip"] and h.get("ip_bad") and not h["conflict"]:
            # 有的列 IP 合法、有的列格式不對：分不出是不是兩台同名的機器，不能合併
            h["conflict"] = True
            err(h["ip_bad"][1], "主機 %s 的 ip 格式不正確（%s），但第 %d 列是 %s：可能是兩台同名的機器（請改用不同的主機名稱），"
                "或修正這一列的 ip" % (hn, h["ip_bad"][0][:40], h["set_at"]["ip"], h["ip"]))
        rel = norm_release(h["release"])
        if not rel:
            err(h["line"], "主機 %s 沒有 release（Ubuntu 版本，例：22.04）" % hn)
        elif rel not in Config.UBUNTU_RELEASES:
            err(at("release"), "主機 %s 的版本 %s 不在 UBUNTU_RELEASES（%s）" % (hn, rel, ",".join(Config.UBUNTU_RELEASES)))
        h["release"] = rel
        p = h["pro"].lower()
        if p and p not in PRO_VALUES:
            err(at("pro"), "主機 %s 的 pro 只能是 yes／no／true／false／1／0：%s" % (hn, h["pro"][:20]))
        h["pro"] = PRO_VALUES.get(p)
        if h["kernel_release"] and not KERNEL_RELEASE.match(h["kernel_release"]):
            err(at("kernel_release"), "主機 %s 的 kernel_release 應是 uname -r 的格式（例：6.8.0-49-generic）：%s" % (hn, h["kernel_release"][:60]))
        if h["collected_at"]:
            t = _parse_time(h["collected_at"])
            if not t:
                err(at("collected_at"), "主機 %s 的 collected_at 不是 ISO 8601 時間：%s" % (hn, h["collected_at"][:40]))
            h["collected_at"] = t.isoformat(timespec="seconds") if t else ""
    if errors:
        raise ImportError_("；".join(errors) + ("（只列前 %d 個）" % MAX_ERRORS if len(errors) >= MAX_ERRORS else ""))
    if not hosts:
        raise ImportError_("檔案裡沒有任何套件資料")
    return hosts


def _kernel(h):
    """回傳 (kernel_release, kernel_version, kernel_status)；和 kernel API 共用同一套推算（kernel.infer_running）
    kernel_version 可以是 /proc/version_signature 整行；看不出版本時改從套件清單找"""
    if not h["kernel_release"] and not h["kernel_version"]:
        return None, None, "disabled"           # 沒給：比對時用「最新安裝的 kernel」推測
    krel, kver = infer_running(h["kernel_release"], h["kernel_version"], h["packages"])
    return (krel, kver, "ok") if krel and kver else (None, None, "missing")


def apply(con, hosts, record=None, t=None):
    """寫入資料庫；HOSTS_FILE_MODE=replace 時，清單裡沒有的主機改成停用。回傳 (主機數, 套件數, 停用數)
    record＝(檔名, sha256)：匯入紀錄和資料寫在同一個交易裡（不會有資料寫進去了、紀錄卻是失敗的情況）"""
    t = t or datetime.datetime.now().isoformat(timespec="seconds")
    seen = set()
    npk = 0
    with con:
        for h in hosts.values():
            krel, kver, kst = _kernel(h)
            # 同名主機沿用原本的紀錄（包含先前從 Landscape 同步的），弱點歷史才會接續
            cur = con.execute("SELECT id FROM host WHERE lower(hostname)=? ORDER BY active DESC, id DESC LIMIT 1",
                              (h["hostname"].lower(),)).fetchone()
            vals = (h["hostname"], h["ip"] or None, h["hostname"], h["release"], h["pro"], len(h["packages"]),     # 沒有合法 IP 時保留原本的
                    h["collected_at"] or t, krel, kver, h["collected_at"] or None, kst)
            if cur:
                hid = cur["id"]
                con.execute("UPDATE host SET hostname=?,ip=COALESCE(?,ip),title=?,release=?,pro_attached=?,package_count=?,last_seen=?,"
                            "kernel_release=?,kernel_version=?,kernel_collected_at=?,kernel_status=?,active=1 WHERE id=?", vals + (hid,))
            else:
                hid = con.execute("INSERT INTO host(hostname,ip,title,release,pro_attached,package_count,last_seen,kernel_release,"
                                  "kernel_version,kernel_collected_at,kernel_status) VALUES (?,?,?,?,?,?,?,?,?,?,?)", vals).lastrowid
            con.execute("DELETE FROM host_package WHERE host_id=?", (hid,))
            con.executemany("INSERT INTO host_package(host_id,name,version) VALUES (?,?,?)",
                            [(hid, n, v) for n, v in h["packages"].items()])
            seen.add(hid)
            npk += len(h["packages"])
        off = 0
        if Config.HOSTS_FILE_MODE == "replace":
            for r in con.execute("SELECT id FROM host WHERE active=1").fetchall():
                if r["id"] not in seen:
                    con.execute("UPDATE host SET active=0 WHERE id=?", (r["id"],))
                    off += 1
        if record:
            ignored = sorted(h["hostname"] for h in hosts.values() if h.get("ip_bad") and not h["ip"])   # 全部列的 ip 都不合法
            note = None
            if ignored:
                note = "略過格式不正確的 ip（主機原本有 IP 的會保留）：%s%s" % ("、".join(ignored[:20]), "等 %d 台" % len(ignored) if len(ignored) > 20 else "")
            con.execute("INSERT INTO host_import(filename,sha256,imported_at,status,hosts,packages,deactivated,message) "
                        "VALUES (?,?,?,'ok',?,?,?,?)", record + (t, len(hosts), npk, off, note))
    return len(hosts), npk, off


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def import_file(con, path):
    """匯入一個 CSV。成功：資料與 ok 紀錄在同一個交易寫入；失敗：整批回復，另外記一筆 failed，丟出 ImportError_
    （呼叫端 run_sync 在跨程序的 job_lock 裡執行：OSV／VEX 匯入不會同時進行，資料庫只會被網頁短暫寫入）"""
    name = os.path.basename(path)
    t = datetime.datetime.now().isoformat(timespec="seconds")     # 成功、失敗紀錄都用開始匯入的時間
    sha = None
    try:
        sha = _sha256(path)
        with open(path, encoding="utf-8-sig", newline="") as f:     # Excel 存的 UTF-8 會有 BOM
            text = f.read()
        n, npk, off = apply(con, parse(text), (name, sha), t)
    except Exception as e:
        if isinstance(e, UnicodeDecodeError):
            msg = "編碼不是 UTF-8"
        elif isinstance(e, (ImportError_, csv.Error)):
            msg = str(e)
        else:
            log.exception("主機清單 %s 匯入時發生錯誤", name)
            msg = "匯入時發生錯誤（%s: %s），請看容器 log；檔案內容沒問題的話，重新上傳即可" % (type(e).__name__, e)
        try:
            with con:
                con.execute("INSERT INTO host_import(filename,sha256,imported_at,status,message) VALUES (?,?,?,'failed',?)",
                            (name, sha, t, msg[:2000]))
        except Exception:
            log.exception("無法記錄主機清單匯入失敗")
        raise ImportError_(msg) from e
    log.info("主機清單 %s：主機 %d、套件 %d、停用 %d", name, n, npk, off)
    return n, npk, off


def pending():
    return sorted(glob.glob(os.path.join(Config.HOSTS_INBOX_DIR, "*.csv")), key=os.path.getmtime)


def check_inbox(con):
    """匯入放檔目錄裡的 CSV（依修改時間先後），處理完移到保存目錄（失敗的檔名加 failed-）。回傳啟用中的主機數"""
    for f in pending():
        ok = True
        try:
            import_file(con, f)
        except Exception as e:      # 任何錯誤（包含記錄紀錄時的錯誤）：移出放檔目錄（檔名加 failed-），不卡住之後的同步
            ok = False
            log.warning("主機清單 %s 匯入失敗：%s", os.path.basename(f), e)
        os.makedirs(Config.HOSTS_ARCHIVE_DIR, exist_ok=True)
        name = "%s-%s" % (datetime.datetime.now().strftime("%Y%m%d%H%M%S"), os.path.basename(f))
        shutil.move(f, os.path.join(Config.HOSTS_ARCHIVE_DIR, name if ok else "failed-" + name))
    keep = sorted(glob.glob(os.path.join(Config.HOSTS_ARCHIVE_DIR, "*.csv")), key=os.path.getmtime)
    for old in keep[:-Config.HOSTS_KEEP_FILES] if Config.HOSTS_KEEP_FILES > 0 else []:
        os.remove(old)
    return con.execute("SELECT COUNT(*) FROM host WHERE active=1").fetchone()[0]
