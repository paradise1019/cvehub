"""匯入 Canonical OSV（osv-all.tar.xz）：直接讀壓縮檔（不解壓到磁碟），整批替換、失敗保留舊資料"""
import datetime
import glob
import hashlib
import json
import logging
import os
import shutil
import tarfile

from .config import Config

log = logging.getLogger(__name__)


def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def wanted_ecosystems(releases):
    eco = set()
    for r in releases:
        eco.update({"Ubuntu:%s:LTS" % r, "Ubuntu:Pro:%s:LTS" % r, "Ubuntu:%s" % r})
    return eco


def iter_osv(path, releases):
    """逐筆產生 ("vuln", row) / ("affected", row) / ("binmap", row)；只保留需要的 Ubuntu 版本。記憶體用量固定"""
    wanted = wanted_ecosystems(releases)
    with tarfile.open(path, "r:xz") as tar:
        for m in tar:
            # 只讀一般檔案、只認 osv/cve/ 底下的 .json；不寫入磁碟
            if not (m.isfile() and m.name.startswith("osv/cve/") and m.name.endswith(".json")):
                continue
            d = json.load(tar.extractfile(m))
            if d.get("withdrawn"):
                continue
            cves = d.get("upstream") or [d["id"].replace("UBUNTU-", "")]
            prio = next((s["score"] for s in d.get("severity", []) if s.get("type") == "Ubuntu"), "")
            cvss = next((s["score"] for s in d.get("severity", []) if s.get("type", "").startswith("CVSS")), "")
            for a in d.get("affected", []):
                eco = a["package"]["ecosystem"]
                if eco not in wanted:
                    continue
                src = a["package"]["name"]
                bins = {b["binary_name"]: b.get("binary_version", "")
                        for b in a.get("ecosystem_specific", {}).get("binaries", [])}
                for b in bins:
                    yield "binmap", (eco, b, src)
                fixed = introduced = None
                for rng in a.get("ranges", []):
                    for ev in rng.get("events", []):
                        if "fixed" in ev:
                            fixed = ev["fixed"]
                        if "introduced" in ev and ev["introduced"] != "0":
                            introduced = ev["introduced"]
                # 只存「版本和 source 修正版本不同」的 binary（絕大多數相同），資料庫可小一個數量級
                # 尚未修正（fixed 為空）的資料不比對版本，不需要 binary 清單
                diff = {b: v for b, v in bins.items() if v and v != fixed} if fixed else {}
                packed = json.dumps(diff, separators=(",", ":")) if diff else None
                for cve in cves:
                    yield "affected", (eco, src, cve, fixed, introduced, packed)
            # 沒有任何指定版本套件的 CVE 也收：輸出報表要列出「不受影響／不在此版本」的 CVE
            for cve in cves:
                yield "vuln", (cve, prio, cvss, d.get("published", ""), (d.get("details") or d.get("summary") or "").strip())


SQL = {"vuln": "INSERT OR REPLACE INTO vuln(cve,priority,cvss,published,details) VALUES (?,?,?,?,?)",
       "affected": "INSERT INTO affected(ecosystem,source,cve,fixed,introduced,binaries) VALUES (?,?,?,?,?,?)",
       "binmap": "INSERT OR IGNORE INTO binmap(ecosystem,binary,source) VALUES (?,?,?)"}
BATCH = 50000
# 資料格式版本：匯入內容有變時加一，舊資料庫會用保存的 OSV 檔自動重匯
# 1＝0.4.0 加 details；2＝0.5.0 收錄所有 CVE（含沒有指定版本套件的）
FORMAT = 2


def import_file(con, path):
    """匯入一個 OSV 檔；成功回傳 import id，失敗丟例外（單一交易，舊資料不動）"""
    sha = _sha256(path)
    mtime = datetime.datetime.fromtimestamp(os.path.getmtime(path)).isoformat(timespec="seconds")
    releases = Config.UBUNTU_RELEASES
    log.info("OSV 匯入開始：%s（sha256 %s…，版本 %s）", path, sha[:12], ",".join(releases))
    try:
        counts = {"vuln": 0, "affected": 0, "binmap": 0}
        buf = {k: [] for k in SQL}
        with con:  # 單一交易：失敗會整批回復
            con.execute("DELETE FROM affected")
            con.execute("DELETE FROM vuln")
            con.execute("DELETE FROM binmap")
            per_release = {r: 0 for r in releases}
            for kind, row in iter_osv(path, releases):
                if kind == "affected":
                    rel = row[0].split(":")[-2] if row[0].endswith(":LTS") else row[0].split(":")[-1]
                    if rel in per_release and ":Pro:" not in row[0]:
                        per_release[rel] += 1
                buf[kind].append(row)
                if len(buf[kind]) >= BATCH:
                    con.executemany(SQL[kind], buf[kind])
                    counts[kind] += len(buf[kind])
                    buf[kind].clear()
            for kind, rows in buf.items():
                if rows:
                    con.executemany(SQL[kind], rows)
                    counts[kind] += len(rows)
            if not counts["affected"]:
                raise ValueError("檔案中沒有任何 %s 的資料，可能不是正確的 osv-all.tar.xz" % ",".join(releases))
            short = {r: n for r, n in per_release.items() if n < Config.OSV_MIN_ROWS_PER_RELEASE}
            if short:
                # 可能是 OSV 改了版本名稱、或檔案不完整：寧可報錯保留舊資料，也不要悄悄缺資料
                raise ValueError("以下版本的資料筆數不足 %d：%s（OSV 格式可能改變，或 UBUNTU_RELEASES 設錯）"
                                 % (Config.OSV_MIN_ROWS_PER_RELEASE, ", ".join("%s=%d" % kv for kv in sorted(short.items()))))
            ncve = con.execute("SELECT COUNT(*) FROM vuln").fetchone()[0]
            con.execute("UPDATE osv_import SET active=0")
            cur = con.execute(
                "INSERT INTO osv_import(filename,sha256,file_mtime,imported_at,releases,cve_count,affected_count,release_counts,status,active,format)"
                " VALUES (?,?,?,?,?,?,?,?,'ok',1,?)",
                (os.path.basename(path), sha, mtime, _now(), ",".join(releases), ncve, counts["affected"],
                 json.dumps(per_release, sort_keys=True), FORMAT))
        con.execute("VACUUM")          # 釋放舊資料佔用的空間
        log.info("OSV 匯入完成：CVE %d、affected %d", ncve, counts["affected"])
        return cur.lastrowid
    except Exception as e:
        with con:
            con.execute("INSERT INTO osv_import(filename,sha256,file_mtime,imported_at,releases,status,message)"
                        " VALUES (?,?,?,?,?,'failed',?)", (os.path.basename(path), sha, mtime, _now(), ",".join(releases), str(e)[:500]))
        log.exception("OSV 匯入失敗：%s", path)
        raise


def reimport_if_outdated(con):
    """使用中的資料是舊格式（format 小於 FORMAT）時，用保存目錄裡同一份 OSV 檔重匯一次"""
    imp = active_import(con)
    if not imp or (imp["format"] or 0) >= FORMAT:
        return False
    for f in sorted(glob.glob(os.path.join(Config.OSV_ARCHIVE_DIR, "*.tar.xz")), key=os.path.getmtime, reverse=True):
        if _sha256(f) == imp["sha256"]:
            log.info("OSV 資料格式 %s 舊於 %d，用保存檔重新匯入：%s", imp["format"], FORMAT, f)
            import_file(con, f)
            return True
    log.warning("OSV 資料格式較舊，但保存目錄找不到目前使用的 OSV 檔；請在資料匯入頁重新上傳")
    return False


def check_inbox(con):
    """檢查放檔目錄；有新檔（sha256 沒匯入過）就匯入，成功後移到保存目錄。回傳是否有新匯入"""
    files = sorted(glob.glob(os.path.join(Config.OSV_INBOX_DIR, "*.tar.xz")), key=os.path.getmtime)
    shas = {f: _sha256(f) for f in files}
    done = {s for s in shas.values() if con.execute("SELECT 1 FROM osv_import WHERE sha256=? AND status='ok'", (s,)).fetchone()}
    if not set(shas.values()) - done:    # 有沒匯入過的新檔就直接匯入新檔，不必先重匯舊檔
        reimport_if_outdated(con)
    imported = False
    for f in files:
        if shas[f] not in done:
            import_file(con, f)
            imported = True
        os.makedirs(Config.OSV_ARCHIVE_DIR, exist_ok=True)
        name = os.path.basename(f)
        if not (len(name) > 9 and name[:8].isdigit() and name[8] == "-"):     # 已有日期前綴就不再加
            name = "%s-%s" % (datetime.date.today().strftime("%Y%m%d"), name)
        dest = os.path.join(Config.OSV_ARCHIVE_DIR, name)
        shutil.move(f, dest)
    keep = sorted(glob.glob(os.path.join(Config.OSV_ARCHIVE_DIR, "*.tar.xz")), key=os.path.getmtime)
    for old in keep[:-Config.OSV_KEEP_FILES] if Config.OSV_KEEP_FILES > 0 else []:
        os.remove(old)
    return imported


def active_import(con):
    return con.execute("SELECT * FROM osv_import WHERE active=1").fetchone()
