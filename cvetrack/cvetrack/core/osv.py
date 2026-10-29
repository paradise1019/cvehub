"""匯入 Canonical OSV（osv-all.tar.xz）並算出與前一份的差異

做法（與原專案共用 SQLite，不能有長交易）：
1. 建立匯入紀錄（loading），公告資料每 IMPORT_BATCH 筆一個短交易寫入，列上帶這次的匯入編號。
2. 檢查筆數；失敗就分批刪掉這次寫入的列，紀錄標 failed，舊資料不受影響。
3. 用 SQL 比較新舊兩份，寫進 AdvisoryChange。
4. 一個短交易切換 active，之後分批刪掉舊資料。
"""
import datetime
import hashlib
import json
import logging
import os
import tarfile

from django.db import connection, transaction
from django.utils import timezone

from ..conf import conf
from ..models import AdvisoryChange, OsvImport
from .kernel import kernel_variant

log = logging.getLogger(__name__)

PURGE_BATCH = 20000


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def file_mtime(path):
    return datetime.datetime.fromtimestamp(os.path.getmtime(path), tz=datetime.timezone.utc)


def wanted_ecosystems(releases):
    eco = set()
    for r in releases:
        eco.update({"Ubuntu:%s:LTS" % r, "Ubuntu:Pro:%s:LTS" % r, "Ubuntu:%s" % r})
    return eco


def _usn_rows(d, wanted):
    """USN：哪一天、以哪個版本修正了哪些 CVE"""
    cves = [u.replace("UBUNTU-", "") for u in d.get("upstream", []) if "CVE-" in u]
    for a in d.get("affected", []):
        eco, src = a["package"]["ecosystem"], a["package"]["name"]
        if eco not in wanted or kernel_variant(src):     # 雲端／OEM kernel 變體不收
            continue
        fixed = next((ev["fixed"] for rng in a.get("ranges", []) for ev in rng.get("events", []) if "fixed" in ev), None)
        if fixed:
            for cve in cves:
                yield (cve, eco, src, fixed, d["id"], d.get("published", "")[:10])


def iter_osv(path, releases):
    """逐筆產生 ("vuln"|"affected"|"binmap"|"usn", row)；只保留需要的 Ubuntu 版本，記憶體用量固定"""
    wanted = wanted_ecosystems(releases)
    with tarfile.open(path, "r:xz") as tar:
        for m in tar:
            # 只讀一般檔案、只認 osv/cve/、osv/usn/ 底下的 .json；不寫入磁碟
            if not (m.isfile() and m.name.endswith(".json") and m.name.startswith(("osv/cve/", "osv/usn/"))):
                continue
            d = json.load(tar.extractfile(m))
            if d.get("withdrawn"):
                continue
            if m.name.startswith("osv/usn/"):
                for row in _usn_rows(d, wanted):
                    yield "usn", row
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
                # 只存「版本和 source 修正版本不同」的 binary（絕大多數相同）；尚未修正的不比對版本
                diff = {b: v for b, v in bins.items() if v and v != fixed} if fixed else {}
                packed = json.dumps(diff, separators=(",", ":")) if diff else None
                for cve in cves:
                    yield "affected", (eco, src, cve, fixed, introduced, packed)
            # 沒有任何指定版本套件的 CVE 也收：輸出報表要列出「不受影響／不在此版本」的 CVE
            for cve in cves:
                yield "vuln", (cve, prio, cvss, d.get("published", ""), (d.get("details") or d.get("summary") or "").strip())


SQL = {"vuln": "INSERT OR REPLACE INTO cvetrack_vuln(imp,cve,priority,cvss,published,details) VALUES (%s,%s,%s,%s,%s,%s)",
       "affected": "INSERT INTO cvetrack_affected(imp,ecosystem,source,cve,fixed,introduced,binaries) VALUES (%s,%s,%s,%s,%s,%s,%s)",
       "binmap": "INSERT OR IGNORE INTO cvetrack_binmap(imp,ecosystem,binary,source) VALUES (%s,%s,%s,%s)",
       "usn": "INSERT OR REPLACE INTO cvetrack_usnfix(imp,cve,ecosystem,source,fixed,usn,published) VALUES (%s,%s,%s,%s,%s,%s,%s)"}
TABLES = ("cvetrack_vuln", "cvetrack_affected", "cvetrack_binmap", "cvetrack_usnfix")


def _write(kind, imp, rows):
    with transaction.atomic(), connection.cursor() as c:
        c.executemany(SQL[kind], [(imp,) + r for r in rows])


def purge_rows(imp, tables=TABLES):
    """分批刪除某次匯入的公告資料（每批一個短交易）"""
    for t in tables:
        while True:
            with transaction.atomic(), connection.cursor() as c:
                c.execute("DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s WHERE imp=%%s LIMIT %d)" % (t, t, PURGE_BATCH), [imp])
                if c.rowcount < PURGE_BATCH:
                    break


def active_import():
    return OsvImport.objects.filter(active=True).first()


def _release_of(eco):
    return eco.split(":")[-2] if eco.endswith(":LTS") else eco.split(":")[-1]


def import_file(path, filename=None):
    """匯入一個 OSV 檔；成功回傳 OsvImport，失敗丟例外（舊資料不動）"""
    cleanup_interrupted()
    sha = sha256(path)
    releases = list(conf.UBUNTU_RELEASES)
    prev = active_import()
    imp = OsvImport.objects.create(filename=filename or os.path.basename(path), sha256=sha, file_mtime=file_mtime(path),
                                   imported_at=timezone.now(), releases=",".join(releases), status="loading", prev=prev)
    log.info("OSV 匯入開始：%s（sha256 %s…，版本 %s）", path, sha[:12], ",".join(releases))
    try:
        batch = conf.IMPORT_BATCH
        counts = {"vuln": 0, "affected": 0, "binmap": 0, "usn": 0}
        buf = {k: [] for k in SQL}
        first_fix = {}       # (cve, ecosystem, source) -> 最早的 USN
        per_release = {r: 0 for r in releases}
        for kind, row in iter_osv(path, releases):
            if kind == "usn":
                k = row[:3]
                # 最早的 USN；沒有日期的排最後（不能蓋掉有日期的）
                if k not in first_fix or (row[5] or "9999", row[4]) < (first_fix[k][5] or "9999", first_fix[k][4]):
                    first_fix[k] = row
                continue
            if kind == "affected":
                rel = _release_of(row[0])
                if rel in per_release and ":Pro:" not in row[0]:
                    per_release[rel] += 1
            buf[kind].append(row)
            if len(buf[kind]) >= batch:
                _write(kind, imp.id, buf[kind])
                counts[kind] += len(buf[kind])
                buf[kind].clear()
        buf["usn"] = list(first_fix.values())
        for kind, rows in buf.items():
            for i in range(0, len(rows), batch):
                _write(kind, imp.id, rows[i:i + batch])
            counts[kind] += len(rows)
        if not counts["affected"]:
            raise ValueError("檔案中沒有任何 %s 的資料，可能不是正確的 osv-all.tar.xz" % ",".join(releases))
        short = {r: n for r, n in per_release.items() if n < conf.OSV_MIN_ROWS_PER_RELEASE}
        if short:
            # 可能是 OSV 改了版本名稱、或檔案不完整：寧可報錯保留舊資料，也不要悄悄缺資料
            raise ValueError("以下版本的資料筆數不足 %d：%s（OSV 格式可能改變，或 UBUNTU_RELEASES 設錯）"
                             % (conf.OSV_MIN_ROWS_PER_RELEASE, ", ".join("%s=%d" % kv for kv in sorted(short.items()))))
        change_counts = compute_changes(imp, prev) if prev else None
        with connection.cursor() as c:
            c.execute("SELECT COUNT(*) FROM cvetrack_vuln WHERE imp=%s", [imp.id])
            ncve = c.fetchone()[0]
        with transaction.atomic():
            OsvImport.objects.filter(active=True).update(active=False)
            imp.status, imp.active = "ok", True
            imp.cve_count, imp.affected_count = ncve, counts["affected"]
            imp.release_counts, imp.change_counts = per_release, change_counts
            imp.save()
        log.info("OSV 匯入完成：CVE %d、affected %d、USN 修正紀錄 %d、差異 %s", ncve, counts["affected"], counts["usn"],
                 change_counts or "（第一份，無差異）")
    except BaseException as e:
        log.exception("OSV 匯入失敗：%s", path)
        AdvisoryChange.objects.filter(imp=imp).delete()
        purge_rows(imp.id)
        OsvImport.objects.filter(pk=imp.pk).update(status="failed", message=str(e)[:500], purged=True)
        raise
    purge_old()
    return imp


def cleanup_interrupted():
    """呼叫端拿著 job_lock：這時還是「匯入中」的，是之前被中斷的（程序被殺、逾時）。刪掉寫到一半的資料"""
    for imp in OsvImport.objects.filter(status="loading"):
        AdvisoryChange.objects.filter(imp=imp).delete()
        purge_rows(imp.id)
        OsvImport.objects.filter(pk=imp.pk).update(status="failed", message="中斷（程序沒有正常結束）", purged=True)


def purge_old():
    """刪掉不再使用的匯入的公告資料（紀錄與差異保留）"""
    for old in OsvImport.objects.filter(active=False, purged=False).exclude(status="loading"):
        purge_rows(old.id)
        OsvImport.objects.filter(pk=old.pk).update(purged=True)


# ---------------------------------------------------------------- 差異

_KEYED = """
SELECT ecosystem, source, cve, MIN(COALESCE(fixed, '')) AS fixed, MIN(COALESCE(introduced, '')) AS introduced
FROM cvetrack_affected WHERE imp=%s GROUP BY ecosystem, source, cve
"""


def compute_changes(new, old):
    """新舊兩份 OSV 的差異寫進 AdvisoryChange；回傳 {kind: 筆數}"""
    log.info("計算 OSV 差異：#%d → #%d", old.id, new.id)
    sql = {
        # 新增：新的有、舊的沒有
        "added": """SELECT n.ecosystem, n.source, n.cve, NULL, NULLIF(n.fixed, '') FROM (%s) n
                    LEFT JOIN (%s) o ON o.ecosystem=n.ecosystem AND o.source=n.source AND o.cve=n.cve
                    WHERE o.cve IS NULL""" % (_KEYED, _KEYED),
        "removed": """SELECT o.ecosystem, o.source, o.cve, NULLIF(o.fixed, ''), NULL FROM (%s) o
                      LEFT JOIN (%s) n ON o.ecosystem=n.ecosystem AND o.source=n.source AND o.cve=n.cve
                      WHERE n.cve IS NULL""" % (_KEYED, _KEYED),
        "fixed": """SELECT n.ecosystem, n.source, n.cve, NULLIF(o.fixed, ''), NULLIF(n.fixed, ''), o.introduced, n.introduced
                    FROM (%s) n JOIN (%s) o ON o.ecosystem=n.ecosystem AND o.source=n.source AND o.cve=n.cve
                    WHERE o.fixed <> n.fixed OR o.introduced <> n.introduced""" % (_KEYED, _KEYED),
    }
    rows = []
    with connection.cursor() as c:
        c.execute(sql["added"], [new.id, old.id])
        rows += [AdvisoryChange(imp=new, ecosystem=e, source=s, cve=v, kind="added", old_value=None, new_value=f)
                 for e, s, v, _, f in c.fetchall()]
        c.execute(sql["removed"], [old.id, new.id])
        rows += [AdvisoryChange(imp=new, ecosystem=e, source=s, cve=v, kind="removed", old_value=f, new_value=None)
                 for e, s, v, f, _ in c.fetchall()]
        c.execute(sql["fixed"], [new.id, old.id])
        for e, s, v, of, nf, oi, ni in c.fetchall():
            if of != nf:
                kind = "fix_added" if not of else "fix_removed" if not nf else "fixed_changed"
                rows.append(AdvisoryChange(imp=new, ecosystem=e, source=s, cve=v, kind=kind, old_value=of, new_value=nf))
            if oi != ni:
                rows.append(AdvisoryChange(imp=new, ecosystem=e, source=s, cve=v, kind="introduced_changed",
                                           old_value=oi or None, new_value=ni or None))
        c.execute("""SELECT n.cve, o.priority, n.priority FROM cvetrack_vuln n JOIN cvetrack_vuln o ON o.cve=n.cve AND o.imp=%s
                     WHERE n.imp=%s AND o.priority <> n.priority""", [old.id, new.id])
        rows += [AdvisoryChange(imp=new, cve=v, kind="priority_changed", old_value=op, new_value=np)
                 for v, op, np in c.fetchall()]
    for i in range(0, len(rows), conf.IMPORT_BATCH):
        with transaction.atomic():
            AdvisoryChange.objects.bulk_create(rows[i:i + conf.IMPORT_BATCH])
    counts = {}
    for r in rows:
        counts[r.kind] = counts.get(r.kind, 0) + 1
    return counts
