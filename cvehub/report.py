"""查詢（網頁與報表共用）與報表輸出"""
import csv
import datetime
import io
import json
import os

from .config import PRIO, Config
from .sync import active_exceptions, excepted

COLUMNS = ["hostname", "release", "cve", "priority", "status", "package", "installed", "running", "fixed",
           "location", "action", "repo", "source", "first_seen", "last_seen", "resolved_at", "exception"]


def query_findings(con, host=None, cve=None, priority=None, status=None, state="open", show_excepted=True, package=None):
    """
    state: open（未解決）| resolved（已解決）| all
    priority: 最低等級（例如 high＝high 和 critical）
    """
    sql = ["SELECT f.*, h.hostname, h.release FROM finding f JOIN host h ON h.id=f.host_id WHERE h.active=1"]
    args = []
    if state == "open":
        sql.append("AND f.resolved_at IS NULL")
    elif state == "resolved":
        sql.append("AND f.resolved_at IS NOT NULL")
    if host:
        sql.append("AND h.hostname LIKE ?")
        args.append("%" + host + "%")
    if cve:
        sql.append("AND f.cve LIKE ?")
        args.append("%" + cve.upper() + "%")
    if package:
        sql.append("AND (f.package LIKE ? OR f.source LIKE ?)")
        args += ["%" + package + "%"] * 2
    if status:
        sql.append("AND f.status=?")
        args.append(status)
    minp = PRIO.get(priority if priority else Config.MIN_PRIORITY, 5)
    exc = active_exceptions(con)
    out = []
    for r in con.execute(" ".join(sql), args):
        if PRIO.get(r["priority"] or "", 5) > minp:
            continue
        e = excepted(exc, r["hostname"], r["cve"])
        if e and not show_excepted:
            continue
        d = dict(r)
        d["exception"] = ("%s（到 %s）" % (e["reason"], e["expires_at"] or "永久")) if e else ""
        out.append(d)
    out.sort(key=lambda x: (x["hostname"], PRIO.get(x["priority"] or "", 5), x["cve"], x["package"]))
    return out


def summary_by_host_cve(rows):
    """一個 (主機, CVE) 一行，packages 合併"""
    g = {}
    for x in rows:
        g.setdefault((x["hostname"], x["cve"]), []).append(x)
    out = []
    for (hn, cve), xs in g.items():
        out.append({"hostname": hn, "cve": cve, "priority": xs[0]["priority"], "status": xs[0]["status"],
                    "packages": "; ".join("%s %s>%s [%s]" % (x["package"], x["running"] or x["installed"], x["fixed"] or "(no fix)", x["action"])
                                          for x in xs),
                    "first_seen": min(x["first_seen"] for x in xs), "exception": xs[0]["exception"]})
    return out


def safe_cell(v):
    """防 CSV／Excel 公式注入：以 = + - @ 開頭（或 tab、CR）的字串前面加 '"""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def to_csv(rows, columns):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    w.writeheader()
    w.writerows({k: safe_cell(v) for k, v in r.items()} for r in rows)
    return "﻿" + buf.getvalue()      # BOM：Excel 直接開啟中文不亂碼


def write_reports(con):
    os.makedirs(Config.REPORT_DIR, exist_ok=True)
    rows = query_findings(con)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    for fmt in Config.REPORT_FORMATS:
        if fmt == "csv":
            for name, data, cols in (("detail", rows, COLUMNS),
                                     ("summary", summary_by_host_cve(rows), ["hostname", "cve", "priority", "status", "packages", "first_seen", "exception"])):
                with open(os.path.join(Config.REPORT_DIR, "cve-%s-%s.csv" % (name, stamp)), "w", encoding="utf-8", newline="") as f:
                    f.write(to_csv(data, cols))
        elif fmt == "json":
            with open(os.path.join(Config.REPORT_DIR, "cve-detail-%s.json" % stamp), "w") as f:
                json.dump(rows, f, ensure_ascii=False, indent=1)
