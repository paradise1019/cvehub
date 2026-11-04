"""查詢（網頁與報表共用）與報表輸出"""
import contextlib
import csv
import datetime
import io
import json
import os
import threading

from .config import PRIO, Config
from .sync import ExceptionMatcher, active_exceptions

COLUMNS = ["hostname", "release", "cve", "priority", "status", "package", "installed", "running", "fixed",
           "location", "action", "repo", "source", "first_seen", "last_seen", "resolved_at", "exception"]


def query_findings(con, host=None, cve=None, priority=None, status=None, state="open", show_excepted=True, package=None, hid=None):
    """
    host: 名稱的一部分（顯示名稱或完整名稱）；hid: 只看這一台（host.id，主機頁與總覽的連結用，名稱互相包含時才不會混到別台；有 hid 時不看 host）
    state: open（未解決）| resolved（已解決）| all
    priority: 最低等級（例如 high＝high 和 critical）
    """
    sql = ["SELECT f.*, h.hostname, h.fqdn, h.release FROM finding f JOIN host h ON h.id=f.host_id WHERE h.active=1"]
    args = []
    if state == "open":
        sql.append("AND f.resolved_at IS NULL")
    elif state == "resolved":
        sql.append("AND f.resolved_at IS NOT NULL")
    if hid:                         # 有 hid 時 host 只是顯示用（名稱改過也照樣找得到）
        sql.append("AND h.id=?")
        args.append(hid)
    elif host:
        sql.append("AND (h.hostname LIKE ? OR h.fqdn LIKE ?)")
        args += ["%" + host + "%"] * 2
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
    match = ExceptionMatcher(active_exceptions(con))
    out = []
    for r in con.execute(" ".join(sql), args):
        if PRIO.get(r["priority"] or "", 5) > minp:
            continue
        e = match(r["hostname"], r["cve"], r["fqdn"])
        if e and not show_excepted:
            continue
        d = dict(r)
        d["exception"] = ("%s（到 %s）" % (e["reason"], e["expires_at"] or "永久")) if e else ""
        out.append(d)
    out.sort(key=lambda x: (x["hostname"], PRIO.get(x["priority"] or "", 5), x["cve"], x["package"]))
    return out


def host_overview(con, today=None):
    """總覽用：每台啟用中主機各等級未解決的 CVE 數（主機×CVE，不含例外、MIN_PRIORITY 以上）與是否需要重開機。
    回傳 {host_id: {"critical": n, …, "": n, "reboot": bool}}，結果和 query_findings(show_excepted=False) 逐筆算相同：
    每個「主機×CVE」算一次，等級取那幾列裡最嚴重的（同一個 CVE 的列等級可能不同，例如 kernel API 查詢失敗時
    執行中 kernel 的列沒有更新）；需要重開機＝不是例外的列裡有執行中 kernel 的。
    比對結果數十萬筆時不能逐筆讀進 Python：先在資料庫裡彙總到「主機×CVE」再到「主機×等級」；例外規則只和主機、CVE 有關，
    所以只讀出被例外的「主機×CVE」扣掉（每條規則符合哪些 CVE 只算一次；每個 CVE 都是例外的主機整台不列）"""
    minp = PRIO.get(Config.MIN_PRIORITY, 5)
    names = {n: p for p, n in PRIO.items()}                         # 0 → critical … 5 → ""
    rank = "CASE f.priority %s ELSE 5 END" % " ".join("WHEN '%s' THEN %d" % (p, n) for p, n in PRIO.items() if p)
    where = "WHERE h.active=1 AND f.resolved_at IS NULL AND %s <= %d" % (rank, minp)
    pairs = ("SELECT f.host_id, f.cve, MIN(%s) r, MAX(COALESCE(f.location, '')='running-kernel') rb "
             "FROM finding f JOIN host h ON h.id=f.host_id " % rank) + where
    out = {}
    with read_snapshot(con):                # 扣掉例外時才不會扣到沒算進去的
        _overview_counts(con, out, pairs, where, names, today)
    for hid in [h for h, ph in out.items() if not any(ph[p] for p in names.values())]:
        del out[hid]                        # 全部都是例外：和逐筆算一樣不列
    for ph in out.values():
        ph["reboot"] = ph["reboot"] > 0
    return out


_overview_cache = (None, None)      # (資料指紋, host_overview 的結果)：同一個程序裡的總覽共用
_overview_lock = threading.Lock()   # 沒有快取時只讓一個請求算，其他的等它的結果
_snapshots = threading.local()      # read_snapshot 開的交易：(連線, 開始時的 total_changes)


def _overview_key(con, today):
    """總覽數量依賴的資料：版本號 data_gen（比對結果、主機、例外規則會影響數量的改寫都會加一，見 db.TRIGGERS）＋
    epoch（建立資料庫時的亂數：換成另一份資料庫時不同；同一份的備份 epoch 相同，所以網頁執行中不要直接換資料庫檔，
    要先停容器，upgrade.sh 的回復就是這樣）、今天的日期（例外規則到期）、MIN_PRIORITY、DB_PATH。沒有 data_gen 時回傳 None（不快取）"""
    row = con.execute("SELECT gen, epoch FROM data_gen WHERE id=1").fetchone()
    if row is None or not row["epoch"]:
        return None
    return (Config.DB_PATH, row["epoch"], Config.MIN_PRIORITY, today), row["gen"]


def _clean_read(con):
    """這個連線看到的都是已送出的資料：沒有交易，或是 read_snapshot 開的、之後沒有寫入"""
    if not con.in_transaction:
        return True
    snap = getattr(_snapshots, "top", None)
    return bool(snap) and snap[0] is con and snap[1] == con.total_changes


def host_overview_cached(con):
    """host_overview，資料沒變時直接用上次的結果（回傳複本）。網頁裡的同步完成後 web.run_job 會先算好
    （從命令列同步時由網頁第一次開總覽時重算）。版本號和數量在同一個讀取交易裡取得，只有版本號完全相同才沿用；
    連線裡有還沒送出的寫入時直接算、不寫進快取。快取放最後算好的那一份（較舊快照算的蓋掉較新的時，下一個請求重算一次）"""
    global _overview_cache
    today = datetime.date.today().isoformat()
    cacheable = _clean_read(con)
    with read_snapshot(con):
        k = _overview_key(con, today) if cacheable else None
        if k is None:
            value = host_overview(con, today)
        else:
            cached_key, value = _overview_cache     # 一次取出（別的執行緒可能同時在換）
            if cached_key != k:
                with _overview_lock:
                    cached_key, value = _overview_cache
                    if cached_key != k:             # 等鎖的時候別人可能已經算好了
                        value = host_overview(con, today)
                        _overview_cache = (k, value)
    return {hid: dict(ph) for hid, ph in value.items()}


@contextlib.contextmanager
def read_snapshot(con):
    """讀取交易：裡面的查詢都看到同一份資料（同步可能同時在寫入）。呼叫端已經開了交易時沿用它"""
    if con.in_transaction:
        yield
        return
    con.execute("BEGIN")
    prev = getattr(_snapshots, "top", None)
    _snapshots.top = (con, con.total_changes)
    try:
        yield
    finally:
        _snapshots.top = prev
        con.rollback()                  # 只有讀取


def _overview_counts(con, out, pairs, where, names, today):
    """host_overview 的查詢（在同一個讀取交易裡）"""

    def slot(hid):
        ph = out.get(hid)
        if ph is None:
            ph = out[hid] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "": 0, "reboot": 0}
        return ph

    for hid, r, n, rb in con.execute("SELECT host_id, r, COUNT(*), SUM(rb) FROM (%s GROUP BY f.host_id, f.cve) GROUP BY host_id, r" % pairs):
        ph = slot(hid)
        ph[names[r]] += n
        ph["reboot"] += rb                  # 先算有執行中 kernel 的 CVE 數，扣掉例外後 > 0 才是需要重開機
    match = ExceptionMatcher(active_exceptions(con, today))
    if match.rules and out:
        hosts = con.execute("SELECT id, hostname, fqdn FROM host WHERE active=1").fetchall()
        groups = {}                         # 套用的規則 → 主機
        for h in hosts:
            rules = match.for_host(h["hostname"], h["fqdn"])
            if rules:
                groups.setdefault(tuple(id(e) for _, e in rules), (rules, []))[1].append(h["id"])
        if groups:
            cves = [r[0] for r in con.execute("SELECT DISTINCT f.cve FROM finding f JOIN host h ON h.id=f.host_id " + where)]
            upper = {}
            for c in cves:
                upper.setdefault(c.upper(), []).append(c)
            per_pattern = {}                # 同一個 CVE 樣式符合哪些 CVE 只算一次（全域規則＋每台各自的規則時，群組會很多）
            hit = {}                        # host_id → 被例外的 CVE
            for rules, hids in groups.values():
                cs = set()
                for rx, e in rules:
                    pat = e["cve"].upper()
                    if pat not in per_pattern:
                        if any(ch in pat for ch in "*?["):
                            per_pattern[pat] = {c for c in cves if rx.match(c.upper())}
                        else:               # 沒有萬用字元：直接查（fnmatch 對一般字串就是完全相同）
                            per_pattern[pat] = set(upper.get(pat, ()))
                    cs |= per_pattern[pat]
                for hid in hids:
                    if len(cs) == len(cves):    # 每個 CVE 都是例外（例如規則的 CVE 是 *）：整台不列，不必逐一讀出來扣
                        out.pop(hid, None)
                    elif cs:
                        hit[hid] = cs
            want = sorted({c for cs in hit.values() for c in cs})
            if want:
                for hid, cve, r, rb in con.execute(
                        pairs + " AND f.host_id IN (SELECT value FROM json_each(?)) AND f.cve IN (SELECT value FROM json_each(?)) "
                        "GROUP BY f.host_id, f.cve", (json.dumps(sorted(hit)), json.dumps(want))):
                    if cve in hit[hid] and hid in out:
                        ph = out[hid]
                        ph[names[r]] -= 1
                        ph["reboot"] -= rb


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
