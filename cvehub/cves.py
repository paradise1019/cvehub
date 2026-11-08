"""歷年弱點：所有 CVE 的清單（呈現方式參考 ubuntu.com/security/cves），和主機有沒有裝無關

  篩選：CVE 編號或描述關鍵字、套件、公開年份（頁籤）、等級、Ubuntu 版本（這個版本有相關套件的）、整體狀態、只看主機有裝的套件
  每個 CVE 的整體狀態（overall）依「套件 × 版本」各格的官方狀態（cells()：和 CVE 頁同一套 resolve 與相關套件的判斷；
  輸出報表另外只看最新的 HWE kernel、不列雲端 kernel 變體）：
    受影響的都修正了＝已修正；有修正也有未解決＝部分有修正（x／y）；都不受影響＝不受影響；
    沒有任何相關格＝版本無此套件；其他＝最需要注意的那個狀態（待評估、受影響、修正中…）
  雲端／OEM kernel 變體（linux-aws…）主機有裝才算（同 CVE 頁）
  版本與整體狀態的篩選用事先算好的 cve_status（build_status：匯入 OSV／VEX 後、主機有裝的 kernel 變體改變後、啟動時重算）；
  還沒算好時這兩個篩選暫不套用，畫面提示「整理中」
"""
import contextlib
import fcntl
import json
import logging
import os
import re
import time

from .config import Config
from .kernel import kernel_variant
from .period import cell_text, resolve
from .sync import KERNEL_ABI, _kernel_source_by_series
from .vex_import import LABEL, RANK, UNRESOLVED

log = logging.getLogger(__name__)
STATUS_FORMAT = 1                   # 整體狀態表的算法版本：改了算法就加一，啟動時會重算
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
LEVELS = ["critical", "high", "medium", "low", "negligible"]
PER_PAGE = 50
EXCERPT = 240
UNRELATED = ("none", "not-in-release")
# 整體狀態篩選：值 → 說明；STATUS_SQL＝cve_status 表上的條件
OVERALL = {
    "open": "有未解決",
    "fixed": "全部已修正",
    "partial": "部分有修正",
    "not-affected": "不受影響或版本無此套件",
}
STATUS_SQL = {"open": "unresolved > 0", "fixed": "code='fixed'", "partial": "code='partial'",
              "not-affected": "code IN ('not-affected','not-in-release')"}


# ---------------------------------------------------------------- 狀態（各格、整體）

def _ecos(releases):
    out = {}
    for rel in releases:
        out["Ubuntu:%s:LTS" % rel] = (rel, "base")
        out["Ubuntu:Pro:%s:LTS" % rel] = (rel, "pro")
    return out


def load_status_data(con, releases, cves=None):
    """(OSV 修正版本 {(cve, src, rel): {"base"/"pro": 版本}}, VEX {(cve, src, rel): 列}, have_vex, {cve: {source}})；cves=None＝全部"""
    have_vex = bool(con.execute("SELECT 1 FROM vex_import WHERE active=1").fetchone())
    ecos = _ecos(releases)
    fixed, vex = {}, {}
    chunks = [None] if cves is None else [cves[i:i + 500] for i in range(0, len(cves), 500)]
    for chunk in chunks:
        if chunk is not None and not chunk:
            continue
        cond, args = ("", []) if chunk is None else (" AND cve IN (%s)" % ",".join("?" * len(chunk)), list(chunk))
        # +ecosystem：有 cve 條件時讓 SQLite 用 cve 索引
        for r in con.execute("SELECT ecosystem, source, cve, fixed FROM affected WHERE %secosystem IN (%s)%s"
                             % ("+" if chunk else "", ",".join("?" * len(ecos)), cond), list(ecos) + args):
            rel, ch = ecos[r[0]]
            fixed.setdefault((r[2], r[1], rel), {})[ch] = r[3] or ""
        if have_vex:
            for r in con.execute("SELECT cve, source, release, base_status, pro_status FROM vex_status WHERE release IN (%s)%s"
                                 % (",".join("?" * len(releases)), cond), list(releases) + args):
                vex[(r[0], r[1], r[2])] = {"base_status": r[3], "pro_status": r[4]}
    by_cve = {}
    for (c, s, _) in list(fixed) + list(vex):
        by_cve.setdefault(c, set()).add(s)
    return fixed, vex, have_vex, by_cve


def cells(cve, sources, releases, fixed, vex, have_vex, variants):
    """一個 CVE 的相關套件與各格：([套件], {(src, rel): (代碼, 文字)})；variants＝要算的 kernel 變體（主機有裝的，其他變體不算）
    相關套件＝有任何一格不是「無紀錄」（同 CVE 頁；版本無此套件也列，整體狀態不算它）"""
    pkgs, out = [], {}
    for src in sorted(sources):
        if kernel_variant(src) and src not in variants:
            continue
        row = {}
        for rel in releases:
            code, pro, fx = resolve(vex.get((cve, src, rel)), fixed.get((cve, src, rel)), rel, have_vex)
            row[rel] = (code, cell_text(code, pro, fx, rel))
        if any(c != "none" for c, _ in row.values()):
            pkgs.append(src)
            out.update({(src, rel): v for rel, v in row.items()})
    return pkgs, out


def overall(codes):
    """各格的狀態代碼 → {"code", "label", "fixed", "total", "unresolved"}（不相關的格不算）"""
    rel = [c for c in codes if c not in UNRELATED]
    n_fixed = sum(c == "fixed" for c in rel)
    unresolved = [c for c in rel if c in UNRESOLVED]
    o = {"fixed": n_fixed, "total": len(rel), "unresolved": len(unresolved)}
    if not rel:
        return dict(o, code="not-in-release", label=LABEL["not-in-release"])
    if n_fixed and unresolved:
        return dict(o, code="partial", label="部分有修正（%d／%d）" % (n_fixed, len(rel)))
    if n_fixed and all(c in ("fixed", "not-affected") for c in rel):     # 受影響的都修正了，其他不受影響
        return dict(o, code="fixed", label=LABEL["fixed"])
    if all(c == "not-affected" for c in rel):
        return dict(o, code="not-affected", label=LABEL["not-affected"])
    worst = min(unresolved or [c for c in rel if c != "fixed"] or rel, key=lambda c: RANK.get(c, 99))
    return dict(o, code=worst, label=LABEL.get(worst, worst))


def details(con, cves, releases, variants):
    """{cve: {"packages", "cells", "overall"}}：這一頁要顯示的"""
    fixed, vex, have_vex, by_cve = load_status_data(con, releases, cves)
    out = {}
    for c in cves:
        pkgs, cs = cells(c, by_cve.get(c, ()), releases, fixed, vex, have_vex, variants)
        out[c] = {"packages": pkgs, "cells": cs, "overall": overall([v[0] for v in cs.values()])}
    return out


# ---------------------------------------------------------------- 事先算好的整體狀態表

def installed_sources(con):
    """主機（啟用中）有裝的 source 套件：和 period.host_sources 相同的對應（binary→source，新版 kernel 還沒在 binmap 時用同系列推測），
    但用一個查詢做完（不逐台主機查）"""
    out = {r[0] for r in con.execute(
        "SELECT DISTINCT b.source FROM host h JOIN host_package p ON p.host_id=h.id "
        "JOIN binmap b ON b.binary=p.name AND b.ecosystem IN ('Ubuntu:' || h.release || ':LTS', 'Ubuntu:Pro:' || h.release || ':LTS') "
        "WHERE h.active=1")}
    for rel, name in con.execute(
            "SELECT DISTINCT h.release, p.name FROM host h JOIN host_package p ON p.host_id=h.id "
            "WHERE h.active=1 AND p.name LIKE 'linux-%' AND NOT EXISTS (SELECT 1 FROM binmap b WHERE b.binary=p.name "
            "AND b.ecosystem IN ('Ubuntu:' || h.release || ':LTS', 'Ubuntu:Pro:' || h.release || ':LTS'))"):
        if KERNEL_ABI.match(name):
            for eco in ("Ubuntu:%s:LTS" % rel, "Ubuntu:Pro:%s:LTS" % rel):
                s = _kernel_source_by_series(con, eco, name)
                if s:
                    out.add(s)
                    break
    return out


def installed_variants(con):
    """主機有裝的 kernel 變體"""
    return sorted(s for s in installed_sources(con) if kernel_variant(s))


def _status_key(con, variants):
    osv = con.execute("SELECT id FROM osv_import WHERE active=1").fetchone()
    vex = con.execute("SELECT id FROM vex_import WHERE active=1").fetchone()
    return json.dumps([osv[0] if osv else None, vex[0] if vex else None, list(Config.UBUNTU_RELEASES), variants, STATUS_FORMAT])


def _meta(con):
    return con.execute("SELECT key, variants FROM cve_status_meta WHERE id=1").fetchone()


def ready(con):
    """狀態表和目前的 OSV／VEX、版本設定相符（主機的 kernel 變體在同步時檢查）"""
    m = _meta(con)
    return m is not None and m["key"] == _status_key(con, json.loads(m["variants"] or "[]"))


@contextlib.contextmanager
def _build_lock(blocking):
    f = open(os.path.join(os.path.dirname(os.path.abspath(Config.DB_PATH)), ".cvehub-cvestatus.lock"), "a")
    try:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
    finally:
        f.close()


def build_status(con, force=False, blocking=True):
    """算好每個 CVE 的整體狀態（全部版本＋各版本）存進 cve_status；資料沒變就不重算。回傳是否重算了
    同步（匯入 OSV／VEX、主機改變後）與指令列匯入時呼叫（blocking：等別人算完再判斷），啟動時在背景呼叫（不等）"""
    with _build_lock(blocking) as ok:
        if not ok:
            return False
        variants = installed_variants(con)
        key = _status_key(con, variants)
        m = _meta(con)
        if not force and m is not None and m["key"] == key:
            return False
        t0 = time.time()
        releases = list(Config.UBUNTU_RELEASES)
        fixed, vex, have_vex, by_cve = load_status_data(con, releases)
        rows = []
        for (cve,) in con.execute("SELECT cve FROM vuln").fetchall():
            pkgs, cs = cells(cve, by_cve.get(cve, ()), releases, fixed, vex, have_vex, set(variants))
            scopes = [("all", [v[0] for v in cs.values()])] + [(rel, [cs[(s, rel)][0] for s in pkgs]) for rel in releases]
            for scope, codes in scopes:
                o = overall(codes)
                rows.append((cve, scope, o["code"], o["fixed"], o["total"], o["unresolved"], len(pkgs)))
        with con:
            con.execute("DELETE FROM cve_status")
            con.executemany("INSERT INTO cve_status(cve,scope,code,fixed,total,unresolved,packages) VALUES (?,?,?,?,?,?,?)", rows)
            con.execute("INSERT OR REPLACE INTO cve_status_meta(id,key,variants,built_at) VALUES (1,?,?,datetime('now'))",
                        (key, json.dumps(variants)))
        log.info("歷年弱點：整體狀態整理完成（CVE %d，%.0f 秒）", len(rows) // (len(releases) + 1), time.time() - t0)
        return True


def known_variants(con):
    """畫面用的主機 kernel 變體：狀態表記下的（不必每次查全部主機的套件）；還沒算過時才現查"""
    m = _meta(con)
    return set(json.loads(m["variants"] or "[]")) if m is not None else set(installed_variants(con))


# ---------------------------------------------------------------- 搜尋


def _where(q=None, year=None, priority=None, release=None, sources=None, package=None, status=None, table=False):
    """vuln（別名 v）的篩選條件；回傳 (SQL, 參數)。release／status 只在狀態表算好（table）時套用"""
    sql, args = ["1"], []
    q = (q or "").strip()
    if q:
        if CVE_ID.match(q):
            sql.append("v.cve=?")
            args.append(q.upper())
        else:
            sql.append("(v.cve LIKE ? OR v.details LIKE ?)")
            args += ["%" + q + "%"] * 2
    if year:
        sql.append("substr(v.published,1,4)=?")
        args.append(year)
    if priority:
        sql.append("v.priority=?")
        args.append(priority)
    if table and (release or status in STATUS_SQL):
        cond = ["scope=?"] + (["code != 'not-in-release'"] if release else []) + ([STATUS_SQL[status]] if status in STATUS_SQL else [])
        sql.append("v.cve IN (SELECT cve FROM cve_status WHERE %s)" % " AND ".join(cond))
        args.append(release or "all")
    rels = list(Config.UBUNTU_RELEASES)
    ecos = list(_ecos(rels))
    in_rel = "release IN (%s)" % ",".join("?" * len(rels))
    in_eco = "ecosystem IN (%s)" % ",".join("?" * len(ecos))
    if package:                 # source 套件名稱（完全相同；只看設定的版本，和畫面一致）
        sql.append("v.cve IN (SELECT cve FROM vex_status WHERE source=? AND %s UNION SELECT cve FROM affected WHERE %s AND source=?)"
                   % (in_rel, in_eco))
        args += [package] + rels + ecos + [package]
    if sources is not None:     # 主機有裝的套件（先找出這些套件的 CVE，再比對；逐筆 EXISTS 太慢）
        js = json.dumps(sorted(sources))
        sql.append("v.cve IN (SELECT cve FROM vex_status WHERE source IN (SELECT value FROM json_each(?)) AND %s "
                   "UNION SELECT cve FROM affected WHERE %s AND source IN (SELECT value FROM json_each(?)))" % (in_rel, in_eco))
        args += [js] + rels + ecos + [js]
    return " AND ".join(sql), args


def years(con, **f):
    """[(年份, 筆數)]（新的在前）；f＝年份以外的篩選（含狀態，數字和列表一致）"""
    where, args = _where(**dict(f, year=None))
    return [(r[0], r[1]) for r in con.execute(
        "SELECT substr(v.published,1,4) y, COUNT(*) FROM vuln v WHERE %s AND v.published IS NOT NULL AND v.published != '' "
        "GROUP BY y ORDER BY y DESC" % where, args)]


def search(con, q=None, year=None, priority=None, release=None, status=None, installed_only=False, package=None,
           page=1, per_page=PER_PAGE):
    """回傳 {"rows", "total", "page", "pages", "years", "have_vex", "status_ready"}；rows 依公開日期新的在前"""
    releases = [release] if release else list(Config.UBUNTU_RELEASES)
    table = ready(con)
    f = {"q": q, "priority": priority, "release": release, "status": status, "table": table,
         "sources": installed_sources(con) if installed_only else None, "package": (package or "").strip() or None}
    where, args = _where(year=year, **f)
    order = "ORDER BY v.published DESC, length(v.cve) DESC, v.cve DESC"
    total = con.execute("SELECT COUNT(*) FROM vuln v WHERE %s" % where, args).fetchone()[0]
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(max(1, page), pages)
    vul = con.execute("SELECT v.cve, v.priority, v.cvss, v.published, v.details FROM vuln v WHERE %s %s LIMIT ? OFFSET ?"
                      % (where, order), args + [per_page, (page - 1) * per_page]).fetchall()
    ids = [r["cve"] for r in vul]
    show = known_variants(con) | ({f["package"]} if f["package"] else set())    # 查的套件一定顯示（即使是主機沒裝的變體）
    info = details(con, ids, releases, show)
    hosts = {}
    if ids:                     # 這頁的 CVE 在受管主機上：待更新（已有修正版本、還沒更新）的台數，和 CVE 頁的「待更新」相同
        for r in con.execute("SELECT f.cve, COUNT(DISTINCT f.host_id) FROM finding f JOIN host h ON h.id=f.host_id "
                             "WHERE h.active=1 AND f.resolved_at IS NULL AND f.status IN ('fix-available','fix-in-pro') "
                             "AND f.cve IN (SELECT value FROM json_each(?)) GROUP BY f.cve", (json.dumps(ids),)):
            hosts[r[0]] = r[1]
    rows = []
    for v in vul:
        d = info[v["cve"]]
        text = " ".join((v["details"] or "").split())
        rows.append({"cve": v["cve"], "priority": v["priority"] or "", "cvss": v["cvss"], "published": (v["published"] or "")[:10],
                     "excerpt": text[:EXCERPT] + ("…" if len(text) > EXCERPT else ""), "packages": d["packages"],
                     "overall": d["overall"], "pending_hosts": hosts.get(v["cve"], 0)})
    have_vex = bool(con.execute("SELECT 1 FROM vex_import WHERE active=1").fetchone())
    return {"rows": rows, "total": total, "page": page, "pages": pages, "years": years(con, **f), "have_vex": have_vex,
            "status_ready": table}


def not_found_notice(con, q):
    """搜尋的是 CVE 編號、資料裡又沒有時的說明（資料日期與 Ubuntu 官網連結）；不是這種情況回傳 None"""
    q = (q or "").strip().upper()
    if not CVE_ID.match(q) or con.execute("SELECT 1 FROM vuln WHERE cve=?", (q,)).fetchone():
        return None
    osv = con.execute("SELECT file_mtime FROM osv_import WHERE active=1").fetchone()
    vex = con.execute("SELECT file_mtime FROM vex_import WHERE active=1").fetchone()
    return {"cve": q, "osv_date": osv[0] if osv else None, "vex_date": vex[0] if vex else None,
            "url": "https://ubuntu.com/security/" + q}
