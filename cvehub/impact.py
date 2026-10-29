"""受影響主機：哪些 CVE 影響哪些主機

主機上的套件來自 Landscape；一台主機對一個 CVE × source 套件的狀態：
- 待更新：已有修正版本、主機還沒更新（比對結果 finding 未解決；含需重開機）
- 尚無修正：主機有裝這個套件，官方狀態是 Needs evaluation／Vulnerable／work in progress／deferred／Ignored（VEX）
- 已修正：曾經待更新、現在已更新（finding 已解決）
- 不受影響：主機有裝這個套件，但官方狀態是 Fixed（且主機已是修正版本）、Not affected 或 Not in release
"""
from .config import PRIO, Config
from .kernel import kernel_variant
from .period import cell_text, host_sources, resolve
from .sync import active_exceptions, excepted
from .vex_import import LABEL, RANK, UNRESOLVED, status_for

STATES = [("pending", "待更新"), ("nofix", "尚無修正"), ("fixed", "已修正"), ("ok", "不受影響")]
STATE_LABEL = dict(STATES)
COLUMNS = ["cve", "priority", "published", "package", "host_count", "pending_n", "nofix_n", "official", "pending_hosts", "nofix_hosts"]
HEADERS = {"published": "公開日期", "host_count": "受影響主機數", "pending_n": "待更新台數", "nofix_n": "尚無修正台數",
           "official": "官方狀態", "pending_hosts": "待更新主機", "nofix_hosts": "尚無修正主機"}
SAMPLE = 3                      # 清單頁每格最多列幾台主機（其餘看 CVE 頁；CSV 列全部）


def _cve_filter(min_priority, date_from, date_to, alias="u"):
    """vuln 的等級／公開日期條件（SQL 片段, 參數）"""
    maxp = PRIO.get(min_priority, 2)
    levels = [lv for lv, p in PRIO.items() if lv and p <= maxp]
    sql = " AND %s.priority IN (%s)" % (alias, ",".join("?" * len(levels)))
    args = list(levels)
    if date_from:
        sql += " AND substr(%s.published,1,10) >= ?" % alias
        args.append(date_from)
    if date_to:
        sql += " AND substr(%s.published,1,10) <= ?" % alias
        args.append(date_to)
    return sql, args


def affected(con, min_priority="medium", date_from=None, date_to=None, host=None, cve=None, state=""):
    """每個 (CVE, 套件) 一列：待更新／尚無修正的主機數與部分主機名稱。state：""｜pending｜nofix

    主機多（數百台）時：尚無修正每個版本只查一次（所有主機的套件聯集），主機用 id 記錄，名稱只在輸出時展開。"""
    hosts = {h["id"]: h["hostname"] for h in con.execute("SELECT id, hostname FROM host WHERE active=1")}
    if host:
        hosts = {k: n for k, n in hosts.items() if host.lower() in n.lower()}
    exc = active_exceptions(con)
    fsql, fargs = _cve_filter(min_priority, date_from, date_to)
    hits = {}            # (cve, source) -> {"pending": {hid: 說明}, "nofix": [hid], "codes": set(), "prio", "pub"}

    def slot(c, src, prio, pub):
        return hits.setdefault((c, src), {"pending": {}, "nofix": [], "codes": set(), "prio": prio or "", "pub": (pub or "")[:10]})

    pending = set()
    if state in ("", "pending"):
        q = ("SELECT f.*, u.priority vprio, u.published FROM finding f JOIN vuln u ON u.cve=f.cve "
             "WHERE f.resolved_at IS NULL AND f.status IN ('fix-available','fix-in-pro')" + fsql)
        args = list(fargs)
        if cve:
            q += " AND f.cve=?"
            args.append(cve)
        for f in con.execute(q, args):
            if f["host_id"] not in hosts:
                continue
            src = f["source"] or f["package"]
            pending.add((f["host_id"], f["cve"], src))
            note = "%s→%s %s" % (f["running"] or f["installed"], f["fixed"], f["action"])
            e = excepted(exc, hosts[f["host_id"]], f["cve"]) if exc else None
            if e:
                note += "（例外：%s）" % e["reason"]
            slot(f["cve"], src, f["vprio"], f["published"])["pending"][f["host_id"]] = note
    if state in ("", "nofix"):
        by_rel = {}                                   # release -> {source: [host_id]}
        for hid, (rel, srcs) in host_sources(con).items():
            if hid in hosts:
                for src in srcs:
                    by_rel.setdefault(rel, {}).setdefault(src, []).append(hid)
        un = ",".join("?" * len(UNRESOLVED))
        for rel, srcmap in by_rel.items():
            srcs = sorted(srcmap)
            for i in range(0, len(srcs), 500):
                chunk = srcs[i:i + 500]
                q = ("SELECT v.*, u.priority vprio, u.published FROM vex_status v JOIN vuln u ON u.cve=v.cve "
                     "WHERE v.release=? AND v.source IN (%s) AND (v.base_status IN (%s) OR v.pro_status IN (%s))" % (
                         ",".join("?" * len(chunk)), un, un)) + fsql
                args = [rel] + chunk + list(UNRESOLVED) * 2 + fargs
                if cve:
                    q += " AND v.cve=?"
                    args.append(cve)
                for r in con.execute(q, args):
                    code, _, _ = status_for(r, rel)
                    if code not in UNRESOLVED:
                        continue
                    g = None
                    for hid in srcmap[r["source"]]:
                        if (hid, r["cve"], r["source"]) in pending:
                            continue
                        g = g or slot(r["cve"], r["source"], r["vprio"], r["published"])
                        g["nofix"].append(hid)
                    if g:
                        g["codes"].add(code)
    rows = []
    for (c, src), g in hits.items():
        pend = sorted(g["pending"].items(), key=lambda kv: hosts[kv[0]])
        nofix = sorted(hosts[h] for h in set(g["nofix"]))
        rows.append({"cve": c, "priority": g["prio"], "published": g["pub"], "package": src,
                     "pending_n": len(pend), "nofix_n": len(nofix),
                     "host_count": len({h for h, _ in pend} | set(g["nofix"])),
                     "pending_sample": ["%s（%s）" % (hosts[h], n) for h, n in pend[:SAMPLE]],
                     "nofix_sample": nofix[:SAMPLE],
                     "pending_hosts": "; ".join("%s（%s）" % (hosts[h], n) for h, n in pend),
                     "nofix_hosts": "; ".join(nofix),
                     "official": "、".join(LABEL[x] for x in sorted(g["codes"], key=RANK.get)),
                     "codes": g["codes"], "needs_eval": "needs-evaluation" in g["codes"]})
    rows.sort(key=lambda x: (PRIO.get(x["priority"], 5), -x["host_count"], x["cve"], x["package"]))
    return rows


def cve_detail(con, cve):
    """一個 CVE：官方狀態表（套件 × 版本）與每台主機的狀態"""
    rels = Config.UBUNTU_RELEASES
    vex = {(r["source"], r["release"]): r for r in con.execute("SELECT * FROM vex_status WHERE cve=?", (cve,))}
    osv = {}
    for r in con.execute("SELECT ecosystem, source, fixed FROM affected WHERE cve=?", (cve,)):
        parts = r["ecosystem"].split(":")
        rel, ch = (parts[2], "pro") if parts[1] == "Pro" else (parts[1], "base")
        osv.setdefault((r["source"], rel), {})[ch] = r["fixed"] or ""
    have_vex = bool(con.execute("SELECT 1 FROM vex_import WHERE active=1").fetchone())
    hs = host_sources(con)
    installed = {s for _, srcs in hs.values() for s in srcs}
    official = {}
    for src in sorted({s for s, _ in vex} | {s for s, _ in osv}):
        if kernel_variant(src) and src not in installed:
            continue                     # 雲端／OEM kernel 變體：主機沒裝就不列（同輸出報表；VEX 也預設不匯入）
        cells = {}
        for rel in rels:
            code, pro, fx = resolve(vex.get((src, rel)), osv.get((src, rel)), rel, have_vex)
            cells[rel] = (code, cell_text(code, pro, fx, rel))
        if any(c != "none" for c, _ in cells.values()):
            official[src] = cells
    exc = active_exceptions(con)
    findings = {}
    for f in con.execute("SELECT * FROM finding WHERE cve=? ORDER BY resolved_at IS NULL DESC, first_seen", (cve,)):
        findings.setdefault((f["host_id"], f["source"] or f["package"]), []).append(f)
    hosts = []
    for hid, (rel, srcs) in hs.items():
        h = con.execute("SELECT * FROM host WHERE id=?", (hid,)).fetchone()
        for src in sorted(srcs & (set(official) | {s for (x, s) in findings if x == hid})):
            code, text = official.get(src, {}).get(rel, ("none", "—"))
            fs = findings.get((hid, src), [])
            open_f = [f for f in fs if not f["resolved_at"]]
            if open_f and open_f[0]["status"] in ("fix-available", "fix-in-pro"):
                st = "pending"
            elif code in UNRESOLVED:
                st = "nofix"
            elif fs:
                st = "fixed"
            else:
                st = "ok"
            f = (open_f or fs or [None])[0]
            e = excepted(exc, h["hostname"], cve)
            hosts.append({"hostname": h["hostname"], "host_id": hid, "release": rel, "package": src, "state": st,
                          "state_label": STATE_LABEL[st], "official": text, "official_code": code,
                          "installed": f and (f["running"] or f["installed"]), "fixed": f and f["fixed"],
                          "action": f and f["action"], "first_seen": f and f["first_seen"],
                          "resolved_at": f and f["resolved_at"], "exception": e["reason"] if e else ""})
    order = {k: i for i, (k, _) in enumerate(STATES)}
    hosts.sort(key=lambda x: (order[x["state"]], x["hostname"], x["package"]))
    return official, hosts
