"""輸出報表（季報表）：依 CVE 公開日期（OSV 的 published），列出 Ubuntu 官方對每個 CVE × 套件 × 版本的處理狀態

跟 cvehub 管理的主機無關（主機受影響情形見 impact.py）。

- 一列＝一個 CVE × 一個 source 套件；沒有任何相關套件的 CVE 也列一列（套件欄空白），CVE 數才會完整
- 狀態來自 Canonical VEX（vex_import.STATUSES，畫面與 Excel 用繁體中文）；還沒匯入 VEX 時退回 OSV，只分已修正／受影響
- ubuntu20 以 Ubuntu Pro（esm）為準（20.04 標準支援已結束）；ubuntu22／ubuntu24 以一般套件庫為準，只有 Pro 修正時標（Pro）
- 修正版本用 OSV 的（第一個修正版本）
- kernel 只留 linux 與 linux-hwe-*，其他 kernel 變體（aws、azure、gcp、oem、lowlatency…）不列；
  HWE 只留各版本最新的系列，以及主機上實際有裝的系列（停止支援的舊 HWE 永遠未修，列出來只會誤導）
- 統計：一個 CVE 在某版本有多個套件時，取最需要注意的狀態（vex_import.STATUSES 的順序）
"""
import datetime
import io

from .config import PRIO
from .sync import KERNEL_ABI, _kernel_source_by_series
from .vex_import import LABEL, LABEL_EN, RANK, STATUSES, UNRESOLVED, status_for

RELEASES = [("ubuntu20", "20.04"), ("ubuntu22", "22.04"), ("ubuntu24", "24.04")]
COLUMNS = ["cve_id", "priority", "published", "package", "ubuntu20", "ubuntu22", "ubuntu24", "description"]
HEADERS = {"cve_id": "CVE", "priority": "等級", "published": "公開日期", "package": "套件",
           "ubuntu20": "Ubuntu 20.04", "ubuntu22": "Ubuntu 22.04", "ubuntu24": "Ubuntu 24.04", "description": "說明"}
LEVELS = ["critical", "high", "medium", "low", "negligible"]
DESC_MAX = 1000                  # kernel CVE 的說明常是整段 commit message
STATUS_FILTERS = [("", "全部"), ("open", "未解決（待評估／受影響／修正中／延後修正／不修正）")] + \
                 [(c, zh) for c, _, zh, _ in STATUSES if c != "unknown"]
FILLS = {"needs-evaluation": "FFB3AD", "vulnerable": "FFD8A8", "vulnerable-wip": "FFE8A3", "deferred": "FFF1B8",
         "ignored": "E1E4E8", "unknown": "E1E4E8", "fixed": "D3F9D8", "not-affected": "F6F8FA", "not-in-release": "F6F8FA",
         "none": "FFFFFF"}
PRIO_FILLS = {"critical": "CF222E", "high": "FB8500", "medium": "FFF1B8", "low": "DDF4FF", "negligible": "EEEEEE"}


def kernel_variant(src):
    """linux 與 linux-hwe-* 以外的 kernel source（雲端、OEM、lowlatency…）；linux-firmware 不是 kernel"""
    return src.startswith("linux-") and not src.startswith("linux-hwe-") and src != "linux-firmware"


def is_kernel(src):
    return src == "linux" or src.startswith("linux-hwe-")


def _hwe_series(src):
    try:
        return tuple(int(x) for x in src[len("linux-hwe-"):].split("."))
    except ValueError:
        return ()


def _ecosystems(rel):
    """(主要, 備用)；20.04 只看 Pro"""
    if rel == "20.04":
        return "Ubuntu:Pro:20.04:LTS", None
    return "Ubuntu:%s:LTS" % rel, "Ubuntu:Pro:%s:LTS" % rel


def latest_hwe(con):
    """各版本 OSV 資料裡最新的 HWE 系列，例：{"22.04": "linux-hwe-6.8"}"""
    out = {}
    for col, rel in RELEASES:
        main, _ = _ecosystems(rel)
        srcs = [r[0] for r in con.execute("SELECT DISTINCT source FROM affected WHERE ecosystem=? AND source LIKE 'linux-hwe-%'", (main,))]
        if srcs:
            out[rel] = max(srcs, key=_hwe_series)
    return out


def _desc(cve, text):
    text = (text or "").strip()
    if len(text) <= DESC_MAX:
        return text
    return text[:DESC_MAX].rstrip() + "…（全文：https://ubuntu.com/security/%s）" % cve


def host_sources(con):
    """{host_id: (release, {source})}：用和比對相同的 binary→source 對應"""
    out = {}
    for h in con.execute("SELECT id, release FROM host WHERE active=1"):
        rel = h["release"]
        ecos = ["Ubuntu:%s:LTS" % rel, "Ubuntu:Pro:%s:LTS" % rel]
        names = [r["name"] for r in con.execute("SELECT name FROM host_package WHERE host_id=?", (h["id"],))]
        found, srcs = set(), set()
        for i in range(0, len(names), 500):
            chunk = names[i:i + 500]
            q = "SELECT binary, source FROM binmap WHERE ecosystem IN (%s) AND binary IN (%s)" % (
                ",".join("?" * len(ecos)), ",".join("?" * len(chunk)))
            for r in con.execute(q, ecos + chunk):
                found.add(r["binary"]); srcs.add(r["source"])
        for n in names:                  # 新版 kernel 還沒出現在 OSV 的 binary 清單時，用同系列推測
            if n not in found and KERNEL_ABI.match(n):
                for e in ecos:
                    s = _kernel_source_by_series(con, e, n)
                    if s:
                        srcs.add(s); break
        out[h["id"]] = (rel, srcs)
    return out


def cell_text(code, pro, fixed, release):
    t = "—" if code == "none" else LABEL.get(code, code)
    if code == "fixed":
        if pro and release != "20.04":
            t += "（Pro）"
        if fixed:
            t += " " + fixed
    return t


def osv_fixed(con, cves, releases):
    """{(cve, source, release): {"base": 修正版本或 "", "pro": ...}}；有列＝OSV 認定受影響"""
    ecos = {}
    for rel in releases:
        ecos["Ubuntu:%s:LTS" % rel] = (rel, "base")
        ecos["Ubuntu:Pro:%s:LTS" % rel] = (rel, "pro")
    out = {}
    for i in range(0, len(cves), 500):
        chunk = cves[i:i + 500]
        # +ecosystem：讓 SQLite 用 cve 索引（不加會改走 ecosystem 索引，慢約 90 倍）
        q = "SELECT ecosystem, source, cve, fixed FROM affected WHERE cve IN (%s) AND +ecosystem IN (%s)" % (
            ",".join("?" * len(chunk)), ",".join("?" * len(ecos)))
        for r in con.execute(q, chunk + list(ecos)):
            rel, ch = ecos[r["ecosystem"]]
            out.setdefault((r["cve"], r["source"], rel), {})[ch] = r["fixed"] or ""
    return out


def _osv_only_status(fx, release):
    """沒有 VEX 時由 OSV 推：有修正版本＝fixed，否則 vulnerable"""
    if not fx:
        return "none", False, ""
    main, other = ("pro", "base") if release == "20.04" else ("base", "pro")
    if fx.get(main):
        return "fixed", main == "pro", fx[main]
    if fx.get(other):
        return "fixed", other == "pro", fx[other]
    return "vulnerable", False, ""


def resolve(vex_row, fx, release, have_vex):
    """一格的 (狀態代碼, 是否靠 Pro, 修正版本)"""
    if have_vex and vex_row is not None:
        return status_for(vex_row, release, fx)
    return _osv_only_status(fx, release)


def build(con, date_from, date_to, min_priority="medium", status_filter="", have_vex=True):
    """回傳 (rows, summary)。date_from／date_to 是 YYYY-MM-DD（含頭尾）"""
    maxp = PRIO.get(min_priority, 2)
    levels = [lv for lv in LEVELS if PRIO[lv] <= maxp]
    rels = [rel for _, rel in RELEASES]
    vulns = {r["cve"]: r for r in con.execute(
        "SELECT cve, priority, details, published FROM vuln WHERE substr(published,1,10) BETWEEN ? AND ? "
        "AND priority IN (%s)" % ",".join("?" * len(levels)), [date_from, date_to] + levels)}
    cves = list(vulns)
    fixed = osv_fixed(con, cves, rels)
    vex = {}
    if have_vex:
        for i in range(0, len(cves), 500):
            chunk = cves[i:i + 500]
            q = "SELECT * FROM vex_status WHERE cve IN (%s) AND release IN (%s)" % (
                ",".join("?" * len(chunk)), ",".join("?" * len(rels)))
            for r in con.execute(q, chunk + rels):
                vex[(r["cve"], r["source"], r["release"])] = r
    keys = {(c, s) for (c, s, _) in fixed} | {(c, s) for (c, s, _) in vex}
    keep_hwe = set(latest_hwe(con).values()) | {s for _, srcs in host_sources(con).values() for s in srcs if s.startswith("linux-hwe-")}
    keys = {(c, s) for (c, s) in keys if not kernel_variant(s) and not (s.startswith("linux-hwe-") and s not in keep_hwe)}
    with_rows = {c for c, _ in keys}
    keys |= {(c, "") for c in cves if c not in with_rows}      # 沒有相關套件的 CVE 也列

    rows = []
    for cve, src in keys:
        v = vulns[cve]
        row = {"cve_id": cve, "priority": v["priority"], "published": (v["published"] or "")[:10],
               "description": _desc(cve, v["details"]), "package": src, "codes": {}}
        for col, rel in RELEASES:
            code, pro, fx = resolve(vex.get((cve, src, rel)), fixed.get((cve, src, rel)), rel, have_vex) if src else ("none", False, "")
            row["codes"][col] = code
            row[col] = cell_text(code, pro, fx, rel)
        rows.append(row)

    summary = _summary(rows, levels)
    if status_filter == "open":
        rows = [r for r in rows if any(c in UNRESOLVED for c in r["codes"].values())]
    elif status_filter:
        rows = [r for r in rows if status_filter in r["codes"].values()]
    rows.sort(key=lambda x: (PRIO.get(x["priority"], 5), x["cve_id"], x["package"]))
    return rows, summary


def _summary(rows, levels):
    """每個等級：CVE 數、kernel CVE 數；每個版本：以 CVE 計的狀態分布（多個套件取最需要注意的）"""
    worst = {}                                  # (cve, col) -> code
    prio, kernel = {}, set()
    for r in rows:
        prio[r["cve_id"]] = r["priority"]
        if is_kernel(r["package"]):
            kernel.add(r["cve_id"])
        for col, code in r["codes"].items():
            k = (r["cve_id"], col)
            if k not in worst or RANK[code] < RANK[worst[k]]:
                worst[k] = code
    by_level = {}
    for lv in levels:
        mine = [c for c, p in prio.items() if p == lv]
        s = {"cves": len(mine), "kernel": len([c for c in mine if c in kernel])}
        for col, _ in RELEASES:
            cnt = {code: 0 for code, _, _, _ in STATUSES}
            for c in mine:
                cnt[worst.get((c, col), "none")] += 1
            s[col] = cnt
        by_level[lv] = s
    used = [code for code, _, _, _ in STATUSES
            if code != "unknown" or any(by_level[lv][col]["unknown"] for lv in levels for col, _ in RELEASES)]
    return {"levels": levels, "by_level": by_level, "statuses": used, "total": len(prio), "total_kernel": len(kernel)}


def sort_rows(rows, key, desc=False):
    """依欄位排序（穩定排序；等級依嚴重度、版本欄依狀態順序、其他依字串）"""
    if key == "priority":
        k = lambda x: PRIO.get(x["priority"], 5)
    elif key in dict(RELEASES):
        k = lambda x: (RANK.get(x["codes"][key], 99), x[key])
    else:
        k = lambda x: str(x[key] or "").lower()
    rows.sort(key=k, reverse=desc)


def to_xlsx(rows, summary, date_from, date_to, min_priority, osv_date=None, vex_date=None, status_filter=""):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
    wb = Workbook()
    ws = wb.active
    ws.title = "統計"
    info = [("報表區間（CVE 公開日期）", "%s ～ %s" % (date_from, date_to)),
            ("等級", "、".join(summary["levels"])),
            ("狀態篩選（只影響明細）", dict(STATUS_FILTERS).get(status_filter, status_filter) if status_filter else "全部"),
            ("OSV 資料日期", osv_date or ""),
            ("VEX 資料日期（官方狀態）", vex_date or "未匯入：狀態只分「已修正／受影響」"),
            ("產生時間", datetime.datetime.now().strftime("%Y-%m-%d %H:%M")),
            ("說明", "跟主機無關，是 Ubuntu 官方對每個 CVE 的處理狀態。CVE 數以 CVE 編號計；"
             "一個 CVE 在某版本有多個套件時，以最需要注意的狀態計（順序見「狀態說明」）。"
             "20.04 以 Ubuntu Pro 為準；22.04／24.04 只有 Pro 修正時標（Pro）。「—」＝官方資料沒有這個套件／版本的紀錄。"
             "kernel 只列 linux、各版本最新的 HWE 與主機上有裝的 HWE。")]
    for k, v in info:
        ws.append([k, v])
    ws.append([])
    head = ["等級", "版本", "CVE 數"] + [LABEL[c] for c in summary["statuses"]]
    ws.append(head)
    for c in ws[ws.max_row]:
        c.font = Font(bold=True)
    for i, code in enumerate(summary["statuses"]):
        ws.cell(ws.max_row, 4 + i).fill = PatternFill("solid", fgColor=FILLS[code])
    for lv in summary["levels"]:
        s = summary["by_level"][lv]
        for col, rel in RELEASES:
            ws.append([lv, "Ubuntu " + rel, s["cves"]] + [s[col][c] for c in summary["statuses"]])
            ws.cell(ws.max_row, 1).fill = PatternFill("solid", fgColor=PRIO_FILLS[lv])
    ws.append(["合計 CVE", "", summary["total"]])
    ws.cell(ws.max_row, 1).font = Font(bold=True)
    ws.append(["其中 kernel", "", summary["total_kernel"]])
    ws.column_dimensions["A"].width = 26
    ws.column_dimensions["B"].width = 14
    for i in range(3, len(head) + 1):
        ws.column_dimensions[get_column_letter(i)].width = 16

    lg = wb.create_sheet("狀態說明")
    lg.append(["狀態", "說明", "Ubuntu 官方名稱"])
    for c in lg[1]:
        c.font = Font(bold=True)
    for code, en, zh, desc in STATUSES:
        lg.append([zh, desc, en])
        lg.cell(lg.max_row, 1).fill = PatternFill("solid", fgColor=FILLS[code])
    lg.column_dimensions["A"].width = 16
    lg.column_dimensions["B"].width = 60
    lg.column_dimensions["C"].width = 30

    d = wb.create_sheet("明細")
    d.append([HEADERS.get(c, c) for c in COLUMNS])
    for c in d[1]:
        c.font = Font(bold=True)
    fills = {k: PatternFill("solid", fgColor=v) for k, v in list(FILLS.items()) + [("p-" + k, v) for k, v in PRIO_FILLS.items()]}
    white = PatternFill("solid", fgColor="FFFFFF")
    wrap = Alignment(wrap_text=True, vertical="top")
    from .report import safe_cell
    for n, r in enumerate(rows, start=2):          # 自己記列號：d.max_row 每次都要掃全表，幾萬列會很慢
        d.append([safe_cell(r[c]) for c in COLUMNS])     # OSV 說明是外部資料：防公式注入
        d.cell(n, 2).fill = fills.get("p-" + (r["priority"] or ""), white)
        for i, (col, _) in enumerate(RELEASES):
            d.cell(n, 5 + i).fill = fills.get(r["codes"][col], white)
        d.cell(n, 8).alignment = wrap
    widths = {"A": 17, "B": 10, "C": 11, "D": 22, "E": 30, "F": 30, "G": 30, "H": 80}
    for k, w in widths.items():
        d.column_dimensions[k].width = w
    d.freeze_panes = "A2"
    d.auto_filter.ref = d.dimensions
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def filename(date_from, date_to):
    return "cve-quarterly-%s-%s.xlsx" % (date_from.replace("-", ""), date_to.replace("-", ""))


def valid_date(s):
    datetime.date.fromisoformat(s)
    return s
