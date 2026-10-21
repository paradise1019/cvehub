"""同步主機與套件、套用 kernel 資訊、比對 CVE、更新歷史"""
import datetime
import fnmatch
import json
import logging
import re

from . import osv_import, vex_import
from .config import Config
from .sources import Landscape, kernel_api, kernel_for_host, match_value, primary_ip
from .vercmp import vercmp

log = logging.getLogger(__name__)

KERNEL_ABI = re.compile(r"^linux-(?:hwe-[0-9.]+-)?(?:image|image-unsigned|modules|modules-extra|headers|tools|cloud-tools|buildinfo)"
                        r"-(\d+\.\d+\.\d+)-(\d+)(?:-[a-z0-9-]+)?$")
SIG_VERSION = re.compile(r"(\d+\.\d+\.\d+-\d+\.\d+(?:~[0-9.]+)?)")


def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def norm_release(r):
    m = re.match(r"(\d+\.\d+)", str(r or ""))
    return m.group(1) if m else ""


def _parse_time(s):
    try:
        t = datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return t.astimezone().replace(tzinfo=None) if t.tzinfo else t
    except ValueError:
        return None

# ---------------------------------------------------------------- 主機同步

def sync_hosts(con):
    ls = Landscape()
    comps = ls.computers()
    kern = None
    per_host = bool(Config.KERNEL_API_URL) and Config.KERNEL_API_MODE == "per-host"
    kstatus_default = "missing" if Config.KERNEL_API_URL else "disabled"
    bulk_error = False
    if Config.KERNEL_API_URL and not per_host:
        try:
            kern = kernel_api()
        except Exception as e:      # kernel API 失敗不影響其他部分
            log.warning("kernel API 讀取失敗：%s", e)
            bulk_error = True
    seen = set()
    for c in comps:
        pk = ls.installed_packages(c["id"])
        pro = (c.get("ubuntu_pro_info") or {}).get("attached")
        hn = c.get("hostname") or c["title"]
        ip = primary_ip(c)
        k = None
        api_error = bulk_error
        if per_host:
            try:
                k = kernel_for_host(hn, ip)
            except Exception as e:
                log.warning("kernel API 查詢 %s 失敗：%s", hn, e)
                api_error = True
        elif kern is not None:
            k = kern.get(match_value(hn, ip))
        krel = kver = kcol = None
        kst = kstatus_default
        if api_error:
            # 查詢失敗（逾時、403、500…）不代表主機換了 kernel：沿用上一次取得的資料，狀態標成 error。
            # 不能退回「最新安裝的 kernel」推測，否則執行中舊 kernel 的 CVE 會被誤標成已解決。
            prev = con.execute("SELECT kernel_release,kernel_version,kernel_collected_at FROM host WHERE landscape_id=?",
                               (c["id"],)).fetchone()
            if prev:
                krel, kver, kcol = prev["kernel_release"], prev["kernel_version"], prev["kernel_collected_at"]
            kst = "error"
        elif k:
            kcol = k["collected_at"]
            t = _parse_time(kcol)
            if t and (datetime.datetime.now() - t).total_seconds() > Config.KERNEL_API_MAX_AGE_HOURS * 3600:
                kst = "stale"
            else:
                krel = k["release"]
                m = SIG_VERSION.search(k["version"] or "")
                kver = m.group(1) if m else None
                if kver and not krel:   # 只有版本（例如純文字回應）：從已安裝套件找出對應的 kernel 名稱
                    krel = next((n[len("linux-image-"):] for n, v in pk.items()
                                 if n.startswith("linux-image-") and v == kver and KERNEL_ABI.match(n)), "")
                if not kver and krel:   # 只有 uname -r：從已安裝套件查版本
                    kver = pk.get("linux-image-" + krel) or pk.get("linux-image-unsigned-" + krel)
                kst = "ok" if (kver and krel) else "missing"
        with con:
            cur = con.execute("SELECT id FROM host WHERE landscape_id=?", (c["id"],)).fetchone()
            vals = (hn, ip, c["title"], norm_release(c.get("distribution")), None if pro is None else int(bool(pro)), len(pk), now(),
                    krel, kver, kcol, kst)
            if cur:
                hid = cur["id"]
                con.execute("UPDATE host SET hostname=?,ip=?,title=?,release=?,pro_attached=?,package_count=?,last_seen=?,"
                            "kernel_release=?,kernel_version=?,kernel_collected_at=?,kernel_status=?,active=1 WHERE id=?", vals + (hid,))
            else:
                hid = con.execute("INSERT INTO host(hostname,ip,title,release,pro_attached,package_count,last_seen,kernel_release,"
                                  "kernel_version,kernel_collected_at,kernel_status,landscape_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                                  vals + (c["id"],)).lastrowid
            con.execute("DELETE FROM host_package WHERE host_id=?", (hid,))
            con.executemany("INSERT INTO host_package(host_id,name,version) VALUES (?,?,?)", [(hid, n, v) for n, v in pk.items()])
        seen.add(c["id"])
        log.info("主機 %s（%s）：套件 %d、kernel %s（%s）", hn, ip or "-", len(pk), kver or "-", kst)
    with con:
        for r in con.execute("SELECT id, landscape_id FROM host WHERE active=1").fetchall():
            if r["landscape_id"] not in seen and not Config.LANDSCAPE_QUERY:
                con.execute("UPDATE host SET active=0 WHERE id=?", (r["id"],))
    return len(comps)

# ---------------------------------------------------------------- 比對

def _old_kernels(pk):
    newest = {}
    for n in pk:
        m = KERNEL_ABI.match(n)
        if m:
            newest[m.group(1)] = max(newest.get(m.group(1), 0), int(m.group(2)))
    return {n for n in pk if (m := KERNEL_ABI.match(n)) and int(m.group(2)) < newest[m.group(1)]}


def _newest_kernel_version(pk, release):
    m = KERNEL_ABI.match("linux-image-" + release)
    best = None
    for n, v in pk.items():
        mm = KERNEL_ABI.match(n)
        if m and mm and mm.group(1) == m.group(1) and n.startswith("linux-image-"):
            if best is None or vercmp(v, best) > 0:
                best = v
    return best


KERNEL_NAME = re.compile(r"^(linux-(?:image|image-unsigned|modules))-(\d+\.\d+\.\d+)-\d+-([a-z0-9-]+)$")


def _kernel_source_by_series(con, eco, name):
    """例：linux-image-6.8.0-139-generic → 找 binmap 裡 linux-image-6.8.0-*-generic 最常對到的 source"""
    m = KERNEL_NAME.match(name)
    if not m:
        return None
    prefix, series, flavor = m.groups()
    rx = re.compile(r"^%s-%s-\d+-%s$" % (re.escape(prefix), re.escape(series), re.escape(flavor)))
    counts = {}
    for r in con.execute("SELECT binary, source FROM binmap WHERE ecosystem=? AND binary LIKE ?",
                         (eco, "%s-%s-%%-%s" % (prefix, series, flavor))):
        if rx.match(r["binary"]):
            counts[r["source"]] = counts.get(r["source"], 0) + 1
    return max(counts, key=counts.get) if counts else None


def evaluate_host(con, h):
    """回傳這台主機目前的比對結果 {key: row}"""
    pk = {r["name"]: r["version"] for r in con.execute("SELECT name,version FROM host_package WHERE host_id=?", (h["id"],))}
    rel = h["release"]
    base, proe = "Ubuntu:%s:LTS" % rel, "Ubuntu:Pro:%s:LTS" % rel
    if Config.PRO_MODE == "auto":
        has_pro = bool(h["pro_attached"]) if h["pro_attached"] is not None else any("+esm" in v for v in pk.values())
    else:
        has_pro = Config.PRO_MODE == "yes"

    items = []     # (binary, version, location)
    running_kernel = h["kernel_status"] in ("ok", "error") and h["kernel_version"] and h["kernel_release"]
    if running_kernel:
        skip = {n for n in pk if KERNEL_ABI.match(n)}
        for n in ("linux-image-", "linux-image-unsigned-", "linux-modules-"):
            items.append((n + h["kernel_release"], h["kernel_version"], "running-kernel"))
        newest_k = _newest_kernel_version(pk, h["kernel_release"])
    else:
        skip = set() if Config.CHECK_OLD_KERNELS else _old_kernels(pk)
        newest_k = None
    items += [(n, v, "installed") for n, v in pk.items() if n not in skip]

    names = sorted({i[0] for i in items})
    srcmap, pro_srcmap = {}, {}
    for i in range(0, len(names), 500):
        chunk = names[i:i + 500]
        q = "SELECT ecosystem, binary, source FROM binmap WHERE ecosystem IN (?,?) AND binary IN (%s)" % ",".join("?" * len(chunk))
        for r in con.execute(q, [base, proe] + chunk):
            (srcmap if r["ecosystem"] == base else pro_srcmap)[r["binary"]] = r["source"]
    for b, s in pro_srcmap.items():      # 一般版本優先，沒有才用 Pro 的對應
        srcmap.setdefault(b, s)
    if running_kernel:
        # 執行中 kernel 的 ABI 名稱不一定出現在 OSV 裡：改用同系列、同 flavor 的其他 ABI 推回 source 套件
        for n in [i[0] for i in items if i[2] == "running-kernel" and i[0] not in srcmap]:
            src = _kernel_source_by_series(con, base, n) or _kernel_source_by_series(con, proe, n)
            if src:
                srcmap[n] = src
    vul = {}
    srcs = sorted(set(srcmap.values()))
    for i in range(0, len(srcs), 500):
        chunk = srcs[i:i + 500]
        q = ("SELECT a.ecosystem, a.source, a.cve, a.fixed, a.introduced, a.binaries, v.priority FROM affected a "
             "LEFT JOIN vuln v ON v.cve=a.cve WHERE a.ecosystem IN (?,?) AND a.source IN (%s)" % ",".join("?" * len(chunk)))
        for r in con.execute(q, [base, proe] + chunk):
            vul.setdefault(r["source"], []).append(r)

    out = {}
    for binname, ver, loc in items:
        src = srcmap.get(binname)
        if not src:
            continue
        for v in vul.get(src, []):
            label = "base" if v["ecosystem"] == base else "pro"
            if v["introduced"] and vercmp(ver, v["introduced"]) < 0:
                continue
            if v["fixed"]:
                fixed = json.loads(v["binaries"] or "{}").get(binname) or v["fixed"]
                if vercmp(ver, fixed) >= 0:
                    continue
                status = "fix-available" if (label == "base" or has_pro) else "fix-in-pro"
                repo = "ubuntu" if label == "base" else "esm"
            else:
                if not Config.INCLUDE_UNFIXED or label == "pro":
                    continue
                status, fixed, repo = "no-fix", "", ""
            if loc == "running-kernel":
                action = "reboot" if (fixed and newest_k and vercmp(newest_k, fixed) >= 0) else "upgrade+reboot"
                pkgname = "kernel " + h["kernel_release"]
            else:
                action, pkgname = "upgrade", binname
            if status == "no-fix":
                action = ""
            key = (v["cve"], pkgname, loc)
            old = out.get(key)
            if old and not (old["status"] == "no-fix" or (old["repo"] != "ubuntu" and repo == "ubuntu")):
                continue
            out[key] = {"cve": v["cve"], "package": pkgname, "source": src, "installed": pk.get(binname, ""),
                        "running": ver if loc == "running-kernel" else "", "fixed": fixed, "status": status, "repo": repo,
                        "location": loc, "action": action, "priority": v["priority"] or ""}
    return out


def update_findings(con, h, current):
    t = now()
    new = resolved = 0
    existing = {(r["cve"], r["package"], r["location"]): r
                for r in con.execute("SELECT * FROM finding WHERE host_id=?", (h["id"],))}
    with con:
        for key, f in current.items():
            r = existing.get(key)
            cols = (f["source"], f["installed"], f["running"], f["fixed"], f["status"], f["repo"], f["action"], f["priority"])
            if r is None:
                con.execute("INSERT INTO finding(host_id,cve,package,location,source,installed,running,fixed,status,repo,action,priority,"
                            "first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (h["id"],) + key + cols + (t, t))
                new += 1
            else:
                if r["resolved_at"]:
                    new += 1       # 修好後又出現（例如降版）
                con.execute("UPDATE finding SET source=?,installed=?,running=?,fixed=?,status=?,repo=?,action=?,priority=?,"
                            "last_seen=?,resolved_at=NULL WHERE id=?", cols + (t, r["id"]))
        for key, r in existing.items():
            if key not in current and not r["resolved_at"]:
                if h["kernel_status"] == "error" and r["location"] == "running-kernel":
                    continue        # kernel API 查詢失敗：不知道是否已重開機，保持未解決
                con.execute("UPDATE finding SET resolved_at=? WHERE id=?", (t, r["id"]))
                resolved += 1
    return new, resolved


def run_sync(con):
    """完整流程：檢查 OSV → 同步主機 → 比對 → 更新歷史。回傳 sync_run id"""
    t0 = now()
    rid = con.execute("INSERT INTO sync_run(started_at,status) VALUES (?,'running')", (t0,)).lastrowid
    con.commit()
    try:
        try:
            osv_import.check_inbox(con)
        except Exception as e:
            log.warning("OSV 匯入失敗，沿用上一份資料：%s", e)
        try:
            vex_import.check_inbox(con)
        except Exception as e:
            log.warning("VEX 匯入失敗，沿用上一份資料：%s", e)
        imp = osv_import.active_import(con)
        if not imp:
            raise RuntimeError("還沒有任何 OSV 資料：請把 osv-all.tar.xz 放到 %s" % Config.OSV_INBOX_DIR)
        n = sync_hosts(con)
        new = res = 0
        for h in con.execute("SELECT * FROM host WHERE active=1").fetchall():
            a, b = update_findings(con, h, evaluate_host(con, h))
            new += a
            res += b
        open_ = con.execute("SELECT COUNT(*) FROM finding f JOIN host h ON h.id=f.host_id WHERE f.resolved_at IS NULL AND h.active=1").fetchone()[0]
        cutoff = (datetime.datetime.now() - datetime.timedelta(days=Config.HISTORY_KEEP_DAYS)).isoformat(timespec="seconds")
        with con:
            con.execute("DELETE FROM finding WHERE resolved_at IS NOT NULL AND resolved_at < ?", (cutoff,))
            con.execute("UPDATE sync_run SET finished_at=?,status='ok',hosts=?,open_findings=?,new_findings=?,resolved_findings=?,"
                        "osv_import_id=? WHERE id=?", (now(), n, open_, new, res, imp["id"], rid))
        log.info("同步完成：主機 %d、未解決 %d、新增 %d、已解決 %d", n, open_, new, res)
        from . import report
        report.write_reports(con)
    except Exception as e:
        with con:
            con.execute("UPDATE sync_run SET finished_at=?,status='failed',message=? WHERE id=?", (now(), str(e)[:500], rid))
        log.exception("同步失敗")
        raise
    return rid

# ---------------------------------------------------------------- 例外

def active_exceptions(con):
    today = datetime.date.today().isoformat()
    return [e for e in con.execute("SELECT * FROM exception").fetchall() if not e["expires_at"] or e["expires_at"] >= today]


def excepted(exceptions, hostname, cve):
    for e in exceptions:
        if fnmatch.fnmatch(hostname.lower(), e["host_pattern"].lower()) and fnmatch.fnmatch(cve.upper(), e["cve"].upper()):
            return e
    return None
