"""同步主機與套件、套用 kernel 資訊、比對 CVE、更新歷史"""
import collections
import datetime
import fnmatch
import json
import logging
import re

from . import db, host_import, hostnames, osv_import, vex_import
from .config import Config
from .kernel import KERNEL_ABI, infer_running
from .util import norm_release, now, parse_time as _parse_time
from .sources import Landscape, kernel_api, kernel_for_host, match_value, primary_ip
from .vercmp import vercmp

log = logging.getLogger(__name__)


# ---------------------------------------------------------------- 主機同步

CONTINUE_DAYS = 30      # Landscape 同步接續清單匯入建的主機：已停用的只接續這麼多天內出現過的


def _landscape_name(c):
    """Landscape 電腦的主機名稱（沒有 hostname 時用標題）"""
    return c.get("hostname") or c["title"]


def _recent(t):
    """時間 t 在 KERNEL_API_MAX_AGE_HOURS 內"""
    return (datetime.datetime.now() - t).total_seconds() <= Config.KERNEL_API_MAX_AGE_HOURS * 3600


def _fresh(collected_at):
    """kernel 資料在 KERNEL_API_MAX_AGE_HOURS 內（沒有時間或格式不對＝不算）"""
    t = _parse_time(collected_at) if collected_at else None
    return bool(t) and _recent(t)


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
    names = collections.Counter(hostnames.key(_landscape_name(c)) for c in comps)
    exact = collections.Counter(hostnames.norm(_landscape_name(c)) for c in comps)
    taken = set()                       # 這次已被接續的清單主機
    since = (datetime.datetime.now() - datetime.timedelta(days=CONTINUE_DAYS)).isoformat(timespec="seconds")
    # 同步開始前的快照（迴圈中途會補 landscape_id，用快照結果才不會依 API 順序而不同）：啟用中的主機，
    # 加上 CONTINUE_DAYS 天內出現過、還沒有 landscape_id 的（可以接續的清單主機）
    snap = db.hosts_by_key(con, hostnames.key, "active=1 OR (landscape_id IS NULL AND last_seen >= ?)", (since,))
    for c in comps:
        pk = ls.installed_packages(c["id"])
        pro = (c.get("ubuntu_pro_info") or {}).get("attached")
        hn = _landscape_name(c)
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
        # 既有主機：先用 landscape_id 找；找不到時接續清單匯入建的同一台主機（hostnames.choose：依 HOST_MATCH_KEY；
        # 這次 Landscape 有別台的比對鍵相同時只認名稱完全相同的。還沒有 landscape_id，啟用中或 CONTINUE_DAYS 天內出現過的：
        # 之前的 Landscape 同步已把它停用、之後才加入 Landscape 的也接得上），弱點歷史才不會斷。不接續的情況：
        #   有兩台以上啟用中、名稱都不完全相同的候選主機（分不出是哪一台）
        #   清單主機已停用，而同步開始時已有啟用中、連到 Landscape 的同名主機（多半是重新註冊的電腦）
        #   設了 LANDSCAPE_QUERY（只看得到部分電腦，無法確認名稱唯一）：log 警告
        key = hostnames.key(hn)
        group = snap.get(key, [])
        cur = con.execute("SELECT * FROM host WHERE landscape_id=?", (c["id"],)).fetchone()
        linked = cur is not None
        if not linked:
            rows = [r for r in group if r["landscape_id"] is None and r["id"] not in taken]
            cand, ambiguous = hostnames.choose(rows, hn, exact_only=names[key] > 1)
            if cand and not cand["active"] and any(r["active"] and r["landscape_id"] is not None
                                                   and hostnames.same_machine(hostnames.full(r), hn)
                                                   and hostnames.same_machine(hostnames.full(r), hostnames.full(cand)) for r in group):
                cand = None
            if exact[hostnames.norm(hn)] > 1:
                if rows:
                    log.warning("Landscape 有 %d 台電腦都叫 %s，不接續清單匯入建立的同名主機", exact[hostnames.norm(hn)], hn)
            elif names[key] > 1 and not cand and hostnames.candidates(rows, hn):
                log.warning("Landscape 有 %d 台電腦都對應到 %s（HOST_MATCH_KEY=%s），只接續名稱完全相同的清單主機",
                            names[key], hn, Config.HOST_MATCH_KEY)
            elif ambiguous:
                log.warning("有多台啟用中、還沒連到 Landscape 的主機都可能是 %s（HOST_MATCH_KEY=%s），不接續", hn, Config.HOST_MATCH_KEY)
            elif cand and Config.LANDSCAPE_QUERY:
                log.warning("設了 LANDSCAPE_QUERY，不依名稱接續清單匯入建立的 %s%s", hn,
                            "（兩筆都會維持啟用，請手動停用不要的那筆）" if cand["active"] else "（舊的那筆已停用）")
            elif cand:
                cur = cand
                taken.add(cand["id"])
            elif hostnames.candidates(rows, hn):
                log.warning("沒有接續停用的同名主機（%s）：分不出是哪一台，或已有連到 Landscape 的同一台；%s 另建一筆",
                            "、".join(hostnames.full(r) for r in hostnames.candidates(rows, hn)), hn)
        krel = kver = kcol = None
        kst = kstatus_default
        if api_error:
            # 查詢失敗（逾時、403、500…）不代表主機換了 kernel：沿用上一次取得的資料，狀態標成 error。
            # 不能退回「最新安裝的 kernel」推測，否則執行中舊 kernel 的 CVE 會被誤標成已解決。
            # 接續清單匯入的主機時，清單裡的 kernel 也要沒過期（KERNEL_API_MAX_AGE_HOURS）才沿用
            if cur and (linked or _fresh(cur["kernel_collected_at"])):
                krel, kver, kcol = cur["kernel_release"], cur["kernel_version"], cur["kernel_collected_at"]
            kst = "error"
        elif k:
            kcol = k["collected_at"]
            t = _parse_time(kcol) if kcol else None
            if t and not _recent(t):
                kst = "stale"
            else:
                krel, kver = infer_running(k["release"], k["version"], pk)
                kst = "ok" if (kver and krel) else "missing"
        with con:
            # Landscape 是權威來源：ip 一律覆寫（keep_ip 不用）。顯示的名稱最後由 refresh_names 依全部啟用中的主機決定；
            # 這裡先保守地判斷（同步途中、或中途失敗時，畫面上也不會有兩台同名）
            alone = names[key] == 1 and not any(r["active"] and r["id"] != (cur and cur["id"]) for r in group)
            db.upsert_host(con, cur and cur["id"], {
                "hostname": hostnames.stored(hn, alone), "fqdn": hn, "title": c["title"], "ip": ip, "release": norm_release(c.get("distribution")),
                "pro_attached": None if pro is None else int(bool(pro)), "last_seen": now(),
                "kernel_release": krel, "kernel_version": kver, "kernel_collected_at": kcol, "kernel_status": kst,
            }, pk, landscape_id=c["id"])
        seen.add(c["id"])
        log.info("主機 %s（%s）：套件 %d、kernel %s（%s）", hn, ip or "-", len(pk), kver or "-", kst)
    with con:
        for r in con.execute("SELECT id, landscape_id FROM host WHERE active=1").fetchall():
            if r["landscape_id"] not in seen and not Config.LANDSCAPE_QUERY:
                con.execute("UPDATE host SET active=0 WHERE id=?", (r["id"],))
        hostnames.refresh_names(con)
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


def prune_history(con, cutoff):
    """紀錄表也依 HISTORY_KEEP_DAYS 刪除過期的列（和 finding 同一個 cutoff，由 run_sync 在同一個交易裡呼叫）。
    畫面與 /healthz 會用到的列一律保留：
      sync_run：首頁顯示的最近 5 筆、最後一次成功（/healthz 的 last_successful_sync）、最後一次完成（輸出報表的快取）
      host_import：最新一筆（資料匯入頁）
      osv_import／vex_import：只刪失敗的紀錄。成功的一律保留：放檔目錄靠它們的 sha256 判斷檔案匯入過了，
        刪掉的話舊檔再放回去會被重新匯入、取代使用中的較新資料；另外保留最新一筆（/healthz 看它是否失敗）、sync_run 還參照的
    """
    con.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,))
    con.execute("DELETE FROM host_import WHERE imported_at < ? AND id != (SELECT MAX(id) FROM host_import)", (cutoff,))
    con.execute("""DELETE FROM sync_run WHERE started_at < ?
                   AND id NOT IN (SELECT id FROM sync_run ORDER BY id DESC LIMIT 5)
                   AND id NOT IN (SELECT COALESCE(MAX(id), 0) FROM sync_run WHERE status='ok')
                   AND id NOT IN (SELECT COALESCE(MAX(id), 0) FROM sync_run WHERE finished_at IS NOT NULL)""", (cutoff,))
    con.execute("""DELETE FROM osv_import WHERE imported_at < ? AND status != 'ok'
                   AND id != (SELECT MAX(id) FROM osv_import)
                   AND id NOT IN (SELECT osv_import_id FROM sync_run WHERE osv_import_id IS NOT NULL)""", (cutoff,))
    con.execute("""DELETE FROM vex_import WHERE imported_at < ? AND status != 'ok'
                   AND id != (SELECT MAX(id) FROM vex_import)""", (cutoff,))


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
        if Config.HOST_SOURCE == "file":
            n = host_import.check_inbox(con)    # 主機清單先處理（還沒有 OSV 也會匯入並記錄，不會一直留在放檔目錄）
        imp = osv_import.active_import(con)
        if not imp:
            raise RuntimeError("還沒有任何 OSV 資料：請把 osv-all.tar.xz 放到 %s" % Config.OSV_INBOX_DIR)
        if Config.HOST_SOURCE != "file":
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
            prune_history(con, cutoff)          # 在這次標成成功之後：「最後一次成功」就是這一次
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

def active_exceptions(con, today=None):
    today = today or datetime.date.today().isoformat()
    return [e for e in con.execute("SELECT * FROM exception").fetchall() if not e["expires_at"] or e["expires_at"] >= today]


class ExceptionMatcher:
    """例外規則的判斷：主機名稱（hostname 或 fqdn）與 CVE 都用 fnmatch 樣式、不分大小寫，取第一條符合的。
    規則先編譯，每台主機適用的規則只算一次
      m = ExceptionMatcher(active_exceptions(con)); m(hostname, cve, fqdn) → 例外或 None"""

    def __init__(self, exceptions):
        self.rules = [(re.compile(fnmatch.translate(e["host_pattern"].lower())), re.compile(fnmatch.translate(e["cve"].upper())), e)
                      for e in exceptions]
        self.cache = {}

    def for_host(self, hostname, fqdn=None):
        """這台主機適用的規則 [(CVE 樣式, 例外)]"""
        k = (hostname, fqdn)
        rs = self.cache.get(k)
        if rs is None:
            names = [n.lower() for n in (hostname, fqdn) if n]
            rs = self.cache[k] = [(c, e) for h, c, e in self.rules if any(h.match(n) for n in names)]
        return rs

    def __call__(self, hostname, cve, fqdn=None):
        rs = self.for_host(hostname, fqdn) if self.rules else ()
        cu = cve.upper()
        return next((e for c, e in rs if c.match(cu)), None)


def excepted(exceptions, hostname, cve, fqdn=None):
    """套用到這台主機、這個 CVE 的例外規則；主機名稱比 hostname 與 fqdn（來源回報的原樣）：
    hostname 只存第一段時，寫成 web01.example.com、*.example.com 的規則照樣套用。判斷都在 ExceptionMatcher（大量比對時直接用它）"""
    return ExceptionMatcher(exceptions)(hostname, cve, fqdn)
