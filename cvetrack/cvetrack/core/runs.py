"""Run：同步主機 → 比對 → 跟上一次比較、產生事件

事件原因的判斷依據：
- PackageChange：這次 Run 主機有變的套件（同步時跟資料庫裡的上一份比對）
- AdvisoryChange：上一次 Run 用的 OSV 到這次用的 OSV 之間的差異
判斷順序：主機狀態 → 套件有沒有變 → OSV 有沒有變 → 其他（設定或資料來源變更）
"""
import datetime
import fnmatch
import json
import logging
import re

from django.db import transaction
from django.utils import timezone

from ..conf import conf
from ..models import (AdvisoryChange, Finding, FindingEvent, Host, HostPackage, OsvImport, PackageChange, RiskException, Run)
from . import osv, vex
from .lock import job_lock
from .matching import KERNEL_ABI, evaluate
from .sources import Landscape, kernel_api, kernel_for_host, match_value, primary_ip

log = logging.getLogger(__name__)

SIG_VERSION = re.compile(r"(\d+\.\d+\.\d+-\d+\.\d+(?:~[0-9.]+)?)")
FIELDS = ("source", "installed", "running", "fixed", "status", "repo", "action", "priority")
BULK = 2000


def norm_release(r):
    m = re.match(r"(\d+\.\d+)", str(r or ""))
    return m.group(1) if m else ""


def _parse_time(s):
    try:
        t = datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else timezone.make_aware(t, datetime.timezone.utc)


# ---------------------------------------------------------------- 主機來源

def landscape_hosts():
    """從 Landscape 與 kernel API 取得主機：產生 dict（landscape_id、hostname、ip、title、release、pro_attached、packages、
    kernel＝{release, version, collected_at}|None、kernel_error）"""
    ls = Landscape()
    comps = ls.computers()
    per_host = bool(conf.KERNEL_API_URL) and conf.KERNEL_API_MODE == "per-host"
    kern, bulk_error = None, False
    if conf.KERNEL_API_URL and not per_host:
        try:
            kern = kernel_api()
        except Exception as e:      # kernel API 失敗不影響其他部分
            log.warning("kernel API 讀取失敗：%s", e)
            bulk_error = True
    for c in comps:
        hn = c.get("hostname") or c["title"]
        ip = primary_ip(c)
        k, err = None, bulk_error
        if per_host:
            try:
                k = kernel_for_host(hn, ip)
            except Exception as e:
                log.warning("kernel API 查詢 %s 失敗：%s", hn, e)
                err = True
        elif kern is not None:
            k = kern.get(match_value(hn, ip))
        yield {"landscape_id": c["id"], "hostname": hn, "ip": ip, "title": c["title"],
               "release": norm_release(c.get("distribution")),
               "pro_attached": (c.get("ubuntu_pro_info") or {}).get("attached"),
               "packages": ls.installed_packages(c["id"]), "kernel": k, "kernel_error": err}


def file_hosts(path):
    """測試或沒有 Landscape 時：從 JSON 檔讀主機（格式同 landscape_hosts 的輸出）"""
    with open(path, encoding="utf-8") as f:
        for h in json.load(f):
            h.setdefault("ip", "")
            h.setdefault("title", h["hostname"])
            h.setdefault("pro_attached", None)
            h.setdefault("kernel", None)
            h.setdefault("kernel_error", False)
            if h["kernel"] and h["kernel"].get("collected_at") == "auto":     # 示範資料：當成剛收集
                h["kernel"] = dict(h["kernel"], collected_at=timezone.now().isoformat(timespec="seconds"))
            yield h


def _kernel_fields(h, prev, pk):
    """回傳 (kernel_release, kernel_version, kernel_collected_at, kernel_status)；ok／error 的規則同 cvehub，stale／missing 會沿用上一次可信值"""
    k = h["kernel"]
    if h["kernel_error"]:
        # 查詢失敗不代表主機換了 kernel：沿用上一次的資料，狀態標 error（不能退回用已安裝套件推測，否則會誤判已解決）
        if prev:
            return prev.kernel_release, prev.kernel_version, prev.kernel_collected_at, "error"
        return None, None, None, "error"
    # 資料過舊或查無資料：沿用上一次可信的 release／版本（比對時當成「執行中 kernel 沒變」），
    # 否則下一次恢復正常時看不出這段期間有沒有重開機
    keep = (None, None)
    if prev and prev.kernel_release and prev.kernel_version:
        t0 = _parse_time(prev.kernel_collected_at)
        if t0 and (timezone.now() - t0).total_seconds() <= conf.KERNEL_KEEP_DAYS * 86400:
            keep = (prev.kernel_release, prev.kernel_version)       # 最多沿用 KERNEL_KEEP_DAYS 天
    if k and k.get("release") and keep[0] and k["release"] != keep[0]:
        keep = (None, None)                                         # API 說已經換了 kernel：舊的不能再用
    if not k:
        if not conf.KERNEL_API_URL:
            return None, None, None, "disabled"
        return keep[0], keep[1], prev.kernel_collected_at if prev and keep[0] else None, "missing"
    kcol = k.get("collected_at") or ""
    t = _parse_time(kcol)
    if t and (timezone.now() - t).total_seconds() > conf.KERNEL_API_MAX_AGE_HOURS * 3600:
        return keep[0], keep[1], (prev.kernel_collected_at if keep[0] else kcol), "stale"
    krel = k.get("release") or ""
    m = SIG_VERSION.search(k.get("version") or "")
    kver = m.group(1) if m else None
    if kver and not krel:   # 只有版本：從已安裝套件找出對應的 kernel 名稱
        krel = next((n[len("linux-image-"):] for n, v in pk.items()
                     if n.startswith("linux-image-") and v == kver and KERNEL_ABI.match(n)), "")
    if not kver and krel:   # 只有 uname -r：從已安裝套件查版本
        kver = pk.get("linux-image-" + krel) or pk.get("linux-image-unsigned-" + krel)
    if kver and krel:
        if not t:       # API 沒給（或給了無法解析的）收集時間：以這次取得的時間為準（之後判斷能沿用多久）
            kcol = timezone.now().isoformat(timespec="seconds")
        return krel, kver, kcol, "ok"
    return keep[0], keep[1], (prev.kernel_collected_at if keep[0] else kcol), "missing"


def sync_hosts(run, source):
    """寫入主機與套件，記錄套件差異。回傳 (這次看到的主機 id, 新主機或重新出現的主機 id)"""
    seen, fresh = set(), set()
    now = timezone.now()
    for h in source:
        pk = h["packages"]
        prev = Host.objects.filter(landscape_id=h["landscape_id"]).first()
        krel, kver, kcol, kst = _kernel_fields(h, prev, pk)
        with transaction.atomic():
            host = prev or Host(landscape_id=h["landscape_id"], first_run=run)
            is_fresh = prev is None or not prev.active
            if is_fresh:
                host.fresh_run = run
            old_kernel = (prev.kernel_release, prev.kernel_version) if prev else (None, None)
            host.hostname, host.ip, host.title = h["hostname"], h["ip"] or "", h["title"] or ""
            host.release = h["release"]
            host.pro_attached = None if h["pro_attached"] is None else bool(h["pro_attached"])
            host.package_count, host.last_seen = len(pk), now
            host.kernel_release, host.kernel_version, host.kernel_collected_at, host.kernel_status = krel, kver, kcol, kst
            host.active, host.retired_run = True, None
            host.save()
            old = dict(HostPackage.objects.filter(host=host).values_list("name", "version"))
            changes = []
            if not is_fresh:
                changes = [PackageChange(run=run, host=host, name=n, old_version=old.get(n), new_version=pk.get(n))
                           for n in sorted(set(old) | set(pk)) if old.get(n) != pk.get(n)]
                # 執行中 kernel 換了：新舊兩邊都要有完整的 release＋版本（stale／missing／error 不算）
                if kst == "ok" and krel and kver and all(old_kernel) and (krel, kver) != old_kernel:
                    changes.append(PackageChange(run=run, host=host, kind="running-kernel", name="kernel",
                                                 old_version="%s %s" % old_kernel, new_version="%s %s" % (krel, kver)))
            gone = [n for n in old if n not in pk]
            if gone:
                for i in range(0, len(gone), 500):
                    HostPackage.objects.filter(host=host, name__in=gone[i:i + 500]).delete()
            upd = [n for n in pk if n in old and old[n] != pk[n]]
            for n in upd:
                HostPackage.objects.filter(host=host, name=n).update(version=pk[n])
            HostPackage.objects.bulk_create([HostPackage(host=host, name=n, version=v) for n, v in pk.items() if n not in old])
            PackageChange.objects.bulk_create(changes)
        seen.add(host.id)
        if is_fresh:
            fresh.add(host.id)
        log.info("主機 %s（%s）：套件 %d、變更 %d、kernel %s（%s）", host.hostname, host.ip or "-", len(pk), len(changes),
                 kver or "-", kst)
    return seen, fresh


# ---------------------------------------------------------------- 事件

class Context:
    """一次 Run 共用的資料：OSV 差異、例外。since_id＝上一次成功的 Run（之後的變化都算這次的，含失敗的 Run 留下的）"""

    def __init__(self, run, since_id=0):
        self.run = run
        self.since_id = since_id
        self.now = timezone.now()
        self.adv = {}
        if run.osv_import_id and run.prev_osv_import_id and run.osv_import_id != run.prev_osv_import_id:
            imps = OsvImport.objects.filter(status="ok", id__gt=run.prev_osv_import_id, id__lte=run.osv_import_id)
            for eco, src, cve, kind in AdvisoryChange.objects.filter(imp__in=imps).values_list("ecosystem", "source", "cve", "kind"):
                self.adv.setdefault((eco, src, cve), set()).add(kind)
        today = timezone.localdate()
        self.exceptions = [(e.host_pattern.lower(), e.cve.upper()) for e in RiskException.objects.all()
                           if not e.expires_at or e.expires_at >= today]

    def excepted(self, hostname, cve):
        hn = hostname.lower()       # 規則同 cvehub：完整主機名稱，不分大小寫
        return any(fnmatch.fnmatchcase(hn, hp) and fnmatch.fnmatchcase(cve.upper(), cp) for hp, cp in self.exceptions)

    def advisory_cause(self, release, source, cve, appeared):
        """只看這台主機的 Ubuntu 版本（一般與 Pro 套件庫）的公告差異"""
        kinds = (self.adv.get(("Ubuntu:%s:LTS" % release, source, cve), set())
                 | self.adv.get(("Ubuntu:Pro:%s:LTS" % release, source, cve), set()))
        if not kinds:
            return None
        if appeared and "added" in kinds:
            return "new_advisory"
        if appeared and "fix_added" in kinds:
            return "fix_released"       # 原本沒有修正（預設不列），現在有修正版本可以更新
        return "advisory_revised"


def _snap(f):
    return {k: getattr(f, k) if not isinstance(f, dict) else f[k] for k in FIELDS}


def update_findings(ctx, host, current, skip):
    """比較這台主機上一次與這次的結果，更新 Finding、新增事件。回傳事件數 {kind: n}

    套件差異取「上一次成功的 Run 之後」的全部（失敗的 Run 已經更新過 HostPackage，它記下的差異也要算進來）"""
    run, now = ctx.run, ctx.now
    pkgchg = {}
    kernel_changed = False
    since = max(ctx.since_id, host.evaluated_run_id or 0)      # 失敗的 Run 已經比對過這台的話，那些差異已經用掉了
    for pc in PackageChange.objects.filter(host=host, run_id__gt=since, run_id__lte=run.id).order_by("id"):
        if pc.kind == "running-kernel":
            kernel_changed = True
        else:
            first = pkgchg.get(pc.name)
            pkgchg[pc.name] = (first[0] if first else pc.old_version, pc.new_version)
    pkgchg = {n: v for n, v in pkgchg.items() if v[0] != v[1]}       # 改了又改回來＝沒變
    is_fresh = bool(host.fresh_run_id and host.fresh_run_id > since)
    kernel_pkg_changed = any(KERNEL_ABI.match(n) for n in pkgchg)
    existing = {(f.cve, f.package, f.location): f for f in Finding.objects.filter(host=host)}
    events, counts = [], {}

    def ev(f, kind, cause, old=None, new=None):
        needs = (not run.baseline) and cause in FindingEvent.TICKET_REQUIRED
        events.append(FindingEvent(run=run, finding=f, host=host, cve=f.cve, package=f.package, location=f.location,
                                   priority=f.priority, kind=kind, cause=cause, old=old, new=new,
                                   excepted=ctx.excepted(host.hostname, f.cve), needs_ticket=needs, created_at=now))
        counts[kind] = counts.get(kind, 0) + 1
        counts["cause:" + cause] = counts.get("cause:" + cause, 0) + 1

    def appear_cause(cur):
        if is_fresh:
            return "new_host"
        if cur["location"] == "running-kernel":
            if kernel_changed:
                return "package_change"
        elif cur["binary"] in pkgchg:
            return "package_change"
        return ctx.advisory_cause(host.release, cur["source"], cur["cve"], True) or "other"

    new, reopened, changed, resolved = [], [], [], []
    for key, cur in current.items():
        f = existing.get(key)
        vals = {k: cur[k] for k in FIELDS}
        if f is None:
            f = Finding(host=host, cve=cur["cve"], package=cur["package"], location=cur["location"],
                        first_seen=now, last_seen=now, first_run=run, **vals)
            new.append(f)
            kind = "initial" if run.baseline else "appeared"
            ev(f, kind, "initial" if kind == "initial" else appear_cause(cur), None, vals)
            continue
        if f.resolved_at:
            for k, v in vals.items():
                setattr(f, k, v)
            f.resolved_at, f.resolved_run = None, None
            reopened.append(f)
            ev(f, "reappeared", appear_cause(cur), None, vals)
            continue
        old = _snap(f)
        if old != vals:
            causes = []
            if old["status"] == "no-fix" and vals["status"] != "no-fix":
                causes.append("fix_released")
            elif old["fixed"] != vals["fixed"]:
                causes.append("fixed_changed")
            if old["action"] != "reboot" and vals["action"] == "reboot":
                causes.append("need_reboot")
            if old["priority"] != vals["priority"]:
                causes.append("priority_changed")
            if not causes and (old["status"], old["repo"]) != (vals["status"], vals["repo"]):
                causes.append("other")       # 例如 Pro 狀態改變
            for c in causes:
                ev(f, "changed", c, old, vals)
            for k, v in vals.items():
                setattr(f, k, v)
            changed.append(f)
    for key, f in existing.items():
        if key in current or f.resolved_at:
            continue
        after = None        # 解決後的版本（事件畫面顯示「原版本 → 新版本」）
        if f.location == "running-kernel":
            if host.kernel_status in ("error", "stale", "missing"):
                continue        # 這次沒有可信的執行中 kernel（查詢失敗、資料過舊、查無資料）：不知道是否已重開機，保持未解決
            cause = "rebooted" if kernel_changed else None
            if kernel_changed:
                after = {"running": host.kernel_version or ""}
        else:
            chg = pkgchg.get(f.package)
            if chg:
                cause = "removed" if chg[1] is None else "patched"
                after = {"installed": chg[1] or "（已移除）"}
            elif f.package in skip and kernel_pkg_changed:
                cause = "patched"       # 裝了較新的 kernel，舊 kernel 不再比對
            else:
                cause = None
        cause = cause or ctx.advisory_cause(host.release, f.source, f.cve, False) or "other"
        ev(f, "resolved", cause, _snap(f), after)
        f.resolved_at, f.resolved_run = now, run
        resolved.append(f)

    # 一台主機一個交易；大量資料用批次寫入
    with transaction.atomic():
        Finding.objects.bulk_create(new, batch_size=BULK)
        Finding.objects.bulk_update(reopened, list(FIELDS) + ["resolved_at", "resolved_run"], batch_size=BULK)
        Finding.objects.bulk_update(changed, list(FIELDS), batch_size=BULK)
        Finding.objects.bulk_update(resolved, ["resolved_at", "resolved_run"], batch_size=BULK)
        still = Finding.objects.filter(host=host, resolved_at__isnull=True)
        if host.kernel_status in ("error", "stale", "missing"):
            still = still.exclude(location="running-kernel")
        still.update(last_seen=now)
        FindingEvent.objects.bulk_create(events, batch_size=BULK)
        Host.objects.filter(pk=host.pk).update(evaluated_run=run)
    return counts


def retire_hosts(ctx, seen):
    """這次沒出現的主機：停用，未解決的 Finding 以 host_retired 結束"""
    counts = {}
    if conf.LANDSCAPE_QUERY:      # 有篩選條件時沒出現不代表主機不見了
        return counts
    for host in Host.objects.filter(active=True).exclude(id__in=seen):
        with transaction.atomic():
            evs = []
            for f in Finding.objects.filter(host=host, resolved_at__isnull=True):
                evs.append(FindingEvent(run=ctx.run, finding=f, host=host, cve=f.cve, package=f.package, location=f.location,
                                        priority=f.priority, kind="resolved", cause="host_retired", old=_snap(f),
                                        excepted=ctx.excepted(host.hostname, f.cve), created_at=ctx.now))
                f.resolved_at, f.resolved_run = ctx.now, ctx.run
            Finding.objects.bulk_update([e.finding for e in evs], ["resolved_at", "resolved_run"], batch_size=BULK)
            FindingEvent.objects.bulk_create(evs, batch_size=BULK)
            host.active, host.retired_run = False, ctx.run
            host.save(update_fields=["active", "retired_run"])
        counts["resolved"] = counts.get("resolved", 0) + len(evs)
        counts["cause:host_retired"] = counts.get("cause:host_retired", 0) + len(evs)
        log.info("主機 %s 已不在主機來源：停用，結束 %d 筆弱點", host.hostname, len(evs))
    return counts


def _merge(a, b):
    for k, v in b.items():
        a[k] = a.get(k, 0) + v


def host_source():
    return landscape_hosts() if conf.HOST_SOURCE == "landscape" else file_hosts(conf.HOST_SOURCE)


def check_retire(seen, fresh):
    """主機來源少了太多主機（或 0 台）：多半是 Landscape 異常或權限改變，不要把主機全部停用"""
    if conf.LANDSCAPE_QUERY:
        return
    active = set(Host.objects.filter(active=True).values_list("id", flat=True))
    before = len(active - fresh)            # 這次同步前就在用的主機
    gone = len(active - seen)
    if before and (not seen or (gone >= 2 and gone > before * conf.RETIRE_MAX_FRACTION)):
        raise RuntimeError("主機來源這次只回傳 %d 台，原本 %d 台中有 %d 台不見了（超過 RETIRE_MAX_FRACTION=%s）。"
                           "可能是 Landscape 異常或帳號權限改變，這次不停用任何主機。確定要移除這些主機時，暫時調高 RETIRE_MAX_FRACTION 再同步一次"
                           % (len(seen), before, gone, conf.RETIRE_MAX_FRACTION))


def run(trigger="manual", source=None, refresh_hosts=True):
    """執行一次 Run（呼叫端要拿著 job_lock）。refresh_hosts=False：不重新同步主機，只用資料庫裡的套件重新比對（例如剛匯入 OSV）"""
    # 拿著鎖時還是「執行中」的 Run，是之前被中斷的（程序被殺、機器重開）
    Run.objects.filter(status="running").update(status="failed", finished_at=timezone.now(), message="中斷（程序沒有正常結束）")
    prev_ok = Run.objects.filter(status="ok").order_by("-id").first()
    imp = osv.active_import()
    r = Run.objects.create(started_at=timezone.now(), trigger=trigger, status="running", baseline=prev_ok is None,
                           osv_import=imp, vex_import=vex.active_import(),
                           prev_osv_import_id=prev_ok.osv_import_id if prev_ok else None)
    try:
        if not imp:
            raise RuntimeError("還沒有任何 OSV 資料：請先匯入 osv-all.tar.xz")
        counts = {}
        if refresh_hosts:
            seen, fresh = sync_hosts(r, source if source is not None else host_source())
            check_retire(seen, fresh)
        else:
            seen = set(Host.objects.filter(active=True).values_list("id", flat=True))
        ctx = Context(r, prev_ok.id if prev_ok else 0)
        for host in Host.objects.filter(id__in=seen, active=True):
            pk = dict(HostPackage.objects.filter(host=host).values_list("name", "version"))
            current, skip = evaluate(host, pk, imp.id)
            _merge(counts, update_findings(ctx, host, current, skip))
        if refresh_hosts:
            _merge(counts, retire_hosts(ctx, seen))
        r.hosts = len(seen)
        r.open_findings = Finding.objects.filter(resolved_at__isnull=True, host__active=True).count()
        r.counts, r.status, r.finished_at = counts, "ok", timezone.now()
        r.save()
        log.info("Run #%d 完成：主機 %d、未解決 %d、事件 %s", r.id, r.hosts, r.open_findings,
                 {k: v for k, v in counts.items() if not k.startswith("cause:")})
    except Exception as e:
        Run.objects.filter(pk=r.pk).update(status="failed", finished_at=timezone.now(), message=str(e)[:500])
        log.exception("Run #%d 失敗", r.id)
        raise
    return Run.objects.get(pk=r.pk)


def run_locked(**kw):
    with job_lock():
        return run(**kw)
