"""cvetrack 網頁：帳號用原專案的 Django 帳號；權限 view／operate／admin（上層包含下層）"""
import datetime
import functools
import os
import re
import secrets
import tempfile

from django.contrib import messages
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from . import __version__, export
from .conf import conf
from .core import inbox, osv, schedule, tickets, vex
from .core.lock import is_busy
from .forms import TicketForm
from .models import (AdvisoryChange, AuditLog, ChangeTicket, Finding, FindingEvent, Host, OsvImport, Run, VexImport, Vuln, audit)

LEVELS = ("view", "operate", "admin")
KIND_LABEL = dict(FindingEvent.KINDS)
CAUSE_LABEL = dict(FindingEvent.CAUSES)
ADV_LABEL = dict(AdvisoryChange.KINDS)
PRIOS = ["critical", "high", "medium", "low", "negligible"]
STATUS_LABEL = {"fix-available": "可更新", "fix-in-pro": "需 Pro", "no-fix": "尚無修正"}
ACTION_LABEL = {"upgrade": "更新套件", "reboot": "重開機", "upgrade+reboot": "更新＋重開機", "": ""}


def level_of(user):
    for lv in reversed(LEVELS):
        if user.has_perm("cvetrack.%s_cvetrack" % lv):
            return lv
    return None


def need(level):
    def deco(view):
        @functools.wraps(view)
        def wrapper(request, *a, **kw):
            if not request.user.is_authenticated:
                return redirect_to_login(request.get_full_path())
            lv = level_of(request.user)
            if lv is None or LEVELS.index(lv) < LEVELS.index(level):
                raise PermissionDenied("需要 cvetrack 的%s權限" % {"view": "查看", "operate": "操作", "admin": "管理"}[level])
            request.cvetrack_level = lv
            return view(request, *a, **kw)
        return wrapper
    return deco


def page(request, cvetrack_page, ctx):
    lv = request.cvetrack_level
    imp, vimp = osv.active_import(), vex.active_import()
    stale = imp and imp.file_mtime and timezone.now() - imp.file_mtime > datetime.timedelta(days=conf.OSV_STALE_WARN_DAYS)
    base = {"base_template": conf.BASE_TEMPLATE, "version": __version__, "level": lv,
            "can_operate": lv in ("operate", "admin"), "can_admin": lv == "admin", "osv": imp, "vex": vimp, "osv_stale": stale,
            "running": Run.objects.filter(status="running").first() if is_busy() else None,
            "sync_requested": schedule.sync_requested(),
            "unticketed_count": tickets.unticketed().count(), "kind_label": KIND_LABEL, "cause_label": CAUSE_LABEL,
            "status_label": STATUS_LABEL, "action_label": ACTION_LABEL, "nav": cvetrack_page}
    base.update(ctx)
    return render(request, "cvetrack/%s.html" % cvetrack_page, base)


def paginate(request, qs):
    p = Paginator(qs, conf.PAGE_SIZE)
    pg = p.get_page(request.GET.get("page"))
    q = request.GET.copy()
    q.pop("page", None)
    pg.query = q.urlencode()
    return pg


def client_ip(request):
    return request.META.get("REMOTE_ADDR", "")


def safe_next(request, default):
    """表單的 next：只接受本站的網址（擋 //evil、/\\evil、https://evil 這類開放式重新導向）"""
    nxt = request.POST.get("next") or ""
    if nxt and url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return nxt
    return default


# ---------------------------------------------------------------- 篩選

EVENT_FILTERS = ("run", "kind", "cause", "priority", "host", "cve", "package", "ticket", "needs", "excepted", "date_from", "date_to")


def filter_events(qs, g):
    if g.get("run"):
        qs = qs.filter(run_id=g["run"]) if g["run"].isdigit() else qs.none()
    if g.get("kind"):
        qs = qs.filter(kind=g["kind"])
    if g.get("cause"):
        qs = qs.filter(cause=g["cause"])
    if g.get("priority"):
        qs = qs.filter(priority__in=PRIOS[:PRIOS.index(g["priority"]) + 1]) if g["priority"] in PRIOS else qs
    if g.get("host"):
        qs = qs.filter(host__hostname__icontains=g["host"].strip())
    if g.get("cve"):
        qs = qs.filter(cve__icontains=g["cve"].strip())
    if g.get("package"):
        qs = qs.filter(package__icontains=g["package"].strip())
    if g.get("ticket") == "none":
        qs = qs.filter(ticket=None)
    elif g.get("ticket"):
        qs = qs.filter(ticket__number=g["ticket"].strip())
    if g.get("needs") == "1":
        qs = qs.filter(needs_ticket=True)
    if g.get("excepted") in ("0", "1"):
        qs = qs.filter(excepted=g["excepted"] == "1")
    for k, op in (("date_from", "gte"), ("date_to", "lt")):
        if g.get(k):
            try:
                d = datetime.date.fromisoformat(g[k])
            except ValueError:
                continue
            if k == "date_to":
                d += datetime.timedelta(days=1)
            qs = qs.filter(**{"created_at__%s" % op: timezone.make_aware(datetime.datetime.combine(d, datetime.time()))})
    return qs


def event_rows(qs):
    for e in qs.select_related("host", "ticket", "run").iterator(chunk_size=2000):
        old, new = e.old or {}, e.new or {}
        yield [e.created_at, e.run_id, e.host.hostname, e.cve, e.priority, e.package, e.location, KIND_LABEL[e.kind],
               CAUSE_LABEL[e.cause], old.get("installed") or old.get("running") or "", new.get("installed") or new.get("running") or "",
               (new or old).get("fixed", ""), "是" if e.excepted else "", "必須" if e.needs_ticket else "",
               e.ticket.number if e.ticket else ""]


EVENT_HEADERS = ["時間", "Run", "主機", "CVE", "等級", "套件", "位置", "事件", "原因", "原版本", "新版本", "修正版本", "例外", "單號",
                 "變更單"]


def events_response(request, qs, name):
    fmt = request.GET.get("format")
    if fmt in ("csv", "xlsx"):
        return export.response(fmt, name, EVENT_HEADERS, event_rows(qs))
    return None


# ---------------------------------------------------------------- 頁面

@need("view")
def index(request):
    open_ = Finding.objects.filter(resolved_at=None, host__active=True)
    by_prio = dict(open_.values_list("priority").annotate(n=Count("id")))
    hosts_by_prio = dict(open_.values_list("priority").annotate(n=Count("host", distinct=True)))
    last = Run.objects.filter(status="ok").first()
    recent = Run.objects.all()[:10]
    top = []
    if last and not last.baseline:
        top = (FindingEvent.objects.filter(run=last, kind__in=["appeared", "reappeared"], priority__in=["critical", "high"])
               .values("cve", "priority", "cause").annotate(hosts=Count("host", distinct=True)).order_by("priority", "-hosts")[:20])
    return page(request, "index", {
        "prio_cards": [(p, by_prio.get(p, 0), hosts_by_prio.get(p, 0)) for p in PRIOS[:4]],
        "hosts": Host.objects.filter(active=True).count(), "last": last, "recent": recent, "top": top,
        "overdue_unticketed": tickets.overdue_unticketed().count(), "tickets_without_events": tickets.tickets_without_events().count(),
        "cfg": conf})


@need("view")
def run_list(request):
    return page(request, "runs", {"page_obj": paginate(request, Run.objects.select_related("osv_import", "vex_import"))})


@need("view")
def run_detail(request, pk):
    r = get_object_or_404(Run, pk=pk)
    qs = filter_events(FindingEvent.objects.filter(run=r), request.GET).order_by("host__hostname", "cve", "package")
    resp = events_response(request, qs, "cvetrack-run-%d-events" % r.id)
    if resp:
        return resp
    matrix = (FindingEvent.objects.filter(run=r).values("kind", "cause")
              .annotate(n=Count("id"), hosts=Count("host", distinct=True), cves=Count("cve", distinct=True),
                        need=Count("id", filter=Q(needs_ticket=True)), crit=Count("id", filter=Q(priority__in=["critical", "high"])))
              .order_by("kind", "-n"))
    return page(request, "run", {"run": r, "matrix": matrix, "page_obj": paginate(request, qs.select_related("host", "ticket")),
                                 "f": request.GET, "kinds": FindingEvent.KINDS, "causes": FindingEvent.CAUSES, "prios": PRIOS,
                                 "osv_changes": r.osv_import if (r.osv_import_id and r.osv_import_id != r.prev_osv_import_id) else None})


@need("view")
def events(request):
    qs = filter_events(FindingEvent.objects.all(), request.GET)
    resp = events_response(request, qs, "cvetrack-events")
    if resp:
        return resp
    return page(request, "events", {"page_obj": paginate(request, qs.select_related("host", "ticket")), "f": request.GET,
                                    "kinds": FindingEvent.KINDS, "causes": FindingEvent.CAUSES, "prios": PRIOS})


@need("view")
def osv_list(request):
    return page(request, "osv_list", {"imports": OsvImport.objects.all()[:50], "vex_imports": VexImport.objects.all()[:20],
                                      "adv_label": ADV_LABEL})


@need("view")
def osv_detail(request, pk):
    imp = get_object_or_404(OsvImport, pk=pk)
    qs = AdvisoryChange.objects.filter(imp=imp)
    g = request.GET
    if g.get("kind"):
        qs = qs.filter(kind=g["kind"])
    if g.get("release"):
        qs = qs.filter(Q(ecosystem__contains=":%s" % g["release"]) | Q(ecosystem=""))
    if g.get("cve"):
        qs = qs.filter(cve__icontains=g["cve"].strip())
    if g.get("source"):
        qs = qs.filter(source__icontains=g["source"].strip())
    if g.get("installed") == "1":
        # 只看受管主機有用到的 source 套件（從目前的弱點反推）
        qs = qs.filter(source__in=Finding.objects.values("source").distinct())
    qs = qs.order_by("kind", "cve", "ecosystem", "source")
    if g.get("format") in ("csv", "xlsx"):
        return export.response(g["format"], "cvetrack-osv-%d-changes" % imp.id, ["CVE", "套件庫", "source", "差異", "原值", "新值"],
                               ([c.cve, c.ecosystem, c.source, ADV_LABEL[c.kind], c.old_value or "", c.new_value or ""]
                                for c in qs.iterator(chunk_size=2000)))
    return page(request, "osv_detail", {"imp": imp, "page_obj": paginate(request, qs), "f": g, "adv_kinds": AdvisoryChange.KINDS,
                                        "adv_label": ADV_LABEL, "releases": conf.UBUNTU_RELEASES})


FINDING_HEADERS = ["主機", "版本", "CVE", "等級", "套件", "位置", "已安裝", "執行中", "修正版本", "狀態", "要做的事", "第一次發現"]


@need("view")
def findings(request):
    qs = Finding.objects.filter(resolved_at=None, host__active=True).select_related("host")
    g = request.GET
    if g.get("host"):
        qs = qs.filter(host__hostname__icontains=g["host"].strip())
    if g.get("cve"):
        qs = qs.filter(cve__icontains=g["cve"].strip())
    if g.get("package"):
        qs = qs.filter(package__icontains=g["package"].strip())
    if g.get("priority") in PRIOS:
        qs = qs.filter(priority__in=PRIOS[:PRIOS.index(g["priority"]) + 1])
    if g.get("status"):
        qs = qs.filter(status=g["status"])
    if g.get("action"):
        qs = qs.filter(action=g["action"])
    qs = qs.order_by("host__hostname", "cve", "package")
    if g.get("format") in ("csv", "xlsx"):
        return export.response(g["format"], "cvetrack-findings", FINDING_HEADERS,
                               ([f.host.hostname, f.host.release, f.cve, f.priority, f.package, f.location, f.installed, f.running,
                                 f.fixed, STATUS_LABEL.get(f.status, f.status), ACTION_LABEL.get(f.action, f.action), f.first_seen]
                                for f in qs.iterator(chunk_size=2000)))
    return page(request, "findings", {"page_obj": paginate(request, qs), "f": g, "prios": PRIOS})


@need("view")
def host_list(request):
    qs = Host.objects.annotate(
        open=Count("findings", filter=Q(findings__resolved_at=None)),
        crit=Count("findings", filter=Q(findings__resolved_at=None, findings__priority__in=["critical", "high"])),
        reboot=Count("findings", filter=Q(findings__resolved_at=None, findings__action__in=["reboot", "upgrade+reboot"])))
    if request.GET.get("q"):
        qs = qs.filter(hostname__icontains=request.GET["q"].strip())
    if request.GET.get("all") != "1":
        qs = qs.filter(active=True)
    return page(request, "hosts", {"page_obj": paginate(request, qs.order_by("hostname")), "f": request.GET})


@need("view")
def host_detail(request, pk):
    h = get_object_or_404(Host, pk=pk)
    tab = request.GET.get("tab", "events")
    if tab == "findings":
        qs = h.findings.filter(resolved_at=None).order_by("priority", "cve", "package")
    else:
        qs = filter_events(FindingEvent.objects.filter(host=h), request.GET).select_related("ticket").order_by("-id")
        resp = events_response(request, qs, "cvetrack-host-%d-events" % h.id)
        if resp:
            return resp
    summary = h.findings.filter(resolved_at=None).values("priority").annotate(n=Count("id"))
    return page(request, "host", {"host": h, "tab": tab, "page_obj": paginate(request, qs), "f": request.GET,
                                  "summary": {s["priority"]: s["n"] for s in summary}, "prios": PRIOS,
                                  "kinds": FindingEvent.KINDS, "causes": FindingEvent.CAUSES,
                                  "tickets": h.tickets.all()[:20]})


CVE_RE = re.compile(r"^[A-Za-z0-9._:-]{3,40}$")


@need("view")
def cve_detail(request, cve):
    if not CVE_RE.match(cve):
        raise Http404
    imp = osv.active_import()
    v = Vuln.objects.filter(imp=imp.id, cve=cve).first() if imp else None
    open_ = Finding.objects.filter(cve=cve, resolved_at=None, host__active=True).select_related("host").order_by("host__hostname")
    evs = FindingEvent.objects.filter(cve=cve).select_related("host", "ticket").order_by("-id")
    adv = AdvisoryChange.objects.filter(cve=cve).select_related("imp").order_by("-imp_id", "ecosystem", "source")
    if not (v or open_.exists() or evs.exists() or adv.exists()):
        raise Http404
    return page(request, "cve", {"cve": cve, "vuln": v, "open": open_[:500], "open_count": open_.count(),
                                 "page_obj": paginate(request, evs), "adv": adv[:200], "adv_label": ADV_LABEL})


# ---------------------------------------------------------------- 變更單

@need("view")
def unticketed(request):
    qs = filter_events(FindingEvent.objects.filter(tickets.ASSIGNABLE), request.GET)
    if not request.GET.get("ticket"):           # 沒指定單號＝只看還沒有單號的（none 也是）
        qs = qs.filter(ticket=None)
    qs = qs.order_by("-run_id", "host__hostname", "cve")
    resp = events_response(request, qs, "cvetrack-unticketed")
    if resp:
        return resp
    warn = timezone.now() - datetime.timedelta(days=conf.UNTICKETED_WARN_DAYS)
    return page(request, "unticketed", {"page_obj": paginate(request, qs.select_related("host", "ticket", "run")),
                                        "f": request.GET, "total": qs.count(), "warn_before": warn,
                                        "causes": [c for c in FindingEvent.CAUSES
                                                   if c[0] in FindingEvent.TICKET_REQUIRED + FindingEvent.TICKET_OPTIONAL],
                                        "prios": PRIOS, "cfg": conf})


@require_POST
@need("operate")
def ticket_assign(request):
    """待補單號／變更單頁送出：勾選的事件（ids）或符合篩選條件的全部（all=1），掛到單號 number"""
    back = safe_next(request, reverse("cvetrack:unticketed"))
    if request.POST.get("all") == "1":
        g = {k: request.POST.get("f_" + k, "") for k in EVENT_FILTERS}
        qs = filter_events(FindingEvent.objects.filter(tickets.ASSIGNABLE), g)
        if not g.get("ticket"):                 # 同「待補單號」頁：沒指定單號＝只看還沒有單號的
            qs = qs.filter(ticket=None)
    else:
        ids = [int(i) for i in request.POST.getlist("ids") if i.isdigit()]
        qs = FindingEvent.objects.filter(pk__in=ids)
    if not qs.exists():
        messages.warning(request, "沒有選擇任何事件")
        return redirect(back)
    if request.POST.get("action") == "unassign":
        n = tickets.unassign(qs, request.user, client_ip(request))
        messages.success(request, "已移除 %d 筆事件的單號" % n)
        return redirect(back)
    try:
        t = tickets.get_or_create(request.POST.get("number"), request.user)
    except tickets.TicketError as e:
        messages.error(request, str(e))
        return redirect(back)
    n, moved = tickets.assign(qs, t, request.user, client_ip(request))
    messages.success(request, "已把 %d 筆事件掛到 %s%s" % (n, t.number, "（其中 %d 筆原本是其他單號）" % moved if moved else ""))
    return redirect(back)


@need("view")
def ticket_list(request):
    qs = ChangeTicket.objects.annotate(n=Count("events"), hosts_n=Count("events__host", distinct=True)).order_by("-id")
    if request.GET.get("q"):
        q = request.GET["q"].strip()
        qs = qs.filter(Q(number__icontains=q) | Q(title__icontains=q))
    return page(request, "tickets", {"page_obj": paginate(request, qs), "f": request.GET,
                                     "without_events": tickets.tickets_without_events()[:50]})


@need("operate")
def ticket_edit(request, pk=None):
    t = get_object_or_404(ChangeTicket, pk=pk) if pk else None
    form = TicketForm(request.POST or None, instance=t)
    if request.method == "POST" and form.is_valid():
        obj = form.save(commit=False)
        if not obj.pk:
            obj.created_by = request.user.get_username()
        obj.save()
        form.save_m2m()
        audit(request.user, "ticket_edit" if t else "ticket_create", obj.number, client_ip(request))
        messages.success(request, "已儲存 %s" % obj.number)
        return redirect("cvetrack:ticket", pk=obj.pk)
    return page(request, "ticket_edit", {"form": form, "ticket": t})


@need("view")
def ticket_detail(request, pk):
    t = get_object_or_404(ChangeTicket, pk=pk)
    qs = t.events.select_related("host", "run").order_by("host__hostname", "cve", "package")
    resp = events_response(request, qs, "cvetrack-ticket-%s" % re.sub(r"[^A-Za-z0-9_-]", "_", t.number))
    if resp:
        return resp
    by_host = qs.values("host__hostname").annotate(n=Count("id"), cves=Count("cve", distinct=True)).order_by("host__hostname")
    sugg = tickets.suggestions(t).select_related("host", "run").order_by("host__hostname", "cve")
    return page(request, "ticket", {"ticket": t, "page_obj": paginate(request, qs), "by_host": by_host,
                                    "suggestions": sugg[:500], "suggestions_count": sugg.count(),
                                    "planned_hosts": t.hosts.all()})


# ---------------------------------------------------------------- 資料匯入、同步、稽核

UPLOAD_NAME = re.compile(r"^[A-Za-z0-9._-]+\.tar\.xz$")


@need("admin")
def data(request):
    if request.method == "POST":
        f = request.FILES.get("file")
        if not f:
            messages.error(request, "請選擇檔案")
        else:
            name = os.path.basename(f.name)
            if not UPLOAD_NAME.match(name) or not re.search(r"(osv|vex)", name, re.I):
                messages.error(request, "檔名要像 osv-all.tar.xz 或 vex-all.tar.xz（只能有英數字 . _ -）")
            else:
                folder, _ = inbox.dirs()
                fd, tmp = tempfile.mkstemp(dir=folder, prefix=".upload-")     # 暫存檔名不重複（同時上傳同名檔案也不會互寫）
                os.fchmod(fd, 0o644)            # 公開的公告資料；排程可能用不同帳號執行，要讀得到
                with os.fdopen(fd, "wb") as out:
                    for chunk in f.chunks():
                        out.write(chunk)
                with open(tmp, "rb") as chk:
                    head = chk.read(6)
                if head != b"\xfd7zXZ\x00":
                    os.remove(tmp)
                    messages.error(request, "不是 xz 壓縮檔")
                else:
                    # 加上時間前綴：不會蓋掉放檔目錄裡還沒處理的同名檔案
                    name = "%s-%s-%s" % (timezone.localtime().strftime("%Y%m%d-%H%M%S"), secrets.token_hex(3), name)
                    os.replace(tmp, os.path.join(folder, name))
                    audit(request.user, "upload", "%s（%d bytes）" % (name, f.size), client_ip(request))
                    messages.success(request, "已放進放檔目錄：%s。排程（cvetrack_tick）幾分鐘內會匯入並比對。" % name)
        return redirect("cvetrack:data")
    return page(request, "data", {"imports": OsvImport.objects.all()[:10], "vex_imports": VexImport.objects.all()[:10],
                                  "pending": [os.path.basename(p) for p in schedule.pending_files()], "cfg": conf,
                                  "inbox": inbox.dirs()[0]})


@require_POST
@need("admin")
def sync_now(request):
    schedule.request_sync(request.user.get_username())
    audit(request.user, "sync_request", "", client_ip(request))
    messages.success(request, "已送出同步要求，排程（cvetrack_tick）幾分鐘內會執行。")
    return redirect(safe_next(request, reverse("cvetrack:index")))


@need("admin")
def audit_log(request):
    return page(request, "audit", {"page_obj": paginate(request, AuditLog.objects.all())})

