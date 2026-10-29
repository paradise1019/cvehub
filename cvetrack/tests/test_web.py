"""網頁：權限、各頁面、補單號、建議對應、上傳、匯出"""
import datetime
import io
import lzma

import pytest
from django.contrib.auth.models import Group, User
from django.core.management import call_command
from django.urls import reverse
from django.utils import timezone

from cvetrack.export import safe_cell
from cvetrack.models import AuditLog, ChangeTicket, FindingEvent, Host

from .helpers import do_run, host, import_osv
from .test_events import OLD, OSV1

pytestmark = pytest.mark.django_db


@pytest.fixture
def users():
    call_command("cvetrack_setup_groups", verbosity=0)
    out = {}
    for name in ("viewer", "operator", "admin"):
        u = User.objects.create_user(name, password="pw-" + name)
        u.groups.add(Group.objects.get(name="cvetrack-" + name))
        out[name] = u
    out["nobody"] = User.objects.create_user("nobody", password="pw")
    return out


@pytest.fixture
def data(tmp_path):
    import_osv(tmp_path, "osv1.tar.xz", OSV1)
    do_run([host(1, OLD), host(2, OLD)])
    pk = dict(OLD, libssl3t64="3.0.13-0ubuntu3.5", openssl="3.0.13-0ubuntu3.5")
    r2 = do_run([host(1, pk), host(2, pk)])
    return r2


def login(client, u):
    client.force_login(u)
    return client


def test_permissions(client, users, data):
    url = reverse("cvetrack:index")
    assert client.get(url).status_code == 302                     # 未登入 → 登入頁
    assert login(client, users["nobody"]).get(url).status_code == 403
    assert login(client, users["viewer"]).get(url).status_code == 200
    assert client.get(reverse("cvetrack:data")).status_code == 403          # viewer 不能匯入
    assert client.post(reverse("cvetrack:ticket_assign"), {"number": "X", "ids": "1"}).status_code == 403
    assert login(client, users["operator"]).get(reverse("cvetrack:ticket_new")).status_code == 200
    assert client.get(reverse("cvetrack:data")).status_code == 403
    assert login(client, users["admin"]).get(reverse("cvetrack:data")).status_code == 200


def test_pages_render(client, users, data):
    login(client, users["viewer"])
    h = Host.objects.get(landscape_id=1)
    urls = [reverse("cvetrack:index"), reverse("cvetrack:runs"), reverse("cvetrack:run", args=[data.id]),
            reverse("cvetrack:events"), reverse("cvetrack:osv_list"), reverse("cvetrack:osv", args=[1]),
            reverse("cvetrack:findings"), reverse("cvetrack:hosts"), reverse("cvetrack:host", args=[h.id]),
            reverse("cvetrack:host", args=[h.id]) + "?tab=findings", reverse("cvetrack:cve", args=["CVE-2026-0001"]),
            reverse("cvetrack:unticketed"), reverse("cvetrack:tickets"),
            reverse("cvetrack:run", args=[data.id]) + "?kind=resolved&cause=patched&priority=high&host=host1&date_from=2020-01-01"]
    for u in urls:
        r = client.get(u)
        assert r.status_code == 200, u
    r = client.get(reverse("cvetrack:run", args=[data.id]))
    assert "已修補" in r.content.decode()
    assert client.get(reverse("cvetrack:cve", args=["CVE-1999-9999"])).status_code == 404
    assert client.get("/cvetrack/cve/%3Cscript%3E/").status_code == 404


def test_assign_ticket_selected_and_all(client, users, data):
    login(client, users["operator"])
    ids = list(FindingEvent.objects.filter(needs_ticket=True, host__landscape_id=1).values_list("id", flat=True))
    assert len(ids) == 2
    r = client.post(reverse("cvetrack:ticket_assign"), {"number": "CHG-1", "ids": ids, "action": "assign"})
    assert r.status_code == 302
    t = ChangeTicket.objects.get(number="CHG-1")
    assert set(t.events.values_list("id", flat=True)) == set(ids)
    # 符合篩選的全部：host2
    r = client.post(reverse("cvetrack:ticket_assign"), {"number": "CHG-2", "all": "1", "f_host": "host2", "f_ticket": ""})
    assert ChangeTicket.objects.get(number="CHG-2").events.count() == 2
    assert FindingEvent.objects.filter(needs_ticket=True, ticket=None).count() == 0
    # 不需要單號的事件（初始）不會被掛上
    init = FindingEvent.objects.filter(kind="initial").first()
    client.post(reverse("cvetrack:ticket_assign"), {"number": "CHG-3", "ids": [init.id]})
    assert ChangeTicket.objects.get(number="CHG-3").events.count() == 0
    # 改單號、移除：都記在稽核
    client.post(reverse("cvetrack:ticket_assign"), {"number": "CHG-2", "ids": ids[:1]})
    assert "CHG-1 1 筆" in AuditLog.objects.filter(action="ticket_assign").first().detail
    client.post(reverse("cvetrack:ticket_assign"), {"ids": ids[:1], "action": "unassign"})
    assert FindingEvent.objects.get(id=ids[0]).ticket is None
    assert AuditLog.objects.filter(action="ticket_unassign").exists()


def test_ticket_pattern(client, users, data, settings):
    settings.CVETRACK["TICKET_PATTERN"] = r"CHG-\d{4}-\d{4}"
    login(client, users["operator"])
    ids = list(FindingEvent.objects.filter(needs_ticket=True).values_list("id", flat=True))
    client.post(reverse("cvetrack:ticket_assign"), {"number": "bad", "ids": ids})
    assert not ChangeTicket.objects.exists()
    client.post(reverse("cvetrack:ticket_assign"), {"number": "CHG-2026-1028", "ids": ids})
    assert ChangeTicket.objects.get().events.count() == len(ids)


def test_open_ticket_first_then_suggestions(client, users, tmp_path):
    import_osv(tmp_path, "osv1.tar.xz", OSV1)
    do_run([host(1, OLD), host(2, OLD)])
    login(client, users["operator"])
    now = timezone.now()
    r = client.post(reverse("cvetrack:ticket_new"), {
        "number": "CHG-9", "title": "openssl 更新", "description": "",
        "planned_start": (now - datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
        "planned_end": (now + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
        "hosts": [Host.objects.get(landscape_id=1).id]})
    assert r.status_code == 302
    t = ChangeTicket.objects.get(number="CHG-9")
    pk = dict(OLD, libssl3t64="3.0.13-0ubuntu3.5", openssl="3.0.13-0ubuntu3.5")
    do_run([host(1, pk), host(2, pk)])
    r = client.get(reverse("cvetrack:ticket", args=[t.id]))
    body = r.content.decode()
    assert "建議對應（2 筆）" in body              # 只有預計主機 host1 的 2 筆，host2 不列
    assert t.events.count() == 0                  # 不會自動掛上


def test_upload_and_sync_request(client, users, settings):
    login(client, users["admin"])
    bad = io.BytesIO(b"not xz")
    bad.name = "osv-all.tar.xz"
    client.post(reverse("cvetrack:data"), {"file": bad})
    good = io.BytesIO(lzma.compress(b"x"))
    good.name = "osv-all.tar.xz"
    client.post(reverse("cvetrack:data"), {"file": good})
    evil = io.BytesIO(lzma.compress(b"x"))
    evil.name = "../../etc/osv.tar.xz"
    client.post(reverse("cvetrack:data"), {"file": evil})
    from cvetrack.core import schedule
    import os
    import re
    names = sorted(re.sub(r"^\d{8}-\d{6}-[0-9a-f]{6}-", "", os.path.basename(p)) for p in schedule.pending_files())
    assert names == ["osv-all.tar.xz", "osv.tar.xz"]                 # 加了時間前綴；../ 被拿掉；假的 xz 被擋
    for evil in ("https://evil.example/", "//evil.example/", "/\\evil.example/"):
        r = client.post(reverse("cvetrack:sync"), {"next": evil})
        assert r["Location"] == reverse("cvetrack:index"), evil
    assert schedule.sync_requested()


def test_export(client, users, data):
    login(client, users["viewer"])
    r = client.get(reverse("cvetrack:run", args=[data.id]) + "?format=csv")
    assert r["Content-Type"].startswith("text/csv") and "已修補" in r.content.decode("utf-8-sig")
    r = client.get(reverse("cvetrack:findings") + "?format=xlsx")
    assert r.content[:2] == b"PK"
    assert safe_cell("=1+1") == "'=1+1" and safe_cell("-x") == "'-x" and safe_cell("abc") == "abc"


def test_tick_runs_only_when_due(tmp_path, settings):
    from cvetrack.core import inbox, schedule
    from cvetrack.models import Run
    from .helpers import write_osv
    settings.CVETRACK["HOST_SOURCE"] = str(tmp_path / "hosts.json")
    (tmp_path / "hosts.json").write_text('[{"landscape_id": 1, "hostname": "h1", "release": "24.04", "packages": {"curl": "8.5.0-2ubuntu10.5"}}]')
    folder, _ = inbox.dirs()
    write_osv(tmp_path / "data" / "inbox" / "osv-all.tar.xz", OSV1)
    call_command("cvetrack_tick", verbosity=0)
    r = Run.objects.get()
    assert (r.trigger, r.status, r.open_findings) == ("osv", "ok", 1)
    call_command("cvetrack_tick", verbosity=0)        # 沒事做
    assert Run.objects.count() == 1
    schedule.request_sync("t")
    call_command("cvetrack_tick", verbosity=0)
    assert Run.objects.count() == 2 and Run.objects.first().trigger == "manual" and not schedule.sync_requested()
    # 壞檔：移到 failed/，不會每次重試
    (tmp_path / "data" / "inbox" / "osv-bad.tar.xz").write_bytes(lzma.compress(b"junk"))
    call_command("cvetrack_tick", verbosity=0)
    assert not schedule.pending_files() and (tmp_path / "data" / "failed" / "osv-bad.tar.xz").exists()


def test_assign_all_keeps_existing_tickets(client, users, data):
    login(client, users["operator"])
    ids = list(FindingEvent.objects.filter(needs_ticket=True, host__landscape_id=1).values_list("id", flat=True))
    client.post(reverse("cvetrack:ticket_assign"), {"number": "CHG-1", "ids": ids})
    # 「待補單號」頁沒有 ticket 參數 → 表單也沒有 f_ticket：只能掛還沒有單號的
    client.post(reverse("cvetrack:ticket_assign"), {"number": "CHG-2", "all": "1"})
    assert ChangeTicket.objects.get(number="CHG-1").events.count() == 2
    assert ChangeTicket.objects.get(number="CHG-2").events.count() == 2


def test_ticket_form_keeps_retired_hosts(client, users, data):
    login(client, users["operator"])
    h1, h2 = Host.objects.get(landscape_id=1), Host.objects.get(landscape_id=2)
    t = ChangeTicket.objects.create(number="CHG-7")
    t.hosts.set([h1, h2])
    Host.objects.filter(pk=h2.pk).update(active=False)
    r = client.post(reverse("cvetrack:ticket_edit", args=[t.id]), {"number": "CHG-7", "title": "x", "hosts": [h1.id, h2.id]})
    assert r.status_code == 302
    assert set(t.hosts.values_list("id", flat=True)) == {h1.id, h2.id}
