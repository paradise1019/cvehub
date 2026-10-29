"""變化追蹤：每種事件類型與原因"""
import pytest

from cvetrack.models import AdvisoryChange, Finding, FindingEvent, Host, PackageChange, RiskException

from .helpers import ECO, do_run, host, import_osv, osv_record

pytestmark = pytest.mark.django_db

OSV1 = [
    osv_record("CVE-2026-0001", [(ECO, "openssl", "3.0.13-0ubuntu3.5", {"libssl3t64": "", "openssl": ""})]),
    osv_record("CVE-2026-0002", [(ECO, "curl", "8.5.0-2ubuntu10.6", {"curl": "", "libcurl4t64": ""})], priority="medium"),
]
OLD = {"libssl3t64": "3.0.13-0ubuntu3.4", "openssl": "3.0.13-0ubuntu3.4", "curl": "8.5.0-2ubuntu10.5", "bash": "5.2.21-2ubuntu4"}


def events(run, **kw):
    return list(FindingEvent.objects.filter(run=run, **kw).order_by("cve", "package"))


def test_baseline_then_no_change(tmp_path):
    import_osv(tmp_path, "osv1.tar.xz", OSV1)
    r1 = do_run([host(1, OLD)])
    assert r1.baseline and r1.open_findings == 3
    evs = events(r1)
    assert {e.kind for e in evs} == {"initial"} and not any(e.needs_ticket for e in evs)
    r2 = do_run([host(1, OLD)])
    assert not r2.baseline and events(r2) == [] and r2.open_findings == 3


def test_patched_removed_and_downgrade(tmp_path):
    import_osv(tmp_path, "osv1.tar.xz", OSV1)
    do_run([host(1, OLD)])
    pk = dict(OLD, libssl3t64="3.0.13-0ubuntu3.5", openssl="3.0.13-0ubuntu3.5")
    del pk["curl"]
    r2 = do_run([host(1, pk)])
    got = {(e.package, e.kind, e.cause, e.needs_ticket) for e in events(r2)}
    assert got == {("libssl3t64", "resolved", "patched", True), ("openssl", "resolved", "patched", True),
                   ("curl", "resolved", "removed", True)}
    assert PackageChange.objects.filter(run=r2).count() == 3
    # 降版：修好的又出現
    r3 = do_run([host(1, dict(pk, openssl="3.0.13-0ubuntu3.4"))])
    (e,) = events(r3)
    assert (e.package, e.kind, e.cause, e.needs_ticket) == ("openssl", "reappeared", "package_change", False)
    assert Finding.objects.get(package="openssl").resolved_at is None


def test_new_advisory_and_revision(tmp_path):
    import_osv(tmp_path, "osv1.tar.xz", OSV1)
    do_run([host(1, OLD)])
    osv2 = [
        # 修正版本下修：主機的版本已經不受影響 → 公告修訂，不用單號
        osv_record("CVE-2026-0001", [(ECO, "openssl", "3.0.13-0ubuntu3.4", {"libssl3t64": "", "openssl": ""})]),
        OSV1[1],
        osv_record("CVE-2026-0003", [(ECO, "bash", "5.2.21-2ubuntu4.1", {"bash": ""})], priority="critical"),
    ]
    imp2 = import_osv(tmp_path, "osv2.tar.xz", osv2)
    assert imp2.change_counts == {"added": 1, "fixed_changed": 1}
    assert AdvisoryChange.objects.filter(imp=imp2, kind="added", cve="CVE-2026-0003").exists()
    r2 = do_run([host(1, OLD)], trigger="osv")
    got = {(e.cve, e.package, e.kind, e.cause, e.needs_ticket) for e in events(r2)}
    assert got == {("CVE-2026-0001", "libssl3t64", "resolved", "advisory_revised", False),
                   ("CVE-2026-0001", "openssl", "resolved", "advisory_revised", False),
                   ("CVE-2026-0003", "bash", "appeared", "new_advisory", False)}


def test_fix_released(tmp_path, settings):
    settings.CVETRACK["INCLUDE_UNFIXED"] = True
    import_osv(tmp_path, "osv1.tar.xz", [osv_record("CVE-2026-0009", [(ECO, "bash", None, {"bash": ""})])])
    do_run([host(1, OLD)])
    assert Finding.objects.get().status == "no-fix"
    import_osv(tmp_path, "osv2.tar.xz", [osv_record("CVE-2026-0009", [(ECO, "bash", "5.2.21-2ubuntu4.1", {"bash": ""})])])
    r2 = do_run([host(1, OLD)], trigger="osv")
    (e,) = events(r2)
    assert (e.kind, e.cause, e.old["status"], e.new["status"]) == ("changed", "fix_released", "no-fix", "fix-available")


def test_new_and_retired_host(tmp_path):
    import_osv(tmp_path, "osv1.tar.xz", OSV1)
    do_run([host(1, OLD)])
    r2 = do_run([host(1, OLD), host(2, OLD)])
    assert {(e.host.landscape_id, e.kind, e.cause) for e in events(r2)} == {(2, "appeared", "new_host")}
    r3 = do_run([host(2, OLD)])
    assert {(e.host.landscape_id, e.kind, e.cause, e.needs_ticket) for e in events(r3)} == {(1, "resolved", "host_retired", False)}
    assert not Host.objects.get(landscape_id=1).active
    # 主機回來：當成新主機
    r4 = do_run([host(1, OLD), host(2, OLD)])
    assert {(e.host.landscape_id, e.kind, e.cause) for e in events(r4)} == {(1, "reappeared", "new_host")}


KOLD = "6.8.0-100.100"
KNEW = "6.8.0-110.110"


def kernel_osv():
    return [osv_record("CVE-2026-1000", [(ECO, "linux", KNEW, {"linux-image-6.8.0-110-generic": KNEW,
                                                                    "linux-image-6.8.0-100-generic": KNEW})])]


def test_kernel_need_reboot_then_rebooted(tmp_path):
    import_osv(tmp_path, "osv1.tar.xz", kernel_osv())
    k_old = {"release": "6.8.0-100-generic", "version": KOLD, "collected_at": "auto"}
    pk = {"linux-image-6.8.0-100-generic": KOLD}
    do_run([host(1, pk, kernel=k_old)])
    f = Finding.objects.get()
    assert (f.location, f.action) == ("running-kernel", "upgrade+reboot")
    # 裝了新 kernel、還沒重開機
    pk2 = dict(pk, **{"linux-image-6.8.0-110-generic": KNEW})
    r2 = do_run([host(1, pk2, kernel=k_old)])
    (e,) = events(r2)
    assert (e.kind, e.cause) == ("changed", "need_reboot")
    # 重開機
    r3 = do_run([host(1, pk2, kernel={"release": "6.8.0-110-generic", "version": KNEW, "collected_at": "auto"})])
    (e,) = events(r3)
    assert (e.kind, e.cause, e.needs_ticket) == ("resolved", "rebooted", True)


def test_kernel_api_error_keeps_open(tmp_path):
    import_osv(tmp_path, "osv1.tar.xz", kernel_osv())
    pk = {"linux-image-6.8.0-100-generic": KOLD}
    do_run([host(1, pk, kernel={"release": "6.8.0-100-generic", "version": KOLD, "collected_at": "auto"})])
    h = dict(host(1, pk), kernel_error=True)
    r2 = do_run([h])
    assert events(r2) == [] and Finding.objects.get().resolved_at is None


def test_old_kernel_superseded_is_patched(tmp_path):
    """沒有 kernel API：裝了新 kernel 後舊 kernel 不再比對 → 已修補"""
    import_osv(tmp_path, "osv1.tar.xz", kernel_osv())
    pk = {"linux-image-6.8.0-100-generic": KOLD}
    do_run([host(1, pk)])
    r2 = do_run([host(1, dict(pk, **{"linux-image-6.8.0-110-generic": KNEW}))])
    (e,) = events(r2)
    assert (e.package, e.kind, e.cause) == ("linux-image-6.8.0-100-generic", "resolved", "patched")


def test_excepted_flag(tmp_path):
    import_osv(tmp_path, "osv1.tar.xz", OSV1)
    RiskException.objects.create(host_pattern="HOST1.*", cve="CVE-2026-0002", reason="test")
    r1 = do_run([host(1, OLD)])
    assert {e.cve: e.excepted for e in events(r1)} == {"CVE-2026-0001": False, "CVE-2026-0002": True}


def test_failed_import_keeps_old_data(tmp_path):
    imp1 = import_osv(tmp_path, "osv1.tar.xz", OSV1)
    with pytest.raises(ValueError):
        import_osv(tmp_path, "bad.tar.xz", [osv_record("CVE-2026-0005", [("Ubuntu:22.04:LTS", "x", "1", {"x": ""})])])
    imp1.refresh_from_db()
    assert imp1.active
    r = do_run([host(1, OLD)])
    assert r.open_findings == 3


def test_fix_released_appears_when_unfixed_hidden(tmp_path):
    """預設不列尚無修正的弱點：釋出修正後才出現，原因是「釋出修正」"""
    import_osv(tmp_path, "osv1.tar.xz", [osv_record("CVE-2026-0009", [(ECO, "bash", None, {"bash": ""})])])
    r1 = do_run([host(1, OLD)])
    assert r1.open_findings == 0
    import_osv(tmp_path, "osv2.tar.xz", [osv_record("CVE-2026-0009", [(ECO, "bash", "5.2.21-2ubuntu4.1", {"bash": ""})])])
    r2 = do_run([host(1, OLD)], trigger="osv")
    (e,) = events(r2)
    assert (e.kind, e.cause, e.needs_ticket) == ("appeared", "fix_released", False)


def test_failed_run_changes_count_in_next_run(tmp_path):
    """Run 中途失敗：已寫入的套件差異，下一次成功的 Run 仍要算成已修補（要單號）"""
    from cvetrack.core import runs
    import_osv(tmp_path, "osv1.tar.xz", OSV1)
    do_run([host(1, OLD), host(2, OLD)])
    pk = dict(OLD, libssl3t64="3.0.13-0ubuntu3.5", openssl="3.0.13-0ubuntu3.5")

    def broken():
        yield host(1, pk)
        raise RuntimeError("Landscape 逾時")
    with pytest.raises(RuntimeError):
        runs.run(source=broken())
    r3 = do_run([host(1, pk), host(2, OLD)])
    got = {(e.host.landscape_id, e.package, e.cause, e.needs_ticket) for e in events(r3)}
    assert got == {(1, "libssl3t64", "patched", True), (1, "openssl", "patched", True)}


def test_new_host_in_failed_run_still_new_host(tmp_path):
    from cvetrack.core import runs
    import_osv(tmp_path, "osv1.tar.xz", OSV1)
    do_run([host(1, OLD)])

    def broken():
        yield host(1, OLD)
        yield host(2, OLD)
        raise RuntimeError("x")
    with pytest.raises(RuntimeError):
        runs.run(source=broken())
    r3 = do_run([host(1, OLD), host(2, OLD)])
    assert {(e.host.landscape_id, e.cause) for e in events(r3)} == {(2, "new_host")}


def test_retire_guard(tmp_path):
    import_osv(tmp_path, "osv1.tar.xz", OSV1)
    do_run([host(i, OLD) for i in range(1, 7)])
    with pytest.raises(RuntimeError, match="不停用"):
        do_run([])                                         # Landscape 回傳 0 台
    with pytest.raises(RuntimeError, match="不停用"):
        do_run([host(1, OLD), host(2, OLD)])               # 6 台少了 4 台
    assert Host.objects.filter(active=True).count() == 6
    r = do_run([host(i, OLD) for i in range(1, 6)])        # 少 1 台：正常移除
    assert {e.cause for e in events(r)} == {"host_retired"}


def test_kernel_stale_keeps_running_findings(tmp_path):
    import_osv(tmp_path, "osv1.tar.xz", kernel_osv())
    pk = {"linux-image-6.8.0-100-generic": KOLD}
    do_run([host(1, pk, kernel={"release": "6.8.0-100-generic", "version": KOLD, "collected_at": "auto"})])
    old = {"release": "6.8.0-100-generic", "version": KOLD, "collected_at": "2020-01-01T00:00:00"}
    r2 = do_run([host(1, pk, kernel=old)])                 # 資料過舊
    assert not events(r2, location="running-kernel")
    assert Finding.objects.get(location="running-kernel").resolved_at is None
    # 只回 uname -r、而且對應的套件已移除（kver 是 None）：不能當成重開機
    r3 = do_run([host(1, {}, kernel={"release": "6.8.0-100-generic", "version": "", "collected_at": "auto"})])
    assert not events(r3, cause="rebooted")


def test_advisory_change_other_release_not_used(tmp_path):
    """24.04 釋出修正、同時 22.04 第一次加入這個 CVE：24.04 主機的原因是「釋出修正」，不是 22.04 的「新公告」"""
    import_osv(tmp_path, "osv1.tar.xz", [osv_record("CVE-2026-0003", [(ECO, "bash", None, {"bash": ""})])])
    do_run([host(1, OLD)])
    import_osv(tmp_path, "osv2.tar.xz", [osv_record("CVE-2026-0003", [(ECO, "bash", "5.2.21-2ubuntu4.1", {"bash": ""}),
                                                                       ("Ubuntu:22.04:LTS", "bash", "5.1-6ubuntu1.1", {"bash": ""})])])
    r = do_run([host(1, OLD)])
    (e,) = events(r)
    assert (e.kind, e.cause) == ("appeared", "fix_released")


def test_interrupted_run_and_import_cleaned(tmp_path):
    from django.utils import timezone
    from cvetrack.models import OsvImport, Affected, Run
    imp1 = import_osv(tmp_path, "osv1.tar.xz", OSV1)
    stale_run = Run.objects.create(started_at=timezone.now(), trigger="schedule", status="running")
    stale_imp = OsvImport.objects.create(filename="x", sha256="0", imported_at=timezone.now(), releases="24.04", status="loading")
    Affected.objects.create(imp=stale_imp.id, ecosystem=ECO, source="x", cve="CVE-1")
    do_run([host(1, OLD)])
    stale_run.refresh_from_db()
    assert stale_run.status == "failed"
    import_osv(tmp_path, "osv2.tar.xz", OSV1)
    stale_imp.refresh_from_db()
    assert stale_imp.status == "failed" and not Affected.objects.filter(imp=stale_imp.id).exists()
    assert imp1.id


def test_reboot_detected_after_stale_period(tmp_path):
    """kernel 資料過舊的期間重開機：恢復正常後仍要判斷成已重開機"""
    import_osv(tmp_path, "osv1.tar.xz", kernel_osv())
    pk = {"linux-image-6.8.0-100-generic": KOLD, "linux-image-6.8.0-110-generic": KNEW}
    do_run([host(1, pk, kernel={"release": "6.8.0-100-generic", "version": KOLD, "collected_at": "auto"})])
    r2 = do_run([host(1, pk, kernel={"release": "6.8.0-100-generic", "version": KOLD, "collected_at": "2020-01-01T00:00:00"})])
    assert events(r2) == []                       # 過舊：沒有任何事件（也不會冒出 installed 的 kernel 弱點）
    r3 = do_run([host(1, pk, kernel={"release": "6.8.0-110-generic", "version": KNEW, "collected_at": "auto"})])
    assert {(e.cause, e.needs_ticket) for e in events(r3)} == {("rebooted", True)}


def test_failed_run_after_host_evaluated_not_double_counted(tmp_path, monkeypatch):
    """失敗的 Run 已經比對過 host1（事件已寫入）：下一次不能再拿同一批套件差異當原因"""
    from cvetrack.core import runs
    import_osv(tmp_path, "osv1.tar.xz", OSV1)
    do_run([host(1, OLD), host(2, OLD)])
    pk = dict(OLD, libssl3t64="3.0.13-0ubuntu3.5", openssl="3.0.13-0ubuntu3.5")
    real = runs.update_findings
    calls = []

    def flaky(ctx, h, current, skip):
        calls.append(h.landscape_id)
        if len(calls) == 2:
            raise RuntimeError("database is locked")
        return real(ctx, h, current, skip)
    monkeypatch.setattr(runs, "update_findings", flaky)
    with pytest.raises(RuntimeError):
        runs.run(source=[host(1, pk), host(2, OLD)])
    monkeypatch.setattr(runs, "update_findings", real)
    assert FindingEvent.objects.filter(cause="patched").count() == 2          # 失敗的 Run 已寫入 host1 的事件
    # 新 OSV 讓 openssl 有新的 CVE：原因是新公告，不是「主機套件變更」
    import_osv(tmp_path, "osv2.tar.xz", OSV1 + [osv_record("CVE-2026-0010", [(ECO, "openssl", "3.0.13-0ubuntu3.6", {"openssl": ""})])])
    r3 = do_run([host(1, pk), host(2, OLD)], trigger="osv")
    assert {(e.host.landscape_id, e.cause) for e in events(r3)} == {(1, "new_advisory"), (2, "new_advisory")}


def test_retire_guard_small_fleet(tmp_path):
    import_osv(tmp_path, "osv1.tar.xz", OSV1)
    do_run([host(i, OLD) for i in range(1, 4)])
    with pytest.raises(RuntimeError, match="不停用"):
        do_run([host(1, OLD)])                     # 3 台少了 2 台（67%）


def test_is_busy(settings):
    from cvetrack.core.lock import is_busy, job_lock
    assert not is_busy()
    with job_lock():
        assert is_busy()
    assert not is_busy()


def test_kernel_keep_limits(tmp_path, settings):
    """沿用上一次可信的 kernel：超過 KERNEL_KEEP_DAYS 不再沿用；API 回報換了 release 也不沿用"""
    import datetime
    from django.utils import timezone
    import_osv(tmp_path, "osv1.tar.xz", kernel_osv())
    pk = {"linux-image-6.8.0-100-generic": KOLD}
    do_run([host(1, pk, kernel={"release": "6.8.0-100-generic", "version": KOLD, "collected_at": "auto"})])
    h = Host.objects.get()
    assert (h.kernel_status, h.kernel_version) == ("ok", KOLD)
    # 只回 release（換了）、找不到版本：不沿用舊的
    do_run([host(1, pk, kernel={"release": "6.8.0-110-generic", "version": "", "collected_at": "auto"})])
    h.refresh_from_db()
    assert (h.kernel_status, h.kernel_release) == ("missing", None)
    # 可信資料超過 7 天：不再沿用
    do_run([host(1, pk, kernel={"release": "6.8.0-100-generic", "version": KOLD, "collected_at": "auto"})])
    old = (timezone.now() - datetime.timedelta(days=8)).isoformat()
    Host.objects.update(kernel_collected_at=old)
    do_run([host(1, pk, kernel=None)])
    h.refresh_from_db()
    assert h.kernel_release is None
