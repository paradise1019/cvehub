"""0.9.14：code review 找到的邏輯錯誤"""
import os
import unittest
from unittest import mock

from cvehub import impact, osv_import, period, report, sources, sync
from cvehub.config import Config
from tests.helpers import RECORDS, E, TempEnv, make_osv_tar, osv_record
from tests.test_sync import add_host

HWE65 = osv_record("CVE-2026-0110", [(E, "linux-hwe-6.5", None, {"linux-image-6.5.0-45-generic": ""})], "high")


class Base(unittest.TestCase):
    records = RECORDS

    def setUp(self):
        self.env = TempEnv().__enter__()
        osv_import.import_file(self.env.con, make_osv_tar(os.path.join(self.env.dir.name, "o.tar.xz"), self.records))

    def tearDown(self):
        self.env.__exit__()


class KernelTest(Base):
    records = RECORDS + [HWE65]
    RUN = {"release": "6.8.0-139-generic", "version": "6.8.0-139.139", "status": "ok"}

    def test_newest_kernel_same_flavour_only(self):
        """別的 flavour 較新不算：重開機後還是開 generic，要先更新"""
        pk = {"linux-image-6.8.0-139-generic": "6.8.0-139.139", "linux-image-6.8.0-150-lowlatency": "6.8.0-150.150.1"}
        self.assertEqual(sync._newest_kernel_version(pk, "6.8.0-139-generic"), "6.8.0-139.139")
        h = add_host(self.env.con, pk, kernel=self.RUN)
        r = sync.evaluate_host(self.env.con, h)[("CVE-2026-0005", "kernel 6.8.0-139-generic", "running-kernel")]
        self.assertEqual(r["action"], "upgrade+reboot")

    def test_host_sources_only_running_kernel(self):
        """尚無修正（host_sources）和比對一樣：執行中的 kernel 已知時，其他已安裝的 kernel（停止支援的 HWE 6.5）不算"""
        c = self.env.con
        pk = {"linux-image-6.8.0-139-generic": "6.8.0-139.139", "linux-image-6.5.0-45-generic": "6.5.0-45.45~22.04.1",
              "openssl": "3.0.13-0ubuntu3"}
        h = add_host(c, pk, kernel=self.RUN)
        self.assertEqual(period.host_sources(c)[h["id"]][1], {"linux", "openssl"})
        h2 = add_host(c, pk, "nokernel.example.com")                          # 不知道執行中的 kernel：已安裝的都看（和比對相同）
        self.assertIn("linux-hwe-6.5", period.host_sources(c)[h2["id"]][1])


class CveDetailTest(Base):
    records = RECORDS + [HWE65]
    def finding(self, hid, package, status, first_seen):
        self.env.con.execute("INSERT INTO finding(host_id,cve,package,location,source,installed,running,fixed,status,repo,action,priority,"
                             "first_seen,last_seen) VALUES (?,?,?,'installed','openssl','1','',?,?,'ubuntu','upgrade','high',?,?)",
                             (hid, "CVE-2026-0001", package, "3.0.13-0ubuntu3.4" if status != "no-fix" else "", status, first_seen, first_seen))
        self.env.con.commit()

    def state(self, hid):
        return {x["host_id"]: x["state"] for x in impact.cve_detail(self.env.con, "CVE-2026-0001")[1]}[hid]

    def test_any_pending_finding_is_pending(self):
        h = add_host(self.env.con, {"openssl": "3.0.13-0ubuntu3", "libssl3t64": "3.0.13-0ubuntu3"})
        self.finding(h["id"], "libssl3t64", "no-fix", "2026-01-01T00:00:00")          # 最早的那筆不是待更新
        self.finding(h["id"], "openssl", "fix-available", "2026-02-01T00:00:00")
        self.assertEqual(self.state(h["id"]), "pending")

    def test_finding_source_listed_even_if_not_running(self):
        """換了 kernel 之後，舊 kernel（不再算進 host_sources）的已修正紀錄仍列在 CVE 頁"""
        c = self.env.con
        h = add_host(c, {"openssl": "3.0.13-0ubuntu3.4"}, kernel={"release": "6.8.0-147-generic", "version": "6.8.0-147.147", "status": "ok"})
        c.execute("INSERT INTO finding(host_id,cve,package,location,source,installed,running,fixed,status,repo,action,priority,"
                  "first_seen,last_seen,resolved_at) VALUES (?,'CVE-2026-0001','linux-image-6.5.0-45-generic','installed','linux-hwe-6.5',"
                  "'1','','2','fix-available','ubuntu','upgrade','high','2026-01-01','2026-01-02','2026-01-02')", (h["id"],))
        c.commit()
        rows = [(x["package"], x["state"]) for x in impact.cve_detail(c, "CVE-2026-0001")[1] if x["host_id"] == h["id"]]
        self.assertIn(("linux-hwe-6.5", "fixed"), rows)

    def test_old_kernel_resolved_finding_is_fixed_not_nofix(self):
        """沒在執行的舊 HWE：官方狀態尚未修正，但這台的紀錄已解決 → 已修正（「尚無修正」只算執行中的）"""
        c = self.env.con
        h = add_host(c, {"linux-image-6.8.0-147-generic": "6.8.0-147.147", "linux-image-6.5.0-45-generic": "6.5.0-45.45"},
                     kernel={"release": "6.8.0-147-generic", "version": "6.8.0-147.147", "status": "ok"})
        c.execute("INSERT INTO finding(host_id,cve,package,location,source,installed,running,fixed,status,repo,action,priority,"
                  "first_seen,last_seen,resolved_at) VALUES (?,'CVE-2026-0110','linux-image-6.5.0-45-generic','installed','linux-hwe-6.5',"
                  "'1','','','no-fix','','','high','2026-01-01','2026-01-02','2026-01-02')", (h["id"],))
        c.commit()
        rows = {x["package"]: x["state"] for x in impact.cve_detail(c, "CVE-2026-0110")[1] if x["host_id"] == h["id"]}
        self.assertEqual(rows, {"linux-hwe-6.5": "fixed"})
        h2 = add_host(c, {"linux-image-6.5.0-45-generic": "6.5.0-45.45"}, "running65.example.com",
                      kernel={"release": "6.5.0-45-generic", "version": "6.5.0-45.45", "status": "ok"})
        rows = {x["package"]: x["state"] for x in impact.cve_detail(c, "CVE-2026-0110")[1] if x["host_id"] == h2["id"]}
        self.assertEqual(rows, {"linux-hwe-6.5": "nofix"})                          # 執行中的照官方狀態

    def test_open_no_fix_finding_is_not_fixed(self):
        h = add_host(self.env.con, {"openssl": "3.0.13-0ubuntu3"})
        self.finding(h["id"], "openssl", "no-fix", "2026-01-01T00:00:00")
        self.assertEqual(self.state(h["id"]), "nofix")                              # 之前：已修正


class ReportTest(Base):
    def test_summary_keeps_hosts_with_same_name_apart(self):
        rows = [{"host_id": i, "hostname": "web01.example.com", "cve": "CVE-1", "priority": "high", "status": "fix-available",
                 "package": "openssl", "running": "", "installed": "1", "fixed": "2", "action": "upgrade",
                 "first_seen": "2026-01-01", "exception": ""} for i in (1, 2)]
        self.assertEqual(len(report.summary_by_host_cve(rows)), 2)

    def test_old_reports_pruned(self):
        d = Config.REPORT_DIR
        os.makedirs(d)
        for i in range(35):
            for name in ("cve-detail-202501%02d-0600.csv" % (i % 28 + 1), "cve-summary-2025%02d01-0600.csv" % (i % 12 + 1)):
                open(os.path.join(d, name.replace("0600", "06%02d" % i)), "w").close()
        open(os.path.join(d, "cve-quarterly-20260101-20260331.xlsx"), "w").close()     # 手動輸出的不動
        open(os.path.join(d, "cve-detail-before-upgrade.csv"), "w").close()              # 自己放的也不動
        report.write_reports(self.env.con)
        names = os.listdir(d)
        self.assertEqual(sum(n.startswith("cve-summary-") for n in names), 30)
        self.assertIn("cve-quarterly-20260101-20260331.xlsx", names)
        self.assertIn("cve-detail-before-upgrade.csv", names)
        self.assertEqual(sum(n.startswith("cve-detail-") and n.endswith(".csv") for n in names), 31)
        import datetime
        today = datetime.datetime.now().strftime("%Y%m%d")
        self.assertTrue(any(n.startswith("cve-detail-" + today) for n in names))     # 這次產生的還在


class KernelIndexTest(Base):
    A = {"release": "6.8.0-50-generic", "version": "6.8.0-50.50", "collected_at": ""}
    B = {"release": "6.8.0-62-generic", "version": "6.8.0-62.62", "collected_at": ""}

    def test_same_short_name_not_mixed(self):
        idx = sources.KernelIndex()
        idx.add("web01.a.example.com", self.A)
        idx.add("web01.b.example.com", self.B)
        self.assertEqual(idx.get("web01.a.example.com", ""), (self.A, None))
        self.assertEqual(idx.get("WEB01.b.example.com", ""), (self.B, None))
        self.assertIn("web01.a.example.com", idx.get("web01", "")[1])               # 分不出是哪一台
        self.assertIsNone(idx.get("web01", "")[0])
        self.assertEqual(idx.get("web01.c.example.com", "", same_key=2)[0], None)
        self.assertTrue(idx.get("web01.c.example.com", "", same_key=2)[1])
        dup = sources.KernelIndex()
        dup.add("web02", self.A)
        dup.add("web02.example.com", self.A)                                        # 同一台的重複資料
        self.assertEqual(dup.get("web02.x.example.com", ""), (self.A, None))

    def test_same_machine_twice(self):
        """同一個名稱有新舊兩筆（重新收集、重新註冊）：取收集時間最新的；有名稱完全相同的就只用它"""
        old, new = dict(self.A, collected_at="2026-11-01T00:00:00"), dict(self.B, collected_at="2026-11-17T00:00:00")
        for order in ((old, new), (new, old)):
            idx = sources.KernelIndex()
            idx.add("web01.example.com", order[0])
            idx.add("web01.example.com", order[1])
            self.assertEqual(idx.get("web01.example.com", ""), (new, None))
        idx = sources.KernelIndex()
        idx.add("web01.example.com", old)
        idx.add("web01", new)
        self.assertEqual(idx.get("web01.example.com", ""), (old, None))
        self.assertEqual(idx.get("web01.other.example.com", ""), (new, None))     # 沒有完全相同的：web01 和 web01.example.com 是同一台

    def test_names_compared_case_insensitively(self):
        """名稱一律不分大小寫：HOST_MATCH_CASE_INSENSITIVE=false 時同一組裡只差大小寫也算名稱完全相同"""
        saved = Config.HOST_MATCH_CASE_INSENSITIVE
        Config.HOST_MATCH_CASE_INSENSITIVE = False
        try:
            idx = sources.KernelIndex()
            idx.add("web01.A.example.com", self.A)
            idx.add("web01.b.example.com", self.B)
            self.assertEqual(idx.get("web01.a.example.com", "", same_key=2), (self.A, None))
            short = sources.KernelIndex()                                           # 第一段大小寫不同：不同組
            short.add("Web01", self.A)
            short.add("web01", self.B)
            self.assertEqual(short.get("Web01", ""), (self.A, None))
            self.assertEqual(short.get("web01", ""), (self.B, None))
            self.assertEqual(short.get("WEB01", ""), (None, None))
        finally:
            Config.HOST_MATCH_CASE_INSENSITIVE = saved

    def test_trailing_dot_ignored(self):
        saved = Config.HOST_MATCH_KEY
        Config.HOST_MATCH_KEY = "hostname"
        try:
            idx = sources.KernelIndex()
            idx.add("web01.example.com.", self.A)
            self.assertEqual(idx.get("web01.example.com", ""), (self.A, None))
            rev = sources.KernelIndex()
            rev.add("web01.example.com", self.A)
            self.assertEqual(rev.get("web01.example.com.", ""), (self.A, None))     # Landscape 那邊有點
        finally:
            Config.HOST_MATCH_KEY = saved

    def kernel_api_with(self, rows, mode):
        import io
        import json
        saved = Config.KERNEL_API_URL, Config.KERNEL_API_MODE, Config.HOST_MATCH_KEY
        Config.KERNEL_API_URL, Config.KERNEL_API_MODE, Config.HOST_MATCH_KEY = "https://k/", "bulk", mode
        try:
            with mock.patch.object(sources.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(rows).encode())):
                return sources.kernel_api()
        finally:
            Config.KERNEL_API_URL, Config.KERNEL_API_MODE, Config.HOST_MATCH_KEY = saved

    def test_rows_without_text_host_skipped(self):
        """不是物件、沒有主機欄位、主機欄位不是文字：略過並記 log，其他照常；主機名稱是空的照舊靜默略過；
        有資料卻一筆都用不上（欄位名稱設錯等）時整批失敗（/healthz 回報 kernel_api_error）"""
        good = {"hostname": "10.0.0.6", "kernel_release": "6.8.0-2-generic", "kernel_version": "6.8.0-2.2"}
        rows = [{"hostname": {"v4": "10.0.0.5"}}, {"hostname": 12345}, {"hostname": True}, "junk", {"host": "x"},
                {"hostname": None}, {"hostname": ""}, {"hostname": "  "}, good]
        rows_short = rows + [{"hostname": ".corp.example.com"}]                     # shortname：比對值是空的
        for mode in ("shortname", "hostname", "ip"):
            with self.assertLogs("cvehub.sources", "WARNING") as cm:
                idx = self.kernel_api_with(rows_short if mode == "shortname" else rows, mode)
            self.assertTrue(any("有 %d 筆資料" % (6 if mode == "shortname" else 5) in m for m in cm.output), (mode, cm.output))
            saved, Config.HOST_MATCH_KEY = Config.HOST_MATCH_KEY, mode
            try:
                self.assertEqual(idx.get("10.0.0.6", "10.0.0.6")[0]["release"], "6.8.0-2-generic", mode)
                self.assertEqual(idx.get("12345", "12345"), (None, None), mode)
                self.assertEqual(idx.get("True", "True"), (None, None), mode)
            finally:
                Config.HOST_MATCH_KEY = saved
            for unusable in ([{"hostname": 1}, {"hostname": 2}], [{"host": "web01"}, {"host": "web02"}],   # 欄位名稱設錯
                             [{"hostname": "  "}, {"hostname": None}]):
                with self.assertRaises(ValueError):
                    self.kernel_api_with(unusable, mode)
            self.assertEqual(len(self.kernel_api_with([], mode).by_key), 0)               # 沒有資料：不算錯
            self.assertEqual(self.kernel_api_with([{"hostname": ""}, good], mode).get("10.0.0.6", "10.0.0.6")[0]["version"], "6.8.0-2.2")

    def test_many_names_listed_briefly(self):
        idx = sources.KernelIndex()
        for i in range(8):
            idx.add("web01.d%d.example.com" % i, dict(self.A, version="6.8.0-%d.1" % i))
        reason = idx.get("web01", "")[1]
        self.assertIn("…等 8 個名稱", reason)
        self.assertIn("web01.d0.example.com", reason)

    def test_cloned_name_and_cross_domain_and_ip(self):
        idx = sources.KernelIndex()
        idx.add("web01.a.example.com", self.A)
        self.assertIn("改名", idx.get("web01.a.example.com", "", same_name=2)[1])   # 兩台同名的電腦
        cross = sources.KernelIndex()
        cross.add("web01.corp.example.com", self.A)
        self.assertEqual(cross.get("web01.lan", ""), (self.A, None))               # 短名稱對應跨網域照舊
        saved_q, Config.LANDSCAPE_QUERY = Config.LANDSCAPE_QUERY, "tag:prod"
        try:                                                                        # 只看得到部分電腦：名稱不同的不用
            self.assertEqual(cross.get("web01.lan", "")[0], None)
            self.assertIn("LANDSCAPE_QUERY", cross.get("web01.lan", "")[1])
            self.assertEqual(cross.get("web01", ""), (self.A, None))
        finally:
            Config.LANDSCAPE_QUERY = saved_q
        saved, Config.HOST_MATCH_KEY = Config.HOST_MATCH_KEY, "ip"
        try:
            ipx = sources.KernelIndex()
            ipx.add("10.0.0.5", dict(self.A, collected_at="2026-11-01T00:00:00"))
            ipx.add("10.0.0.5", dict(self.B, collected_at="2026-11-17T00:00:00"))
            self.assertEqual(ipx.get("web01", "10.0.0.5")[0]["release"], self.B["release"])
            self.assertIn("10.0.0.5", ipx.get("web01", "10.0.0.5", same_key=2)[1])
        finally:
            Config.HOST_MATCH_KEY = saved

    def test_sync_gives_each_host_its_own_kernel(self):
        c = self.env.con
        idx = sources.KernelIndex()
        idx.add("web01.a.example.com", dict(self.A, collected_at=sync.now()))
        idx.add("web01.b.example.com", dict(self.B, collected_at=sync.now()))
        comps = [{"id": i, "hostname": n, "title": n, "distribution": "24.04"}
                 for i, n in ((1, "web01.a.example.com"), (2, "web01.b.example.com"))]
        ls = mock.Mock()
        ls.computers.return_value = comps
        ls.installed_packages.return_value = {"linux-image-6.8.0-50-generic": "6.8.0-50.50", "linux-image-6.8.0-62-generic": "6.8.0-62.62"}
        saved = Config.KERNEL_API_URL, Config.KERNEL_API_MODE
        Config.KERNEL_API_URL, Config.KERNEL_API_MODE = "http://k/", "bulk"
        try:
            with mock.patch.object(sync, "Landscape", return_value=ls), mock.patch.object(sync, "kernel_api", return_value=idx):
                sync.sync_hosts(c)
        finally:
            Config.KERNEL_API_URL, Config.KERNEL_API_MODE = saved
        got = {r["landscape_id"]: r["kernel_release"] for r in c.execute("SELECT landscape_id, kernel_release FROM host")}
        self.assertEqual(got, {1: "6.8.0-50-generic", 2: "6.8.0-62-generic"})


class KernelIndexSyncTest(Base):
    def test_cloned_names_get_no_kernel(self):
        """Landscape 有兩台名稱完全相同的電腦：kernel API 只有一筆也分不出是哪一台，兩台都當成沒有資料（記 log）"""
        c = self.env.con
        idx = sources.KernelIndex()
        idx.add("web01.example.com", {"release": "6.8.0-62-generic", "version": "6.8.0-62.62", "collected_at": sync.now()})
        comps = [{"id": i, "hostname": "web01.example.com", "title": "web01-%d" % i, "distribution": "24.04"} for i in (1, 2)]
        ls = mock.Mock()
        ls.computers.return_value = comps
        ls.installed_packages.return_value = {"linux-image-6.8.0-62-generic": "6.8.0-62.62"}
        saved = Config.KERNEL_API_URL, Config.KERNEL_API_MODE
        Config.KERNEL_API_URL, Config.KERNEL_API_MODE = "http://k/", "bulk"
        try:
            with mock.patch.object(sync, "Landscape", return_value=ls), mock.patch.object(sync, "kernel_api", return_value=idx), \
                    self.assertLogs("cvehub.sync", "WARNING") as cm:
                sync.sync_hosts(c)
        finally:
            Config.KERNEL_API_URL, Config.KERNEL_API_MODE = saved
        self.assertEqual(sum("改名" in m for m in cm.output), 2)                   # 兩台都記
        self.assertEqual([r[0] for r in c.execute("SELECT kernel_status FROM host")], ["missing", "missing"])


class UncomparedReleaseTest(Base):
    def test_landscape_host_with_other_release_is_reported(self):
        c = self.env.con
        ls = mock.Mock()
        ls.computers.return_value = [{"id": 1, "hostname": "old01", "title": "old01", "distribution": "18.04"},
                                     {"id": 2, "hostname": "new01", "title": "new01", "distribution": "24.04"}]
        ls.installed_packages.return_value = {"openssl": "1"}
        with mock.patch.object(sync, "Landscape", return_value=ls), self.assertLogs("cvehub.sync", "WARNING") as cm:
            sync.sync_hosts(c)
        self.assertTrue(any("old01" in m and "UBUNTU_RELEASES" in m for m in cm.output))
        self.assertEqual(sync.uncompared_hosts(c), ["old01"])
