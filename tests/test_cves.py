"""歷年弱點（cves.py）：搜尋、年度頁籤、整體狀態、事先算好的狀態表、找不到時的說明"""
import os
import unittest

from cvehub import cves, osv_import
from tests.helpers import TempEnv, make_osv_tar, osv_record


class CvesTest(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv(UBUNTU_RELEASES=["22.04", "24.04"], OSV_MIN_ROWS_PER_RELEASE=1).__enter__()
        self.addCleanup(self.env.__exit__)
        c = self.env.con
        recs = [
            osv_record("CVE-2026-0001", [("Ubuntu:24.04:LTS", "openssl", "3.0.13-0ubuntu3.1", {"libssl3t64": "3.0.13-0ubuntu3.1"}),
                                         ("Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.10", {"libssl3": "3.0.2-0ubuntu1.10"})],
                       priority="high", details="OpenSSL buffer overflow"),
            osv_record("CVE-2026-0002", [("Ubuntu:24.04:LTS", "curl", None, {"curl": "8.5.0"}),
                                         ("Ubuntu:22.04:LTS", "curl", "7.81.0-1ubuntu1.20", {"curl": "7.81.0-1ubuntu1.20"})],
                       priority="medium", details="curl header injection"),
            osv_record("CVE-2025-0003", [("Ubuntu:24.04:LTS", "apt", None, {"apt": "2.8"}), ("Ubuntu:22.04:LTS", "apt", None, {"apt": "2.4"})],
                       priority="critical", details="APT remote code execution"),
            osv_record("CVE-2024-0004", [("Ubuntu:24.04:LTS", "linux-aws", None, {"linux-image-aws": "6.8"})],
                       priority="low", details="kernel variant only"),
        ]
        for r, pub in zip(recs, ["2026-03-01T00:00:00Z", "2026-02-01T00:00:00Z", "2025-05-01T00:00:00Z", "2024-01-01T00:00:00Z"]):
            r["published"] = pub
        osv_import.import_file(c, make_osv_tar(os.path.join(self.env.dir.name, "o.tar.xz"), recs))

    def ids(self, **kw):
        return [x["cve"] for x in cves.search(self.env.con, **kw)["rows"]]

    def test_list_years_and_filters(self):
        self.assertEqual(self.ids(), ["CVE-2026-0001", "CVE-2026-0002", "CVE-2025-0003", "CVE-2024-0004"])     # 新的在前
        r = cves.search(self.env.con)
        self.assertEqual(r["years"], [("2026", 2), ("2025", 1), ("2024", 1)])
        self.assertEqual(self.ids(year="2026"), ["CVE-2026-0001", "CVE-2026-0002"])
        self.assertEqual(self.ids(q="remote code"), ["CVE-2025-0003"])                       # 描述
        self.assertEqual(self.ids(q="cve-2026-0002"), ["CVE-2026-0002"])                     # 編號（不分大小寫）
        self.assertEqual(self.ids(q="2026-00"), ["CVE-2026-0001", "CVE-2026-0002"])         # 編號的一部分
        self.assertEqual(self.ids(priority="critical"), ["CVE-2025-0003"])
        self.assertEqual(self.ids(package="curl"), ["CVE-2026-0002"])
        self.assertEqual(cves.search(self.env.con, year="2026", priority="high")["years"], [("2026", 1)])  # 頁籤數字跟著其他篩選

    def test_overall_status_and_variants(self):
        rows = {x["cve"]: x for x in cves.search(self.env.con)["rows"]}
        self.assertEqual(rows["CVE-2026-0001"]["overall"]["code"], "fixed")
        o = rows["CVE-2026-0002"]["overall"]
        self.assertEqual((o["code"], o["fixed"], o["total"]), ("partial", 1, 2))
        self.assertIn("1／2", o["label"])
        self.assertEqual(rows["CVE-2025-0003"]["overall"]["code"], "vulnerable")
        self.assertEqual(rows["CVE-2024-0004"]["packages"], [])                              # 主機沒裝的 kernel 變體不列
        self.assertEqual(rows["CVE-2024-0004"]["overall"]["code"], "not-in-release")
        self.assertEqual(rows["CVE-2026-0001"]["packages"], ["openssl"])

    def test_overall_rules(self):
        o = cves.overall
        self.assertEqual(o([])["code"], "not-in-release")
        self.assertEqual(o(["none", "not-in-release"])["code"], "not-in-release")
        self.assertEqual(o(["fixed", "fixed"])["code"], "fixed")
        self.assertEqual(o(["fixed", "vulnerable", "none"])["code"], "partial")
        self.assertEqual(o(["not-affected", "not-affected"])["code"], "not-affected")
        self.assertEqual(o(["deferred", "needs-evaluation", "not-affected"])["code"], "needs-evaluation")     # 最需要注意的
        self.assertEqual(o(["fixed", "not-affected"])["code"], "fixed")
        self.assertEqual(o(["fixed", "not-affected", "ignored"])["code"], "partial")

    def test_release_filter(self):
        self.assertEqual(len(self.ids(release="22.04")), 4)                                  # 狀態表還沒算好：不套用
        cves.build_status(self.env.con)
        self.assertEqual(self.ids(release="22.04"), ["CVE-2026-0001", "CVE-2026-0002", "CVE-2025-0003"])
        rows = cves.search(self.env.con, release="24.04")["rows"]
        self.assertEqual([x["cve"] for x in rows], ["CVE-2026-0001", "CVE-2026-0002", "CVE-2025-0003"])       # 變體只在 24.04 但主機沒裝
        self.assertEqual({x["cve"]: x["overall"]["code"] for x in rows}["CVE-2026-0002"], "vulnerable")     # 只看 24.04

    def test_status_table(self):
        c = self.env.con
        r = cves.search(c, status="open")
        self.assertFalse(r["status_ready"])                                                 # 還沒算：不套用狀態篩選
        self.assertEqual(r["total"], 4)
        self.assertTrue(cves.build_status(c))
        self.assertFalse(cves.build_status(c))                                              # 資料沒變不重算
        self.assertEqual(self.ids(status="open"), ["CVE-2026-0002", "CVE-2025-0003"])
        self.assertEqual(self.ids(status="fixed"), ["CVE-2026-0001"])
        self.assertEqual(self.ids(status="partial"), ["CVE-2026-0002"])
        self.assertEqual(self.ids(status="not-affected"), ["CVE-2024-0004"])
        self.assertEqual(self.ids(status="fixed", release="22.04"), ["CVE-2026-0001", "CVE-2026-0002"])        # 只看 22.04
        osv_import.import_file(c, make_osv_tar(os.path.join(self.env.dir.name, "o2.tar.xz"),
                                               [osv_record("CVE-2026-0009", [("Ubuntu:24.04:LTS", "zlib", None, {"zlib1g": "1"}),
                                                                               ("Ubuntu:22.04:LTS", "zlib", None, {"zlib1g": "1"})])]))
        self.assertFalse(cves.ready(c))                                                     # 換了 OSV：要重算
        self.assertTrue(cves.build_status(c))

    def test_years_follow_status_filter(self):
        cves.build_status(self.env.con)
        r = cves.search(self.env.con, status="open")
        self.assertEqual(r["years"], [("2026", 1), ("2025", 1)])
        self.assertEqual(sum(n for _, n in r["years"]), r["total"])

    def test_installed_kernel_variant_counts(self):
        """主機有裝的 kernel 變體算進整體狀態（顯示與篩選一致）；裝了之後同步重算狀態表"""
        c = self.env.con
        cves.build_status(c)
        self.assertEqual(self.ids(status="open"), ["CVE-2026-0002", "CVE-2025-0003"])
        c.execute("INSERT INTO host(id, hostname, release, last_seen, active) VALUES (1,'aws01','24.04','x',1)")
        c.execute("INSERT INTO host_package VALUES (1, 'linux-image-aws', '6.8')")
        c.commit()
        self.assertTrue(cves.build_status(c))                                                # 變體改變：重算
        rows = {x["cve"]: x for x in cves.search(c)["rows"]}
        self.assertEqual(rows["CVE-2024-0004"]["packages"], ["linux-aws"])
        self.assertEqual(rows["CVE-2024-0004"]["overall"]["code"], "vulnerable")
        self.assertIn("CVE-2024-0004", self.ids(status="open"))

    def test_package_filter_shows_that_package(self):
        rows = cves.search(self.env.con, package="linux-aws")["rows"]
        self.assertEqual([(x["cve"], x["packages"]) for x in rows], [("CVE-2024-0004", ["linux-aws"])])

    def test_sync_rebuilds_after_hosts(self):
        """同步：主機匯入之後才判斷 kernel 變體，同一次同步就反映"""
        from cvehub import sync
        from cvehub.config import Config
        from unittest import mock
        c = self.env.con
        cves.build_status(c)
        os.makedirs(Config.HOSTS_INBOX_DIR, exist_ok=True)
        with open(os.path.join(Config.HOSTS_INBOX_DIR, "h.csv"), "w") as f:
            f.write("hostname,release,package,version\naws01,24.04,linux-image-aws,6.8\n")
        with mock.patch.object(Config, "HOST_SOURCE", "file"):
            sync.run_sync(c)
        self.assertIn("CVE-2024-0004", self.ids(status="open"))

    def test_not_found_notice(self):
        c = self.env.con
        n = cves.not_found_notice(c, "cve-2026-109518")
        self.assertEqual(n["cve"], "CVE-2026-109518")
        self.assertIn("ubuntu.com/security/CVE-2026-109518", n["url"])
        self.assertIsNotNone(n["osv_date"])
        self.assertIsNone(cves.not_found_notice(c, "CVE-2026-0001"))                         # 有收錄
        self.assertIsNone(cves.not_found_notice(c, "openssl"))                               # 不是編號

    def test_pending_hosts_count(self):
        c = self.env.con
        c.execute("INSERT INTO host(id, hostname, release, last_seen, active) VALUES (1,'web01','24.04','x',1),(2,'web02','24.04','x',0)")
        c.execute("INSERT INTO host(id, hostname, release, last_seen, active) VALUES (3,'web03','24.04','x',1)")
        c.execute("INSERT INTO finding(host_id,cve,package,location,priority,status,first_seen,last_seen) VALUES "
                  "(1,'CVE-2026-0001','libssl3t64','installed','high','fix-available','x','x'),"
                  "(2,'CVE-2026-0001','libssl3t64','installed','high','fix-available','x','x'),"
                  "(3,'CVE-2026-0001','libssl3t64','installed','high','no-fix','x','x')")
        c.commit()
        rows = {x["cve"]: x for x in cves.search(c)["rows"]}
        self.assertEqual(rows["CVE-2026-0001"]["pending_hosts"], 1)                          # 停用的主機、尚無修正的不算


if __name__ == "__main__":
    unittest.main()
