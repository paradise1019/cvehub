import os
import unittest

from cvehub import osv_import, sync
from tests.helpers import RECORDS, TempEnv, make_osv_tar


def add_host(con, packages, hostname="h1.example.com", pro=0, kernel=None):
    k = kernel or {}
    hid = con.execute("INSERT INTO host(landscape_id,hostname,release,pro_attached,package_count,last_seen,kernel_release,kernel_version,"
                      "kernel_status) VALUES (?,?,?,?,?,?,?,?,?)",
                      (abs(hash(hostname)) % 100000, hostname, "24.04", pro, len(packages), sync.now(),
                       k.get("release"), k.get("version"), k.get("status", "disabled"))).lastrowid
    con.executemany("INSERT INTO host_package VALUES (?,?,?)", [(hid, n, v) for n, v in packages.items()])
    con.commit()
    return con.execute("SELECT * FROM host WHERE id=?", (hid,)).fetchone()


class SyncTest(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv().__enter__()
        osv_import.import_file(self.env.con, make_osv_tar(os.path.join(self.env.dir.name, "o.tar.xz"), RECORDS))

    def tearDown(self):
        self.env.__exit__()

    def cves(self, res):
        return {k[0] for k in res}

    def test_fixed_and_unfixed_versions(self):
        c = self.env.con
        h = add_host(c, {"openssl": "3.0.13-0ubuntu3", "libssl3t64": "3.0.13-0ubuntu3", "curl": "8.5.0-2ubuntu10"})
        res = sync.evaluate_host(c, h)
        self.assertEqual(self.cves(res), {"CVE-2026-0001", "CVE-2026-0002"})      # 0003 未修正（預設不列）
        r = res[("CVE-2026-0001", "openssl", "installed")]
        self.assertEqual((r["status"], r["fixed"], r["action"], r["priority"]), ("fix-available", "3.0.13-0ubuntu3.4", "upgrade", "high"))

    def test_partially_patched(self):
        c = self.env.con
        h = add_host(c, {"openssl": "3.0.13-0ubuntu3.4"})                          # 已修 0001、未修 0002
        self.assertEqual(self.cves(sync.evaluate_host(c, h)), {"CVE-2026-0002"})

    def test_fully_patched(self):
        c = self.env.con
        h = add_host(c, {"openssl": "3.0.13-0ubuntu3.16", "libssl3t64": "3.0.13-0ubuntu3.16"})
        self.assertEqual(sync.evaluate_host(c, h), {})

    def test_include_unfixed(self):
        from cvehub.config import Config
        Config.INCLUDE_UNFIXED = True
        h = add_host(self.env.con, {"curl": "8.5.0-2ubuntu10"})
        res = sync.evaluate_host(self.env.con, h)
        self.assertEqual(res[("CVE-2026-0003", "curl", "installed")]["status"], "no-fix")

    def test_pro_only_fix(self):
        c = self.env.con
        h = add_host(c, {"nodejs": "18.19.1+dfsg-6ubuntu5"}, "nopro.example.com", pro=0)
        self.assertEqual(sync.evaluate_host(c, h)[("CVE-2026-0004", "nodejs", "installed")]["status"], "fix-in-pro")
        h2 = add_host(c, {"nodejs": "18.19.1+dfsg-6ubuntu5"}, "pro.example.com", pro=1)
        self.assertEqual(sync.evaluate_host(c, h2)[("CVE-2026-0004", "nodejs", "installed")]["status"], "fix-available")

    def test_old_kernel_skipped_without_kernel_api(self):
        c = self.env.con
        pk = {"linux-image-6.8.0-139-generic": "6.8.0-139.139", "linux-image-6.8.0-147-generic": "6.8.0-147.147"}
        self.assertEqual(sync.evaluate_host(c, add_host(c, pk)), {})                # 舊的 139 不看、147 已修

    def test_running_kernel_reboot(self):
        c = self.env.con
        pk = {"linux-image-6.8.0-139-generic": "6.8.0-139.139", "linux-image-6.8.0-147-generic": "6.8.0-147.147"}
        h = add_host(c, pk, kernel={"release": "6.8.0-139-generic", "version": "6.8.0-139.139", "status": "ok"})
        res = sync.evaluate_host(c, h)
        r = res[("CVE-2026-0005", "kernel 6.8.0-139-generic", "running-kernel")]
        self.assertEqual((r["action"], r["running"]), ("reboot", "6.8.0-139.139"))  # 147 已安裝 → 重開機即可

    def test_running_kernel_needs_upgrade(self):
        c = self.env.con
        pk = {"linux-image-6.8.0-139-generic": "6.8.0-139.139"}
        h = add_host(c, pk, kernel={"release": "6.8.0-139-generic", "version": "6.8.0-139.139", "status": "ok"})
        self.assertEqual(sync.evaluate_host(c, h)[("CVE-2026-0005", "kernel 6.8.0-139-generic", "running-kernel")]["action"],
                         "upgrade+reboot")

    def test_running_kernel_name_not_in_osv(self):
        """執行中 kernel 的 ABI 名稱沒出現在 OSV：要用同系列推回 source，不能漏掉"""
        c = self.env.con
        self.assertIsNone(c.execute("SELECT 1 FROM binmap WHERE binary='linux-image-6.8.0-139-generic'").fetchone())
        h = add_host(c, {}, kernel={"release": "6.8.0-139-generic", "version": "6.8.0-139.139", "status": "ok"})
        self.assertIn("CVE-2026-0005", self.cves(sync.evaluate_host(c, h)))

    def test_history_new_resolve_reopen(self):
        c = self.env.con
        h = add_host(c, {"openssl": "3.0.13-0ubuntu3"})
        self.assertEqual(sync.update_findings(c, h, sync.evaluate_host(c, h)), (2, 0))      # 新增 2
        self.assertEqual(sync.update_findings(c, h, sync.evaluate_host(c, h)), (0, 0))      # 不變
        c.execute("UPDATE host_package SET version='3.0.13-0ubuntu3.16' WHERE host_id=?", (h["id"],))
        self.assertEqual(sync.update_findings(c, h, sync.evaluate_host(c, h)), (0, 2))      # 修好 2
        self.assertEqual(c.execute("SELECT COUNT(*) FROM finding WHERE resolved_at IS NOT NULL").fetchone()[0], 2)
        c.execute("UPDATE host_package SET version='3.0.13-0ubuntu3' WHERE host_id=?", (h["id"],))
        self.assertEqual(sync.update_findings(c, h, sync.evaluate_host(c, h)), (2, 0))      # 降版又出現
        self.assertEqual(c.execute("SELECT COUNT(*) FROM finding WHERE resolved_at IS NULL").fetchone()[0], 2)

    def test_kernel_api_error_keeps_running_kernel(self):
        """kernel API 查詢失敗：沿用上次的執行中 kernel，不能把 kernel CVE 誤標成已解決"""
        from unittest import mock
        from cvehub.config import Config
        c = self.env.con
        Config.KERNEL_API_URL, Config.KERNEL_API_MODE = "http://k/?h={hostname}", "per-host"
        pk = {"linux-image-6.8.0-139-generic": "6.8.0-139.139", "linux-image-6.8.0-147-generic": "6.8.0-147.147"}
        ls = mock.Mock()
        ls.computers.return_value = [{"id": 7, "hostname": "k1.example.com", "title": "k1", "distribution": "24.04"}]
        ls.installed_packages.return_value = pk
        ok = {"release": "6.8.0-139-generic", "version": "Ubuntu 6.8.0-139.139-generic 6.8.12", "collected_at": sync.now()}
        with mock.patch.object(sync, "Landscape", return_value=ls), mock.patch.object(sync, "kernel_for_host", return_value=ok):
            sync.sync_hosts(c)
        h = c.execute("SELECT * FROM host WHERE landscape_id=7").fetchone()
        self.assertEqual(sync.update_findings(c, h, sync.evaluate_host(c, h)), (1, 0))      # 執行中 139 → 1 個 kernel CVE
        with mock.patch.object(sync, "Landscape", return_value=ls), \
                mock.patch.object(sync, "kernel_for_host", side_effect=RuntimeError("HTTP Error 403: Forbidden")):
            sync.sync_hosts(c)
        h = c.execute("SELECT * FROM host WHERE landscape_id=7").fetchone()
        self.assertEqual((h["kernel_status"], h["kernel_version"]), ("error", "6.8.0-139.139"))
        self.assertEqual(sync.update_findings(c, h, sync.evaluate_host(c, h)), (0, 0))      # 不會變成「已解決」
        c.execute("UPDATE host SET kernel_release=NULL, kernel_version=NULL WHERE id=?", (h["id"],))
        h = c.execute("SELECT * FROM host WHERE id=?", (h["id"],)).fetchone()
        self.assertEqual(sync.update_findings(c, h, sync.evaluate_host(c, h))[1], 0)        # 沒有舊資料也不解決 running-kernel

    def test_exceptions(self):
        c = self.env.con
        c.execute("INSERT INTO exception(host_pattern,cve,reason,expires_at,created_at) VALUES ('web*','CVE-2026-0001','ok','2099-01-01','x')")
        c.execute("INSERT INTO exception(host_pattern,cve,reason,expires_at,created_at) VALUES ('*','CVE-2026-0002','old','2000-01-01','x')")
        ex = sync.active_exceptions(c)
        self.assertTrue(sync.excepted(ex, "web01.example.com", "CVE-2026-0001"))
        self.assertFalse(sync.excepted(ex, "db01.example.com", "CVE-2026-0001"))
        self.assertFalse(sync.excepted(ex, "web01.example.com", "CVE-2026-0002"))         # 已過期


if __name__ == "__main__":
    unittest.main()
