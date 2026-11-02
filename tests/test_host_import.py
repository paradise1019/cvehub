import os
import unittest

from cvehub import host_import, osv_import, sync
from cvehub.config import Config
from tests.helpers import RECORDS, TempEnv, make_osv_tar

HEADER = "hostname,release,pro,kernel_release,kernel_version,collected_at,package,version\n"


class HostImportTest(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv(HOST_SOURCE="file").__enter__()
        d = self.env.dir.name
        osv_import.import_file(self.env.con, make_osv_tar(os.path.join(d, "o.tar.xz"), RECORDS))

    def tearDown(self):
        self.env.__exit__()

    def drop(self, text, name="hosts.csv"):
        os.makedirs(Config.HOSTS_INBOX_DIR, exist_ok=True)
        with open(os.path.join(Config.HOSTS_INBOX_DIR, name), "w", encoding="utf-8") as f:
            f.write(text)

    def open_cves(self, hostname):
        return {r["cve"] for r in self.env.con.execute(
            "SELECT f.cve FROM finding f JOIN host h ON h.id=f.host_id WHERE h.hostname=? AND f.resolved_at IS NULL", (hostname,))}

    def test_import_and_compare(self):
        self.drop(HEADER +
                  "web01,24.04,no,,,,openssl,3.0.13-0ubuntu3\n"
                  "web01,24.04,no,,,,libssl3t64:amd64,3.0.13-0ubuntu3\n"
                  "web01,24.04,no,,,,nodejs,18.19.1+dfsg-6ubuntu5\n"
                  "db01,Ubuntu 24.04.3 LTS,yes,,,,nodejs,18.19.1+dfsg-6ubuntu5\n")
        sync.run_sync(self.env.con)
        self.assertEqual(self.open_cves("web01"), {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0004"})
        st = dict(self.env.con.execute("SELECT h.hostname, f.status FROM finding f JOIN host h ON h.id=f.host_id WHERE f.cve='CVE-2026-0004'").fetchall())
        self.assertEqual(st, {"web01": "fix-in-pro", "db01": "fix-available"})
        h = self.env.con.execute("SELECT * FROM host WHERE hostname='db01'").fetchone()
        self.assertEqual((h["release"], h["pro_attached"], h["landscape_id"], h["kernel_status"]), ("24.04", 1, None, "disabled"))
        self.assertEqual(os.listdir(Config.HOSTS_INBOX_DIR), [])
        self.assertEqual(len(os.listdir(Config.HOSTS_ARCHIVE_DIR)), 1)

    def test_update_resolves_and_merge_keeps_missing_host(self):
        self.drop(HEADER + "web01,24.04,,,,,openssl,3.0.13-0ubuntu3\ndb01,24.04,,,,,openssl,3.0.13-0ubuntu3\n")
        sync.run_sync(self.env.con)
        self.drop(HEADER + "web01,24.04,,,,,openssl,3.0.13-0ubuntu3.16\n", "second.csv")
        sync.run_sync(self.env.con)
        self.assertEqual(self.open_cves("web01"), set())                     # 更新後已解決
        self.assertEqual(self.open_cves("db01"), {"CVE-2026-0001", "CVE-2026-0002"})   # merge：沒列出的主機保留
        self.assertEqual(self.env.con.execute("SELECT COUNT(*) FROM host WHERE active=1").fetchone()[0], 2)

    def test_replace_deactivates_missing_host(self):
        Config.HOSTS_FILE_MODE = "replace"
        self.drop(HEADER + "web01,24.04,,,,,openssl,3.0.13-0ubuntu3\ndb01,24.04,,,,,openssl,3.0.13-0ubuntu3\n")
        sync.run_sync(self.env.con)
        self.drop(HEADER + "WEB01,24.04,,,,,openssl,3.0.13-0ubuntu3\n", "second.csv")      # 名稱不分大小寫
        sync.run_sync(self.env.con)
        rows = dict(self.env.con.execute("SELECT lower(hostname), active FROM host").fetchall())
        self.assertEqual(rows, {"web01": 1, "db01": 0})

    def test_running_kernel_from_csv(self):
        self.drop(HEADER +
                  "k1,24.04,,6.8.0-100-generic,Ubuntu 6.8.0-100.100-generic 6.8.12,2026-11-01T00:00:00Z,linux-image-6.8.0-100-generic,6.8.0-100.100\n"
                  "k1,24.04,,,,,linux-image-6.8.0-147-generic,6.8.0-147.147\n")
        sync.run_sync(self.env.con)
        h = self.env.con.execute("SELECT * FROM host WHERE hostname='k1'").fetchone()
        self.assertEqual((h["kernel_release"], h["kernel_version"], h["kernel_status"]), ("6.8.0-100-generic", "6.8.0-100.100", "ok"))
        r = self.env.con.execute("SELECT action FROM finding WHERE cve='CVE-2026-0005' AND location='running-kernel'").fetchone()
        self.assertEqual(r["action"], "reboot")                              # 新 kernel 已裝、還沒重開

    def test_kernel_release_only_uses_package_version(self):
        h = host_import.parse(HEADER + "k1,24.04,,6.8.0-100-generic,,,linux-image-6.8.0-100-generic,6.8.0-100.100\n")["k1"]
        self.assertEqual(host_import._kernel(h), ("6.8.0-100-generic", "6.8.0-100.100", "ok"))

    def test_bom_repeated_header_and_extra_columns(self):
        os.makedirs(Config.HOSTS_INBOX_DIR, exist_ok=True)
        with open(os.path.join(Config.HOSTS_INBOX_DIR, "a.csv"), "w", encoding="utf-8-sig") as f:
            f.write("Hostname,Release,Package,Version,Note\nweb01,24.04,openssl,3.0.13-0ubuntu3,x\n\n"
                    "Hostname,Release,Package,Version,Note\nweb02,24.04,openssl,3.0.13-0ubuntu3,y\n")
        sync.run_sync(self.env.con)
        self.assertEqual(self.env.con.execute("SELECT COUNT(*) FROM host").fetchone()[0], 2)

    def test_invalid_file_is_rejected_whole(self):
        self.drop(HEADER + "web01,24.04,,,,,openssl,3.0.13-0ubuntu3\nweb02,18.04,,,,,openssl,1.1.1\n"
                  "web03,24.04,maybe,,,,curl,8.5.0\nweb01,22.04,,,,,curl,8.5.0\n")
        sync.run_sync(self.env.con)
        self.assertEqual(self.env.con.execute("SELECT COUNT(*) FROM host").fetchone()[0], 0)
        r = self.env.con.execute("SELECT * FROM host_import").fetchone()
        self.assertEqual(r["status"], "failed")
        for s in ("18.04", "pro", "web01 的 release"):
            self.assertIn(s, r["message"])
        self.assertTrue(os.listdir(Config.HOSTS_ARCHIVE_DIR)[0].startswith("failed-"))

    def test_missing_columns(self):
        with self.assertRaises(host_import.ImportError_) as e:
            host_import.parse("hostname,package\nweb01,openssl\n")
        self.assertIn("release", str(e.exception))

    def test_landscape_host_continues_history(self):
        c = self.env.con
        c.execute("INSERT INTO host(landscape_id,hostname,release,last_seen,kernel_status) VALUES (7,'web01.example.com','24.04','x','disabled')")
        c.commit()
        self.drop(HEADER + "WEB01.example.com,24.04,,,,,openssl,3.0.13-0ubuntu3\n")
        sync.run_sync(c)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM host").fetchone()[0], 1)

    def test_unexpected_error_is_archived_not_stuck(self):
        """vercmp 無法比較的版本、或其他非預期錯誤：記成失敗並移出放檔目錄，之後的同步照常"""
        self.drop("hostname,release,package,version\nh,24.04,p,a:1.0\nh,24.04,p,b:1.0\n")
        sync.run_sync(self.env.con)
        r = self.env.con.execute("SELECT status, message FROM host_import").fetchone()
        self.assertEqual(r["status"], "failed")
        self.assertEqual(os.listdir(Config.HOSTS_INBOX_DIR), [])
        from unittest import mock
        self.drop(HEADER + "web01,24.04,,,,,openssl,3.0.13-0ubuntu3\n", "boom.csv")
        with mock.patch.object(host_import, "apply", side_effect=RuntimeError("boom")), self.assertLogs("cvehub.host_import", "ERROR"):
            sync.run_sync(self.env.con)
        r = self.env.con.execute("SELECT status, message FROM host_import ORDER BY id DESC").fetchone()
        self.assertEqual(r["status"], "failed")
        self.assertIn("boom", r["message"])
        self.assertEqual(os.listdir(Config.HOSTS_INBOX_DIR), [])
        self.assertEqual(self.env.con.execute("SELECT status FROM sync_run ORDER BY id DESC").fetchone()[0], "ok")

    def test_hosts_imported_before_osv_exists(self):
        """還沒有 OSV 時上傳的清單也會匯入並記錄（不會一直留在放檔目錄）"""
        self.env.con.execute("UPDATE osv_import SET active=0")
        self.env.con.commit()
        self.drop(HEADER + "web01,24.04,,,,,openssl,3.0.13-0ubuntu3\n")
        with self.assertRaises(RuntimeError):
            sync.run_sync(self.env.con)
        self.assertEqual(self.env.con.execute("SELECT status FROM host_import").fetchone()[0], "ok")
        self.assertEqual(os.listdir(Config.HOSTS_INBOX_DIR), [])

    def test_cli_import_hosts(self):
        from cvehub import cli
        path = os.path.join(self.env.dir.name, "x.txt")        # 副檔名不是 .csv 也可以
        with open(path, "w") as f:
            f.write(HEADER + "web01,24.04,,,,,openssl,3.0.13-0ubuntu3\n")
        self.assertEqual(cli.main(["import-hosts", path]), 0)
        self.assertEqual(self.open_cves("web01"), {"CVE-2026-0001", "CVE-2026-0002"})
        with open(path, "w") as f:
            f.write("hostname,package\nweb01,openssl\n")
        self.assertEqual(cli.main(["import-hosts", path]), 1)
        self.assertEqual(cli.main(["import-hosts", path + ".missing"]), 1)

    def test_single_uncomparable_version_rejected(self):
        with self.assertRaises(host_import.ImportError_) as e:
            host_import.parse("hostname,release,package,version\nh,24.04,openssl,a:1.0\n")
        self.assertIn("版本格式不正確", str(e.exception))

    def test_kernel_version_only_with_unsigned_image(self):
        h = host_import.parse(HEADER + "k1,24.04,,,6.8.0-49.49,,linux-image-unsigned-6.8.0-49-generic,6.8.0-49.49\n")["k1"]
        self.assertEqual(host_import._kernel(h), ("6.8.0-49-generic", "6.8.0-49.49", "ok"))

    def test_database_error_is_archived(self):
        import sqlite3
        from unittest import mock
        self.drop(HEADER + "web01,24.04,,,,,openssl,3.0.13-0ubuntu3\n")
        with mock.patch.object(host_import, "apply", side_effect=sqlite3.OperationalError("disk I/O error")), \
                self.assertLogs("cvehub.host_import", "ERROR"):
            host_import.check_inbox(self.env.con)
        self.assertEqual(os.listdir(Config.HOSTS_INBOX_DIR), [])
        self.assertEqual(self.env.con.execute("SELECT status FROM host_import").fetchone()[0], "failed")

    def test_cli_exit_code_when_compare_fails(self):
        from cvehub import cli
        self.env.con.execute("UPDATE osv_import SET active=0")
        self.env.con.commit()
        path = os.path.join(self.env.dir.name, "h.csv")
        with open(path, "w") as f:
            f.write(HEADER + "web01,24.04,,,,,openssl,3.0.13-0ubuntu3\n")
        self.assertEqual(cli.main(["import-hosts", path]), 1)       # 匯入成功但比對失敗（沒有 OSV）
        self.assertEqual(self.env.con.execute("SELECT status FROM host_import").fetchone()[0], "ok")

    def test_unreadable_file_still_recorded(self):
        from unittest import mock
        self.drop(HEADER + "web01,24.04,,,,,openssl,3.0.13-0ubuntu3\n")
        with mock.patch.object(host_import, "_sha256", side_effect=PermissionError("denied")), \
                self.assertLogs("cvehub.host_import", "ERROR"):
            host_import.check_inbox(self.env.con)
        r = self.env.con.execute("SELECT status, message FROM host_import").fetchone()
        self.assertEqual(r["status"], "failed")
        self.assertIn("denied", r["message"])

    def test_record_written_with_data(self):
        """ok 紀錄和資料同一個交易：寫紀錄失敗時資料也回復"""
        from unittest import mock
        self.drop(HEADER + "web01,24.04,,,,,openssl,3.0.13-0ubuntu3\n")
        real = host_import.apply

        def broken(con, hosts, record=None, t=None):
            return real(con, hosts, ("x", None, "too", "many"), t)        # 讓 INSERT 紀錄失敗
        with mock.patch.object(host_import, "apply", side_effect=broken), self.assertLogs("cvehub.host_import", "ERROR"):
            host_import.check_inbox(self.env.con)
        self.assertEqual(self.env.con.execute("SELECT COUNT(*) FROM host").fetchone()[0], 0)
        self.assertEqual([tuple(r) for r in self.env.con.execute("SELECT status FROM host_import")], [("failed",)])

    def test_multiarch_takes_newer(self):
        h = host_import.parse("hostname,release,package,version\nh,24.04,libc6:amd64,2.39-0ubuntu8.4\nh,24.04,libc6:i386,2.39-0ubuntu8.3\n")["h"]
        self.assertEqual(h["packages"], {"libc6": "2.39-0ubuntu8.4"})


if __name__ == "__main__":
    unittest.main()
