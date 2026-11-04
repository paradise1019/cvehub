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

    def test_findings_filter_by_host_id(self):
        """總覽與主機頁的連結用 hid：名稱互相包含（web01、web010）時不會混到別台"""
        from cvehub import report
        self.drop(HEADER + "web01,24.04,,,,,openssl,3.0.13-0ubuntu3\nweb010,24.04,,,,,openssl,3.0.13-0ubuntu3\n")
        sync.run_sync(self.env.con)
        hid = self.env.con.execute("SELECT id FROM host WHERE hostname='web01'").fetchone()[0]
        self.assertEqual({r["hostname"] for r in report.query_findings(self.env.con, host="web01")}, {"web01", "web010"})
        self.assertEqual({r["hostname"] for r in report.query_findings(self.env.con, host="web01", hid=hid)}, {"web01"})
        self.assertEqual({r["hostname"] for r in report.query_findings(self.env.con, host="舊名稱", hid=hid)}, {"web01"})   # 有 hid 時不看 host

    def test_trailing_dot_is_the_same_host_in_one_file(self):
        """HOST_MATCH_KEY=hostname：同一個檔案裡 web01.example.com. 與 web01.example.com 是同一台（同一段時合併，不拒收）"""
        from unittest import mock
        with mock.patch.object(Config, "HOST_MATCH_KEY", "hostname"):
            hosts = host_import.parse("hostname,release,package,version\n"
                                      "web01.example.com.,24.04,openssl,1\nweb01.example.com,24.04,zlib1g,1\n")
        self.assertEqual([(h["hostname"], sorted(h["packages"])) for h in hosts.values()], [("web01.example.com.", ["openssl", "zlib1g"])])

    def test_note_when_inactive_same_name_hosts_are_different_machines(self):
        host_import.apply(self.env.con, host_import.parse("hostname,release,package,version\n"
                                                          "web01.a.example.com,24.04,openssl,1\nweb01.b.example.com,24.04,openssl,1\n"))
        self.env.con.execute("UPDATE host SET active=0")
        self.env.con.commit()
        host_import.apply(self.env.con, host_import.parse("hostname,release,package,version\nweb01,24.04,openssl,1\n"), ("f.csv", "x"))
        self.assertIn("另建一筆：web01", self.env.con.execute("SELECT message FROM host_import").fetchone()[0])

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
        self.assertEqual(c.execute("SELECT landscape_id FROM host").fetchone()[0], 7)      # 保留：之後切回 Landscape 還能接續

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

    def test_mixed_headers_from_old_and_new_collectors(self):
        """舊版（沒有 ip）與新版 playbook、README 手動指令的檔案串在一起：中間的標題列改用新的對應"""
        text = ("hostname,release,pro,kernel_release,kernel_version,collected_at,package,version\n"
                "old01,24.04,,,,,openssl,3.0.13-0ubuntu3\n"
                "hostname,ip,release,pro,kernel_release,kernel_version,collected_at,package,version\n"
                "new01,10.0.0.21,24.04,,,,,openssl,3.0.13-0ubuntu3\n"
                "Hostname,Release,Package,Version,IP\n"
                "man01,24.04,curl,8.5.0-2ubuntu10,10.0.0.22\n")
        h = host_import.parse(text)
        self.assertEqual({k: (v["release"], v["ip"]) for k, v in h.items()},
                         {"old01": ("24.04", ""), "new01": ("24.04", "10.0.0.21"), "man01": ("24.04", "10.0.0.22")})

    def test_same_value_in_different_forms_is_not_a_conflict(self):
        text = ("hostname,release,pro,kernel_release,kernel_version,collected_at,package,version\n"
                "h,22.04,yes,6.8.0-49-generic,Ubuntu 6.8.0-49.49~22.04.1-generic 6.8.12,2026-11-01T01:00:00Z,openssl,3.0.2-0ubuntu1.18\n"
                "h,Ubuntu 22.04.5 LTS,true,6.8.0-49-generic,6.8.0-49.49~22.04.1,2026-11-01T01:00:00Z,curl,7.81.0-1ubuntu1.20\n")
        Config.UBUNTU_RELEASES = ["22.04", "24.04"]
        h = host_import.parse(text)["h"]
        self.assertEqual((h["release"], h["pro"], h["kernel_version"]), ("22.04", 1, "6.8.0-49.49~22.04.1"))

    def test_field_error_points_at_the_row_that_set_it(self):
        with self.assertRaises(host_import.ImportError_) as e:
            host_import.parse("hostname,release,collected_at,package,version\nh,24.04,,a,1\nh,24.04,,b,1\nh,24.04,garbage,c,1\n")
        self.assertIn("第 4 列", str(e.exception))

    def test_ip_placeholders(self):
        h = host_import.parse("hostname,ip,release,package,version\nh,N/A,24.04,openssl,3.0.13-0ubuntu3\n"
                              "h,-,24.04,curl,8.5.0-2ubuntu10\nh,n/a,24.04,less,590-2\n")["h"]
        self.assertEqual((h["ip"], h.get("ip_bad")), ("", None))

    def test_bom_in_middle_header(self):
        text = ('\ufeffhostname,release,package,version\na,24.04,openssl,3.0.13-0ubuntu3\n'
                '\ufeff"hostname","release","package","version"\n"b","24.04","curl","8.5.0-2ubuntu10"\n')
        self.assertEqual(sorted(host_import.parse(text)), ["a", "b"])

    def test_same_host_in_two_segments_rejected(self):
        """每列欄位名稱開始一段（一次收集）：同一個名稱出現在兩段＝兩台同名或兩次收集，欄位都一樣也拒收"""
        seg = "hostname,ip,release,collected_at,package,version\n"
        for second in ("web01,,24.04,,curl,8.5.0-2ubuntu10\n",                          # 欄位全部相同、IP 空白
                       "web01,10.0.0.9,24.04,2026-11-01T00:00:00Z,curl,8.5.0-2ubuntu10\n"):
            with self.assertRaises(host_import.ImportError_) as e:
                host_import.parse(seg + "web01,,24.04,,openssl,3.0.13-0ubuntu3\n" + seg + second)
            self.assertIn("出現在兩段資料裡（第 1 列與第 3 列開始的兩段）", str(e.exception))
        rows = "".join("web01,,24.04,,p%d,1\n" % i for i in range(30))                 # 每台只報一次
        with self.assertRaises(host_import.ImportError_) as e:
            host_import.parse(seg + "web01,,24.04,,a,1\n" + seg + rows + "x,,99.99,,b,1\n")
        self.assertEqual(str(e.exception).count("出現在兩段資料裡"), 1)
        self.assertIn("99.99", str(e.exception))
        h = host_import.parse(seg + "a,,24.04,,openssl,1\nb,,24.04,,curl,1\na,,24.04,,less,1\n")      # 同一段裡交錯：沒問題
        self.assertEqual(len(h["a"]["packages"]), 2)

    def test_inconsistent_fields_in_one_collection(self):
        with self.assertRaises(host_import.ImportError_) as e:
            host_import.parse("%sh,10.0.0.1,24.04,openssl,1\nh,10.0.0.2,24.04,curl,1\n" % "hostname,ip,release,package,version\n")
        self.assertIn("前後不一致", str(e.exception))
        h = host_import.parse("hostname,release,collected_at,package,version\n"
                              "h,24.04,2026-11-01T00:00:00Z,a,1\nh,24.04,2026-11-01T00:00:00+00:00,b,1\n")["h"]   # 同一個時間的兩種寫法
        self.assertEqual(len(h["packages"]), 2)
        with self.assertRaises(host_import.ImportError_) as e:                     # 拿掉標題列串接的新舊檔：只有一段
            host_import.parse("hostname,release,collected_at,package,version\n"
                              "h,24.04,2026-01-01T00:00:00Z,oldpkg,1.0\nh,24.04,2026-11-01T00:00:00Z,openssl,3.0.13-0ubuntu3\n")
        self.assertIn("兩次收集", str(e.exception))

    def test_bad_ip_skipped(self):
        for bad in ("10.0.0.1 x", "cafe", "10.0.0", "999.1.1.1", "0"):
            h = host_import.parse("%sh,%s,24.04,openssl,3.0.13-0ubuntu3\n" % ("hostname,ip,release,package,version\n", bad))["h"]
            self.assertEqual((h["ip"], h["ip_bad"]), ("", bad), bad)
        h = host_import.parse("hostname,ip,release,package,version\nh,cafe,24.04,a,1\nh,10.0.0.1,24.04,b,1\nh,dead,24.04,c,1\n")["h"]
        self.assertEqual(h["ip"], "10.0.0.1")                                       # 格式不對的略過，用合法的

    def test_ip_storage(self):
        """有合法的就寫入；沒有欄位／空白／佔位字＝清掉；只有格式不對的值＝保留原本的"""
        def imp(csv_text, name):
            self.drop(csv_text, name)
            sync.run_sync(self.env.con)
            return self.env.con.execute("SELECT ip FROM host WHERE hostname='web01'").fetchone()[0]
        H = "hostname,ip,release,package,version\n"
        self.assertEqual(imp(H + "web01,10.0.0.21,24.04,openssl,3.0.13-0ubuntu3\n", "1.csv"), "10.0.0.21")
        self.assertEqual(imp(H + "web01,cafe,24.04,openssl,3.0.13-0ubuntu3\n", "2.csv"), "10.0.0.21")        # 格式不對：保留
        self.assertIn("web01", self.env.con.execute("SELECT message FROM host_import ORDER BY id DESC").fetchone()[0])
        self.assertIsNone(imp(H + "web01,N/A,24.04,openssl,3.0.13-0ubuntu3\n", "3.csv"))                   # 佔位字：清掉
        imp(H + "web01,10.0.0.21,24.04,openssl,3.0.13-0ubuntu3\n", "4.csv")
        self.assertIsNone(imp("hostname,release,package,version\nweb01,24.04,openssl,3.0.13-0ubuntu3\n", "5.csv"))   # 沒有欄位：清掉

    # ---- 0.9.3 review 修正的測試 ----

    def test_same_host_in_two_segments_rejected_even_if_fields_match(self):
        """同一個主機名稱出現在兩段（各有自己的標題列）：就算欄位全部相同或空白，也是兩台同名或兩次收集，不能合併"""
        seg = "hostname,ip,release,package,version\n"
        with self.assertRaises(host_import.ImportError_) as e:
            host_import.parse(seg + "web01,,24.04,openssl,3.0.13-0ubuntu3\n"
                              + seg + "web01,,24.04,openssl,3.0.13-0ubuntu1\n")
        msg = str(e.exception)
        self.assertIn("web01", msg)
        self.assertIn("同名", msg)
        self.assertIn("第 4 列", msg)          # 指向第二段裡那台主機的第一列
        with self.assertRaises(host_import.ImportError_):        # 名稱不分大小寫
            host_import.parse(seg + "web01,,24.04,a,1\n" + seg + "WEB01,,24.04,b,1\n")

    def test_same_host_many_rows_in_one_segment_ok(self):
        """同一段裡同一台主機很多列（正常情況）、不同主機各一段：照常匯入"""
        seg = "hostname,release,package,version\n"
        h = host_import.parse(seg + "a,24.04,openssl,3.0.13-0ubuntu3\na,24.04,curl,8.5.0-2ubuntu10\n"
                              + seg + "b,24.04,openssl,3.0.13-0ubuntu3\n")
        self.assertEqual(sorted(h), ["a", "b"])
        self.assertEqual(len(h["a"]["packages"]), 2)

    def test_same_host_in_two_segments_reported_once(self):
        """同一台出現在三段：只報一次，其他主機的錯誤不被蓋掉"""
        seg = "hostname,release,package,version\n"
        with self.assertRaises(host_import.ImportError_) as e:
            host_import.parse(seg + "h,24.04,a,1\n" + seg + "h,24.04,b,1\n" + seg + "h,24.04,c,1\n"
                              + seg + "x,99.99,d,1\n")
        msg = str(e.exception)
        self.assertEqual(msg.count("同名"), 1)
        self.assertIn("99.99", msg)

    def test_collected_at_same_instant_different_notation_not_conflict(self):
        """同一個時間點的不同寫法（Z／+00:00／+08:00／小數秒）不算兩次收集"""
        for a, b in (("2026-11-01T00:00:00Z", "2026-11-01T00:00:00+00:00"),
                     ("2026-11-01T00:00:00Z", "2026-11-01T08:00:00+08:00"),
                     ("2026-11-01T00:00:00Z", "2026-11-01T00:00:00.000Z")):
            h = host_import.parse("hostname,release,collected_at,package,version\n"
                                  "h,24.04,%s,a,1\nh,24.04,%s,b,1\n" % (a, b))["h"]
            self.assertEqual(len(h["packages"]), 2, (a, b))

    def test_collected_at_different_instant_still_conflict(self):
        with self.assertRaises(host_import.ImportError_) as e:
            host_import.parse("hostname,release,collected_at,package,version\n"
                              "h,24.04,2026-11-01T00:00:00Z,a,1\nh,24.04,2026-11-01T00:00:01Z,b,1\n")
        self.assertIn("兩次收集", str(e.exception))

    def test_collected_at_invalid_still_reported(self):
        """不是 ISO 8601 的值仍要報錯（比對改用解析後的時間，不能因此漏掉格式錯誤）"""
        with self.assertRaises(host_import.ImportError_) as e:
            host_import.parse("hostname,release,collected_at,package,version\nh,24.04,garbage,a,1\nh,24.04,garbage,b,1\n")
        self.assertIn("ISO 8601", str(e.exception))

    def _ip_of(self, hostname="web01"):
        return self.env.con.execute("SELECT ip FROM host WHERE hostname=?", (hostname,)).fetchone()[0]

    def test_ip_cleared_when_new_import_has_no_ip(self):
        """新的匯入沒有 IP（沒有 ip 欄位、空白、佔位字）：清掉舊的 IP，不沿用過時的位址"""
        cases = ("hostname,release,package,version\nweb01,24.04,openssl,3.0.13-0ubuntu3\n",          # 沒有 ip 欄位
                 "hostname,ip,release,package,version\nweb01,,24.04,openssl,3.0.13-0ubuntu3\n",      # 空白
                 "hostname,ip,release,package,version\nweb01,N/A,24.04,openssl,3.0.13-0ubuntu3\n")   # 佔位字
        for i, text in enumerate(cases):
            self.drop("hostname,ip,release,package,version\nweb01,10.0.0.21,24.04,openssl,3.0.13-0ubuntu3\n", "a%d.csv" % i)
            sync.run_sync(self.env.con)
            self.assertEqual(self._ip_of(), "10.0.0.21")
            self.drop(text, "b%d.csv" % i)
            sync.run_sync(self.env.con)
            self.assertIsNone(self._ip_of(), text)

    def test_ip_kept_only_when_malformed(self):
        """只有 IP 格式不對時才保留原本的 IP，並在匯入紀錄註明"""
        self.drop("hostname,ip,release,package,version\nweb01,10.0.0.21,24.04,openssl,3.0.13-0ubuntu3\n")
        sync.run_sync(self.env.con)
        self.drop("hostname,ip,release,package,version\nweb01,cafe,24.04,openssl,3.0.13-0ubuntu3\n", "second.csv")
        sync.run_sync(self.env.con)
        self.assertEqual(self._ip_of(), "10.0.0.21")
        r = self.env.con.execute("SELECT status, message FROM host_import ORDER BY id DESC").fetchone()
        self.assertEqual(r["status"], "ok")
        self.assertIn("web01", r["message"])

    def test_ip_replaced_by_new_valid_ip(self):
        self.drop("hostname,ip,release,package,version\nweb01,10.0.0.21,24.04,openssl,3.0.13-0ubuntu3\n")
        sync.run_sync(self.env.con)
        self.drop("hostname,ip,release,package,version\nweb01,10.0.0.99,24.04,openssl,3.0.13-0ubuntu3\n", "second.csv")
        sync.run_sync(self.env.con)
        self.assertEqual(self._ip_of(), "10.0.0.99")

    def test_multiarch_takes_newer(self):
        h = host_import.parse("hostname,release,package,version\nh,24.04,libc6:amd64,2.39-0ubuntu8.4\nh,24.04,libc6:i386,2.39-0ubuntu8.3\n")["h"]
        self.assertEqual(h["packages"], {"libc6": "2.39-0ubuntu8.4"})


if __name__ == "__main__":
    unittest.main()
