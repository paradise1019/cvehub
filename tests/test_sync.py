import os
import re
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


class PruneHistoryTest(unittest.TestCase):
    """紀錄表依 HISTORY_KEEP_DAYS 刪除過期的列；畫面與 /healthz 會用到的列保留"""
    OLD, NEW = "2000-01-01T00:00:00", "2099-01-01T00:00:00"          # 一定過期／一定沒過期

    def setUp(self):
        self.env = TempEnv(HOST_SOURCE="file").__enter__()             # 清單匯入模式：run_sync 不連 Landscape
        osv_import.import_file(self.env.con, make_osv_tar(os.path.join(self.env.dir.name, "o.tar.xz"), RECORDS))

    def tearDown(self):
        self.env.__exit__()

    def ids(self, table, where="1"):
        return [r[0] for r in self.env.con.execute("SELECT id FROM %s WHERE %s ORDER BY id" % (table, where))]

    def test_expired_rows_deleted_and_needed_rows_kept(self):
        c = self.env.con
        with c:
            c.execute("INSERT INTO audit_log(ts,username,action) VALUES (?,'old','x'),(?,'new','x')", (self.OLD, self.NEW))
            c.execute("INSERT INTO host_import(filename,imported_at,status) VALUES ('old.csv',?,'ok'),('new.csv',?,'ok')", (self.OLD, self.NEW))
            # osv：使用中的那筆改成過期（不能刪）、再放一筆過期與一筆沒過期的舊匯入
            active = c.execute("SELECT id FROM osv_import WHERE active=1").fetchone()[0]
            c.execute("UPDATE osv_import SET imported_at=? WHERE id=?", (self.OLD, active))
            c.execute("INSERT INTO osv_import(filename,sha256,imported_at,status,active) VALUES ('old',?,?,'ok',0)", ("a" * 64, self.OLD))
            c.execute("INSERT INTO osv_import(filename,sha256,imported_at,status,active) VALUES ('old-failed',?,?,'failed',0)", ("g" * 64, self.OLD))
            c.execute("INSERT INTO osv_import(filename,sha256,imported_at,status,active) VALUES ('new',?,?,'ok',0)", ("b" * 64, self.NEW))
            c.execute("INSERT INTO vex_import(filename,sha256,imported_at,status,active) VALUES ('active',?,?,'ok',1)", ("c" * 64, self.OLD))
            c.execute("INSERT INTO vex_import(filename,sha256,imported_at,status,active) VALUES ('old',?,?,'ok',0)", ("d" * 64, self.OLD))
            c.execute("INSERT INTO vex_import(filename,sha256,imported_at,status,active) VALUES ('old-failed',?,?,'failed',0)", ("h" * 64, self.OLD))
            c.execute("INSERT INTO vex_import(filename,sha256,imported_at,status,active) VALUES ('new',?,?,'ok',0)", ("e" * 64, self.NEW))
            # sync_run：一筆過期的成功紀錄，之後 6 筆過期的失敗紀錄（首頁只顯示最近 5 筆）
            c.execute("INSERT INTO sync_run(started_at,finished_at,status) VALUES (?,?,'ok')", (self.OLD, self.OLD))
            c.executemany("INSERT INTO sync_run(started_at,finished_at,status) VALUES (?,?,'failed')", [(self.OLD, self.OLD)] * 6)
        before_runs = self.ids("sync_run")
        sync.run_sync(c)
        self.assertEqual([r[0] for r in c.execute("SELECT username FROM audit_log")], ["new"])
        self.assertEqual([r[0] for r in c.execute("SELECT filename FROM host_import")], ["new.csv"])
        self.assertIn(active, self.ids("osv_import"))                                 # 使用中：保留
        # 成功的匯入紀錄一律保留（放檔目錄靠 sha256 判斷匯入過了，舊檔再放回去才不會蓋掉使用中的資料）；過期的失敗紀錄刪掉
        self.assertEqual([r[0] for r in c.execute("SELECT filename FROM osv_import WHERE active=0 ORDER BY id")], ["old", "new"])
        self.assertEqual([r[0] for r in c.execute("SELECT filename FROM vex_import ORDER BY id")], ["active", "old", "new"])
        runs = self.ids("sync_run")
        self.assertEqual(len(runs), 5)                                                # 最近 5 筆（含這次）
        self.assertNotIn(before_runs[0], runs)                                        # 過期的舊成功紀錄：這次成功了，可以刪
        self.assertEqual(c.execute("SELECT status FROM sync_run ORDER BY id DESC LIMIT 1").fetchone()[0], "ok")

    def test_last_success_and_latest_import_kept_even_if_expired(self):
        c = self.env.con
        with c:
            c.execute("UPDATE osv_import SET imported_at=?", (self.OLD,))
            c.execute("INSERT INTO osv_import(filename,sha256,imported_at,status,active) VALUES ('bad',?,?,'failed',0)", ("f" * 64, self.OLD))
            c.execute("INSERT INTO sync_run(started_at,finished_at,status) VALUES (?,?,'ok')", (self.OLD, self.OLD))
            last_ok = c.execute("SELECT MAX(id) FROM sync_run").fetchone()[0]
            c.executemany("INSERT INTO sync_run(started_at,finished_at,status) VALUES (?,?,'failed')", [(self.OLD, self.OLD)] * 6)
        sync.prune_history(c, "2050-01-01T00:00:00")                                  # 全部都算過期
        c.commit()
        self.assertIn(last_ok, self.ids("sync_run"))                                  # /healthz 的 last_successful_sync
        self.assertEqual(len(self.ids("sync_run")), 6)                                # 最近 5 筆＋最後一次成功
        self.assertEqual(c.execute("SELECT status FROM osv_import ORDER BY id DESC LIMIT 1").fetchone()[0], "failed")   # 最新一筆
        self.assertEqual(len(self.ids("osv_import", "active=1")), 1)


    def test_latest_host_import_kept_even_if_expired(self):
        c = self.env.con
        with c:
            c.execute("INSERT INTO host_import(filename,imported_at,status) VALUES ('a.csv',?,'ok'),('b.csv',?,'ok')", (self.OLD, self.OLD))
        sync.prune_history(c, "2050-01-01T00:00:00")
        c.commit()
        self.assertEqual([r[0] for r in c.execute("SELECT filename FROM host_import")], ["b.csv"])   # 資料匯入頁顯示的最新一筆

    def test_pruned_inbox_file_not_reimported(self):
        """過期的成功匯入紀錄不刪：同一份舊檔再放回放檔目錄時不會重新匯入、取代使用中的資料"""
        from cvehub.config import Config
        c = self.env.con
        with c:
            c.execute("UPDATE osv_import SET imported_at=?, active=0", (self.OLD,))
            c.execute("INSERT INTO osv_import(filename,sha256,imported_at,status,active,format) VALUES ('newer',?,?,'ok',1,?)",
                      ("n" * 64, self.NEW, osv_import.FORMAT))
        newer = c.execute("SELECT id FROM osv_import WHERE active=1").fetchone()[0]
        sync.prune_history(c, "2050-01-01T00:00:00")
        c.commit()
        os.makedirs(Config.OSV_INBOX_DIR, exist_ok=True)
        make_osv_tar(os.path.join(Config.OSV_INBOX_DIR, "o.tar.xz"), RECORDS)      # 同一份舊檔放回放檔目錄
        self.assertFalse(osv_import.check_inbox(c))
        self.assertEqual(c.execute("SELECT id FROM osv_import WHERE active=1").fetchone()[0], newer)


class OverviewTest(unittest.TestCase):
    """report.host_overview（總覽用，在資料庫裡彙總）和 query_findings 逐筆算的結果相同；ExceptionMatcher 和 excepted 相同"""

    def setUp(self):
        from cvehub import report
        self.env = TempEnv(HOST_SOURCE="file").__enter__()
        report._overview_cache = (None, None)
        self.addCleanup(setattr, report, "_overview_cache", (None, None))

    def tearDown(self):
        self.env.__exit__()

    def old(self):
        from cvehub import report
        rows = report.query_findings(self.env.con, show_excepted=False)
        per, cves = {}, {}
        for r in rows:
            cves.setdefault((r["host_id"], r["cve"]), r)
        for (hid, _), r in cves.items():
            ph = per.setdefault(hid, {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "": 0, "reboot": False})
            ph[r["priority"] if r["priority"] in ph else ""] += 1
        for r in rows:
            if r["location"] == "running-kernel":
                per[r["host_id"]]["reboot"] = True
        return per

    def test_same_as_row_by_row(self):
        import random
        from unittest import mock
        from cvehub import report
        from cvehub.config import Config
        c = self.env.con
        rnd = random.Random(7)
        now = sync.now()
        for i in range(1, 31):
            c.execute("INSERT INTO host(id, hostname, fqdn, release, last_seen, active) VALUES (?,?,?,'24.04',?,?)",
                      (i, "%s%02d" % (rnd.choice(["web", "db", "app"]), i), "h%02d.%s.example.com" % (i, rnd.choice(["a", "b"])), now, int(i != 30)))
            for j in range(rnd.randint(0, 25)):
                cve = "CVE-%d-%04d" % (rnd.choice([2023, 2024, 2025]), rnd.randint(1, 40))
                prio = ["critical", "high", "medium", "low", "negligible", None, "untriaged"][int(cve[-2:]) % 7]
                if rnd.random() < 0.2:      # 同一個 CVE 的列等級不同（kernel API 失敗時執行中 kernel 的列沒有更新）
                    prio = rnd.choice(["critical", "high", "low", None])
                c.execute("INSERT OR IGNORE INTO finding(host_id,cve,package,location,priority,status,first_seen,last_seen,resolved_at) "
                          "VALUES (?,?,?,?,?,'fix-available',?,?,?)", (i, cve, "p%d" % rnd.randint(1, 3), rnd.choice(["installed", "running-kernel", None]),
                                                                       prio, now, now, rnd.choice([None, None, None, now])))
        for hp, cv, exp in [("web*", "CVE-2024-*", None), ("*.b.example.com", "CVE-2023-00[1-2]?", None), ("db1*", "*", None),
                            ("*", "CVE-2025-0001", None), ("*", "*", "2000-01-01"), ("app*", " *", None), ("app2*", "cve-2025-00?2", None)]:
            c.execute("INSERT INTO exception(host_pattern,cve,reason,expires_at,created_at) VALUES (?,?,'t',?,?)", (hp, cv, exp, now))
        c.commit()
        for minp in ("critical", "medium", "low", "negligible", ""):
            with mock.patch.object(Config, "MIN_PRIORITY", minp):
                self.assertEqual(report.host_overview(c), self.old(), minp)
        c.execute("DELETE FROM exception")
        c.commit()
        self.assertEqual(report.host_overview(c), self.old())

    def test_mixed_priority_and_reboot(self):
        """同一台、同一個 CVE：a 套件 critical、b 套件 high 在執行中 kernel → 只算一個 critical，而且需要重開機"""
        from cvehub import report
        c = self.env.con
        now = sync.now()
        c.execute("INSERT INTO host(id, hostname, fqdn, release, last_seen, active) VALUES (1,'web01','web01','24.04',?,1)", (now,))
        c.execute("INSERT INTO finding(host_id,cve,package,location,priority,status,first_seen,last_seen) VALUES "
                  "(1,'CVE-1','a','installed','critical','fix-available',?,?),(1,'CVE-1','b','running-kernel','high','fix-available',?,?)",
                  (now,) * 4)
        c.commit()
        want = {"critical": 1, "high": 0, "medium": 0, "low": 0, "negligible": 0, "": 0, "reboot": True}
        self.assertEqual(report.host_overview(c), {1: want})
        c.execute("INSERT INTO exception(host_pattern,cve,reason,created_at) VALUES ('web*','CVE-9','t',?)", (now,))   # 套用到這台、但不是這個 CVE
        c.commit()
        self.assertEqual(report.host_overview(c), {1: want})
        self.assertEqual(report.host_overview(c), self.old())

    def test_many_rule_groups(self):
        """全域規則＋每台各自的規則（每台一個群組）：結果相同，每條規則只比對一次 CVE"""
        from cvehub import report
        c = self.env.con
        now = sync.now()
        for i in range(1, 41):
            c.execute("INSERT INTO host(id, hostname, fqdn, release, last_seen, active) VALUES (?,?,?,'24.04',?,1)", (i, "h%02d" % i, "h%02d" % i, now))
            c.execute("INSERT INTO exception(host_pattern,cve,reason,created_at) VALUES (?,?,'t',?)", ("h%02d" % i, "CVE-%d-*" % (i % 3), now))
            for j in range(30):
                c.execute("INSERT INTO finding(host_id,cve,package,location,priority,status,first_seen,last_seen) VALUES (?,?,'p','installed','high','x',?,?)",
                          (i, "CVE-%d-%d" % (j % 3, j), now, now))
        c.execute("INSERT INTO exception(host_pattern,cve,reason,created_at) VALUES ('*','CVE-1-4','t',?)", (now,))
        c.commit()
        self.assertEqual(report.host_overview(c), self.old())

    def test_kernel_sort_key(self):
        from cvehub import web
        h = lambda v, st="ok": {"kernel_version": v, "kernel_status": st}
        rows = [h("6.8.0-100.100"), h("~custom"), h("#45-Ubuntu SMP x"), h("6.8.0-45.45"), h("6.8.0-9.9", "stale"), h(None), h("x:y"), h("1:5.0-1"), h("6.8.0-1.1\n")]
        self.assertEqual([r["kernel_version"] for r in sorted(rows, key=web._kernel_key)],
                         ["6.8.0-45.45", "6.8.0-100.100", "1:5.0-1", "#45-Ubuntu SMP x", "6.8.0-1.1\n", "x:y", "~custom", "6.8.0-9.9", None])

    def test_cache_invalidated_when_data_changes(self):
        """快取：資料沒變時沿用；比對結果（含筆數不變的修改）、主機名稱／啟用、例外規則、MIN_PRIORITY 變了就重算"""
        from unittest import mock
        from cvehub import report
        from cvehub.config import Config
        c = self.env.con
        now = sync.now()
        c.execute("INSERT INTO host(id, hostname, fqdn, release, last_seen, active) VALUES (1,'web01','web01','24.04',?,1),(2,'db01','db01','24.04',?,1)", (now, now))
        c.execute("INSERT INTO finding(host_id,cve,package,location,priority,status,first_seen,last_seen) VALUES "
                  "(1,'CVE-1','a','installed','high','x',?,?),(2,'CVE-2','a','installed','low','x',?,?)", (now,) * 4)
        c.commit()
        calls = []
        real = report.host_overview
        with mock.patch.object(report, "host_overview", side_effect=lambda con, today=None: calls.append(1) or real(con, today)):
            first = report.host_overview_cached(c)
            self.assertEqual(report.host_overview_cached(c), first)           # 沒變：沿用（沒有重算）
            self.assertEqual(len(calls), 1)
            c.execute("INSERT INTO sync_run(started_at,status) VALUES (?,'running')", (now,))     # 和數量無關：不重算
            c.commit()
            report.host_overview_cached(c)
            self.assertEqual(len(calls), 1)
            steps = [
                lambda: c.execute("UPDATE finding SET resolved_at=? WHERE host_id=2", (now,)),
                lambda: c.execute("UPDATE host SET hostname='web01.example.com' WHERE id=1"),
                lambda: c.execute("UPDATE host SET active=0 WHERE id=2"),
                lambda: c.execute("INSERT INTO exception(host_pattern,cve,reason,created_at) VALUES ('web*','CVE-1','t',?)", (now,)),
                lambda: c.execute("UPDATE exception SET expires_at='2000-01-01'"),       # 到期
                lambda: c.execute("UPDATE finding SET priority='critical' WHERE host_id=1"),  # 筆數不變、等級變了（同步途中）
                lambda: c.execute("DELETE FROM exception"),
            ]
            for i, step in enumerate(steps):
                step()
                c.commit()
                n = len(calls)
                self.assertEqual(report.host_overview_cached(c), real(c), i)
                self.assertEqual(len(calls), n + 1, i)                           # 重算了
            n = len(calls)
            with mock.patch.object(Config, "MIN_PRIORITY", "medium"):
                self.assertEqual(report.host_overview_cached(c), real(c))
            self.assertEqual(len(calls), n + 1)
        self.assertFalse(c.in_transaction)
        got = report.host_overview_cached(c)
        got[1]["high"] = 99                                                      # 回傳複本：改了不影響快取
        self.assertNotEqual(report.host_overview_cached(c)[1]["high"], 99)

    def test_cache_hit_needs_same_generation(self):
        """版本號不同（較大或較小）都重算，不沿用"""
        from cvehub import report
        c = self.env.con
        scope = report._overview_key(c, sync.datetime.date.today().isoformat())[0]
        for g in (10 ** 9, -1):
            report._overview_cache = ((scope, g), {"x": {}})
            self.assertEqual(report.host_overview_cached(c), {})

    def test_upgrade_from_dev_data_gen(self):
        """0.9.5 開發中的資料庫：data_gen 沒有 epoch、觸發器是舊的（不分欄位）→ 補上、換成新的定義"""
        from cvehub import db
        c = self.env.con
        c.executescript("DROP TABLE data_gen; CREATE TABLE data_gen (id INTEGER PRIMARY KEY CHECK (id = 1), gen INTEGER NOT NULL);"
                        "INSERT INTO data_gen VALUES (1, 0); DROP TRIGGER finding_gen_u;"
                        "CREATE TRIGGER finding_gen_u AFTER UPDATE ON finding BEGIN UPDATE data_gen SET gen = gen + 1 WHERE id = 1; END;")
        c.execute("UPDATE data_gen SET gen=41")
        c.commit()
        db.init(c)
        self.assertTrue(c.execute("SELECT epoch FROM data_gen").fetchone()[0])
        self.assertEqual(self.gen(), 41)                                     # 版本號保留
        self.assertIn("WHEN", c.execute("SELECT sql FROM sqlite_master WHERE name='finding_gen_u'").fetchone()[0])
        self.assertEqual(c.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'").fetchone()[0], 9)
        c.execute("INSERT INTO exception(host_pattern,cve,reason,created_at) VALUES ('a','b','c','d')")   # 新的觸發器有作用
        c.commit()
        self.assertEqual(self.gen(), 42)
        stmts = []
        c.set_trace_callback(stmts.append)
        db.init(c)                                                          # 定義相同：不再動觸發器
        c.set_trace_callback(None)
        self.assertFalse([q for q in stmts if re.match(r"\s*(DROP|CREATE) TRIGGER", q, re.I)])
        self.assertEqual(self.gen(), 42)
        c.execute("CREATE TRIGGER host_gen_audit AFTER UPDATE ON host BEGIN SELECT 1; END")   # 別人的觸發器：不動
        c.commit()
        db.init(c)
        self.assertIsNotNone(c.execute("SELECT 1 FROM sqlite_master WHERE name='host_gen_audit'").fetchone())

    def gen(self):
        return self.env.con.execute("SELECT gen FROM data_gen").fetchone()[0]

    def test_generation_only_for_changes_that_matter(self):
        c = self.env.con
        now = sync.now()
        g0 = self.gen()
        c.execute("INSERT INTO host(id, hostname, fqdn, release, last_seen, active) VALUES (1,'web01','web01','24.04',?,1)", (now,))
        c.execute("INSERT INTO finding(host_id,cve,package,location,priority,status,first_seen,last_seen) VALUES (1,'CVE-1','a','installed','high','x',?,?)", (now, now))
        c.commit()
        g1 = self.gen()
        self.assertEqual(g1, g0 + 2)
        c.execute("UPDATE finding SET last_seen='2099-01-01', installed='1', priority='high', resolved_at=NULL")   # 每次同步都會做的：不算
        c.execute("UPDATE host SET last_seen='2099-01-01', package_count=5, hostname='web01'")
        c.commit()
        self.assertEqual(self.gen(), g1)
        for q in ("UPDATE finding SET priority='critical'", "UPDATE finding SET location='running-kernel'", "UPDATE finding SET resolved_at='x'",
                  "UPDATE finding SET priority=NULL", "UPDATE host SET fqdn='web01.example.com'", "UPDATE host SET active=0",
                  "INSERT INTO exception(host_pattern,cve,reason,created_at) VALUES ('a','b','c','d')", "UPDATE exception SET reason='z'",
                  "DELETE FROM exception", "DELETE FROM finding"):
            before = self.gen()
            c.execute(q)
            c.commit()
            self.assertEqual(self.gen(), before + 1, q)

    def test_uncommitted_write_not_cached(self):
        """連線裡有還沒送出的寫入時：算出來的不寫進快取（rollback 後版本號可能再出現一次）"""
        from cvehub import report
        c = self.env.con
        now = sync.now()
        c.execute("INSERT INTO host(id, hostname, fqdn, release, last_seen, active) VALUES (1,'web01','web01','24.04',?,1)", (now,))
        c.execute("INSERT INTO finding(host_id,cve,package,location,priority,status,first_seen,last_seen) VALUES (1,'CVE-1','a','installed','high','x',?,?)", (now, now))
        c.commit()
        c.execute("UPDATE finding SET priority='critical'")                   # 不送出
        self.assertEqual(report.host_overview_cached(c)[1]["critical"], 1)
        self.assertEqual(report._overview_cache, (None, None))
        c.rollback()
        c.execute("UPDATE finding SET last_seen='x', installed='y'")         # 另一個不影響數量的寫入
        c.commit()
        self.assertEqual(report.host_overview_cached(c)[1]["high"], 1)
        with report.read_snapshot(c):                                         # read_snapshot 裡、沒有寫入：可以快取
            report._overview_cache = (None, None)
            report.host_overview_cached(c)
        self.assertIsNotNone(report._overview_cache[0])

    def test_other_database_not_mixed(self):
        """還原成另一份資料庫（版本號相同）：epoch 不同，不會沿用"""
        from cvehub import report
        c = self.env.con
        report.host_overview_cached(c)
        k = report._overview_cache[0]
        c.execute("UPDATE data_gen SET epoch='other'")
        c.commit()
        report.host_overview_cached(c)
        self.assertNotEqual(report._overview_cache[0], k)
        c.execute("DELETE FROM data_gen")                                    # 沒有版本號：不快取，照樣算
        c.commit()
        report._overview_cache = (None, None)
        self.assertEqual(report.host_overview_cached(c), {})
        self.assertEqual(report._overview_cache, (None, None))

    def test_upgrade_from_older_database(self):
        """0.9.4 的資料庫（有 finding_open、沒有 data_gen 與觸發器）：init 補上，觸發器有作用"""
        from cvehub import db
        c = self.env.con
        c.executescript("DROP TABLE data_gen;" + "".join("DROP TRIGGER %s_gen_%s;" % (t, o) for t in ("finding", "host", "exception") for o in "idu") +
                        "DROP INDEX finding_open_cover; CREATE INDEX finding_open ON finding(resolved_at, host_id);"
                        "INSERT INTO host(id, hostname, release, last_seen, active) VALUES (1,'web01','24.04','x',1);")
        db.init(c)
        c.commit()
        idx = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertIn("finding_open_cover", idx)
        self.assertNotIn("finding_open", idx)
        g = self.gen()
        c.execute("UPDATE host SET active=0")
        c.commit()
        self.assertEqual(self.gen(), g + 1)

    def test_matcher_same_as_excepted(self):
        exc = [{"host_pattern": "Web*", "cve": "cve-2024-*", "reason": "a"}, {"host_pattern": "*.example.com", "cve": "CVE-2025-00?1", "reason": "b"},
               {"host_pattern": "db[0-9]", "cve": "*", "reason": "c"}, {"host_pattern": "x", "cve": "[!C]*", "reason": "d"}]
        m = sync.ExceptionMatcher(exc)
        for hn, fq in [("web01", None), ("WEB01", "web01.example.com"), ("db1", ""), ("db10", None), ("x", None), ("app", "app.example.com")]:
            for cve in ("CVE-2024-1", "cve-2025-0011", "CVE-2025-0012", "CVE-2023-9", "X-1"):
                self.assertEqual(m(hn, cve, fq), sync.excepted(exc, hn, cve, fq), (hn, fq, cve))


class UpsertHostTest(unittest.TestCase):
    """db.upsert_host：Landscape 同步與主機清單匯入共用的主機寫入"""

    def setUp(self):
        self.env = TempEnv(HOST_SOURCE="file").__enter__()
        osv_import.import_file(self.env.con, make_osv_tar(os.path.join(self.env.dir.name, "o.tar.xz"), RECORDS))

    def tearDown(self):
        self.env.__exit__()

    def fields(self, **kw):
        f = dict(hostname="web01", fqdn="web01", title="web01", ip="10.0.0.21", release="24.04", pro_attached=0, last_seen=sync.now(),
                 kernel_release=None, kernel_version=None, kernel_collected_at=None, kernel_status="disabled")
        f.update(kw)
        return f

    def host(self, hid):
        return self.env.con.execute("SELECT * FROM host WHERE id=?", (hid,)).fetchone()

    def pkgs(self, hid):
        return dict(self.env.con.execute("SELECT name, version FROM host_package WHERE host_id=?", (hid,)).fetchall())

    def test_insert_update_and_packages(self):
        from cvehub import db
        c = self.env.con
        hid = db.upsert_host(c, None, self.fields(), {"openssl": "1", "curl": "2"}, landscape_id=7)
        h = self.host(hid)
        self.assertEqual((h["landscape_id"], h["package_count"], h["active"], h["ip"]), (7, 2, 1, "10.0.0.21"))
        c.execute("UPDATE host SET active=0 WHERE id=?", (hid,))
        self.assertEqual(db.upsert_host(c, hid, self.fields(hostname="WEB01", release="22.04"), {"less": "3"}), hid)
        h = self.host(hid)
        self.assertEqual((h["hostname"], h["release"], h["active"], h["landscape_id"], h["package_count"]), ("WEB01", "22.04", 1, 7, 1))
        self.assertEqual(self.pkgs(hid), {"less": "3"})                         # 套件清單整份取代

    def test_ip_overwrite_or_keep(self):
        from cvehub import db
        c = self.env.con
        hid = db.upsert_host(c, None, self.fields(), {})
        db.upsert_host(c, hid, self.fields(ip=None), {}, keep_ip=True)          # 只有格式不對的 ip：保留
        self.assertEqual(self.host(hid)["ip"], "10.0.0.21")
        db.upsert_host(c, hid, self.fields(ip=None), {})                        # 沒有 ip：清掉
        self.assertIsNone(self.host(hid)["ip"])
        db.upsert_host(c, hid, self.fields(ip=""), {})                          # Landscape 沒回報網卡：原樣覆寫（空字串）
        self.assertEqual(self.host(hid)["ip"], "")

    def test_landscape_id_filled_but_never_replaced_by_none(self):
        from cvehub import db
        c = self.env.con
        hid = db.upsert_host(c, None, self.fields(), {})                        # 清單匯入建的：沒有 landscape_id
        self.assertIsNone(self.host(hid)["landscape_id"])
        db.upsert_host(c, hid, self.fields(), {}, landscape_id=9)               # Landscape 接續：補上
        self.assertEqual(self.host(hid)["landscape_id"], 9)
        db.upsert_host(c, hid, self.fields(), {})                               # 清單匯入再寫一次：保留
        self.assertEqual(self.host(hid)["landscape_id"], 9)


class LandscapeContinuesFileHostTest(unittest.TestCase):
    """從主機清單匯入切換到 Landscape：同名主機接續原本的紀錄（同一個 id、弱點歷史不斷）"""

    def setUp(self):
        self.env = TempEnv(HOST_SOURCE="file").__enter__()
        osv_import.import_file(self.env.con, make_osv_tar(os.path.join(self.env.dir.name, "o.tar.xz"), RECORDS))

    def tearDown(self):
        self.env.__exit__()

    def landscape(self, computers, packages):
        from unittest import mock
        ls = mock.Mock()
        ls.computers.return_value = computers
        ls.installed_packages.side_effect = lambda cid: packages[cid]
        return mock.patch.object(sync, "Landscape", return_value=ls)

    def test_continue_file_host(self):
        from cvehub import host_import
        c = self.env.con
        host_import.apply(c, host_import.parse("hostname,ip,release,package,version\nweb01,10.0.0.21,24.04,openssl,3.0.13-0ubuntu3\n"))
        hid = c.execute("SELECT id FROM host WHERE hostname='web01'").fetchone()[0]
        h = c.execute("SELECT * FROM host WHERE id=?", (hid,)).fetchone()
        sync.update_findings(c, h, sync.evaluate_host(c, h))
        first = dict(c.execute("SELECT cve, first_seen FROM finding WHERE host_id=?", (hid,)).fetchall())
        self.assertTrue(first)
        with self.landscape([{"id": 7, "hostname": "WEB01", "title": "web01", "distribution": "24.04"}],
                            {7: {"openssl": "3.0.13-0ubuntu3"}}):
            sync.sync_hosts(c)
        rows = c.execute("SELECT id, landscape_id, hostname, active FROM host").fetchall()
        self.assertEqual([tuple(r) for r in rows], [(hid, 7, "WEB01", 1)])       # 同一筆、補上 landscape_id、沒有被停用
        h = c.execute("SELECT * FROM host WHERE id=?", (hid,)).fetchone()
        sync.update_findings(c, h, sync.evaluate_host(c, h))
        self.assertEqual(dict(c.execute("SELECT cve, first_seen FROM finding WHERE host_id=?", (hid,)).fetchall()), first)  # 歷史接續

    def file_host(self, name="web01", kernel=""):
        from cvehub import host_import
        text = "hostname,release,kernel_release,kernel_version,package,version\n%s,24.04,%s,openssl,3.0.13-0ubuntu3\n" % (
            name, "6.8.0-100-generic,6.8.0-100.100" if kernel else ",")
        host_import.apply(self.env.con, host_import.parse(text))
        return self.env.con.execute("SELECT id FROM host WHERE hostname=?", (name,)).fetchone()[0]

    def test_ambiguous_landscape_names_not_continued(self):
        c = self.env.con
        hid = self.file_host()
        with self.landscape([{"id": 7, "hostname": "web01", "title": "a", "distribution": "24.04"},
                             {"id": 8, "hostname": "WEB01", "title": "b", "distribution": "24.04"}],
                            {7: {"openssl": "1"}, 8: {"curl": "1"}}), self.assertLogs("cvehub.sync", "WARNING"):
            sync.sync_hosts(c)
        self.assertIsNone(c.execute("SELECT landscape_id FROM host WHERE id=?", (hid,)).fetchone()[0])   # 分不出是哪一台：不接續
        self.assertEqual(sorted(r[0] for r in c.execute("SELECT landscape_id FROM host WHERE landscape_id IS NOT NULL")), [7, 8])

    def test_recently_seen_inactive_file_host_continued(self):
        """第一次 Landscape 同步時還沒加入、被停用的清單主機，之後加入 Landscape：30 天內出現過的照樣接續"""
        c = self.env.con
        hid = self.file_host()
        with self.landscape([], {}):
            sync.sync_hosts(c)                                                  # 這次沒出現：被停用
        self.assertEqual(c.execute("SELECT active FROM host WHERE id=?", (hid,)).fetchone()[0], 0)
        with self.landscape([{"id": 7, "hostname": "web01", "title": "web01", "distribution": "24.04"}], {7: {"openssl": "1"}}):
            sync.sync_hosts(c)
        self.assertEqual(tuple(c.execute("SELECT landscape_id, active FROM host WHERE id=?", (hid,)).fetchone()), (7, 1))
        self.assertEqual(c.execute("SELECT COUNT(*) FROM host").fetchone()[0], 1)

    def test_inactive_file_host_not_continued(self):
        """太久沒出現的舊清單主機：不讓同名的新機器接走（舊弱點會被重新打開）"""
        c = self.env.con
        hid = self.file_host()
        c.execute("UPDATE host SET active=0, last_seen='2000-01-01T00:00:00' WHERE id=?", (hid,))
        c.commit()
        with self.landscape([{"id": 7, "hostname": "web01", "title": "web01", "distribution": "24.04"}], {7: {"openssl": "1"}}):
            sync.sync_hosts(c)
        self.assertEqual(tuple(c.execute("SELECT landscape_id, active FROM host WHERE id=?", (hid,)).fetchone()), (None, 0))
        self.assertEqual(c.execute("SELECT COUNT(*) FROM host WHERE landscape_id=7").fetchone()[0], 1)

    def test_kernel_api_error_on_continue_no_collected_at_not_reused(self):
        """清單裡的 kernel 沒有收集時間：不知道多舊，不沿用"""
        from unittest import mock
        from cvehub.config import Config
        c = self.env.con
        hid = self.file_host(kernel=True)
        self.assertIsNone(c.execute("SELECT kernel_collected_at FROM host WHERE id=?", (hid,)).fetchone()[0])
        Config.KERNEL_API_URL, Config.KERNEL_API_MODE = "http://k/?h={hostname}", "per-host"
        with self.landscape([{"id": 7, "hostname": "web01", "title": "web01", "distribution": "24.04"}], {7: {"openssl": "1"}}), \
                mock.patch.object(sync, "kernel_for_host", side_effect=RuntimeError("timeout")):
            sync.sync_hosts(c)
        self.assertIsNone(c.execute("SELECT kernel_release FROM host WHERE id=?", (hid,)).fetchone()[0])

    def test_kernel_api_error_on_continue_does_not_reuse_stale_file_kernel(self):
        from unittest import mock
        from cvehub.config import Config
        c = self.env.con
        hid = self.file_host(kernel=True)                                       # 清單匯入時有執行中 kernel
        c.execute("UPDATE host SET kernel_collected_at='2000-01-01T00:00:00' WHERE id=?", (hid,))   # 早就超過 KERNEL_API_MAX_AGE_HOURS
        c.commit()
        Config.KERNEL_API_URL, Config.KERNEL_API_MODE = "http://k/?h={hostname}", "per-host"
        with self.landscape([{"id": 7, "hostname": "web01", "title": "web01", "distribution": "24.04"}], {7: {"openssl": "1"}}), \
                mock.patch.object(sync, "kernel_for_host", side_effect=RuntimeError("timeout")):
            sync.sync_hosts(c)
        h = c.execute("SELECT * FROM host WHERE id=?", (hid,)).fetchone()
        self.assertEqual((h["landscape_id"], h["kernel_status"], h["kernel_release"]), (7, "error", None))

    def test_landscape_query_set_no_continue(self):
        from cvehub.config import Config
        c = self.env.con
        hid = self.file_host()
        from unittest import mock
        with mock.patch.object(Config, "LANDSCAPE_QUERY", "tag:prod"), self.assertLogs("cvehub.sync", "WARNING") as logs, \
                self.landscape([{"id": 7, "hostname": "web01", "title": "web01", "distribution": "24.04"}], {7: {"openssl": "1"}}):
            sync.sync_hosts(c)
        self.assertTrue(any("LANDSCAPE_QUERY" in m and "兩筆都會維持啟用" in m for m in logs.output), logs.output)
        rows = {r["landscape_id"]: r["active"] for r in c.execute("SELECT landscape_id, active FROM host")}
        self.assertEqual(rows, {None: 1, 7: 1})                                  # 清單主機沒被接走，也沒被停用

    def test_kernel_api_error_on_continue_reuses_fresh_file_kernel(self):
        from unittest import mock
        from cvehub import host_import
        from cvehub.config import Config
        c = self.env.con
        host_import.apply(c, host_import.parse("hostname,release,kernel_release,kernel_version,collected_at,package,version\n"
                                               "web01,24.04,6.8.0-100-generic,6.8.0-100.100,%s,openssl,3.0.13-0ubuntu3\n" % sync.now()))
        Config.KERNEL_API_URL, Config.KERNEL_API_MODE = "http://k/?h={hostname}", "per-host"
        with self.landscape([{"id": 7, "hostname": "web01", "title": "web01", "distribution": "24.04"}], {7: {"openssl": "1"}}), \
                mock.patch.object(sync, "kernel_for_host", side_effect=RuntimeError("timeout")):
            sync.sync_hosts(c)
        h = c.execute("SELECT * FROM host WHERE hostname='web01'").fetchone()
        self.assertEqual((h["landscape_id"], h["kernel_status"], h["kernel_release"]), (7, "error", "6.8.0-100-generic"))

    def test_rename_order_does_not_matter(self):
        """同一批資料，Landscape 回傳的順序不同，結果相同（用同步開始前的快照判斷）"""
        results = []
        for order in (0, 1):
            self.tearDown(); self.setUp()
            c = self.env.con
            hid = self.file_host()
            c.execute("UPDATE host SET active=0 WHERE id=?", (hid,))
            c.execute("INSERT INTO host(landscape_id,hostname,release,last_seen,kernel_status,active) VALUES (7,'web01','24.04',?,'disabled',1)", (sync.now(),))
            c.commit()
            comps = [{"id": 7, "hostname": "web01-old", "title": "a", "distribution": "24.04"},
                     {"id": 9, "hostname": "web01", "title": "b", "distribution": "24.04"}]
            with self.landscape(comps if order == 0 else comps[::-1], {7: {"openssl": "1"}, 9: {"curl": "1"}}):
                sync.sync_hosts(c)
            results.append(c.execute("SELECT landscape_id FROM host WHERE id=?", (hid,)).fetchone()[0])
        self.assertEqual(results, [None, None])

    def test_inactive_file_host_not_taken_when_active_same_name_exists(self):
        """已停用的清單主機：目前有啟用中的同名主機（例如電腦重新註冊）時不接續"""
        c = self.env.con
        hid = self.file_host()
        c.execute("UPDATE host SET active=0 WHERE id=?", (hid,))
        c.execute("INSERT INTO host(landscape_id,hostname,release,last_seen,kernel_status,active) VALUES (7,'web01','24.04',?,'disabled',1)", (sync.now(),))
        c.commit()
        with self.landscape([{"id": 9, "hostname": "web01", "title": "web01", "distribution": "24.04"}], {9: {"openssl": "1"}}):
            sync.sync_hosts(c)
        self.assertIsNone(c.execute("SELECT landscape_id FROM host WHERE id=?", (hid,)).fetchone()[0])
        self.assertEqual(sorted(r[0] for r in c.execute("SELECT landscape_id FROM host WHERE landscape_id IS NOT NULL")), [7, 9])

    def test_same_name_with_other_landscape_id_not_taken(self):
        c = self.env.con
        c.execute("INSERT INTO host(landscape_id,hostname,release,last_seen,kernel_status) VALUES (5,'web01','24.04','x','disabled')")
        c.commit()
        with self.landscape([{"id": 5, "hostname": "web01", "title": "web01", "distribution": "24.04"},
                             {"id": 7, "hostname": "web01", "title": "web01-b", "distribution": "24.04"}],
                            {5: {"openssl": "1"}, 7: {"curl": "1"}}):
            sync.sync_hosts(c)
        self.assertEqual(sorted(r[0] for r in c.execute("SELECT landscape_id FROM host")), [5, 7])   # 兩台各自一筆


class HostMatchKeyTest(unittest.TestCase):
    """名稱依 HOST_MATCH_KEY 比對與儲存：清單用短名稱、Landscape 用完整名稱時也接得上"""

    def setUp(self):
        self.env = TempEnv(HOST_SOURCE="file").__enter__()

    def tearDown(self):
        self.env.__exit__()

    landscape = LandscapeContinuesFileHostTest.landscape

    def csv(self, *names):
        from cvehub import host_import
        host_import.apply(self.env.con, host_import.parse(
            "hostname,release,package,version\n" + "".join("%s,24.04,openssl,3.0.13-0ubuntu3\n" % n for n in names)))

    def comp(self, cid, hostname):
        return {"id": cid, "hostname": hostname, "title": hostname, "distribution": "24.04"}

    def rows(self):
        return sorted(tuple(r) for r in self.env.con.execute("SELECT id, landscape_id, hostname, active FROM host"))

    def test_fqdn_continues_short_list_host_and_is_stored_short(self):
        c = self.env.con
        self.csv("web01")
        hid = c.execute("SELECT id FROM host").fetchone()[0]
        with self.landscape([self.comp(7, "WEB01.example.com")], {7: {"openssl": "1"}}):
            sync.sync_hosts(c)
        self.assertEqual(self.rows(), [(hid, 7, "WEB01", 1)])
        self.assertEqual(c.execute("SELECT fqdn FROM host").fetchone()[0], "WEB01.example.com")
        self.csv("web01.example.com")                                           # 之後再匯入完整名稱的清單：同一台，不會多一筆
        self.assertEqual(self.rows(), [(hid, 7, "web01", 1)])
        self.assertEqual(c.execute("SELECT fqdn FROM host").fetchone()[0], "web01.example.com")

    def test_linked_fqdn_host_renamed_to_short(self):
        """升級前存成完整名稱、已連到 Landscape 的主機：下次同步改存短名稱（同一筆，歷史不變）"""
        c = self.env.con
        c.execute("INSERT INTO host(landscape_id,hostname,release,last_seen,kernel_status) VALUES (7,'web01.example.com','24.04','x','disabled')")
        c.commit()
        hid = c.execute("SELECT id FROM host").fetchone()[0]
        with self.landscape([self.comp(7, "web01.example.com")], {7: {"openssl": "1"}}):
            sync.sync_hosts(c)
        self.assertEqual(self.rows(), [(hid, 7, "web01", 1)])

    def test_hostname_and_ip_keys_use_full_name(self):
        from unittest import mock
        from cvehub.config import Config
        for key in ("hostname", "ip"):
            self.tearDown(); self.setUp()
            c = self.env.con
            with mock.patch.object(Config, "HOST_MATCH_KEY", key):
                self.csv("web01", "db01.example.com")
                with self.landscape([self.comp(7, "web01.example.com"), self.comp(8, "DB01.example.com")],
                                    {7: {"openssl": "1"}, 8: {"openssl": "1"}}):
                    sync.sync_hosts(c)
            names = {r["hostname"]: r["landscape_id"] for r in c.execute("SELECT * FROM host WHERE active=1")}
            self.assertEqual(names, {"web01.example.com": 7, "DB01.example.com": 8}, key)     # 短名稱不接續；完整名稱相同才接續
            self.assertEqual(c.execute("SELECT landscape_id FROM host WHERE hostname='web01'").fetchone()[0], None, key)

    def test_landscape_names_with_same_short_name_not_continued(self):
        c = self.env.con
        self.csv("web01")
        hid = c.execute("SELECT id FROM host").fetchone()[0]
        with self.landscape([self.comp(7, "web01.a.example.com"), self.comp(8, "web01.b.example.com")],
                            {7: {"openssl": "1"}, 8: {"openssl": "1"}}), self.assertLogs("cvehub.sync", "WARNING") as logs:
            sync.sync_hosts(c)
        self.assertTrue(any("2 台電腦都對應到" in m for m in logs.output), logs.output)
        self.assertIsNone(c.execute("SELECT landscape_id FROM host WHERE id=?", (hid,)).fetchone()[0])
        self.assertEqual(sorted(r[0] for r in c.execute("SELECT hostname FROM host WHERE landscape_id IS NOT NULL")),
                         ["web01.a.example.com", "web01.b.example.com"])

    def test_same_short_name_in_landscape_continues_exact_names(self):
        c = self.env.con
        self.csv("web01.a.example.com", "web01.b.example.com")
        ids = dict(c.execute("SELECT hostname, id FROM host").fetchall())
        self.assertEqual(sorted(ids), ["web01.a.example.com", "web01.b.example.com"])   # 檔案裡兩台第一段相同：存完整名稱
        with self.landscape([self.comp(8, "web01.b.example.com"), self.comp(7, "web01.a.example.com")],
                            {7: {"openssl": "1"}, 8: {"openssl": "1"}}):
            sync.sync_hosts(c)
        self.assertEqual(dict(c.execute("SELECT hostname, landscape_id FROM host").fetchall()),
                         {"web01.a.example.com": 7, "web01.b.example.com": 8})
        self.assertEqual(dict(c.execute("SELECT hostname, id FROM host").fetchall()), ids)

    def test_two_active_list_hosts_with_same_key(self):
        """升級前留下的資料：web01 與 web01.example.com 兩台都啟用中、都沒連 Landscape：接續名稱完全相同的那台"""
        c = self.env.con
        for n in ("web01", "web01.example.com"):
            c.execute("INSERT INTO host(hostname,release,last_seen,kernel_status) VALUES (?,'24.04',?,'disabled')", (n, sync.now()))
        c.commit()
        with self.landscape([self.comp(7, "web01.example.com")], {7: {"openssl": "1"}}):
            sync.sync_hosts(c)
        self.assertEqual(self.rows(), [(1, None, "web01", 0), (2, 7, "web01", 1)])

    def test_two_active_list_hosts_ambiguous(self):
        c = self.env.con
        for n in ("web01.a.example.com", "web01.b.example.com"):
            c.execute("INSERT INTO host(hostname,release,last_seen,kernel_status) VALUES (?,'24.04',?,'disabled')", (n, sync.now()))
        c.commit()
        with self.landscape([self.comp(7, "web01")], {7: {"openssl": "1"}}), self.assertLogs("cvehub.sync", "WARNING") as logs:
            sync.sync_hosts(c)
        self.assertTrue(any("多台啟用中" in m for m in logs.output), logs.output)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM host WHERE landscape_id IS NULL").fetchone()[0], 2)

    def test_csv_names_with_same_key_rejected(self):
        from cvehub import host_import
        with self.assertRaises(host_import.ImportError_) as e:
            self.csv("web01", "WEB01.example.com")
        self.assertIn("第 3 列：主機 WEB01.example.com 和第 2 列的 web01", str(e.exception))

    def test_csv_ambiguous_existing_hosts(self):
        """依短名稱對到兩台啟用中的主機：整份不匯入，要寫完整名稱；寫了完整名稱就對到那一台"""
        from cvehub import host_import
        c = self.env.con
        for n in ("web01.a.example.com", "web01.b.example.com"):
            c.execute("INSERT INTO host(hostname,release,last_seen,kernel_status) VALUES (?,'24.04','x','disabled')", (n,))
        c.commit()
        before = self.rows()
        with self.assertRaises(host_import.ImportError_) as e:
            self.csv("web01")
        self.assertIn("完整名稱", str(e.exception))
        self.assertEqual(self.rows(), before)
        self.csv("WEB01.b.example.com")
        self.assertEqual(len(self.rows()), 2)
        self.assertEqual(c.execute("SELECT package_count FROM host WHERE hostname='WEB01.b.example.com'").fetchone()[0], 1)

    def test_same_short_name_in_landscape_stored_full(self):
        c = self.env.con
        with self.landscape([self.comp(7, "web01.a.example.com"), self.comp(8, "web01.b.example.com"), self.comp(9, "db01.example.com")],
                            {7: {"openssl": "1"}, 8: {"openssl": "1"}, 9: {"openssl": "1"}}):
            sync.sync_hosts(c)
        self.assertEqual(sorted(r[0] for r in c.execute("SELECT hostname FROM host")), ["db01", "web01.a.example.com", "web01.b.example.com"])

    def test_exception_matches_hostname_or_fqdn(self):
        ex = lambda p: [{"host_pattern": p, "cve": "CVE-1"}]
        for p in ("web01", "WEB01.example.com", "*.example.com", "web*.example.com", "web0?"):
            self.assertTrue(sync.excepted(ex(p), "web01", "CVE-1", "web01.example.com"), p)
        self.assertFalse(sync.excepted(ex("web01.lab.example.com"), "web01", "CVE-1", "web01.example.com"))
        self.assertFalse(sync.excepted(ex("*.example.com"), "web01", "CVE-1"))             # 沒有 fqdn：只比 hostname
        self.assertFalse(sync.excepted(ex("web01"), "web01.example.com", "CVE-2"))

    def test_upgrade_fills_fqdn(self):
        from cvehub import db
        c = self.env.con
        c.execute("DROP TRIGGER host_gen_u")                     # 0.9.3 的資料庫沒有這個觸發器（用到 fqdn）
        c.execute("ALTER TABLE host DROP COLUMN fqdn")
        c.execute("INSERT INTO host(hostname,release,last_seen,kernel_status) VALUES ('web01.example.com','24.04','x','disabled')")
        c.commit()
        db.init(c)
        self.assertEqual(c.execute("SELECT fqdn FROM host").fetchone()[0], "web01.example.com")
    def test_short_name_kept_full_when_other_active_host_has_it(self):
        """沒接續的清單主機 web01 還在（LANDSCAPE_QUERY）：Landscape 那台存完整名稱，兩筆分得出來"""
        from unittest import mock
        from cvehub.config import Config
        c = self.env.con
        self.csv("web01")
        with mock.patch.object(Config, "LANDSCAPE_QUERY", "tag:x"), self.assertLogs("cvehub.sync", "WARNING"), \
                self.landscape([self.comp(7, "web01.example.com")], {7: {"openssl": "1"}}):
            sync.sync_hosts(c)
        self.assertEqual(sorted(r[0] for r in c.execute("SELECT hostname FROM host WHERE active=1")), ["web01", "web01.example.com"])

    def test_ip_as_name_not_cut(self):
        c = self.env.con
        with self.landscape([self.comp(7, "10.1.20.5")], {7: {"openssl": "1"}}):
            sync.sync_hosts(c)
        self.assertEqual(c.execute("SELECT hostname FROM host").fetchone()[0], "10.1.20.5")

    def test_csv_exact_inactive_does_not_revive_beside_active(self):
        """停用的 web01.example.com 和啟用中的 web01：匯入 web01.example.com 更新啟用中那台，不會變成兩台啟用中"""
        c = self.env.con
        c.execute("INSERT INTO host(hostname,release,last_seen,kernel_status,active) VALUES ('web01.example.com','24.04','x','disabled',0)")
        c.execute("INSERT INTO host(hostname,release,last_seen,kernel_status,active) VALUES ('web01','24.04','x','disabled',1)")
        c.commit()
        self.csv("web01.example.com")
        self.assertEqual(c.execute("SELECT COUNT(*) FROM host WHERE active=1").fetchone()[0], 1)
        self.assertEqual(c.execute("SELECT id FROM host WHERE active=1").fetchone()[0], 2)

    def test_csv_two_active_same_exact_name_takes_newest(self):
        c = self.env.con
        for _ in range(2):
            c.execute("INSERT INTO host(hostname,release,last_seen,kernel_status) VALUES ('web01','24.04','x','disabled')")
        c.commit()
        self.csv("WEB01")
        self.assertEqual(c.execute("SELECT id FROM host WHERE package_count=1").fetchone()[0], 2)

    def test_different_fqdn_is_not_short_stored_host(self):
        """web01（實際是 web01.a）已存成短名稱；清單只有 web01.b：是另一台，新增一筆，兩台都改顯示完整名稱"""
        c = self.env.con
        self.csv("web01.a.example.com")
        self.assertEqual(self.rows(), [(1, None, "web01", 1)])
        self.csv("web01.b.example.com")
        self.assertEqual(self.rows(), [(1, None, "web01.a.example.com", 1), (2, None, "web01.b.example.com", 1)])
        from unittest import mock
        from cvehub.config import Config
        with mock.patch.object(Config, "HOSTS_FILE_MODE", "replace"):
            self.csv("web01.b.example.com")                                 # a 被停用：b 改回短名稱
        self.assertEqual(self.rows(), [(1, None, "web01.a.example.com", 0), (2, None, "web01", 1)])

    def test_exact_only_matches_short_stored_host_by_fqdn(self):
        c = self.env.con
        self.csv("web01.a.example.com")
        self.csv("web01.a.example.com", "web01.b.example.com")
        self.assertEqual(self.rows(), [(1, None, "web01.a.example.com", 1), (2, None, "web01.b.example.com", 1)])
        with self.landscape([self.comp(8, "web01.b.example.com"), self.comp(7, "web01.a.example.com")],
                            {7: {"openssl": "1"}, 8: {"openssl": "1"}}):
            sync.sync_hosts(c)
        self.assertEqual(self.rows(), [(1, 7, "web01.a.example.com", 1), (2, 8, "web01.b.example.com", 1)])

    def test_host_match_key_changed_to_hostname(self):
        from unittest import mock
        from cvehub.config import Config
        self.csv("web01.example.com")
        self.assertEqual(self.rows(), [(1, None, "web01", 1)])
        with mock.patch.object(Config, "HOST_MATCH_KEY", "hostname"):
            self.csv("web01.example.com")
        self.assertEqual(self.rows(), [(1, None, "web01.example.com", 1)])

    def test_inactive_list_host_continued_beside_other_linked_machine(self):
        """停用的清單主機 web01.a 和連到 Landscape 的 web01.b 是不同台：web01.a 加入 Landscape 時照樣接續"""
        c = self.env.con
        self.csv("web01.a.example.com")
        c.execute("UPDATE host SET active=0 WHERE id=1")
        c.execute("INSERT INTO host(landscape_id,hostname,fqdn,release,last_seen,kernel_status) "
                  "VALUES (5,'web01','web01.b.example.com','24.04',?,'disabled')", (sync.now(),))
        c.commit()
        with self.landscape([self.comp(5, "web01.b.example.com"), self.comp(7, "web01.a.example.com")],
                            {5: {"openssl": "1"}, 7: {"openssl": "1"}}):
            sync.sync_hosts(c)
        self.assertEqual(self.rows(), [(1, 7, "web01.a.example.com", 1), (2, 5, "web01.b.example.com", 1)])

    def test_csv_short_name_keeps_landscape_fqdn(self):
        c = self.env.con
        with self.landscape([self.comp(7, "web01.example.com")], {7: {"openssl": "1"}}):
            sync.sync_hosts(c)
        self.csv("web01")
        self.assertEqual(tuple(c.execute("SELECT hostname, fqdn FROM host").fetchone()), ("web01", "web01.example.com"))
        self.assertTrue(sync.excepted([{"host_pattern": "*.example.com", "cve": "*"}], "web01", "CVE-1",
                                      c.execute("SELECT fqdn FROM host").fetchone()[0]))

    def test_inactive_exact_name_preferred(self):
        from cvehub import hostnames
        r = lambda i, n: {"id": i, "hostname": hostnames.short(n), "fqdn": n, "active": 0}
        old, other = r(5, "web01"), r(9, "web01.b.example.com")
        self.assertEqual(hostnames.choose([other, old], "web01"), (old, False))

    def test_inactive_different_machines_not_continued_by_short_name(self):
        """都停用、候選是不同台（web01.a…、web01.b…）：只寫 web01 時分不出是哪一台，另建一筆"""
        from cvehub import hostnames
        r = lambda i, n: {"id": i, "hostname": n, "fqdn": n, "active": 0}
        a, b = r(5, "web01.a.example.com"), r(9, "web01.b.example.com")
        self.assertEqual(hostnames.choose([b, a], "web01"), (None, False))
        self.assertEqual(hostnames.choose([b, a], "web01.a.example.com"), (a, False))
        self.csv("web01.a.example.com", "web01.b.example.com")
        self.env.con.execute("UPDATE host SET active=0")
        self.env.con.commit()
        self.csv("web01")
        self.assertEqual(self.rows(), [(1, None, "web01.a.example.com", 0), (2, None, "web01.b.example.com", 0), (3, None, "web01", 1)])

    def test_list_spelling_variant_keeps_existing_full_name(self):
        """清單的名稱多了結尾的點：沿用原本的完整名稱（Landscape 同步的 web01.example.com）"""
        c = self.env.con
        with self.landscape([self.comp(7, "web01.example.com")], {7: {"openssl": "1"}}):
            sync.sync_hosts(c)
        for name in ("web01.example.com.", "web01."):
            self.csv(name)
            self.assertEqual([tuple(r) for r in c.execute("SELECT id, landscape_id, fqdn FROM host ORDER BY id")], [(1, 7, "web01.example.com")])

    def test_trailing_dot(self):
        from cvehub import hostnames
        self.assertTrue(hostnames.same_machine("web01.example.com.", "WEB01.example.com"))
        self.assertTrue(hostnames.same_machine("web01.", "web01.example.com"))

    def test_csv_note_when_existing_host_not_continued(self):
        from cvehub import host_import
        c = self.env.con
        self.csv("web01")
        host_import.apply(c, host_import.parse("hostname,release,package,version\n"
                                               "web01.a.example.com,24.04,openssl,1\nweb01.b.example.com,24.04,openssl,1\n"), ("f.csv", "x"))
        note = c.execute("SELECT message FROM host_import").fetchone()[0]
        self.assertIn("沒有接續：web01", note)

    def test_no_duplicate_short_name_mid_sync(self):
        """同步途中失敗：已寫入的主機不會和別的啟用中主機同名"""
        c = self.env.con
        self.csv("web01.a.example.com")
        with self.landscape([self.comp(7, "web01.b.example.com"), self.comp(8, "db01")], {7: {"openssl": "1"}}):
            with self.assertRaises(KeyError):
                sync.sync_hosts(c)                                          # 第二台讀套件失敗
        self.assertEqual(sorted(r[0] for r in c.execute("SELECT hostname FROM host WHERE active=1")), ["web01", "web01.b.example.com"])

    def test_block_needs_linked_host_same_as_new_computer(self):
        c = self.env.con
        self.csv("web01")
        c.execute("UPDATE host SET active=0 WHERE id=1")
        c.execute("INSERT INTO host(landscape_id,hostname,fqdn,release,last_seen,kernel_status) "
                  "VALUES (5,'web01.b.example.com','web01.b.example.com','24.04',?,'disabled')", (sync.now(),))
        c.commit()
        with self.landscape([self.comp(7, "web01.a.example.com")], {7: {"openssl": "1"}}):
            sync.sync_hosts(c)
        self.assertEqual(c.execute("SELECT landscape_id FROM host WHERE id=1").fetchone()[0], 7)

    def test_inactive_host_shows_full_name(self):
        c = self.env.con
        self.csv("web01.a.example.com")
        from unittest import mock
        from cvehub.config import Config
        with mock.patch.object(Config, "HOSTS_FILE_MODE", "replace"):
            self.csv("web01.b.example.com")
        self.assertEqual(self.rows(), [(1, None, "web01.a.example.com", 0), (2, None, "web01", 1)])

    def test_identical_names_with_trailing_dot_not_continued(self):
        c = self.env.con
        self.csv("web01.example.com")
        with self.landscape([self.comp(7, "web01.example.com."), self.comp(8, "web01.example.com")],
                            {7: {"openssl": "1"}, 8: {"openssl": "1"}}), self.assertLogs("cvehub.sync", "WARNING"):
            sync.sync_hosts(c)
        self.assertIsNone(c.execute("SELECT landscape_id FROM host WHERE id=1").fetchone()[0])

    def test_no_exact_only_warning_for_unrelated_host(self):
        c = self.env.con
        self.csv("web01.c.example.com")
        from unittest import mock
        with self.landscape([self.comp(7, "web01.a.example.com"), self.comp(8, "web01.b.example.com")],
                            {7: {"openssl": "1"}, 8: {"openssl": "1"}}), mock.patch.object(sync.log, "warning") as w:
            sync.sync_hosts(c)
        w.assert_not_called()

    def test_pick_host(self):
        from cvehub import hostnames
        h = lambda i, act, n="web01": {"id": i, "active": act, "hostname": n, "fqdn": n}
        a, i1, i2 = h(3, 1), h(2, 0), h(1, 0, "web01.example.com")
        self.assertEqual(hostnames.pick([i1, a, i2]), (a, False))
        self.assertEqual(hostnames.pick([i1, i2]), (i1, False))
        self.assertEqual(hostnames.pick([h(2, 0, "web01.b.example.com"), h(1, 0, "web01.a.example.com")]), (None, False))
        self.assertEqual(hostnames.pick([]), (None, False))
        self.assertEqual(hostnames.pick([a, dict(a, id=4)]), (None, True))

    def test_choose(self):
        from cvehub import hostnames
        r = lambda i, n, a=1: {"id": i, "hostname": hostnames.short(n), "fqdn": n, "active": a}   # 比對用 fqdn
        a, b = r(2, "web01.a.example.com"), r(1, "web01.b.example.com", 0)
        self.assertEqual(hostnames.choose([a, b], "web01.b.example.com"), (b, False))    # 不同的完整名稱不是同一台
        self.assertEqual(hostnames.choose([a], "web01.b.example.com"), (None, False))
        self.assertEqual(hostnames.choose([a, r(1, "web01")], "web01"), (r(1, "web01"), False))
        self.assertEqual(hostnames.choose([a, r(1, "web01.b.example.com")], "web01"), (None, True))
        self.assertEqual(hostnames.choose([r(3, "web01"), a], "web01.a.example.com"), (a, False))   # 分不出來：名稱完全相同的優先
        self.assertEqual(hostnames.choose([r(1, "web01")], "web01.a.example.com", exact_only=True), (None, False))
        short = r(1, "web01")
        self.assertEqual(hostnames.choose([short, r(4, "web01.example.com", 0)], "web01.example.com"), (short, False))  # 啟用中的優先


if __name__ == "__main__":
    unittest.main()
