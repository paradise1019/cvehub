import json
import os
import shutil
import unittest

from cvehub import osv_import
from cvehub.config import Config
from tests.helpers import RECORDS, TempEnv, make_osv_tar, osv_record, E


class OsvImportTest(unittest.TestCase):
    def test_import_basic(self):
        with TempEnv() as t:
            f = make_osv_tar(os.path.join(t.dir.name, "osv-all.tar.xz"), RECORDS)
            osv_import.import_file(t.con, f)
            c = t.con
            # 已撤回（0006）不匯入；其他版本（0007）的 CVE 也收（季報表要列），但沒有 affected
            cves = {r[0] for r in c.execute("SELECT cve FROM vuln")}
            self.assertEqual(cves, {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0007"})
            self.assertIsNone(c.execute("SELECT 1 FROM affected WHERE cve='CVE-2026-0007'").fetchone())
            # binary 對應 source
            self.assertEqual(c.execute("SELECT source FROM binmap WHERE ecosystem=? AND binary='libssl3t64'", (E,)).fetchone()[0], "openssl")
            # binary 版本與 source 修正版本相同時不存（省空間）
            self.assertIsNone(c.execute("SELECT binaries FROM affected WHERE cve='CVE-2026-0001'").fetchone()[0])
            imp = osv_import.active_import(c)
            self.assertEqual(imp["status"], "ok")
            self.assertEqual(json.loads(imp["release_counts"])["24.04"], 4)

    def test_ignores_files_outside_osv_cve(self):
        with TempEnv() as t:
            f = make_osv_tar(os.path.join(t.dir.name, "x.tar.xz"), RECORDS,
                             extra_files={"../../evil.json": b"{}", "osv/usn/USN-1.json": b"{}"})
            osv_import.import_file(t.con, f)
            self.assertFalse(os.path.exists(os.path.join(t.dir.name, "..", "evil.json")))

    def test_missing_release_keeps_old_data(self):
        with TempEnv(UBUNTU_RELEASES=["24.04", "22.04"], OSV_MIN_ROWS_PER_RELEASE=2) as t:
            good = RECORDS + [osv_record("CVE-2026-0008", [("Ubuntu:22.04:LTS", "curl", "7.81.0-1ubuntu1.20", {})])]
            osv_import.import_file(t.con, make_osv_tar(os.path.join(t.dir.name, "a.tar.xz"), good))
            before = t.con.execute("SELECT COUNT(*) FROM affected").fetchone()[0]
            # 新檔缺 22.04 的資料 → 失敗，舊資料保留
            bad = [r for r in RECORDS if "0007" not in r["id"]]
            with self.assertRaises(ValueError):
                osv_import.import_file(t.con, make_osv_tar(os.path.join(t.dir.name, "b.tar.xz"), bad))
            self.assertEqual(t.con.execute("SELECT COUNT(*) FROM affected").fetchone()[0], before)
            self.assertEqual(osv_import.active_import(t.con)["filename"], "a.tar.xz")
            self.assertEqual(t.con.execute("SELECT status FROM osv_import ORDER BY id DESC LIMIT 1").fetchone()[0], "failed")

    def test_wrong_file_fails(self):
        with TempEnv() as t:
            with self.assertRaises(ValueError):
                osv_import.import_file(t.con, make_osv_tar(os.path.join(t.dir.name, "empty.tar.xz"), []))
            self.assertIsNone(osv_import.active_import(t.con))

    def test_inbox(self):
        with TempEnv() as t:
            os.makedirs(Config.OSV_INBOX_DIR)
            make_osv_tar(os.path.join(Config.OSV_INBOX_DIR, "20261017-anything.tar.xz"), RECORDS)
            self.assertTrue(osv_import.check_inbox(t.con))
            self.assertEqual(os.listdir(Config.OSV_INBOX_DIR), [])
            self.assertEqual(len(os.listdir(Config.OSV_ARCHIVE_DIR)), 1)

    def test_reimport_when_format_outdated(self):
        with TempEnv() as t:
            rec = osv_record("CVE-2026-0001", [(E, "openssl", "1.0", {})], details="some description")
            os.makedirs(Config.OSV_ARCHIVE_DIR)
            f = make_osv_tar(os.path.join(Config.OSV_ARCHIVE_DIR, "20261017-osv-all.tar.xz"), [rec])
            osv_import.import_file(t.con, f)
            self.assertFalse(osv_import.reimport_if_outdated(t.con))              # 已是新格式：不重匯
            t.con.execute("UPDATE osv_import SET format=NULL")                     # 模擬舊版匯入的資料
            t.con.execute("UPDATE vuln SET details=NULL")
            t.con.commit()
            self.assertTrue(osv_import.reimport_if_outdated(t.con))
            self.assertEqual(t.con.execute("SELECT details FROM vuln").fetchone()[0], "some description")
            self.assertEqual(osv_import.active_import(t.con)["format"], osv_import.FORMAT)
            # 放檔目錄只有已匯入過的同一份檔案：照樣要把舊格式重匯
            t.con.execute("UPDATE osv_import SET format=NULL")
            t.con.commit()
            os.makedirs(Config.OSV_INBOX_DIR)
            shutil.copy2(f, os.path.join(Config.OSV_INBOX_DIR, "same.tar.xz"))
            self.assertFalse(osv_import.check_inbox(t.con))
            self.assertEqual(osv_import.active_import(t.con)["format"], osv_import.FORMAT)

if __name__ == "__main__":
    unittest.main()
