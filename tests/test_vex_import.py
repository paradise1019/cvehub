import json
import os
import tarfile
import io
import unittest

from cvehub import vex_import
from cvehub.config import Config
from tests.helpers import NOTE, TempEnv, make_vex_tar


class ClassifyTest(unittest.TestCase):
    def test_all_known_notes(self):
        expect = {"fixed": "fixed", "vulnerable": "vulnerable", "vulnerable-wip": "vulnerable-wip", "deferred": "deferred",
                  "ignored": "ignored", "eol": "ignored", "needs-evaluation": "needs-evaluation",
                  "not-affected": "not-affected", "not-in-release": "not-in-release"}
        for key, code in expect.items():
            self.assertEqual(vex_import.classify(*NOTE[key]), code, key)
        self.assertEqual(vex_import.classify("under_investigation", None,
                         "The vulnerability of this package (for the given release) is not known and needs to be evaluated."),
                         "needs-evaluation")
        self.assertIsNone(vex_import.classify("affected", None, "Some new wording"))

    def test_status_for(self):
        row = {"base_status": "ignored", "pro_status": "fixed"}
        self.assertEqual(vex_import.status_for(row, "20.04", {"pro": "1.0+esm1"}), ("fixed", True, "1.0+esm1"))
        self.assertEqual(vex_import.status_for(row, "22.04", {"pro": "1.0+esm1"}), ("fixed", True, "1.0+esm1"))
        self.assertEqual(vex_import.status_for({"base_status": "deferred", "pro_status": None}, "24.04"), ("deferred", False, ""))
        self.assertEqual(vex_import.status_for({"base_status": None, "pro_status": "vulnerable"}, "24.04"), ("vulnerable", True, ""))
        self.assertEqual(vex_import.status_for(None, "24.04"), ("none", False, ""))


class ImportTest(unittest.TestCase):
    DOCS = {
        "CVE-2026-0001": [("fixed", [("openssl", "noble"), ("openssl", "esm-infra/focal")]),
                          ("eol", [("openssl", "focal")]),
                          ("vulnerable", [("linux-aws", "noble"), ("linux", "noble"), ("linux-hwe-6.8", "jammy")]),
                          ("fixed", [("openssl", "fips/noble"), ("openssl", "xenial")])],      # 不需要的通道／版本
    }

    def test_import(self):
        with TempEnv(UBUNTU_RELEASES=["20.04", "22.04", "24.04"]) as t:
            vex_import.import_file(t.con, make_vex_tar(os.path.join(t.dir.name, "v.tar.xz"), self.DOCS))
            rows = {(r["release"], r["source"]): (r["base_status"], r["pro_status"]) for r in t.con.execute("SELECT * FROM vex_status")}
            self.assertEqual(rows, {("24.04", "openssl"): ("fixed", None), ("20.04", "openssl"): ("ignored", "fixed"),
                                    ("24.04", "linux"): ("vulnerable", None), ("22.04", "linux-hwe-6.8"): ("vulnerable", None)})
            imp = vex_import.active_import(t.con)
            self.assertEqual((imp["status"], imp["cve_count"], imp["unknown_count"]), ("ok", 1, 0))

    def test_keep_kernel_variant(self):
        with TempEnv(UBUNTU_RELEASES=["24.04"], VEX_KEEP_KERNEL_VARIANTS=["linux-aws*"]) as t:
            vex_import.import_file(t.con, make_vex_tar(os.path.join(t.dir.name, "v.tar.xz"), self.DOCS))
            self.assertTrue(t.con.execute("SELECT 1 FROM vex_status WHERE source='linux-aws'").fetchone())

    def test_unknown_note_recorded(self):
        with TempEnv() as t:
            path = os.path.join(t.dir.name, "v.tar.xz")
            doc = {"statements": [{"vulnerability": {"name": "CVE-2026-0009"}, "status": "affected", "action_statement": "Brand new wording",
                                   "products": [{"@id": "pkg:deb/ubuntu/curl@1?arch=source&distro=noble"}]}]}
            with tarfile.open(path, "w:xz") as tar:
                data = json.dumps(doc).encode()
                ti = tarfile.TarInfo("vex/cve/2026/CVE-2026-0009.json")
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))
            vex_import.import_file(t.con, path)
            self.assertEqual(t.con.execute("SELECT base_status FROM vex_status").fetchone()[0], "unknown")
            imp = vex_import.active_import(t.con)
            self.assertEqual(imp["unknown_count"], 1)
            self.assertIn("Brand new wording", imp["message"])

    def test_bad_file_keeps_old_data(self):
        with TempEnv() as t:
            vex_import.import_file(t.con, make_vex_tar(os.path.join(t.dir.name, "v.tar.xz"), self.DOCS))
            bad = make_vex_tar(os.path.join(t.dir.name, "bad.tar.xz"), {"CVE-2026-0002": [("fixed", [("x", "jammy")])]})
            with self.assertRaises(ValueError):
                vex_import.import_file(t.con, bad)                               # 沒有 24.04 的資料
            self.assertEqual(vex_import.active_import(t.con)["filename"], "v.tar.xz")
            self.assertTrue(t.con.execute("SELECT 1 FROM vex_status").fetchone())

    def test_inbox(self):
        with TempEnv() as t:
            os.makedirs(Config.VEX_INBOX_DIR)
            make_vex_tar(os.path.join(Config.VEX_INBOX_DIR, "vex-all.tar.xz"), self.DOCS)
            self.assertTrue(vex_import.check_inbox(t.con))
            self.assertEqual(os.listdir(Config.VEX_INBOX_DIR), [])
            self.assertEqual(len(os.listdir(Config.VEX_ARCHIVE_DIR)), 1)


if __name__ == "__main__":
    unittest.main()
