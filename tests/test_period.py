import io
import os
import unittest

from cvehub import osv_import, period, vex_import
from tests.helpers import TempEnv, make_osv_tar, make_vex_tar, osv_record

E20P, E22, E22P, E24 = "Ubuntu:Pro:20.04:LTS", "Ubuntu:22.04:LTS", "Ubuntu:Pro:22.04:LTS", "Ubuntu:24.04:LTS"


def rec(cve, affected, prio, published, details="說明"):
    d = osv_record(cve, affected, prio)
    d["published"] = published
    d["details"] = details
    return d


RECS = [
    # 三個版本都有，20.04 只在 Pro 修好
    rec("CVE-2026-1001", [(E20P, "openssl", "1.1.1f-1ubuntu2.24+esm1", {"openssl": "1.1.1f-1ubuntu2.24+esm1"}),
                          ("Ubuntu:20.04:LTS", "openssl", None, {}),
                          (E22, "openssl", "3.0.2-0ubuntu1.20", {"openssl": "3.0.2-0ubuntu1.20"}),
                          (E24, "openssl", "3.0.13-0ubuntu3.16", {"openssl": "3.0.13-0ubuntu3.16", "libssl3t64": "3.0.13-0ubuntu3.16"})],
        "high", "2026-07-10T00:00:00Z", "openssl 的問題"),
    # kernel：只留 linux 與 linux-hwe-*，雲端變體不列；24.04 尚未修正
    rec("CVE-2026-1002", [(E22, "linux", "5.15.0-160.170", {}), (E22, "linux-hwe-6.8", "6.8.0-90.91~22.04.1", {}),
                          (E22, "linux-aws", "5.15.0-1090.97", {}), (E24, "linux", None, {}),
                          (E24, "linux-firmware", "20240318.git3b128b60-0ubuntu2.20", {})],
        "critical", "2026-08-01T12:00:00Z"),
    # 舊的 HWE 系列（6.5）不是最新、也沒有主機裝 → 不列
    rec("CVE-2026-1006", [(E22, "linux-hwe-6.5", None, {}), (E22, "linux-hwe-6.8", "6.8.0-91.92~22.04.1", {})],
        "high", "2026-08-02T00:00:00Z", "x" * 1500),
    # 22.04 只有 Pro（universe）才有修正
    rec("CVE-2026-1003", [(E22P, "nodejs", "12.22.9~dfsg-1ubuntu3.6+esm1", {})], "medium", "2026-09-30T23:00:00Z"),
    # 區間外、等級太低
    rec("CVE-2026-1004", [(E24, "curl", "8.5.0-2ubuntu10.9", {})], "high", "2026-10-01T00:00:00Z"),
    rec("CVE-2026-1005", [(E24, "curl", "8.5.0-2ubuntu10.9", {})], "low", "2026-08-15T00:00:00Z"),
    # OSV 沒有任何指定版本的套件（只有 26.04）：季報表仍要列出這個 CVE
    rec("CVE-2026-1007", [("Ubuntu:26.04:LTS", "zlib", "1:1.3", {})], "medium", "2026-09-01T00:00:00Z"),
]

VEX = {
    "CVE-2026-1001": [("fixed", [("openssl", "esm-infra/focal"), ("openssl", "jammy"), ("openssl", "noble")]),
                      ("eol", [("openssl", "focal")]),
                      ("not-affected", [("openssl1.0", "jammy")])],
    "CVE-2026-1002": [("fixed", [("linux", "jammy"), ("linux-hwe-6.8", "jammy"), ("linux-firmware", "noble")]),
                      ("vulnerable-wip", [("linux", "noble")]),
                      ("ignored", [("linux-aws", "jammy")])],
    "CVE-2026-1003": [("fixed", [("nodejs", "esm-apps/jammy")]), ("deferred", [("nodejs", "jammy")]),
                      ("needs-evaluation", [("nodejs", "noble")]), ("not-in-release", [("nodejs", "esm-infra/focal")])],
    "CVE-2026-1006": [("fixed", [("linux-hwe-6.8", "jammy")]), ("ignored", [("linux-hwe-6.5", "jammy")])],
    "CVE-2026-1007": [("not-affected", [("zlib", "jammy"), ("zlib", "noble")])],
}


class PeriodTest(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv(UBUNTU_RELEASES=["20.04", "22.04", "24.04"]).__enter__()
        osv_import.import_file(self.env.con, make_osv_tar(os.path.join(self.env.dir.name, "o.tar.xz"), RECS))
        c = self.env.con
        c.execute("INSERT INTO host(id, hostname, release, active) VALUES (1, 'web01', '24.04', 1)")
        c.execute("INSERT INTO host_package VALUES (1, 'libssl3t64', '3.0.13-0ubuntu3')")
        c.commit()

    def tearDown(self):
        self.env.__exit__()

    def with_vex(self):
        vex_import.import_file(self.env.con, make_vex_tar(os.path.join(self.env.dir.name, "v.tar.xz"), VEX))

    def rows(self, minp="medium", status="", have_vex=True):
        rows, summary = period.build(self.env.con, "2026-07-01", "2026-09-30", minp, status, have_vex=have_vex)
        return {(r["cve_id"], r["package"]): r for r in rows}, summary

    def test_osv_only(self):
        """沒有 VEX：只分 Fixed／Vulnerable"""
        rows, _ = self.rows(have_vex=False)
        r = rows[("CVE-2026-1001", "openssl")]
        self.assertEqual(r["description"], "openssl 的問題")
        self.assertEqual(r["ubuntu20"], "已修正 1.1.1f-1ubuntu2.24+esm1")      # 20.04 以 Pro 為準、不標 Pro
        self.assertEqual(r["ubuntu22"], "已修正 3.0.2-0ubuntu1.20")
        self.assertEqual(rows[("CVE-2026-1003", "nodejs")]["ubuntu22"], "已修正（Pro） 12.22.9~dfsg-1ubuntu3.6+esm1")
        self.assertEqual(rows[("CVE-2026-1003", "nodejs")]["codes"]["ubuntu24"], "none")
        self.assertEqual(rows[("CVE-2026-1002", "linux")]["codes"]["ubuntu24"], "vulnerable")

    def test_vex_statuses(self):
        self.with_vex()
        rows, _ = self.rows()
        r = rows[("CVE-2026-1001", "openssl")]
        self.assertEqual(r["codes"], {"ubuntu20": "fixed", "ubuntu22": "fixed", "ubuntu24": "fixed"})
        self.assertEqual(r["ubuntu24"], "已修正 3.0.13-0ubuntu3.16")           # 版本用 OSV 的（第一個修正版本）
        self.assertEqual(rows[("CVE-2026-1001", "openssl1.0")]["codes"]["ubuntu22"], "not-affected")
        n = rows[("CVE-2026-1003", "nodejs")]
        self.assertEqual(n["codes"], {"ubuntu20": "not-in-release", "ubuntu22": "fixed", "ubuntu24": "needs-evaluation"})
        self.assertEqual(n["ubuntu22"], "已修正（Pro） 12.22.9~dfsg-1ubuntu3.6+esm1")
        self.assertEqual(rows[("CVE-2026-1002", "linux")]["ubuntu24"], "修正中")
        self.assertEqual(rows[("CVE-2026-1001", "openssl1.0")]["ubuntu24"], "—")
        # 20.04 的 focal 已不支援（Ignored），但 esm-infra 有修正 → 以 Pro 為準
        self.assertEqual(rows[("CVE-2026-1001", "openssl")]["ubuntu20"], "已修正 1.1.1f-1ubuntu2.24+esm1")

    def test_cve_without_packages_listed(self):
        self.with_vex()
        rows, summary = self.rows()
        z = rows[("CVE-2026-1007", "zlib")]
        self.assertEqual(z["codes"], {"ubuntu20": "none", "ubuntu22": "not-affected", "ubuntu24": "not-affected"})
        rows, _ = self.rows(have_vex=False)          # 沒有 VEX 也要列出 CVE（套件欄空白）
        self.assertIn(("CVE-2026-1007", ""), rows)

    def test_kernel_filter(self):
        self.with_vex()
        rows, _ = self.rows()
        pk = sorted(p for c, p in rows if c == "CVE-2026-1002")
        self.assertEqual(pk, ["linux", "linux-firmware", "linux-hwe-6.8"])   # 雲端變體不列；22.04 最新的 HWE
        self.assertNotIn(("CVE-2026-1006", "linux-hwe-6.5"), rows)            # 舊 HWE 不列
        d = rows[("CVE-2026-1006", "linux-hwe-6.8")]["description"]
        self.assertTrue(d.startswith("x" * period.DESC_MAX) and "ubuntu.com/security/CVE-2026-1006" in d)

    def test_summary_worst_status(self):
        self.with_vex()
        rows, summary = self.rows()
        self.assertEqual({c for c, _ in rows}, {"CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003", "CVE-2026-1006", "CVE-2026-1007"})
        self.assertEqual(summary["total"], 5)
        crit = summary["by_level"]["critical"]
        self.assertEqual((crit["cves"], crit["kernel"]), (1, 1))
        self.assertEqual(crit["ubuntu24"]["vulnerable-wip"], 1)               # linux（wip）比 linux-firmware（fixed）優先
        self.assertEqual(crit["ubuntu20"]["none"], 1)
        med = summary["by_level"]["medium"]
        self.assertEqual(med["ubuntu24"]["needs-evaluation"], 1)
        self.assertEqual(med["ubuntu24"]["not-affected"], 1)
        self.assertNotIn("unknown", summary["statuses"])
        rows, _ = self.rows(minp="low")
        self.assertIn(("CVE-2026-1005", "curl"), rows)

    def test_status_filter_and_sort(self):
        self.with_vex()
        rows, summary = self.rows(status="open")
        self.assertEqual(sorted(rows), [("CVE-2026-1002", "linux"), ("CVE-2026-1003", "nodejs")])
        self.assertEqual(summary["total"], 5)                                 # 篩選不影響統計
        rows, _ = self.rows(status="needs-evaluation")
        self.assertEqual(list(rows), [("CVE-2026-1003", "nodejs")])
        lst, _ = period.build(self.env.con, "2026-07-01", "2026-09-30", "medium")
        period.sort_rows(lst, "ubuntu24")
        self.assertEqual(lst[0]["codes"]["ubuntu24"], "needs-evaluation")    # 依狀態順序，最需要注意的在前

    def test_xlsx(self):
        from openpyxl import load_workbook
        self.with_vex()
        rows, summary = period.build(self.env.con, "2026-07-01", "2026-09-30", "medium")
        wb = load_workbook(io.BytesIO(period.to_xlsx(rows, summary, "2026-07-01", "2026-09-30", "medium", vex_date="2026-10-21")))
        self.assertEqual(wb.sheetnames, ["統計", "狀態說明", "明細"])
        head = [c.value for c in wb["明細"][1]]
        self.assertEqual(head, ["CVE", "等級", "公開日期", "套件", "Ubuntu 20.04", "Ubuntu 22.04", "Ubuntu 24.04", "說明"])
        self.assertEqual(wb["明細"].max_row, len(rows) + 1)
        self.assertTrue(any(c.value == "待評估" for c in wb["統計"][9]))
        self.assertEqual([c.value for c in wb["狀態說明"][2]], ["待評估", "官方還沒判斷是否受影響", "Needs evaluation"])


if __name__ == "__main__":
    unittest.main()
