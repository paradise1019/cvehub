import io
import os
import re
import unittest

from werkzeug.security import generate_password_hash

from cvehub import osv_import, sync, vex_import
from cvehub.config import Config
from tests.helpers import RECORDS, TempEnv, make_osv_tar, make_vex_tar


class WebTest(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv(WEB_AUTH_USER="admin", WEB_AUTH_PASSWORD_HASH=generate_password_hash("correct horse battery"),
                           OSV_STALE_WARN_DAYS=100000).__enter__()
        osv_import.import_file(self.env.con, make_osv_tar(os.path.join(self.env.dir.name, "o.tar.xz"), RECORDS))
        from cvehub.web import create_app
        self.app = create_app(start_scheduler=False)
        self.c = self.app.test_client()
        self.auth = {"Authorization": "Basic " + __import__("base64").b64encode(b"admin:correct horse battery").decode()}

    def tearDown(self):
        self.env.__exit__()

    def test_requires_login(self):
        self.assertEqual(self.c.get("/").status_code, 401)
        bad = {"Authorization": "Basic " + __import__("base64").b64encode(b"admin:wrong").decode()}
        self.assertEqual(self.c.get("/", headers=bad).status_code, 401)
        self.assertEqual(self.c.get("/", headers=self.auth).status_code, 200)

    def test_csrf(self):
        self.assertEqual(self.c.post("/sync", headers=self.auth).status_code, 403)
        h = dict(self.auth, Origin="http://evil.example.com")
        self.assertEqual(self.c.post("/sync", headers=h).status_code, 403)

    def test_xss_escaped(self):
        h = dict(self.auth, Origin="http://localhost")
        self.c.post("/exceptions", headers=h, data={"host_pattern": "x", "cve": "CVE-1", "reason": "<script>alert(1)</script>"})
        page = self.c.get("/exceptions", headers=self.auth).get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_healthz(self):
        r = self.c.get("/healthz")                      # 不需登入
        self.assertEqual(r.status_code, 503)
        self.assertIn("never_synced", r.get_json()["problems"])
        self.env.con.execute("INSERT INTO sync_run(started_at,finished_at,status) VALUES (?,?,'ok')", (sync.now(), sync.now()))
        self.env.con.commit()
        r = self.c.get("/healthz")
        self.assertEqual((r.status_code, r.get_json()["status"]), (200, "ok"))
        self.assertNotIn("hostname", r.get_data(as_text=True))
        self.env.con.execute("INSERT INTO host(landscape_id,hostname,release,kernel_status,active) VALUES (1,'h.example.com','24.04','error',1)")
        self.env.con.commit()
        r = self.c.get("/healthz")
        self.assertEqual((r.status_code, r.get_json()["problems"]), (503, ["kernel_api_error"]))

    def test_bad_input_400_and_redirect(self):
        h = dict(self.auth, Origin="http://localhost")
        self.assertEqual(self.c.post("/exceptions", headers=h, data={"delete": "x"}).status_code, 400)
        self.assertEqual(self.c.post("/exceptions", headers=h, data={"host_pattern": "a", "cve": "b", "reason": "c", "expires_at": "bad"}).status_code, 400)
        r = self.c.post("/sync", headers=dict(self.auth, Referer="http://localhost/period?x=1"))
        self.assertEqual(r.headers["Location"], "/period")
        from cvehub import report
        self.assertEqual(report.safe_cell("=HYPERLINK(1)"), "'=HYPERLINK(1)")
        self.assertEqual(report.safe_cell("ok"), "ok")
        self.assertEqual(report.safe_cell(3), 3)

    def test_csv_export(self):
        r = self.c.get("/findings?format=csv&view=summary", headers=self.auth)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_data(as_text=True).startswith("﻿hostname,cve"))



class PeriodWebTest(unittest.TestCase):
    setUp = WebTest.setUp
    tearDown = WebTest.tearDown

    def with_vex(self):
        make_vex_tar(os.path.join(self.env.dir.name, "v.tar.xz"), {
            "CVE-2026-0001": [("fixed", [("openssl", "noble")])],
            "CVE-2026-0003": [("needs-evaluation", [("curl", "noble")])],
            "CVE-2026-0002": [("fixed", [("openssl", "noble")])]})
        vex_import.import_file(self.env.con, os.path.join(self.env.dir.name, "v.tar.xz"))

    def test_period_page_and_xlsx(self):
        r = self.c.get("/period?from=2025-12-01&to=2026-01-31&min_priority=low", headers=self.auth)
        self.assertEqual(r.status_code, 200)
        page = r.get_data(as_text=True)
        self.assertIn("CVE-2026-0001", page)
        self.assertIn("尚未匯入 VEX", page)
        x = self.c.get("/period?from=2025-12-01&to=2026-01-31&format=xlsx", headers=self.auth)
        self.assertEqual(x.status_code, 200)
        self.assertTrue(x.data.startswith(b"PK"))          # xlsx 是 zip
        self.assertIn("cve-quarterly-20251201-20260131.xlsx", x.headers["Content-Disposition"])
        self.assertEqual(self.c.get("/period?from=bad&to=2026-01-31", headers=self.auth).status_code, 400)
        self.assertEqual(self.c.get("/period", headers=self.auth).status_code, 200)       # 預設本季

    def test_period_vex_and_filter(self):
        self.with_vex()
        base = "/period?from=2025-12-01&to=2026-01-31&min_priority=low"
        page = self.c.get(base, headers=self.auth).get_data(as_text=True)
        self.assertIn('s-needs-evaluation" title="Needs evaluation">待評估', page)
        self.assertNotIn("尚未匯入 VEX", page)
        page = self.c.get(base + "&status=needs-evaluation", headers=self.auth).get_data(as_text=True)
        self.assertIn("CVE-2026-0003", page)
        self.assertNotIn(">CVE-2026-0001<", page)

    def test_period_sort(self):
        base = "/period?from=2025-12-01&to=2026-01-31&min_priority=low"
        first = lambda q: re.search(r'<td class="nowrap"><a href="[^"]*">(CVE-[0-9-]+)</a>', self.c.get(base + q, headers=self.auth).get_data(as_text=True)).group(1)
        self.assertEqual(first("&sort=cve_id&dir=asc"), "CVE-2026-0001")
        self.assertEqual(first("&sort=cve_id&dir=desc"), "CVE-2026-0007")
        self.assertIn("▼", self.c.get(base + "&sort=cve_id&dir=desc", headers=self.auth).get_data(as_text=True))
        for col in ("priority", "published", "package", "ubuntu20", "ubuntu24", "description"):
            self.assertEqual(self.c.get(base + "&sort=" + col + "&dir=desc", headers=self.auth).status_code, 200)
        self.assertEqual(self.c.get(base + "&sort=evil", headers=self.auth).status_code, 200)   # 不認得的欄位忽略

    def test_impact_and_cve_pages(self):
        self.with_vex()
        c = self.env.con
        c.execute("INSERT INTO host(id, landscape_id, hostname, release, active) VALUES (1, 1, 'web01', '24.04', 1)")
        c.executemany("INSERT INTO host_package VALUES (1, ?, ?)", [("curl", "8.5.0-2ubuntu10"), ("libssl3t64", "3.0.13-0ubuntu3")])
        c.execute("INSERT INTO finding(host_id, cve, package, source, installed, fixed, status, location, action, priority, first_seen, last_seen) "
                  "VALUES (1, 'CVE-2026-0001', 'libssl3t64', 'openssl', '3.0.13-0ubuntu3', '3.0.13-0ubuntu3.4', 'fix-available', 'installed', 'upgrade', 'high', 'x', 'x')")
        c.commit()
        page = self.c.get("/impact?min_priority=low", headers=self.auth).get_data(as_text=True)
        self.assertIn("CVE-2026-0001", page)          # 待更新
        self.assertIn("CVE-2026-0003", page)          # 尚無修正（Needs evaluation）
        self.assertIn("s-needs-evaluation", page)
        page = self.c.get("/impact?min_priority=low&state=pending", headers=self.auth).get_data(as_text=True)
        self.assertNotIn("CVE-2026-0003", page)
        csv = self.c.get("/impact?min_priority=low&format=csv", headers=self.auth).get_data(as_text=True)
        self.assertIn("待更新主機", csv.splitlines()[0])
        page = self.c.get("/cve/cve-2026-0003", headers=self.auth).get_data(as_text=True)
        self.assertIn("web01", page)
        self.assertIn("尚無修正", page)
        page = self.c.get("/cve/CVE-2026-0005", headers=self.auth).get_data(as_text=True)
        self.assertIn("<td>linux</td>", page)
        self.env.con.execute("INSERT INTO affected(ecosystem,source,cve,fixed) VALUES ('Ubuntu:24.04:LTS','linux-aws','CVE-2026-0005',NULL)")
        self.env.con.commit()
        self.assertNotIn("linux-aws", self.c.get("/cve/CVE-2026-0005", headers=self.auth).get_data(as_text=True))   # 主機沒裝的變體不列
        page = self.c.get("/cve/CVE-2026-0002", headers=self.auth).get_data(as_text=True)
        self.assertIn("不受影響", page)               # 有裝 openssl、官方 Fixed、沒有待更新

    def test_impact_many_hosts_and_paging(self):
        self.with_vex()
        c = self.env.con
        for i in range(1, 8):          # 7 台都裝了 curl（CVE-2026-0003：待評估）
            c.execute("INSERT INTO host(id, landscape_id, hostname, release, active) VALUES (?, ?, ?, '24.04', 1)", (i, i, "web%02d" % i))
            c.execute("INSERT INTO host_package VALUES (?, 'curl', '8.5.0-2ubuntu10')", (i,))
        c.commit()
        page = self.c.get("/impact?min_priority=low", headers=self.auth).get_data(as_text=True)
        self.assertIn("7 台</b>：web01、web02、web03", page)
        self.assertNotIn("web04", page)                    # 只列 3 台，其餘點 CVE 頁
        self.assertIn("…等 7 台", page)
        csv = self.c.get("/impact?min_priority=low&format=csv", headers=self.auth).get_data(as_text=True)
        self.assertIn("web07", csv)                         # CSV 列全部
        self.assertIn("web07", self.c.get("/cve/CVE-2026-0003", headers=self.auth).get_data(as_text=True))
        from cvehub import web
        saved, web.PER_PAGE = web.PER_PAGE, 2
        try:
            p2 = self.c.get("/period?from=2025-12-01&to=2026-01-31&min_priority=low&page=2", headers=self.auth).get_data(as_text=True)
            self.assertIn("第 2／", p2)
            self.assertEqual(len(re.findall(r'<td class="nowrap"><a href="[^"]*/cve/', p2)), 2)
            self.assertEqual(self.c.get("/period?from=2025-12-01&to=2026-01-31&page=x", headers=self.auth).status_code, 200)
        finally:
            web.PER_PAGE = saved

    def test_data_page_upload(self):
        self.assertEqual(self.c.get("/osv", headers=self.auth).status_code, 302)
        self.assertEqual(self.c.get("/data", headers=self.auth).status_code, 200)
        h = dict(self.auth, Origin="http://localhost")
        r = self.c.post("/data", headers=h, data={"kind": "evil", "file": (io.BytesIO(b"x"), "a.tar.xz")})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
