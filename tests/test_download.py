"""自動下載 OSV／VEX（download.py）：用本機的 HTTP 伺服器模擬 Canonical（ETag、304、Last-Modified）"""
import http.server
import os
import threading
import unittest
from unittest import mock

from cvehub import download, osv_import
from cvehub.config import Config
from tests.helpers import RECORDS, TempEnv, make_osv_tar, osv_record

LAST_MOD = "Wed, 04 Nov 2026 06:20:18 GMT"


class Server:
    """files：路徑 → (內容, ETag)；short：回報的 Content-Length 比實際多（模擬連線中斷）"""

    def __init__(self):
        self.files, self.short, self.requests = {}, set(), []
        srv = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                srv.requests.append((self.path, self.headers.get("If-None-Match")))
                if self.path not in srv.files:
                    self.send_response(404)
                    self.end_headers()
                    return
                body, etag = srv.files[self.path]
                if self.headers.get("If-None-Match") == etag:
                    self.send_response(304)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("ETag", etag)
                self.send_header("Last-Modified", LAST_MOD)
                self.send_header("Content-Length", str(len(body) + (10 if self.path in srv.short else 0)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = "http://127.0.0.1:%d" % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class DownloadTest(unittest.TestCase):
    def setUp(self):
        self.srv = Server()
        self.addCleanup(self.srv.close)
        self.env = TempEnv(CVE_DATA_DOWNLOAD=True, OSV_DOWNLOAD_URL=self.srv.base + "/osv/osv-all.tar.xz",
                           VEX_DOWNLOAD_URL=self.srv.base + "/vex/vex-all.tar.xz", DOWNLOAD_PROXY="", DOWNLOAD_CA_FILE="",
                           DOWNLOAD_TIMEOUT=10, DOWNLOAD_MAX_MB=50, DOWNLOAD_ALERT_HOURS=48, DOWNLOAD_MAX_MINUTES=5,
                           DOWNLOAD_ALLOW_HTTP=True).__enter__()
        self.addCleanup(self.env.__exit__)
        p = mock.patch.dict(os.environ, {"no_proxy": "*", "NO_PROXY": "*"})
        p.start()
        self.addCleanup(p.stop)

    def osv_bytes(self, records=RECORDS, name="o.tar.xz"):
        path = make_osv_tar(os.path.join(self.env.dir.name, name), records)
        with open(path, "rb") as f:
            return f.read()

    def inbox(self):
        return sorted(os.listdir(Config.OSV_INBOX_DIR)) if os.path.isdir(Config.OSV_INBOX_DIR) else []

    def test_new_then_not_modified(self):
        self.srv.files["/osv/osv-all.tar.xz"] = (self.osv_bytes(), '"v1"')
        res, msg = download.fetch(self.env.con, "osv")
        self.assertEqual(res, "new", msg)
        self.assertEqual(len(self.inbox()), 1)
        self.assertRegex(self.inbox()[0], r"^osv-all-download-\d+\.tar\.xz$")       # 不重複的檔名：正在匯入的不會被換掉
        f = os.path.join(Config.OSV_INBOX_DIR, self.inbox()[0])
        self.assertEqual(int(os.path.getmtime(f)), 1793773218)                        # Canonical 的 Last-Modified
        self.assertTrue(osv_import.check_inbox(self.env.con))                         # 和上傳的一樣匯入
        self.assertEqual(download.fetch(self.env.con, "osv"), ("same", "沒有更新"))     # 304
        self.assertEqual(self.srv.requests[-1], ("/osv/osv-all.tar.xz", '"v1"'))
        st = download.load_state()["osv"]
        self.assertEqual((st["etag"], st["last_modified"], st["result"]), ('"v1"', LAST_MOD, "same"))
        self.assertEqual(download.failing(), [])

    def test_same_content_new_etag_not_dropped(self):
        body = self.osv_bytes()
        self.srv.files["/osv/osv-all.tar.xz"] = (body, '"v1"')
        download.fetch(self.env.con, "osv")
        osv_import.check_inbox(self.env.con)
        self.srv.files["/osv/osv-all.tar.xz"] = (body, '"v2"')                        # ETag 變了、內容一樣
        self.assertEqual(download.fetch(self.env.con, "osv"), ("same", "內容和已匯入的相同"))
        self.assertEqual(self.inbox(), [])

    def test_changed_content_downloaded_again(self):
        self.srv.files["/osv/osv-all.tar.xz"] = (self.osv_bytes(), '"v1"')
        download.fetch(self.env.con, "osv")
        osv_import.check_inbox(self.env.con)
        newer = RECORDS + [osv_record("CVE-2026-0999", [("Ubuntu:24.04:LTS", "zlib", "1:1.3", {"zlib1g": "1:1.3"})])]
        self.srv.files["/osv/osv-all.tar.xz"] = (self.osv_bytes(newer, "n.tar.xz"), '"v2"')
        self.assertEqual(download.fetch(self.env.con, "osv")[0], "new")
        self.assertTrue(osv_import.check_inbox(self.env.con))

    def test_errors_leave_nothing_in_inbox(self):
        body = self.osv_bytes()
        cases = {
            "truncated": lambda: (self.srv.short.add("/osv/osv-all.tar.xz"), self.srv.files.update({"/osv/osv-all.tar.xz": (body, '"t"')})),
            "not xz": lambda: self.srv.files.update({"/osv/osv-all.tar.xz": (b"<html>proxy login</html>", '"h"')}),
            "missing": lambda: self.srv.files.clear(),
        }
        for name, setup in cases.items():
            self.srv.short.clear()
            setup()
            res, msg = download.fetch(self.env.con, "osv")
            self.assertEqual(res, "error", name)
            self.assertEqual(self.inbox(), [], name)                                  # 沒有寫一半的檔案、也沒有 .part
        st = download.load_state()["osv"]
        self.assertNotIn("etag", {k: v for k, v in st.items() if v})                  # 失敗不記 ETag：下次重新下載

    def test_bad_content_moved_aside_then_refetched(self):
        """內容有問題的檔案（筆數不足）：匯入失敗後移到保存目錄（failed-），不擋住之後的新檔；
        下次檢查不帶條件重新下載（設定改正或 Canonical 修正後自動恢復）"""
        bad = self.osv_bytes([osv_record("CVE-2026-0001", [("Ubuntu:22.04:LTS", "x", "1", {"x": "1"})])], "bad.tar.xz")   # 沒有 24.04
        self.srv.files["/osv/osv-all.tar.xz"] = (bad, '"bad"')
        self.assertEqual(download.fetch(self.env.con, "osv")[0], "new")
        with self.assertRaises(ValueError):
            osv_import.check_inbox(self.env.con)
        self.assertEqual(self.inbox(), [])
        self.assertTrue(any(n.startswith("failed-") for n in os.listdir(Config.OSV_ARCHIVE_DIR)))
        self.assertEqual(download.fetch(self.env.con, "osv")[0], "new")
        self.assertEqual(self.srv.requests[-1], ("/osv/osv-all.tar.xz", None))
        self.srv.files["/osv/osv-all.tar.xz"] = (self.osv_bytes(), '"good"')
        for f in self.inbox():
            os.remove(os.path.join(Config.OSV_INBOX_DIR, f))
        self.assertEqual(download.fetch(self.env.con, "osv")[0], "new")
        self.assertTrue(osv_import.check_inbox(self.env.con))
        self.assertIsNotNone(osv_import.active_import(self.env.con))

    def test_failed_files_do_not_evict_good_archives(self):
        from cvehub import util
        os.makedirs(Config.OSV_ARCHIVE_DIR, exist_ok=True)
        for i, n in enumerate(["good1", "good2", "failed-a", "failed-b", "failed-c", "failed-d"]):
            p = os.path.join(Config.OSV_ARCHIVE_DIR, n + ".tar.xz")
            open(p, "w").close()
            os.utime(p, (i, i))
        util.prune_archive(Config.OSV_ARCHIVE_DIR, 2)
        self.assertEqual(sorted(os.listdir(Config.OSV_ARCHIVE_DIR)),
                         ["failed-b.tar.xz", "failed-c.tar.xz", "failed-d.tar.xz", "good1.tar.xz", "good2.tar.xz"])

    def test_bad_upload_does_not_block_newer_file(self):
        """放檔目錄裡先有一份壞的，再有一份好的：好的照樣匯入（之前會卡在壞的那份）"""
        os.makedirs(Config.OSV_INBOX_DIR, exist_ok=True)
        with open(os.path.join(Config.OSV_INBOX_DIR, "a-broken.tar.xz"), "wb") as f:
            f.write(b"not xz")
        os.utime(os.path.join(Config.OSV_INBOX_DIR, "a-broken.tar.xz"), (1, 1))
        with open(os.path.join(Config.OSV_INBOX_DIR, "b-good.tar.xz"), "wb") as f:
            f.write(self.osv_bytes())
        with self.assertRaises(Exception):
            osv_import.check_inbox(self.env.con)
        self.assertIsNotNone(osv_import.active_import(self.env.con))
        self.assertEqual(self.inbox(), [])

    def test_malformed_json_and_duplicates(self):
        """JSON 結構不對（KeyError 類）也算內容有問題：移到 failed-，不擋住後面的；同一份兩個副本只匯入一次"""
        import io, lzma, tarfile, time
        os.makedirs(Config.OSV_INBOX_DIR, exist_ok=True)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            data = b'{"no_id": true, "affected": [{}]}'
            info = tarfile.TarInfo("osv/cve/2026/UBUNTU-CVE-2026-9.json")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        bad = os.path.join(Config.OSV_INBOX_DIR, "a-shape.tar.xz")
        with open(bad, "wb") as f:
            f.write(lzma.compress(buf.getvalue()))
        os.utime(bad, (1, 1))
        good = self.osv_bytes()
        for n in ("b-good.tar.xz", "c-good-copy.tar.xz"):
            with open(os.path.join(Config.OSV_INBOX_DIR, n), "wb") as f:
                f.write(good)
        with self.assertRaises(Exception):
            osv_import.check_inbox(self.env.con)
        self.assertEqual(self.inbox(), [])
        self.assertEqual(self.env.con.execute("SELECT COUNT(*) FROM osv_import WHERE status='ok'").fetchone()[0], 1)

    def test_size_limit(self):
        self.srv.files["/osv/osv-all.tar.xz"] = (self.osv_bytes(), '"v1"')
        with mock.patch.object(Config, "DOWNLOAD_MAX_MB", 0):
            res, msg = download.fetch(self.env.con, "osv")
        self.assertEqual(res, "error")
        self.assertIn("DOWNLOAD_MAX_MB", msg)
        self.assertEqual(self.inbox(), [])

    def test_url_change_drops_etag(self):
        self.srv.files["/osv/osv-all.tar.xz"] = (self.osv_bytes(), '"v1"')
        download.fetch(self.env.con, "osv")
        self.srv.files["/mirror/osv-all.tar.xz"] = self.srv.files["/osv/osv-all.tar.xz"]
        with mock.patch.object(Config, "OSV_DOWNLOAD_URL", self.srv.base + "/mirror/osv-all.tar.xz"):
            download.fetch(self.env.con, "osv")
        self.assertEqual(self.srv.requests[-1], ("/mirror/osv-all.tar.xz", None))

    def test_failing_and_disabled(self):
        self.assertEqual(download.failing(), [])                                      # 還沒檢查過
        res = download.fetch_all(self.env.con)                                        # 兩個都 404
        self.assertEqual({k: r for k, (r, _) in res.items()}, {"osv": "error", "vex": "error"})
        with mock.patch.object(Config, "DOWNLOAD_ALERT_HOURS", -1):
            self.assertEqual(download.failing(), ["osv", "vex"])                      # 從來沒成功過、已超過時限
            with mock.patch.object(Config, "CVE_DATA_DOWNLOAD", False):
                self.assertEqual(download.failing(), [])

    def test_fetch_all_single_runner_across_processes(self):
        import fcntl
        with open(os.path.join(os.path.dirname(Config.DB_PATH), ".cvehub-download.lock"), "a") as f:   # 別的程序拿著鎖
            fcntl.flock(f, fcntl.LOCK_EX)
            self.assertIsNone(download.fetch_all(self.env.con))
        self.assertIsNotNone(download.fetch_all(self.env.con))

    def test_https_only(self):
        with mock.patch.object(Config, "DOWNLOAD_ALLOW_HTTP", False):
            res, msg = download.fetch(self.env.con, "osv")
            self.assertEqual(res, "error")
            self.assertIn("只能用 https", msg)
            for u in ("http://x/a", "ftp://x/a", "file:///etc/passwd"):
                with self.assertRaises(ValueError):
                    download._check_url(u)
            download._check_url("https://x/a")
            req = __import__("urllib.request").request.Request("https://x/a")
            with self.assertRaises(ValueError):                                       # 轉址到 http 也拒絕
                download._Redirect().redirect_request(req, None, 302, "Found", {}, "http://evil/a")
        self.assertNotIn("FileHandler", [type(h).__name__ for h in download._opener().handlers])

    def test_refetch_when_last_download_lost(self):
        """上次下載的那份沒有匯入、也不在放檔目錄（被清掉）：304 不算數，不帶條件重新下載"""
        self.srv.files["/osv/osv-all.tar.xz"] = (self.osv_bytes(), '"v1"')
        self.assertEqual(download.fetch(self.env.con, "osv")[0], "new")
        os.remove(os.path.join(Config.OSV_INBOX_DIR, self.inbox()[0]))
        self.assertEqual(download.fetch(self.env.con, "osv")[0], "new")
        self.assertEqual(self.srv.requests[-1], ("/osv/osv-all.tar.xz", None))
        self.assertEqual(download.fetch(self.env.con, "osv"), ("same", "沒有更新"))     # 還在放檔目錄：照常 304

    def test_disk_space_and_time_limit(self):
        self.srv.files["/osv/osv-all.tar.xz"] = (self.osv_bytes(), '"v1"')
        usage = __import__("collections").namedtuple("u", "total used free")
        with mock.patch("shutil.disk_usage", return_value=usage(10, 9, 100 * 2 ** 20)):
            res, msg = download.fetch(self.env.con, "osv")
        self.assertEqual(res, "error")
        self.assertIn("磁碟空間不足", msg)
        with mock.patch.object(Config, "DOWNLOAD_MAX_MINUTES", -1):
            res, msg = download.fetch(self.env.con, "osv")
        self.assertIn("DOWNLOAD_MAX_MINUTES", msg)
        self.assertEqual(self.inbox(), [])

    def test_failing_waits_for_alert_hours(self):
        download.fetch_all(self.env.con)                                              # 第一次就失敗（404）
        self.assertEqual(download.failing(), [])                                      # 還沒超過 48 小時
        st = download.load_state()
        st["osv"]["first_checked_at"] = "2000-01-01T00:00:00"
        download._save_state(st)
        self.assertEqual(download.failing(), ["osv"])
        with open(download.state_path(), "w") as f:                                  # 狀態檔壞掉：全部算失敗
            f.write("{bad")
        self.assertEqual(download.failing(), ["osv", "vex"])
        download._save_state({})                                                     # 修好後恢復
        self.assertEqual(download.failing(), [])
        with mock.patch("os.replace", side_effect=OSError("read-only")):
            download._save_state({})                                                 # 寫不進去：讀得到舊檔也照樣回報
        self.assertEqual(download.failing(), ["osv", "vex"])
        download._save_state({})


if __name__ == "__main__":
    unittest.main()
