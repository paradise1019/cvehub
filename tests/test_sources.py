import http.server
import json
import threading
import unittest

from cvehub import sources
from cvehub.config import Config


class _H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.seen.append(self.path)
        if self.headers.get("Authorization") != "Token T":
            self.send_response(401); self.end_headers(); return
        if "missing" in self.path:
            self.send_response(404); self.end_headers(); return
        if self.path.startswith("/text"):
            body, ctype = b"6.8.0-147.147\n", "text/plain"
        else:
            body = json.dumps({"hostname": "h1", "kernel_release": "6.8.0-147-generic",
                               "kernel_version": "Ubuntu 6.8.0-147.147-generic 6.8.12", "collected_at": "2026-10-17T00:00:00"}).encode()
            ctype = "application/json"
        self.send_response(200); self.send_header("Content-Type", ctype); self.end_headers(); self.wfile.write(body)

    def log_message(self, *a):
        pass


class _Landscape401(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        body = json.dumps({"message": "No user with access key 'b'AKID123SECRETISH''", "error": "AuthFailure"}).encode()
        self.send_response(401); self.end_headers(); self.wfile.write(body)

    def log_message(self, *a):
        pass


class SafetyTest(unittest.TestCase):
    def test_same_origin_next(self):
        base = "https://k.example.com/api/kernel/"
        self.assertEqual(sources._same_origin(base, "/api/kernel/?page=2"), "https://k.example.com/api/kernel/?page=2")
        self.assertEqual(sources._same_origin(base, "https://k.example.com/api/kernel/?page=3"), "https://k.example.com/api/kernel/?page=3")
        self.assertIsNone(sources._same_origin(base, "https://evil.example.net/steal"))     # token 不能送到別台
        self.assertIsNone(sources._same_origin(base, "http://k.example.com/api/kernel/?page=2"))  # 降級成 http 也不行
        self.assertIsNone(sources._same_origin(base, None))

    def test_landscape_error_hides_access_key(self):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Landscape401)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        saved = {k: getattr(Config, k) for k in ("LANDSCAPE_API_URI", "LANDSCAPE_API_KEY", "LANDSCAPE_API_SECRET", "LANDSCAPE_CA_FILE")}
        Config.LANDSCAPE_API_URI = "http://127.0.0.1:%d/api/" % srv.server_address[1]
        Config.LANDSCAPE_API_KEY, Config.LANDSCAPE_API_SECRET, Config.LANDSCAPE_CA_FILE = "AKID123SECRETISH", "s", ""
        try:
            with self.assertRaises(RuntimeError) as cm:
                sources.Landscape().call("GetComputers")
            self.assertNotIn("AKID123SECRETISH", str(cm.exception))
            self.assertIn("***", str(cm.exception))
        finally:
            srv.shutdown()
            for k, v in saved.items():
                setattr(Config, k, v)


class SourcesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
        cls.srv.seen = []
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_address[1]
        cls.saved = {k: getattr(Config, k) for k in ("KERNEL_API_URL", "KERNEL_API_AUTH", "KERNEL_API_TOKEN", "HOST_MATCH_KEY")}
        Config.KERNEL_API_AUTH, Config.KERNEL_API_TOKEN = "token", "T"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        for k, v in cls.saved.items():
            setattr(Config, k, v)

    def test_per_host_json_and_encoding(self):
        Config.KERNEL_API_URL = self.base + "/api/kernel/?hostname={hostname}&short={shortname}&ip={ip}"
        r = sources.kernel_for_host("web 01.example.com", "10.0.0.1")
        self.assertEqual(r["release"], "6.8.0-147-generic")
        self.assertIn("hostname=web%2001.example.com&short=web%2001&ip=10.0.0.1", self.srv.seen[-1])

    def test_per_host_text(self):
        Config.KERNEL_API_URL = self.base + "/text/?hostname={hostname}"
        self.assertEqual(sources.kernel_for_host("h1", "")["version"], "6.8.0-147.147")

    def test_per_host_404(self):
        Config.KERNEL_API_URL = self.base + "/missing/?hostname={hostname}"
        self.assertIsNone(sources.kernel_for_host("h1", ""))

    def test_match_keys(self):
        Config.HOST_MATCH_KEY = "shortname"
        self.assertEqual(sources.match_value("Web01.Example.com", "10.0.0.1"), "web01")
        Config.HOST_MATCH_KEY = "ip"
        self.assertEqual(sources.match_value("web01", "10.0.0.1"), "10.0.0.1")
        self.assertEqual(sources.primary_ip({"network_devices": [{"ip_address": "127.0.0.1"}, {"ip_address": "10.0.0.9"}]}), "10.0.0.9")


if __name__ == "__main__":
    unittest.main()
