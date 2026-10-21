#!/usr/bin/env python3
"""模擬你的 Django kernel API（測試用）。
用法：python3 mock_kernel_api.py hosts.json 8090 [token]
  token 也可以放在環境變數 MOCK_KERNEL_API_TOKEN（建議：不會出現在 ps／systemd 的指令列）
  hosts.json 的 collected_at 填 "auto"＝回傳目前時間（模擬持續收集，資料不會過期）
  GET /                          → 全部主機（bulk 模式）
  GET /api/kernel/?hostname=…&ip=… → 單台主機（per-host 模式），查無資料 404
  GET /text/?hostname=…          → 單台主機，只回純文字版本
"""
import datetime
import http.server
import json
import os
import sys
import urllib.parse

path, port = sys.argv[1], int(sys.argv[2])
token = sys.argv[3] if len(sys.argv) > 3 else os.environ["MOCK_KERNEL_API_TOKEN"]


def load():
    now = datetime.datetime.now().isoformat(timespec="seconds")
    hosts = json.load(open(path))
    for h in hosts:
        if h.get("collected_at") == "auto":
            h["collected_at"] = now
    return hosts


class H(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.headers.get("Authorization") != "Token " + token:
            return self._send(401, '{"error":"unauthorized"}')
        u = urllib.parse.urlparse(self.path)
        hosts = load()
        if u.path in ("/", ""):
            return self._send(200, json.dumps(hosts))
        q = urllib.parse.parse_qs(u.query)
        hn, ip = (q.get("hostname") or [""])[0].lower(), (q.get("ip") or [""])[0]
        h = next((x for x in hosts if x["hostname"].lower() == hn or (ip and x.get("ip") == ip)), None)
        if not h:
            return self._send(404, '{"error":"not found"}')
        if u.path.startswith("/text"):
            v = h["kernel_version"].split()[1].replace("-generic", "") if h["kernel_version"].startswith("Ubuntu ") else h["kernel_version"]
            return self._send(200, v, "text/plain")
        return self._send(200, json.dumps(h))

    def log_message(self, fmt, *a):
        sys.stderr.write("mock %s\n" % (fmt % a))


http.server.ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
