"""外部資料來源：Landscape legacy API、kernel API"""
import base64
import datetime
import hashlib
import hmac
import json
import logging
import ssl
import time
import urllib.parse
import urllib.request

from ..conf import conf

log = logging.getLogger(__name__)


def _ctx(cafile):
    ctx = ssl.create_default_context(cafile=cafile or None)
    if cafile:
        ctx.check_hostname = False   # quickstart 自簽憑證的 CN 常與網址不同；仍驗證是否由此 CA 簽發
    return ctx


# ---------------------------------------------------------------- Landscape

class Landscape:
    def __init__(self):
        c = conf
        if not (c.LANDSCAPE_API_URI and c.LANDSCAPE_API_KEY and c.LANDSCAPE_API_SECRET):
            raise RuntimeError("LANDSCAPE_API_URI / LANDSCAPE_API_KEY / LANDSCAPE_API_SECRET 未設定")
        self.uri, self.key, self.secret = c.LANDSCAPE_API_URI, c.LANDSCAPE_API_KEY, c.LANDSCAPE_API_SECRET
        self.ctx = _ctx(c.LANDSCAPE_CA_FILE)

    def call(self, action, **params):
        u = urllib.parse.urlparse(self.uri)
        last = None
        for attempt in range(1, conf.LANDSCAPE_RETRIES + 1):
            p = {"action": action, "access_key_id": self.key, "signature_method": "HmacSHA256",
                 "signature_version": "2", "version": "2011-08-01",
                 "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
            p.update({k: str(v) for k, v in params.items()})
            q = "&".join("%s=%s" % (urllib.parse.quote(k, safe=""), urllib.parse.quote(p[k], safe="-_.~")) for k in sorted(p))
            msg = "POST\n%s\n%s\n%s" % (u.hostname.lower(), u.path, q)
            sig = base64.b64encode(hmac.new(self.secret.encode(), msg.encode(), hashlib.sha256).digest()).decode()
            body = (q + "&signature=" + urllib.parse.quote(sig, safe="")).encode()
            req = urllib.request.Request(self.uri, body, {"Content-Type": "application/x-www-form-urlencoded"})
            try:
                return json.load(urllib.request.urlopen(req, context=self.ctx, timeout=conf.LANDSCAPE_TIMEOUT))
            except urllib.error.HTTPError as e:
                # Landscape 的錯誤訊息會帶出 access key ID：遮掉再記錄／顯示
                detail = e.read().decode(errors="replace")[:300].replace(self.key, "***")
                if e.code < 500:
                    raise RuntimeError("Landscape API %s 失敗：HTTP %s %s" % (action, e.code, detail))
                last = "HTTP %s %s" % (e.code, detail)
            except (urllib.error.URLError, OSError) as e:
                last = str(e)
            log.warning("Landscape API %s 第 %d 次失敗：%s", action, attempt, last)
            time.sleep(min(30, 2 ** attempt))
        raise RuntimeError("Landscape API %s 重試 %d 次仍失敗：%s" % (action, conf.LANDSCAPE_RETRIES, last))

    def computers(self):
        q = {"query": conf.LANDSCAPE_QUERY} if conf.LANDSCAPE_QUERY else {}
        out, offset = [], 0
        while True:
            page = self.call("GetComputers", limit=1000, offset=offset, with_network="true", **q)
            out += page
            if len(page) < 1000:
                return out
            offset += 1000

    def installed_packages(self, computer_id):
        pk, offset = {}, 0
        while True:
            page = self.call("GetPackages", query="id:%d" % computer_id, installed="true", limit=1000, offset=offset)
            for p in page:
                pk[p["name"]] = p["version"]
            if len(page) < 1000:
                return pk
            offset += 1000


# ---------------------------------------------------------------- kernel API

def primary_ip(computer):
    """Landscape 回報的第一個非 loopback IPv4"""
    for d in computer.get("network_devices") or []:
        ip = d.get("ip_address") or ""
        if ip and not ip.startswith("127.") and ":" not in ip:
            return ip
    return ""


def host_key(name):
    if not name:
        return ""
    if conf.HOST_MATCH_KEY == "shortname":
        name = name.split(".")[0]
    return name.lower() if conf.HOST_MATCH_CASE_INSENSITIVE else name


def match_value(hostname, ip):
    """依 HOST_MATCH_KEY 取出這台主機用來對應 kernel API 的值"""
    return ip if conf.HOST_MATCH_KEY == "ip" else host_key(hostname)


def _auth_headers():
    c = conf
    headers = {"Accept": "application/json, text/plain"}
    if c.KERNEL_API_AUTH == "token":
        headers["Authorization"] = "Token " + c.KERNEL_API_TOKEN
    elif c.KERNEL_API_AUTH == "bearer":
        headers["Authorization"] = "Bearer " + c.KERNEL_API_TOKEN
    elif c.KERNEL_API_AUTH == "basic":
        headers["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % (c.KERNEL_API_USER, c.KERNEL_API_PASSWORD)).encode()).decode()
    return headers


def _record(it):
    c = conf
    return {"release": it.get(c.KERNEL_API_FIELD_RELEASE) or "",
            "version": it.get(c.KERNEL_API_FIELD_VERSION) or "",
            "collected_at": it.get(c.KERNEL_API_FIELD_COLLECTED_AT) or ""}


def kernel_for_host(hostname, ip):
    """
    per-host 模式：查一台主機。回傳 {"release","version","collected_at"}；查無資料回傳 None
    回應可以是 JSON 物件、只有一筆的 JSON 清單，或純文字（只有版本，例如 6.8.0-147.147）
    """
    c = conf
    vals = {"hostname": hostname or "", "shortname": (hostname or "").split(".")[0], "ip": ip or ""}
    url = c.KERNEL_API_URL
    for k, v in vals.items():
        url = url.replace("{%s}" % k, urllib.parse.quote(v, safe=""))
    req = urllib.request.Request(url, headers=_auth_headers())
    try:
        r = urllib.request.urlopen(req, context=_ctx(c.KERNEL_API_CA_FILE), timeout=c.KERNEL_API_TIMEOUT)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    body = r.read().decode(errors="replace").strip()
    if "json" in (r.headers.get("Content-Type") or ""):
        data = json.loads(body)
        if isinstance(data, list):
            data = data[0] if data else None
        if not data:
            return None
        return _record(data)
    return {"release": "", "version": body, "collected_at": ""} if body else None


def _same_origin(base, url):
    """分頁的 next 只接受和 KERNEL_API_URL 同一個 scheme／主機／port（否則 token 會送到別台主機）"""
    if not url:
        return None
    a, b = urllib.parse.urlparse(base), urllib.parse.urlparse(urllib.parse.urljoin(base, url))
    if (a.scheme, a.netloc) != (b.scheme, b.netloc):
        log.warning("kernel API 分頁的 next 指向其他主機，已忽略：%s", b.netloc)
        return None
    return b.geturl()


def kernel_api():
    """bulk 模式：回傳 {對應值: {"release","version","collected_at"}}；未設定或 per-host 模式回傳 None"""
    c = conf
    if not c.KERNEL_API_URL or c.KERNEL_API_MODE == "per-host":
        return None
    out, url = {}, c.KERNEL_API_URL
    while url:
        req = urllib.request.Request(url, headers=_auth_headers())
        data = json.load(urllib.request.urlopen(req, context=_ctx(c.KERNEL_API_CA_FILE), timeout=c.KERNEL_API_TIMEOUT))
        # 支援三種回傳格式：清單、{"results":[...],"next":url}（Django REST framework 分頁）、{主機: {...}}
        if isinstance(data, dict) and "results" in data:
            items, url = data["results"], _same_origin(c.KERNEL_API_URL, data.get("next"))
        elif isinstance(data, list):
            items, url = data, None
        else:
            items, url = [dict(v, **{c.KERNEL_API_FIELD_HOST: k}) for k, v in data.items()], None
        for it in items:
            v = it.get(c.KERNEL_API_FIELD_HOST)
            k = v if c.HOST_MATCH_KEY == "ip" else host_key(v)
            if k:
                out[k] = _record(it)
    return out
