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

from . import hostnames
from .config import Config
from .util import parse_time as _parse_time

log = logging.getLogger(__name__)


def _ctx(cafile):
    ctx = ssl.create_default_context(cafile=cafile or None)
    if cafile:
        ctx.check_hostname = False   # quickstart 自簽憑證的 CN 常與網址不同；仍驗證是否由此 CA 簽發
    return ctx


# ---------------------------------------------------------------- Landscape

class Landscape:
    def __init__(self):
        c = Config
        if not (c.LANDSCAPE_API_URI and c.LANDSCAPE_API_KEY and c.LANDSCAPE_API_SECRET):
            raise RuntimeError("LANDSCAPE_API_URI / LANDSCAPE_API_KEY / LANDSCAPE_API_SECRET 未設定")
        self.uri, self.key, self.secret = c.LANDSCAPE_API_URI, c.LANDSCAPE_API_KEY, c.LANDSCAPE_API_SECRET
        self.ctx = _ctx(c.LANDSCAPE_CA_FILE)

    def call(self, action, **params):
        u = urllib.parse.urlparse(self.uri)
        last = None
        for attempt in range(1, Config.LANDSCAPE_RETRIES + 1):
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
                return json.load(urllib.request.urlopen(req, context=self.ctx, timeout=Config.LANDSCAPE_TIMEOUT))
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
        raise RuntimeError("Landscape API %s 重試 %d 次仍失敗：%s" % (action, Config.LANDSCAPE_RETRIES, last))

    def computers(self):
        q = {"query": Config.LANDSCAPE_QUERY} if Config.LANDSCAPE_QUERY else {}
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
    name = name.rstrip(".")                 # web01.example.com. 與 web01.example.com 相同
    if Config.HOST_MATCH_KEY == "shortname":
        name = hostnames.short(name)
    return name.lower() if Config.HOST_MATCH_CASE_INSENSITIVE else name


def match_value(hostname, ip):
    """依 HOST_MATCH_KEY 取出這台主機用來對應 kernel API 的值"""
    return ip if Config.HOST_MATCH_KEY == "ip" else host_key(hostname)


def _auth_headers():
    c = Config
    headers = {"Accept": "application/json, text/plain"}
    if c.KERNEL_API_AUTH == "token":
        headers["Authorization"] = "Token " + c.KERNEL_API_TOKEN
    elif c.KERNEL_API_AUTH == "bearer":
        headers["Authorization"] = "Bearer " + c.KERNEL_API_TOKEN
    elif c.KERNEL_API_AUTH == "basic":
        headers["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % (c.KERNEL_API_USER, c.KERNEL_API_PASSWORD)).encode()).decode()
    return headers


def _record(it):
    c = Config
    return {"release": it.get(c.KERNEL_API_FIELD_RELEASE) or "",
            "version": it.get(c.KERNEL_API_FIELD_VERSION) or "",
            "collected_at": it.get(c.KERNEL_API_FIELD_COLLECTED_AT) or ""}


def kernel_for_host(hostname, ip):
    """
    per-host 模式：查一台主機。回傳 {"release","version","collected_at"}；查無資料回傳 None
    回應可以是 JSON 物件、只有一筆的 JSON 清單，或純文字（只有版本，例如 6.8.0-147.147）
    """
    c = Config
    vals = {"hostname": hostname or "", "shortname": hostnames.short(hostname or ""), "ip": ip or ""}
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


class KernelIndex:
    """bulk 模式的 kernel 資料，依主機查（get）。同一個比對值（短名稱、IP）可能有好幾筆：
    web01.a.example.com 和 web01.b.example.com 是兩台。之前後面那筆直接蓋掉前面的，兩台拿到同一個 kernel，
    還跑著舊 kernel 的那台會被當成已重開機（執行中 kernel 的弱點變成已解決）"""

    def __init__(self):
        self.by_key = {}            # 比對值 → [(API 的主機名稱, 紀錄)]

    def add(self, name, rec):
        """加入一筆；比對值是空的（名稱只有「.」之類）時不加，回傳 False"""
        k = name if Config.HOST_MATCH_KEY == "ip" else host_key(name)
        if k:
            self.by_key.setdefault(k, []).append((name, rec))
        return bool(k)

    def get(self, hostname, ip, same_key=1, same_name=1):
        """回傳 (紀錄或 None, 分不出來的原因或 None)。
        same_key／same_name：這次 Landscape 有幾台電腦的比對值相同／完整名稱完全相同（含這台）。規則：
          1. 名稱完全相同的電腦有兩台以上（複製的 VM 沒改名）：分不出來
          2. kernel API 有名稱完全相同的紀錄：只用那些
          3. 沒有：Landscape 有好幾台比對值相同時分不出來；設了 LANDSCAPE_QUERY（只看得到部分電腦，無法確認唯一）時
             只用和這台是同一台的名稱（只差在有沒有網域）；都不是時用全部候選（短名稱就是識別，跨網域 web01.lan／web01.corp 照樣對得到）
          4. 候選裡有不同台的名稱（web01.a… 與 web01.b…）而內容不一樣：分不出來；其他取收集時間最新的一筆（重新收集、重新註冊）
        IP 模式：Landscape 有好幾台是同一個 IP 時分不出來，其他取最新的一筆。
        名稱的比較（完全相同、是不是同一台）一律不分大小寫、不看結尾的點（hostnames.norm：DNS 名稱本來就不分大小寫）；
        HOST_MATCH_CASE_INSENSITIVE 只影響比對值（分組；shortname 模式是第一段、hostname 模式是完整名稱）：設成 false 時
        比對值只差大小寫的分在不同組，彼此不會成為候選，也不會有 log（Landscape 的 Web01 對不到 kernel API 的 web01）"""
        cands = self.by_key.get(match_value(hostname, ip), [])
        if not cands:
            return None, None
        want = hostnames.norm(hostname or "")
        if Config.HOST_MATCH_KEY == "ip":
            if same_key > 1:
                return None, "Landscape 有 %d 台電腦的 IP 都是 %s" % (same_key, ip)
        else:
            if same_name > 1:
                return None, "Landscape 有 %d 台電腦都叫 %s（請把複製的電腦改名）" % (same_name, hostname)
            exact = [(n, r) for n, r in cands if hostnames.norm(n) == want]
            if exact:
                cands = exact
            elif same_key > 1:
                return None, "Landscape 有 %d 台電腦的比對值相同，kernel API 沒有名稱完全相同的資料" % same_key
            elif Config.LANDSCAPE_QUERY:
                cands = [(n, r) for n, r in cands if hostnames.same_machine(n, want)]
                if not cands:
                    return None, "設了 LANDSCAPE_QUERY，無法確認 kernel API 裡名稱不同的資料是不是這一台"
        recs = []
        for _, r in cands:
            if r not in recs:
                recs.append(r)
        names = {hostnames.norm(n) for n, _ in cands}
        if len(recs) > 1 and not all(hostnames.same_machine(a, b) for a in names for b in names):
            shown = sorted(names)
            return None, "kernel API 有多筆不同電腦的資料：%s%s" % ("、".join(shown[:5]), "…等 %d 個名稱" % len(shown) if len(shown) > 5 else "")
        # 收集時間相同或沒有時取後面那筆（和之前一樣）
        return max(reversed(recs), key=lambda r: _parse_time(r.get("collected_at")) or datetime.datetime.min), None


def kernel_api():
    """bulk 模式：回傳 KernelIndex；未設定或 per-host 模式回傳 None"""
    c = Config
    if not c.KERNEL_API_URL or c.KERNEL_API_MODE == "per-host":
        return None
    out, url = KernelIndex(), c.KERNEL_API_URL
    total = bad = 0
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
            total += 1
            if not isinstance(it, dict) or c.KERNEL_API_FIELD_HOST not in it:
                bad += 1            # 不是物件、或沒有主機欄位：格式問題，略過這筆
                continue
            v = it[c.KERNEL_API_FIELD_HOST]
            if v is None or (isinstance(v, str) and not v.strip()):
                continue            # 主機名稱是空的（還沒填的資料）：和之前一樣略過、不記 log
            if not isinstance(v, str):
                bad += 1            # 主機欄位不是文字（物件、數字、true）：略過這筆
                continue
            if not out.add(v.strip(), _record(it)):
                bad += 1            # 名稱算不出比對值（只有「.」、以點開頭的網域…）
    if total and not out.by_key:
        # 有資料卻一筆都用不上：多半是格式或 KERNEL_API_FIELD_HOST 設錯。整批失敗（/healthz 回報 kernel_api_error），
        # 不是悄悄變成每台都沒有 kernel 資料
        raise ValueError("kernel API 回傳 %d 筆資料，沒有一筆有可用的主機名稱（欄位 %s）：格式不對，或 KERNEL_API_FIELD_HOST 設錯"
                         % (total, c.KERNEL_API_FIELD_HOST))
    if bad:
        log.warning("kernel API 有 %d 筆資料不是物件、沒有主機欄位（%s），或主機名稱不能用：略過", bad, c.KERNEL_API_FIELD_HOST)
    return out
