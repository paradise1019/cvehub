"""
cvehub 用的 kernel 版本查詢 API（貼進你的 Django 專案）

cvehub 會這樣呼叫（每台主機一次）：
    GET http://<你的 IP>:<port>/api/kernel/?hostname=web01.example.com&ip=10.0.0.21
    Authorization: Token <CVEHUB_TOKEN>

回應（JSON）：
    {"hostname": "web01.example.com",
     "kernel_release": "6.8.0-147-generic",                       # uname -r
     "kernel_version": "Ubuntu 6.8.0-147.147-generic 6.8.12",      # /proc/version_signature（建議提供）
     "collected_at": "2026-10-17T13:00:00+08:00"}                  # 這筆資料的收集時間
查無資料回 404。

只用 Django 內建功能（不需要 Django REST framework）。

安裝步驟
  1. 把這個檔案放到你的某個 app，例如 inventory/kernel_view.py
  2. 改下面的 lookup_kernel()：從你自己的資料取出 kernel 資訊
  3. settings.py 加：
         CVEHUB_TOKEN = os.environ["CVEHUB_TOKEN"]     # 和 cvehub .env 的 KERNEL_API_TOKEN 相同
         CVEHUB_ALLOWED_IPS = ["10.0.0.50"]            # cvehub 主機的 IP；空清單＝不限制
  4. urls.py 加：
         from inventory.kernel_view import kernel_version
         urlpatterns += [path("api/kernel/", kernel_version)]
  5. cvehub 的 .env：
         KERNEL_API_MODE=per-host
         KERNEL_API_URL=http://<IP>:<port>/api/kernel/?hostname={hostname}&ip={ip}
         KERNEL_API_AUTH=token
         KERNEL_API_TOKEN=<同一組 token>
"""
import hmac

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_GET


def lookup_kernel(hostname, ip):
    """
    ★ 只要改這裡 ★
    依 hostname（Landscape 回報的完整名稱）或 ip 找出這台主機的 kernel 資訊。
    回傳 dict（欄位見上方說明），找不到回傳 None。

    範例（假設你有一個 Host model，欄位 name、ip、kernel_release、kernel_signature、updated_at）：

        from inventory.models import Host
        h = (Host.objects.filter(name__iexact=hostname).first()
             or Host.objects.filter(name__iexact=hostname.split(".")[0]).first()
             or (Host.objects.filter(ip=ip).first() if ip else None))
        if not h:
            return None
        return {
            "hostname": h.name,
            "kernel_release": h.kernel_release,          # uname -r
            "kernel_version": h.kernel_signature,        # cat /proc/version_signature
            "collected_at": h.updated_at.isoformat(),
        }

    只有 uname -r 也可以：kernel_version 留空，cvehub 會從 Landscape 的套件清單查完整版本。
    """
    raise NotImplementedError("請實作 lookup_kernel()")


def _client_ip(request):
    # 如果前面有反向代理，改成讀 X-Forwarded-For（並確認只信任自己的代理）
    return request.META.get("REMOTE_ADDR", "")


@require_GET
def kernel_version(request):
    allowed = getattr(settings, "CVEHUB_ALLOWED_IPS", [])
    if allowed and _client_ip(request) not in allowed:
        return JsonResponse({"error": "forbidden"}, status=403)

    expected = "Token " + getattr(settings, "CVEHUB_TOKEN", "")
    given = request.headers.get("Authorization", "")
    if not getattr(settings, "CVEHUB_TOKEN", "") or not hmac.compare_digest(given.encode(), expected.encode()):
        return JsonResponse({"error": "unauthorized"}, status=401)

    hostname = (request.GET.get("hostname") or "").strip()
    ip = (request.GET.get("ip") or "").strip()
    if not hostname and not ip:
        return JsonResponse({"error": "hostname or ip required"}, status=400)

    rec = lookup_kernel(hostname, ip)
    if not rec:
        return JsonResponse({"error": "not found"}, status=404)
    return JsonResponse(rec)
