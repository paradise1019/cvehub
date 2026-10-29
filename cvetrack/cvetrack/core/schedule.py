"""排程判斷：cvetrack_tick 每幾分鐘執行一次，有事要做才跑 Run"""
import datetime
import glob
import os

from django.utils import timezone

from ..conf import conf
from ..models import Run
from . import inbox


def request_path():
    return os.path.join(inbox.dirs()[0], ".sync-request")


def request_sync(user=""):
    """網頁「立即同步」：留下一個要求檔，下一次 tick 處理"""
    with open(request_path(), "w") as f:
        f.write("%s %s\n" % (timezone.now().isoformat(), user))


def sync_requested():
    return os.path.exists(request_path())


def pending_files():
    """放檔目錄的檔案，加上之前中斷、留在 processing/ 的"""
    return sorted(glob.glob(os.path.join(inbox.dirs()[0], "*.tar.xz")) + glob.glob(os.path.join(conf.path("processing"), "*.tar.xz")))


def due():
    """回傳要跑的原因（file／request／schedule），不用跑回傳 None"""
    if pending_files():
        return "file"
    if sync_requested():
        return "request"
    if conf.SYNC_EVERY_HOURS:
        last = Run.objects.filter(status="ok", trigger__in=["schedule", "manual", "osv", "vex"]).order_by("-id").first()
        if not last or timezone.now() - last.started_at >= datetime.timedelta(hours=conf.SYNC_EVERY_HOURS):
            return "schedule"
    return None
