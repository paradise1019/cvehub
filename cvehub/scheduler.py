"""內建排程：定期同步、定期檢查 OSV 放檔目錄"""
import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from . import db, osv_import
from .config import Config

log = logging.getLogger(__name__)
_sched = None


def _osv_check():
    from .web import run_job
    con = db.connect()
    try:
        import glob, os
        if glob.glob(os.path.join(Config.OSV_INBOX_DIR, "*.tar.xz")) or glob.glob(os.path.join(Config.VEX_INBOX_DIR, "*.tar.xz")):
            run_job("sync")          # sync 會先匯入新檔
    finally:
        con.close()


def _sync():
    from .web import run_job
    if not run_job("sync"):
        log.info("上一次同步還在執行，略過這次排程")


def start():
    global _sched
    if _sched:
        return
    _sched = BackgroundScheduler(timezone=Config.TZ)
    _sched.add_job(_sync, CronTrigger.from_crontab(Config.SCHEDULE_SYNC, timezone=Config.TZ), id="sync", max_instances=1, coalesce=True)
    _sched.add_job(_osv_check, CronTrigger.from_crontab(Config.SCHEDULE_OSV_CHECK, timezone=Config.TZ), id="osv", max_instances=1, coalesce=True)
    _sched.start()
    log.info("排程啟動：同步 [%s]，OSV 檢查 [%s]（%s）", Config.SCHEDULE_SYNC, Config.SCHEDULE_OSV_CHECK, Config.TZ)
