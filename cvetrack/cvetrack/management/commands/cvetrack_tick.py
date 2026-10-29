import logging
import os

from django.core.management.base import BaseCommand

from cvetrack.core import inbox, runs, schedule
from cvetrack.core.lock import Busy, job_lock

log = logging.getLogger("cvetrack")


class Command(BaseCommand):
    help = ("排程用（systemd timer 每 5 分鐘）：放檔目錄有新檔、網頁按了「立即同步」、或距離上次同步超過 SYNC_EVERY_HOURS，"
            "才匯入／同步；其他時候什麼都不做")

    def handle(self, **_):
        why = schedule.due()
        if not why:
            return
        try:
            with job_lock():
                why = schedule.due()          # 拿到鎖之後再確認一次（可能剛被別的程序做完）
                if not why:
                    return
                if schedule.sync_requested():
                    os.remove(schedule.request_path())
                done = inbox.check()
                trigger = "osv" if "osv" in done else "vex" if "vex" in done else "manual" if why == "request" else "schedule"
                r = runs.run(trigger=trigger)
                self.stdout.write("Run #%d（%s）：主機 %d、未解決 %d、事件 %s" % (r.id, trigger, r.hosts, r.open_findings, r.counts))
        except Busy:
            log.info("另一個同步／匯入正在執行，這次略過")
