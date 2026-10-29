from django.core.management.base import BaseCommand, CommandError

from cvetrack.core import inbox, runs
from cvetrack.core.lock import Busy, job_lock


class Command(BaseCommand):
    help = "檢查放檔目錄（有新的 OSV／VEX 就匯入）→ 同步主機 → 比對 → 產生事件（一個 Run）。排程用這個指令"

    def add_arguments(self, p):
        p.add_argument("--no-inbox", action="store_true", help="不檢查放檔目錄")
        p.add_argument("--trigger", default="schedule", choices=["schedule", "manual"])

    def handle(self, no_inbox=False, trigger="schedule", **_):
        try:
            with job_lock():
                done = set() if no_inbox else inbox.check()
                r = runs.run(trigger="osv" if "osv" in done else "vex" if "vex" in done else trigger)
                self.stdout.write("Run #%d：主機 %d、未解決 %d、事件 %s" % (r.id, r.hosts, r.open_findings, r.counts))
        except Busy as e:
            raise CommandError(str(e))
