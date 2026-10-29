from django.core.management.base import BaseCommand, CommandError

from cvetrack.core import inbox, osv, runs, vex
from cvetrack.core.lock import Busy, job_lock


class Command(BaseCommand):
    help = "匯入 OSV 或 VEX 檔（osv-all.tar.xz／vex-all.tar.xz），匯入後用資料庫裡的主機套件重新比對（一個 Run）"

    def add_arguments(self, p):
        p.add_argument("file")
        p.add_argument("--kind", choices=["osv", "vex"], help="預設依檔名判斷（含 vex＝VEX）")
        p.add_argument("--no-run", action="store_true", help="只匯入，不比對")

    def handle(self, file, kind=None, no_run=False, **_):
        kind = kind or inbox.kind_of(file)
        try:
            with job_lock():
                imp = (osv if kind == "osv" else vex).import_file(file)
                self.stdout.write("%s 匯入 #%d 完成%s" % (kind.upper(), imp.id,
                                  "，差異 %s" % imp.change_counts if kind == "osv" and imp.change_counts else ""))
                if not no_run:
                    r = runs.run(trigger=kind, refresh_hosts=False)
                    self.stdout.write("Run #%d：未解決 %d、事件 %s" % (r.id, r.open_findings, r.counts))
        except Busy as e:
            raise CommandError(str(e))
