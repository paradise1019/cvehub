"""指令列：python -m cvehub.cli <指令>

  init                    建立資料庫
  import-osv FILE         匯入 osv-all.tar.xz
  import-vex FILE         匯入 vex-all.tar.xz（官方處理狀態）
  sync                    同步主機並比對（會先檢查 OSV／VEX 放檔目錄）
  report                  輸出報表到 REPORT_DIR
  period FROM TO [最低等級]
                          輸出報表（CVE 公開日期 FROM～TO，YYYY-MM-DD），輸出 Excel 到 REPORT_DIR
  user-add NAME [admin|viewer]   新增帳號（互動輸入密碼；預設 viewer）
  user-passwd NAME        重設密碼（互動輸入）；也會解除鎖定
  user-role NAME admin|viewer    變更角色
  user-disable NAME／user-enable NAME
  user-list               列出帳號
  hash-password           產生密碼雜湊（舊版 WEB_AUTH_PASSWORD_HASH 用；新部署改用 user-add）
"""
import getpass
import logging
import os
import sys

from werkzeug.security import generate_password_hash

from . import auth, db, osv_import, period, report, sync, vex_import
from .lock import Busy, job_lock
from .config import Config


def main(argv=None):
    argv = argv or sys.argv[1:]
    logging.basicConfig(level=Config.LOG_LEVEL.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd = argv[0]
    if cmd == "hash-password":
        p1 = getpass.getpass("新密碼：")
        p2 = getpass.getpass("再輸入一次：")
        if p1 != p2 or len(p1) < 12:
            print("兩次不一致，或少於 12 個字元", file=sys.stderr)
            return 1
        print(generate_password_hash(p1))
        return 0
    con = db.connect()
    db.init(con)
    if cmd.startswith("user-"):
        return _user_cmd(con, cmd, argv[1:])
    if cmd == "init":
        print("資料庫：", Config.DB_PATH)
    elif cmd in ("import-osv", "import-vex", "sync"):
        try:
            with job_lock():
                if cmd == "import-osv":
                    osv_import.import_file(con, argv[1])
                elif cmd == "import-vex":
                    vex_import.import_file(con, argv[1])
                else:
                    sync.run_sync(con)
        except Busy as e:
            print(e, file=sys.stderr)
            return 2
    elif cmd == "period":
        if len(argv) < 3:
            print(__doc__)
            return 1
        try:
            d1, d2 = period.valid_date(argv[1]), period.valid_date(argv[2])
        except ValueError:
            print("日期格式要是 YYYY-MM-DD", file=sys.stderr)
            return 1
        minp = argv[3] if len(argv) > 3 else "medium"
        if minp not in period.LEVELS:
            print(__doc__)
            return 1
        vex = vex_import.active_import(con)
        rows, summary = period.build(con, d1, d2, minp, have_vex=bool(vex))
        imp = osv_import.active_import(con)
        os.makedirs(Config.REPORT_DIR, exist_ok=True)
        path = os.path.join(Config.REPORT_DIR, period.filename(d1, d2))
        with open(path, "wb") as f:
            f.write(period.to_xlsx(rows, summary, d1, d2, minp, imp["file_mtime"] if imp else None,
                                   vex["file_mtime"] if vex else None))
        for lv in summary["levels"]:
            b = summary["by_level"][lv]
            print("%-10s %5d（其中 kernel %d）" % (lv, b["cves"], b["kernel"]))
        print("合計 %d 個 CVE、%d 列，已輸出 %s" % (summary["total"], len(rows), path))
    elif cmd == "report":
        report.write_reports(con)
        print("報表已輸出到", Config.REPORT_DIR)
    else:
        print(__doc__)
        return 1
    return 0


def _ask_password():
    p1 = getpass.getpass("密碼（至少 %d 個字元）：" % auth.PASSWORD_MIN)
    p2 = getpass.getpass("再輸入一次：")
    if p1 != p2:
        raise ValueError("兩次輸入不一致")
    return p1


def _user_cmd(con, cmd, args):
    try:
        if cmd == "user-list":
            for u in con.execute("SELECT * FROM users ORDER BY lower(username)"):
                print("%-20s %-6s %s  最後登入 %s%s" % (u["username"], u["role"], "啟用" if u["active"] else "停用",
                                                   u["last_login"] or "-", "  鎖定到 " + u["locked_until"] if u["locked_until"] else ""))
            return 0
        if not args:
            print(__doc__)
            return 1
        name = args[0]
        if cmd == "user-add":
            role = args[1] if len(args) > 1 else "viewer"
            auth.create_user(con, name, _ask_password(), role)
            auth.audit(con, "cli", "", "user-add", "%s（%s）" % (name, role))
            print("已新增 %s（%s）" % (name, auth.ROLE_LABEL[role]))
            return 0
        u = con.execute("SELECT * FROM users WHERE lower(username)=lower(?)", (name,)).fetchone()
        if not u:
            raise ValueError("帳號不存在：%s" % name)
        if cmd == "user-passwd":
            auth.set_password(con, u["id"], _ask_password())
        elif cmd == "user-role" and len(args) > 1:
            auth.update_user(con, u["id"], role=args[1])
        elif cmd in ("user-disable", "user-enable"):
            auth.update_user(con, u["id"], active=(cmd == "user-enable"))
        else:
            print(__doc__)
            return 1
        auth.audit(con, "cli", "", cmd, name)
        print("已完成")
        return 0
    except ValueError as e:
        print(e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
