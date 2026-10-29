"""網頁與 API（Flask）"""
import datetime
import hmac
import logging
import os
import secrets
import threading
import time
import urllib.parse

from flask import Flask, Response, abort, g, jsonify, redirect, render_template, request, session, url_for

from . import __version__, auth, db, impact, osv_import, period, report, sync, vex_import
from .lock import Busy, job_lock
from .config import PRIO, Config

log = logging.getLogger(__name__)
_sync_lock = threading.Lock()
_status = {"running": False, "message": ""}


def run_job(kind, path=None):
    """在背景執行同步或匯入（同時只會有一個在跑）"""
    if not _sync_lock.acquire(blocking=False):
        return False

    def work():
        _status.update(running=True, message="%s 執行中…" % kind)
        con = db.connect()
        try:
            with job_lock():
                if kind == "import" and path:
                    osv_import.import_file(con, path)
                    _status["message"] = "OSV 匯入完成，開始重新比對…"
                sync.run_sync(con)
            _status["message"] = "%s 完成（%s）" % (kind, sync.now())
        except Busy as e:
            _status["message"] = "%s 略過：%s" % (kind, e)
        except Exception as e:
            _status["message"] = "%s 失敗：%s" % (kind, e)
        finally:
            con.close()
            _status["running"] = False
            _sync_lock.release()
    threading.Thread(target=work, daemon=True).start()
    return True


def _age_days(imp):
    if not imp or not imp["file_mtime"]:
        return 0
    return (datetime.datetime.now() - datetime.datetime.fromisoformat(imp["file_mtime"])).days


PER_PAGE = 100
LOGIN_MAX_BODY = 16 * 1024


def _page(rows):
    """(這一頁的列, 頁碼, 總頁數)；頁碼來自 ?page="""
    pages = max(1, (len(rows) + PER_PAGE - 1) // PER_PAGE)
    try:
        page = min(max(1, int(request.args.get("page", 1))), pages)
    except ValueError:
        page = 1
    return rows[(page - 1) * PER_PAGE:page * PER_PAGE], page, pages


def _quarters(today):
    """今年與去年的各季 [(名稱, 起, 迄)]，新的在前；迄日不超過今天"""
    out = []
    for y in (today.year, today.year - 1):
        for q in (4, 3, 2, 1):
            start = datetime.date(y, 3 * q - 2, 1)
            if start > today:
                continue
            end = (datetime.date(y + (q == 4), (3 * q) % 12 + 1, 1) - datetime.timedelta(days=1))
            out.append(("%d Q%d" % (y, q), start.isoformat(), min(end, today).isoformat()))
    return out


def create_app(start_scheduler=True):
    logging.basicConfig(level=Config.LOG_LEVEL.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024     # OSV 檔約 50 MB
    if Config.WEB_BASE_PATH:
        app.config["APPLICATION_ROOT"] = Config.WEB_BASE_PATH
    con = db.connect()
    db.init(con)
    auth.bootstrap(con)
    con.close()
    app.secret_key = auth.secret_key()
    app.config.update(SESSION_COOKIE_NAME="cvehub_session", SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_SECURE=Config.WEB_COOKIE_SECURE or bool(Config.WEB_TLS_CERT))

    def _safe_next(target):
        """登入後只導回本站的相對路徑"""
        t = urllib.parse.urlparse(target or "")
        if t.scheme or t.netloc or not t.path.startswith("/") or t.path.startswith("//"):
            return url_for("index")
        return t.path + ("?" + t.query if t.query else "")

    @app.before_request
    def authenticate():
        g.con = db.connect()
        g.user, g.role = None, None
        ep = request.endpoint or ""
        if ep in ("healthz", "static"):          # 監控用，不需登入，只回健康狀態
            return None
        if request.path.startswith("/api/"):     # 給腳本用：Basic Auth（任何啟用中的帳號）
            a = request.authorization
            u, _ = auth.verify_login(g.con, a.username, a.password) if a else (None, "")
            if not u:
                return Response("需要登入", 401, {"WWW-Authenticate": 'Basic realm="cvehub-api"'})
            g.user, g.role = u["username"], u["role"]
            return None
        def check_csrf():
            # 防 CSRF：POST 必須來自同一個網站，並帶 session 裡的 token（這裡才會讀表單內容）
            src = request.headers.get("Origin") or request.headers.get("Referer") or ""
            if urllib.parse.urlparse(src).netloc != request.host:
                abort(403)
            if not hmac.compare_digest(str(request.form.get("csrf", "")), str(session.get("csrf", "-"))):
                abort(Response("表單已過期，請重新整理頁面再試一次", 400))

        if ep == "login":
            if request.method == "POST":
                # 登入表單很小：這個請求最多讀 LOGIN_MAX_BODY（有 Content-Length 超過就 413；chunked 讀到上限就停）
                request.max_content_length = LOGIN_MAX_BODY
                check_csrf()
            return None
        # 先確認已登入、有權限，才讀 POST 的內容（未登入的上傳不會被解析或寫到磁碟）
        u = auth.get_user(g.con, session.get("uid", 0)) if session.get("uid") else None
        idle = time.time() - session.get("seen", 0) > Config.WEB_SESSION_IDLE_MINUTES * 60
        if not u or not u["active"] or u["session_ver"] != session.get("ver") or idle:
            session.clear()
            if request.method == "GET":
                return redirect(url_for("login", next=request.full_path if request.query_string else request.path))
            abort(401)
        g.user, g.role = u["username"], u["role"]
        if g.role != "admin" and (request.method == "POST" and ep not in ("logout", "account") or ep == "users"):
            abort(Response("需要管理權限", 403))
        if request.method == "POST":
            check_csrf()
        session["seen"] = int(time.time())

    def _ip():
        return request.remote_addr or ""

    def _csrf():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    @app.teardown_request
    def close(_exc):
        c = g.pop("con", None)
        if c:
            c.close()

    @app.context_processor
    def ctx():
        imp = osv_import.active_import(g.con) if "con" in g else None
        vex = vex_import.active_import(g.con) if "con" in g else None
        return {"osv": imp, "osv_stale": _age_days(imp) >= Config.OSV_STALE_WARN_DAYS, "vex": vex,
                "osv_outdated": osv_import.outdated(g.con) if "con" in g else False,
                "vex_stale": _age_days(vex) >= Config.OSV_STALE_WARN_DAYS,
                "data_gap": abs(_age_days(imp) - _age_days(vex)) if imp and vex else 0,
                "job": _status, "version": __version__, "PRIO": PRIO, "cfg": Config,
                "user": g.get("user"), "role": g.get("role"), "is_admin": g.get("role") == "admin",
                "role_label": auth.ROLE_LABEL, "csrf_token": _csrf}

    # ------------------------------------------------------------ 登入／帳號
    @app.route("/login", methods=["GET", "POST"])
    def login():
        err = ""
        if request.method == "POST":
            name = request.form.get("username", "")
            why = []
            u, err = auth.verify_login(g.con, name, request.form.get("password", ""), why)
            if u:
                session.clear()                  # 換一個新的 session（防 session fixation）
                session.update(uid=u["id"], ver=u["session_ver"], seen=int(time.time()), csrf=secrets.token_urlsafe(32))
                auth.audit(g.con, u["username"], _ip(), "login")
                return redirect(_safe_next(request.form.get("next")))
            auth.audit(g.con, name[:64], _ip(), "login-failed", "；".join(why) or err)
        return render_template("login.html", err=err, next=request.values.get("next", ""))

    @app.route("/logout", methods=["POST"])
    def logout():
        auth.audit(g.con, g.user, _ip(), "logout")
        session.clear()
        return redirect(url_for("login"))

    @app.route("/account", methods=["GET", "POST"])
    def account():
        msg, err = "", ""
        if request.method == "POST":
            u, _ = auth.verify_login(g.con, g.user, request.form.get("current", ""))
            if not u:
                err = "目前的密碼不正確"
            elif request.form.get("new") != request.form.get("new2"):
                err = "兩次輸入的新密碼不一致"
            else:
                try:
                    auth.set_password(g.con, u["id"], request.form.get("new", ""))
                    session["ver"] = auth.get_user(g.con, u["id"])["session_ver"]     # 其他地方的登入失效，這裡保留
                    auth.audit(g.con, g.user, _ip(), "password-changed")
                    msg = "密碼已更新；其他裝置上的登入已登出"
                except ValueError as e:
                    err = str(e)
        return render_template("account.html", msg=msg, err=err)

    @app.route("/users", methods=["GET", "POST"])
    def users():
        """帳號管理（管理員）"""
        c, msg, err = g.con, "", ""
        if request.method == "POST":
            act = request.form.get("action")
            try:
                if act == "add":
                    auth.create_user(c, request.form.get("username", ""), request.form.get("password", ""), request.form.get("role", ""))
                    detail = "%s（%s）" % (request.form.get("username", "").strip(), request.form.get("role"))
                else:
                    uid = int(request.form.get("uid", "0"))
                    target = auth.get_user(c, uid) or abort(400)
                    if act == "password":
                        auth.set_password(c, uid, request.form.get("password", ""))
                    elif act == "role":
                        auth.update_user(c, uid, role=request.form.get("role"))
                    elif act in ("disable", "enable"):
                        auth.update_user(c, uid, active=(act == "enable"))
                    else:
                        abort(400)
                    detail = target["username"]
                auth.audit(c, g.user, _ip(), "user-" + act, detail)
                msg = "已完成"
            except ValueError as e:
                err = str(e)
        rows = c.execute("SELECT * FROM users ORDER BY lower(username)").fetchall()
        logs = c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
        return render_template("users.html", rows=rows, logs=logs, roles=auth.ROLES, msg=msg, err=err,
                               min_len=auth.PASSWORD_MIN, now=datetime.datetime.now().isoformat(timespec="seconds"))

    # ------------------------------------------------------------ pages
    @app.route("/")
    def index():
        c = g.con
        rows = report.query_findings(c, show_excepted=False)
        by_prio = {}
        per_host = {}
        cves = {}
        for r in rows:
            cves.setdefault((r["hostname"], r["cve"]), r)
        for (hn, _), r in cves.items():
            by_prio[r["priority"]] = by_prio.get(r["priority"], 0) + 1
            ph = per_host.setdefault(hn, {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "": 0, "reboot": False})
            ph[r["priority"] or ""] += 1
        for r in rows:
            if r["location"] == "running-kernel":
                per_host[r["hostname"]]["reboot"] = True
        hosts = c.execute("SELECT * FROM host WHERE active=1 ORDER BY hostname").fetchall()
        last = c.execute("SELECT * FROM sync_run ORDER BY id DESC LIMIT 5").fetchall()
        return render_template("index.html", hosts=hosts, per_host=per_host, by_prio=by_prio, last=last)

    def _filters():
        a = request.args
        return {k: a.get(k) or None for k in ("host", "cve", "priority", "status", "package")} | {
            "state": a.get("state") or "open", "show_excepted": a.get("excepted", "1") == "1"}

    @app.route("/findings")
    def findings():
        f = _filters()
        rows = report.query_findings(g.con, **f)
        view = request.args.get("view", "detail")
        data = report.summary_by_host_cve(rows) if view == "summary" else rows
        fmt = request.args.get("format")
        if fmt == "csv":
            cols = ["hostname", "cve", "priority", "status", "packages", "first_seen", "exception"] if view == "summary" else report.COLUMNS
            name = "cve-%s-%s.csv" % (view, datetime.datetime.now().strftime("%Y%m%d-%H%M"))
            return Response(report.to_csv(data, cols), mimetype="text/csv",
                            headers={"Content-Disposition": "attachment; filename=" + name})
        export_url = url_for("findings", **dict(request.args.to_dict(), format="csv"))
        return render_template("findings.html", rows=data, view=view, f=f, export_url=export_url, limit=2000)

    @app.route("/period")
    def period_report():
        """輸出報表：依 CVE 公開日期列出官方處理狀態；有 format=xlsx 時直接下載 Excel"""
        a = request.args
        today = datetime.date.today()
        quarters = _quarters(today)
        f = {"from": a.get("from") or quarters[0][1], "to": a.get("to") or quarters[0][2],
             "min_priority": a.get("min_priority") if a.get("min_priority") in period.LEVELS else "medium",
             "status": a.get("status") if a.get("status") in dict(period.STATUS_FILTERS) else ""}
        try:
            f["from"], f["to"] = period.valid_date(f["from"]), period.valid_date(f["to"])
        except ValueError:
            abort(400)
        if f["from"] > f["to"]:
            abort(400)
        vex = vex_import.active_import(g.con)
        rows, summary = period.build(g.con, f["from"], f["to"], f["min_priority"], f["status"], have_vex=bool(vex))
        sort_cols = ["cve_id", "priority", "published", "package"] + [c for c, _ in period.RELEASES] + ["description"]
        sort_key = a.get("sort") if a.get("sort") in sort_cols else ""
        sort_dir = "desc" if a.get("dir") == "desc" else "asc"
        if sort_key:
            period.sort_rows(rows, sort_key, sort_dir == "desc")
        if a.get("format") == "xlsx":
            imp = osv_import.active_import(g.con)
            data = period.to_xlsx(rows, summary, f["from"], f["to"], f["min_priority"],
                                  imp["file_mtime"] if imp else None, vex["file_mtime"] if vex else None, f["status"])
            return Response(data, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            headers={"Content-Disposition": "attachment; filename=" + period.filename(f["from"], f["to"])})
        sort_args = {"sort": sort_key, "dir": sort_dir} if sort_key else {}
        export_url = url_for("period_report", **dict(f, format="xlsx", **sort_args))
        page_rows, page, pages = _page(rows)
        return render_template("period.html", f=f, sort_key=sort_key, sort_dir=sort_dir, sort_args=sort_args, quarters=quarters,
                               summary=summary, rows=page_rows, page=page, pages=pages, total_rows=len(rows),
                               per_page=PER_PAGE, have_vex=bool(vex),
                               export_url=export_url, levels=period.LEVELS, releases=period.RELEASES,
                               status_filters=period.STATUS_FILTERS, statuses=vex_import.STATUSES,
                               label=vex_import.LABEL, label_en=vex_import.LABEL_EN, kinds=period.KINDS)

    @app.route("/impact")
    def impact_page():
        """受影響主機：每個 CVE × 套件影響哪些主機"""
        a = request.args
        f = {"min_priority": a.get("min_priority") if a.get("min_priority") in period.LEVELS else "medium",
             "from": a.get("from") or "", "to": a.get("to") or "", "host": (a.get("host") or "").strip(),
             "cve": (a.get("cve") or "").strip().upper(), "state": a.get("state") if a.get("state") in ("pending", "nofix") else ""}
        for k in ("from", "to"):
            if f[k]:
                try:
                    f[k] = period.valid_date(f[k])
                except ValueError:
                    abort(400)
        rows = impact.affected(g.con, f["min_priority"], f["from"] or None, f["to"] or None, f["host"] or None,
                               f["cve"] or None, f["state"])
        if a.get("format") == "csv":
            name = "cve-impact-%s.csv" % datetime.datetime.now().strftime("%Y%m%d-%H%M")
            data = [{impact.HEADERS.get(k, k): r[k] for k in impact.COLUMNS} for r in rows]
            return Response(report.to_csv(data, [impact.HEADERS.get(k, k) for k in impact.COLUMNS]), mimetype="text/csv",
                            headers={"Content-Disposition": "attachment; filename=" + name})
        export_url = url_for("impact_page", **dict(f, format="csv"))
        page_rows, page, pages = _page(rows)
        return render_template("impact.html", f=f, rows=page_rows, page=page, pages=pages, total_rows=len(rows),
                               per_page=PER_PAGE, export_url=export_url, levels=period.LEVELS, sample=impact.SAMPLE,
                               have_vex=bool(vex_import.active_import(g.con)), quarters=_quarters(datetime.date.today()))

    @app.route("/host/<int:hid>")
    def host(hid):
        h = g.con.execute("SELECT * FROM host WHERE id=?", (hid,)).fetchone() or abort(404)
        state = request.args.get("state", "open")
        rows = [r for r in report.query_findings(g.con, state=state) if r["host_id"] == hid]
        return render_template("host.html", h=h, rows=rows, state=state)

    @app.route("/cve/<cve>")
    def cve(cve):
        cve = cve.upper()
        v = g.con.execute("SELECT * FROM vuln WHERE cve=?", (cve,)).fetchone()
        official, hosts = impact.cve_detail(g.con, cve)
        return render_template("cve.html", cve=cve, v=v, official=official, hosts=hosts, releases=Config.UBUNTU_RELEASES,
                               label_en=vex_import.LABEL_EN,
                               have_vex=bool(vex_import.active_import(g.con)), states=impact.STATES)

    @app.route("/exceptions", methods=["GET", "POST"])
    def exceptions():
        c = g.con
        if request.method == "POST":
            if request.form.get("delete"):
                try:
                    eid = int(request.form["delete"])
                except ValueError:
                    abort(400)
                with c:
                    c.execute("DELETE FROM exception WHERE id=?", (eid,))
                auth.audit(c, g.user, _ip(), "exception-delete", str(eid))
            else:
                hp, cv, reason = (request.form.get(k, "").strip() for k in ("host_pattern", "cve", "reason"))
                exp = request.form.get("expires_at", "").strip() or None
                if not (hp and cv and reason):
                    abort(400)
                if exp:
                    try:
                        datetime.date.fromisoformat(exp)
                    except ValueError:
                        abort(400)
                with c:
                    c.execute("INSERT INTO exception(host_pattern,cve,reason,expires_at,created_by,created_at) VALUES (?,?,?,?,?,?)",
                              (hp, cv.upper(), reason, exp, g.user, sync.now()))
                auth.audit(c, g.user, _ip(), "exception-add", "%s %s %s" % (hp, cv.upper(), reason))
            return redirect(url_for("exceptions"))
        return render_template("exceptions.html", rows=c.execute("SELECT * FROM exception ORDER BY id DESC").fetchall(),
                               today=datetime.date.today().isoformat())

    @app.route("/osv")
    def osv():
        return redirect(url_for("data"))

    @app.route("/data", methods=["GET", "POST"])
    def data():
        """資料匯入：OSV（比對主機用）與 VEX（官方狀態）"""
        if request.method == "POST":
            kind = request.form.get("kind")
            f = request.files.get("file")
            if kind not in ("osv", "vex") or not f or not f.filename.endswith(".tar.xz"):
                abort(400)
            inbox = Config.OSV_INBOX_DIR if kind == "osv" else Config.VEX_INBOX_DIR
            os.makedirs(inbox, exist_ok=True)
            f.save(os.path.join(inbox, "%s-all-upload-%s.tar.xz" % (kind, datetime.datetime.now().strftime("%Y%m%d%H%M%S"))))
            auth.audit(g.con, g.user, _ip(), "upload-" + kind, f.filename[:200])
            run_job("sync")      # sync 會先檢查放檔目錄並匯入
            return redirect(url_for("data"))
        rows = g.con.execute("SELECT * FROM osv_import ORDER BY id DESC LIMIT 20").fetchall()
        vex_rows = g.con.execute("SELECT * FROM vex_import ORDER BY id DESC LIMIT 20").fetchall()
        return render_template("data.html", rows=rows, vex_rows=vex_rows)

    @app.route("/sync", methods=["POST"])
    def sync_now():
        run_job("sync")
        auth.audit(g.con, g.user, _ip(), "sync")
        ref = urllib.parse.urlparse(request.referrer or "")   # 只回到本站的頁面
        return redirect(ref.path if ref.netloc == request.host and ref.path.startswith("/") else url_for("index"))

    # ------------------------------------------------------------ 監控
    @app.route("/healthz")
    def healthz():
        """正常回 200；有問題回 503。只回狀態，不含任何主機或 CVE 資料"""
        c, problems = g.con, []
        nowt = datetime.datetime.now()
        imp = osv_import.active_import(c)
        if not imp:
            problems.append("no_osv_data")
        elif imp["file_mtime"] and (nowt - datetime.datetime.fromisoformat(imp["file_mtime"])).days >= Config.OSV_STALE_WARN_DAYS:
            problems.append("osv_data_stale")
        last_ok = c.execute("SELECT finished_at FROM sync_run WHERE status='ok' ORDER BY id DESC LIMIT 1").fetchone()
        last = c.execute("SELECT status FROM sync_run ORDER BY id DESC LIMIT 1").fetchone()
        if not last_ok:
            problems.append("never_synced")
        elif (nowt - datetime.datetime.fromisoformat(last_ok["finished_at"])).total_seconds() > Config.HEALTH_MAX_SYNC_AGE_HOURS * 3600:
            problems.append("sync_too_old")
        if last and last["status"] == "failed":
            problems.append("last_sync_failed")
        if c.execute("SELECT 1 FROM host WHERE active=1 AND kernel_status='error' LIMIT 1").fetchone():
            problems.append("kernel_api_error")
        bad_imp = c.execute("SELECT status FROM osv_import ORDER BY id DESC LIMIT 1").fetchone()
        if bad_imp and bad_imp["status"] == "failed":
            problems.append("last_osv_import_failed")
        vex = vex_import.active_import(c)        # VEX 可以不匯入（輸出報表退回只分已修正／受影響），有匯入才檢查
        if vex and _age_days(vex) >= Config.OSV_STALE_WARN_DAYS:
            problems.append("vex_data_stale")
        bad_vex = c.execute("SELECT status FROM vex_import ORDER BY id DESC LIMIT 1").fetchone()
        if bad_vex and bad_vex["status"] == "failed":
            problems.append("last_vex_import_failed")
        body = {"status": "ok" if not problems else "degraded", "problems": problems,
                "osv_file_date": imp["file_mtime"] if imp else None, "vex_file_date": vex["file_mtime"] if vex else None,
                "last_successful_sync": last_ok["finished_at"] if last_ok else None, "version": __version__}
        return jsonify(body), (200 if not problems else 503)

    # ------------------------------------------------------------ JSON API
    @app.route("/api/findings")
    def api_findings():
        f = _filters()
        rows = report.query_findings(g.con, **f)
        if request.args.get("view") == "summary":
            rows = report.summary_by_host_cve(rows)
        return jsonify(rows)

    @app.route("/api/status")
    def api_status():
        imp = osv_import.active_import(g.con)
        vex = vex_import.active_import(g.con)
        last = g.con.execute("SELECT * FROM sync_run ORDER BY id DESC LIMIT 1").fetchone()
        return jsonify({"version": __version__, "osv": dict(imp) if imp else None, "vex": dict(vex) if vex else None, "last_sync": dict(last) if last else None, "job": _status})

    if start_scheduler:
        from .scheduler import start
        start()
    return app
