"""帳號、角色、登入與稽核紀錄

- 角色：viewer（檢視：看所有頁面、下載報表）／admin（管理：上傳資料、例外、立即同步、帳號管理）
- 密碼只存雜湊（werkzeug scrypt）；至少 PASSWORD_MIN 個字元
- 連續輸錯 LOCK_AFTER 次鎖 LOCK_MINUTES 分鐘
- session 裡放 user id 與 session_ver：改密碼、改角色、停用時 session_ver 加一，舊的登入全部失效
- 第一次啟動時，若沒有任何帳號而 .env 有 WEB_AUTH_USER／WEB_AUTH_PASSWORD_HASH（舊版的單一帳號），自動轉成第一個管理員
"""
import datetime
import os
import secrets

from werkzeug.security import check_password_hash, generate_password_hash

from .config import Config

ROLES = [("viewer", "檢視"), ("admin", "管理")]
ROLE_LABEL = dict(ROLES)
PASSWORD_MIN = 12
LOCK_AFTER = 5
LOCK_MINUTES = 15
# 拿來比對不存在帳號的假雜湊：讓「帳號不存在」和「密碼錯」花一樣的時間
_DUMMY_HASH = generate_password_hash("not-a-real-password-" + secrets.token_hex(8))


def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def audit(con, user, ip, action, detail=""):
    with con:
        con.execute("INSERT INTO audit_log(ts,username,ip,action,detail) VALUES (?,?,?,?,?)",
                    (_now(), user or "", ip or "", action, (detail or "")[:500]))


def check_password_policy(pw):
    if len(pw or "") < PASSWORD_MIN:
        raise ValueError("密碼至少 %d 個字元" % PASSWORD_MIN)


def create_user(con, username, password, role, password_hash=None):
    username = (username or "").strip()
    if not username or len(username) > 64 or any(c.isspace() for c in username):
        raise ValueError("帳號不可空白、不可有空白字元、最多 64 個字元")
    if role not in ROLE_LABEL:
        raise ValueError("角色只能是 viewer 或 admin")
    if password_hash is None:
        check_password_policy(password)
        password_hash = generate_password_hash(password)
    if con.execute("SELECT 1 FROM users WHERE lower(username)=lower(?)", (username,)).fetchone():
        raise ValueError("帳號已存在")
    with con:
        cur = con.execute("INSERT INTO users(username,password_hash,role,active,created_at,session_ver) VALUES (?,?,?,1,?,1)",
                          (username, password_hash, role, _now()))
    return cur.lastrowid


def get_user(con, uid):
    return con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def set_password(con, uid, password):
    check_password_policy(password)
    with con:
        con.execute("UPDATE users SET password_hash=?, session_ver=session_ver+1, failed_count=0, locked_until=NULL WHERE id=?",
                    (generate_password_hash(password), uid))


def _active_admins(con, exclude=None):
    return con.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1 AND id<>?", (exclude or 0,)).fetchone()[0]


def update_user(con, uid, role=None, active=None):
    u = get_user(con, uid)
    if not u:
        raise ValueError("帳號不存在")
    new_role = role if role is not None else u["role"]
    new_active = int(active) if active is not None else u["active"]
    if new_role not in ROLE_LABEL:
        raise ValueError("角色只能是 viewer 或 admin")
    if u["role"] == "admin" and u["active"] and (new_role != "admin" or not new_active) and not _active_admins(con, uid):
        raise ValueError("至少要保留一個啟用中的管理員")
    with con:
        con.execute("UPDATE users SET role=?, active=?, session_ver=session_ver+1, failed_count=0, locked_until=NULL WHERE id=?",
                    (new_role, new_active, uid))


def verify_login(con, username, password):
    """回傳 (user 或 None, 錯誤訊息)。錯誤訊息不透露帳號是否存在"""
    u = con.execute("SELECT * FROM users WHERE lower(username)=lower(?)", ((username or "").strip(),)).fetchone()
    if not u or not u["active"]:
        check_password_hash(_DUMMY_HASH, password or "")
        return None, "帳號或密碼錯誤"
    if u["locked_until"] and u["locked_until"] > _now():
        return None, "錯誤次數太多，帳號暫時鎖定，請 %d 分鐘後再試" % LOCK_MINUTES
    if not check_password_hash(u["password_hash"], password or ""):
        n = (u["failed_count"] or 0) + 1
        locked = (datetime.datetime.now() + datetime.timedelta(minutes=LOCK_MINUTES)).isoformat(timespec="seconds") if n >= LOCK_AFTER else None
        with con:
            con.execute("UPDATE users SET failed_count=?, locked_until=? WHERE id=?", (0 if locked else n, locked, u["id"]))
        return None, ("錯誤次數太多，帳號暫時鎖定，請 %d 分鐘後再試" % LOCK_MINUTES) if locked else "帳號或密碼錯誤"
    with con:
        con.execute("UPDATE users SET failed_count=0, locked_until=NULL, last_login=? WHERE id=?", (_now(), u["id"]))
    return get_user(con, u["id"]), ""


def bootstrap(con):
    """沒有任何帳號時，把舊版 .env 的單一帳號轉成第一個管理員。回傳是否有建立"""
    if con.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        return False
    h = Config.WEB_AUTH_PASSWORD_HASH
    if not h or h == "CHANGE_ME" or ":" not in h:
        return False
    create_user(con, Config.WEB_AUTH_USER or "admin", None, "admin", password_hash=h)
    audit(con, "system", "", "bootstrap-admin", "由 .env 的 WEB_AUTH_USER 建立第一個管理員")
    return True


def secret_key():
    """session 簽章用金鑰：WEB_SECRET_KEY，沒設定就在資料目錄產生一個（權限 600，不進 git）"""
    if Config.WEB_SECRET_KEY:
        return Config.WEB_SECRET_KEY
    path = os.path.join(os.path.dirname(Config.DB_PATH) or ".", ".secret_key")
    try:
        with open(path) as f:
            k = f.read().strip()
            if k:
                return k
    except FileNotFoundError:
        pass
    k = secrets.token_hex(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(k)
    return k
