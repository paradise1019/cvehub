"""SQLite 資料庫：連線與資料表"""
import sqlite3

from .config import Config

SCHEMA = """
PRAGMA journal_mode=WAL;

-- 每次 OSV 匯入的紀錄（可追溯報表用的是哪一份資料）
CREATE TABLE IF NOT EXISTS osv_import (
    id INTEGER PRIMARY KEY,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    file_mtime TEXT,
    imported_at TEXT NOT NULL,
    releases TEXT,
    cve_count INTEGER,
    affected_count INTEGER,
    release_counts TEXT,           -- JSON：{版本: affected 筆數}
    status TEXT NOT NULL,          -- ok | failed
    message TEXT,
    active INTEGER NOT NULL DEFAULT 0,
    format INTEGER                 -- 匯入程式的資料格式版本（osv_import.FORMAT），舊的會自動重匯
);

-- 目前使用中的漏洞資料（每次匯入成功後整批替換）
CREATE TABLE IF NOT EXISTS vuln (
    cve TEXT PRIMARY KEY,
    priority TEXT,
    cvss TEXT,
    published TEXT,
    details TEXT                   -- OSV 的說明（區間報表的 description 欄）
);
CREATE TABLE IF NOT EXISTS affected (
    id INTEGER PRIMARY KEY,
    ecosystem TEXT NOT NULL,
    source TEXT NOT NULL,
    cve TEXT NOT NULL,
    fixed TEXT,
    introduced TEXT,
    binaries TEXT                  -- JSON：{binary: fixed_version}
);
CREATE INDEX IF NOT EXISTS affected_eco_src ON affected(ecosystem, source);
CREATE INDEX IF NOT EXISTS affected_cve ON affected(cve);       -- 區間報表用
-- 每個 CVE × 套件庫 × source 第一次被修正的 USN（輸出報表「截至期末」判斷修正日期）
CREATE TABLE IF NOT EXISTS usn_fix (
    cve TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    source TEXT NOT NULL,
    fixed TEXT,
    usn TEXT,
    published TEXT,                -- USN 發布日 YYYY-MM-DD
    PRIMARY KEY (cve, ecosystem, source)
);
CREATE TABLE IF NOT EXISTS binmap (
    ecosystem TEXT NOT NULL,
    binary TEXT NOT NULL,
    source TEXT NOT NULL,
    PRIMARY KEY (ecosystem, binary)
);

-- 每次 VEX 匯入的紀錄（官方處理狀態）
CREATE TABLE IF NOT EXISTS vex_import (
    id INTEGER PRIMARY KEY,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    file_mtime TEXT,
    imported_at TEXT NOT NULL,
    releases TEXT,
    cve_count INTEGER,
    row_count INTEGER,
    release_counts TEXT,
    unknown_count INTEGER,         -- 說明文字無法辨識的 statement 數
    status TEXT NOT NULL,          -- ok | failed
    message TEXT,
    active INTEGER NOT NULL DEFAULT 0
);
-- CVE × Ubuntu 版本 × source 套件的官方狀態（base＝一般套件庫，pro＝esm-infra／esm-apps）
CREATE TABLE IF NOT EXISTS vex_status (
    cve TEXT NOT NULL,
    release TEXT NOT NULL,
    source TEXT NOT NULL,
    base_status TEXT,
    pro_status TEXT,
    PRIMARY KEY (cve, release, source)
);
CREATE INDEX IF NOT EXISTS vex_rel_src ON vex_status(release, source);
CREATE INDEX IF NOT EXISTS vex_source ON vex_status(source);          -- 歷年弱點的套件篩選

-- 主機（來自 Landscape 或主機清單 CSV；kernel 欄位來自 kernel API 或 CSV；清單匯入的主機 landscape_id 是 NULL）
CREATE TABLE IF NOT EXISTS host (
    id INTEGER PRIMARY KEY,
    landscape_id INTEGER UNIQUE,
    hostname TEXT NOT NULL,
    fqdn TEXT,                     -- 來源回報的名稱原樣（hostname 依 HOST_MATCH_KEY 可能只存第一段）
    ip TEXT,
    title TEXT,
    release TEXT,
    pro_attached INTEGER,
    package_count INTEGER,
    last_seen TEXT,
    kernel_release TEXT,
    kernel_version TEXT,
    kernel_collected_at TEXT,
    kernel_status TEXT,            -- ok | stale | missing | disabled
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS host_package (
    host_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    PRIMARY KEY (host_id, name)
);

-- 比對結果（含歷史：first_seen／last_seen／resolved_at）
CREATE TABLE IF NOT EXISTS finding (
    id INTEGER PRIMARY KEY,
    host_id INTEGER NOT NULL,
    cve TEXT NOT NULL,
    package TEXT NOT NULL,
    source TEXT,
    installed TEXT,
    running TEXT,
    fixed TEXT,
    status TEXT,                   -- fix-available | fix-in-pro | no-fix
    repo TEXT,
    location TEXT,                 -- installed | running-kernel
    action TEXT,                   -- upgrade | reboot | upgrade+reboot
    priority TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    resolved_at TEXT,
    UNIQUE (host_id, cve, package, location)
);
DROP INDEX IF EXISTS finding_open;               -- 0.9.5 起由 finding_open_cover 取代（開頭欄位相同）
-- 總覽的彙總只讀這個索引（不必回表、已依主機×CVE 排好）；升級後第一次啟動時建立（40 萬筆約數秒）
CREATE INDEX IF NOT EXISTS finding_open_cover ON finding(resolved_at, host_id, cve, priority, location);
CREATE INDEX IF NOT EXISTS finding_cve ON finding(cve);
DROP INDEX IF EXISTS host_lname;                -- 0.9.4 開發中曾建立，已不用

-- 資料版本號：比對結果、主機、例外規則有會影響總覽數量的改寫就加一（觸發器在 TRIGGERS），總覽的快取依它判斷要不要重算
-- epoch：建立時的亂數，換成另一份資料庫時靠它分辨（同一份的備份 epoch 相同：還原前要先停容器）
CREATE TABLE IF NOT EXISTS data_gen (id INTEGER PRIMARY KEY CHECK (id = 1), gen INTEGER NOT NULL, epoch TEXT NOT NULL);

-- 歷年弱點：每個 CVE 的整體狀態（cves.build_status 在匯入 OSV／VEX 後算好；scope＝all 或 Ubuntu 版本）
CREATE TABLE IF NOT EXISTS cve_status (
    cve TEXT NOT NULL,
    scope TEXT NOT NULL,
    code TEXT,                     -- fixed | partial | not-affected | not-in-release | 最需要注意的狀態代碼
    fixed INTEGER, total INTEGER, unresolved INTEGER, packages INTEGER,
    PRIMARY KEY (scope, cve)
);
CREATE TABLE IF NOT EXISTS cve_status_meta (id INTEGER PRIMARY KEY CHECK (id = 1), key TEXT, variants TEXT, built_at TEXT);

-- 例外／風險接受
CREATE TABLE IF NOT EXISTS exception (
    id INTEGER PRIMARY KEY,
    host_pattern TEXT NOT NULL,    -- 主機名稱，可用 * 萬用字元
    cve TEXT NOT NULL,             -- CVE 編號，可用 *
    reason TEXT NOT NULL,
    expires_at TEXT,               -- YYYY-MM-DD；空白＝永久
    created_by TEXT,
    created_at TEXT NOT NULL
);


-- 帳號（角色 viewer／admin）與稽核紀錄
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,            -- viewer | admin
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login TEXT,
    failed_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    session_ver INTEGER NOT NULL DEFAULT 1   -- 改密碼／角色／停用時加一，舊的登入失效
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    username TEXT,
    ip TEXT,
    action TEXT NOT NULL,
    detail TEXT
);

-- 主機清單匯入紀錄（HOST_SOURCE=file）
CREATE TABLE IF NOT EXISTS host_import (
    id INTEGER PRIMARY KEY,
    filename TEXT,
    sha256 TEXT,
    imported_at TEXT NOT NULL,
    status TEXT,                   -- ok | failed
    hosts INTEGER,
    packages INTEGER,
    deactivated INTEGER,
    message TEXT
);

-- 每次同步的紀錄
CREATE TABLE IF NOT EXISTS sync_run (
    id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT,                   -- running | ok | failed
    hosts INTEGER,
    open_findings INTEGER,
    new_findings INTEGER,
    resolved_findings INTEGER,
    osv_import_id INTEGER,
    message TEXT
);
"""


BUSY_TIMEOUT = 60     # 秒：資料庫被其他連線鎖住時最多等多久


def connect(path=None):
    con = sqlite3.connect(path or Config.DB_PATH, timeout=BUSY_TIMEOUT)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


# data_gen 的觸發器：在舊版資料庫升級（補欄位）之後才建立（觸發器用到 host.fqdn）；定義和資料庫裡的不同時換掉（_ensure_triggers）。
# 總覽數量用到的欄位（finding 的 host_id／cve／priority／location／resolved_at、host 的 hostname／fqdn／active、exception 全部）
# 有增減時要一起改這裡
TRIGGERS = {          # 名稱 → 觸發時機（內容都是把 data_gen.gen 加一）
    # 只在總覽數量可能改變時加一：同步每次都會更新所有比對結果的 last_seen，那些不算
    "finding_gen_i": "AFTER INSERT ON finding",
    "finding_gen_d": "AFTER DELETE ON finding",
    "finding_gen_u": "AFTER UPDATE OF host_id, cve, priority, location, resolved_at ON finding "
                     "WHEN OLD.host_id IS NOT NEW.host_id OR OLD.cve IS NOT NEW.cve OR OLD.priority IS NOT NEW.priority "
                     "OR OLD.location IS NOT NEW.location OR OLD.resolved_at IS NOT NEW.resolved_at",
    "host_gen_i": "AFTER INSERT ON host",
    "host_gen_d": "AFTER DELETE ON host",
    "host_gen_u": "AFTER UPDATE OF hostname, fqdn, active ON host "
                  "WHEN OLD.hostname IS NOT NEW.hostname OR OLD.fqdn IS NOT NEW.fqdn OR OLD.active IS NOT NEW.active",
    "exception_gen_i": "AFTER INSERT ON exception",
    "exception_gen_d": "AFTER DELETE ON exception",
    "exception_gen_u": "AFTER UPDATE ON exception",
}
_BUMP = "BEGIN UPDATE data_gen SET gen = gen + 1 WHERE id = 1; END"


def init(con):
    con.executescript(SCHEMA)
    # 舊版資料庫升級
    cols = {r[1] for r in con.execute("PRAGMA table_info(host)")}
    if "ip" not in cols:
        con.execute("ALTER TABLE host ADD COLUMN ip TEXT")
    if "fqdn" not in cols:
        con.execute("ALTER TABLE host ADD COLUMN fqdn TEXT")
        con.execute("UPDATE host SET fqdn=hostname")              # 0.9.4 之前 hostname 都是原樣
    cols = {r[1] for r in con.execute("PRAGMA table_info(osv_import)")}
    if "release_counts" not in cols:
        con.execute("ALTER TABLE osv_import ADD COLUMN release_counts TEXT")
    if "format" not in cols:
        con.execute("ALTER TABLE osv_import ADD COLUMN format INTEGER")
    cols = {r[1] for r in con.execute("PRAGMA table_info(vuln)")}
    if "details" not in cols:
        con.execute("ALTER TABLE vuln ADD COLUMN details TEXT")      # 0.4.0：重新匯入 OSV 後才有內容
    cols = {r[1] for r in con.execute("PRAGMA table_info(cve_status_meta)")}
    if "variants" not in cols:                                        # 0.9.8 開發中的資料庫
        con.execute("ALTER TABLE cve_status_meta ADD COLUMN variants TEXT")
    cols = {r[1] for r in con.execute("PRAGMA table_info(data_gen)")}
    if "epoch" not in cols:                                           # 0.9.5 開發中的資料庫
        con.execute("ALTER TABLE data_gen ADD COLUMN epoch TEXT")
        con.execute("UPDATE data_gen SET epoch=lower(hex(randomblob(8)))")
    con.execute("INSERT OR IGNORE INTO data_gen(id, gen, epoch) VALUES (1, 0, lower(hex(randomblob(8))))")
    con.commit()
    _ensure_triggers(con)


def _ensure_triggers(con):
    """建立或換掉 data_gen 的觸發器（TRIGGERS 裡的名稱）：只有定義不同時才動，整批在同一個寫入交易裡
    （和別的程序同時啟動、或同步正在寫入時，不會有一段時間沒有觸發器）。改名時要把舊名稱另外刪掉"""
    want = {n: "CREATE TRIGGER %s %s %s" % (n, when, _BUMP) for n, when in TRIGGERS.items()}
    norm = lambda q: " ".join((q or "").split())

    def changed():
        have = {r[0]: r[1] for r in con.execute("SELECT name, sql FROM sqlite_master WHERE type='trigger'")}
        return [n for n, q in want.items() if norm(have.get(n)) != norm(q)]

    if not changed():
        return
    con.execute("BEGIN IMMEDIATE")
    try:
        for n in changed():
            con.execute("DROP TRIGGER IF EXISTS %s" % n)
            con.execute(want[n])
        con.commit()
    except BaseException:
        con.rollback()
        raise


HOST_COLUMNS = ("hostname", "fqdn", "title", "ip", "release", "pro_attached", "last_seen",
                "kernel_release", "kernel_version", "kernel_collected_at", "kernel_status")


def hosts_by_key(con, keyfn, where="1", params=(), cols="*"):
    """依名稱比對鍵分組的主機：{keyfn(完整名稱): [row, …]}，每組新的在前（cols 要含 hostname、fqdn）。
    同步／匯入開始前一次讀進來（不用每台各查一次；也不會因為處理順序不同，前面寫入的影響後面的判斷）"""
    groups = {}
    for r in con.execute("SELECT %s FROM host WHERE %s ORDER BY id DESC" % (cols, where), params):
        groups.setdefault(keyfn(r["fqdn"] or r["hostname"]), []).append(r)
    return groups


def upsert_host(con, existing_id, fields, packages, keep_ip=False, landscape_id=None):
    """寫入一台主機（Landscape 同步與主機清單匯入共用）；不自己開交易，由呼叫端決定範圍。回傳 host id
      existing_id：呼叫端找到的既有主機（找法各來源不同），None＝新增
      fields：HOST_COLUMNS 的值（package_count 由 packages 算）；寫入後一律 active=1
      packages：{套件名稱: 版本}，整份取代這台主機原本的套件清單
      keep_ip：True＝不改原本的 ip（主機清單裡只有格式不對的 ip 時）
      landscape_id：有值時寫入（既有主機原本沒有時補上）；None＝不動原本的
    """
    if existing_id:
        cols = [k for k in HOST_COLUMNS if k != "ip"]
        con.execute("UPDATE host SET %s,ip=CASE WHEN ? THEN ip ELSE ? END,package_count=?,"
                    "landscape_id=COALESCE(?,landscape_id),active=1 WHERE id=?" % ",".join("%s=?" % k for k in cols),
                    tuple(fields[k] for k in cols) + (int(bool(keep_ip)), fields["ip"], len(packages), landscape_id, existing_id))
        hid = existing_id
    else:
        hid = con.execute("INSERT INTO host(%s,package_count,landscape_id) VALUES (%s)"
                          % (",".join(HOST_COLUMNS), ",".join("?" * (len(HOST_COLUMNS) + 2))),
                          tuple(fields[k] for k in HOST_COLUMNS) + (len(packages), landscape_id)).lastrowid
    con.execute("DELETE FROM host_package WHERE host_id=?", (hid,))
    con.executemany("INSERT INTO host_package(host_id,name,version) VALUES (?,?,?)", [(hid, n, v) for n, v in packages.items()])
    return hid
