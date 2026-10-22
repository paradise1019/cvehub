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

-- 主機（來自 Landscape；kernel 欄位來自 kernel API）
CREATE TABLE IF NOT EXISTS host (
    id INTEGER PRIMARY KEY,
    landscape_id INTEGER UNIQUE,
    hostname TEXT NOT NULL,
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
CREATE INDEX IF NOT EXISTS finding_open ON finding(resolved_at, host_id);
CREATE INDEX IF NOT EXISTS finding_cve ON finding(cve);

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


def connect(path=None):
    con = sqlite3.connect(path or Config.DB_PATH, timeout=60)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init(con):
    con.executescript(SCHEMA)
    # 舊版資料庫升級
    cols = {r[1] for r in con.execute("PRAGMA table_info(host)")}
    if "ip" not in cols:
        con.execute("ALTER TABLE host ADD COLUMN ip TEXT")
    cols = {r[1] for r in con.execute("PRAGMA table_info(osv_import)")}
    if "release_counts" not in cols:
        con.execute("ALTER TABLE osv_import ADD COLUMN release_counts TEXT")
    if "format" not in cols:
        con.execute("ALTER TABLE osv_import ADD COLUMN format INTEGER")
    cols = {r[1] for r in con.execute("PRAGMA table_info(vuln)")}
    if "details" not in cols:
        con.execute("ALTER TABLE vuln ADD COLUMN details TEXT")      # 0.4.0：重新匯入 OSV 後才有內容
    con.commit()
