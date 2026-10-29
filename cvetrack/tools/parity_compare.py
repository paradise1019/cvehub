"""一致性比對：同一批主機、同一份 OSV，cvehub 0.8 的 evaluate_host 與 cvetrack 的比對結果要完全相同

用法（用 cvehub 的 venv 執行）：
  python parity_compare.py <cvehub 原始碼目錄> <cvehub.sqlite3（已匯入同一份 OSV）> <cvetrack 的 db.sqlite3>
主機（套件、kernel 欄位、Pro）從 cvetrack 資料庫複製到 cvehub 資料庫，再用 cvehub 比對。
"""
import os
import sqlite3
import sys

src, hub_db, ct_db = sys.argv[1:4]
sys.path.insert(0, src)
os.environ.update({"PRO_MODE": "auto", "INCLUDE_UNFIXED": "false", "CHECK_OLD_KERNELS": "false"})
from cvehub import sync  # noqa: E402
from cvehub.config import Config  # noqa: E402

Config.PRO_MODE, Config.INCLUDE_UNFIXED, Config.CHECK_OLD_KERNELS = "auto", False, False

hub = sqlite3.connect(hub_db)
hub.row_factory = sqlite3.Row
ct = sqlite3.connect(ct_db)
ct.row_factory = sqlite3.Row

with hub:
    hub.execute("DELETE FROM finding")
    hub.execute("DELETE FROM host_package")
    hub.execute("DELETE FROM host")
    for h in ct.execute("SELECT * FROM cvetrack_host WHERE active=1"):
        hid = hub.execute("INSERT INTO host(landscape_id,hostname,ip,title,release,pro_attached,package_count,last_seen,"
                          "kernel_release,kernel_version,kernel_collected_at,kernel_status,active) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)",
                          (h["landscape_id"], h["hostname"], h["ip"], h["title"], h["release"], h["pro_attached"], h["package_count"],
                           "", h["kernel_release"], h["kernel_version"], h["kernel_collected_at"], h["kernel_status"])).lastrowid
        hub.executemany("INSERT INTO host_package(host_id,name,version) VALUES (?,?,?)",
                        [(hid, r["name"], r["version"]) for r in ct.execute("SELECT name,version FROM cvetrack_hostpackage WHERE host_id=?",
                                                                            (h["id"],))])

FIELDS = ("source", "installed", "running", "fixed", "status", "repo", "action", "priority")
total = diff = 0
for h in hub.execute("SELECT * FROM host").fetchall():
    a = {k: tuple(v[f] for f in FIELDS) for k, v in sync.evaluate_host(hub, h).items()}
    hid = ct.execute("SELECT id FROM cvetrack_host WHERE landscape_id=?", (h["landscape_id"],)).fetchone()[0]
    b = {(r["cve"], r["package"], r["location"]): tuple(r[f] for f in FIELDS)
         for r in ct.execute("SELECT * FROM cvetrack_finding WHERE host_id=? AND resolved_at IS NULL", (hid,))}
    total += len(a)
    bad = {k for k in set(a) | set(b) if a.get(k) != b.get(k)}
    diff += len(bad)
    print("%-32s %-6s kernel=%-8s cvehub %5d  cvetrack %5d  不同 %d" % (h["hostname"], h["release"], h["kernel_status"], len(a), len(b), len(bad)))
    for k in sorted(bad)[:5]:
        print("    ", k, "\n      cvehub  ", a.get(k), "\n      cvetrack", b.get(k))
print("合計：cvehub %d 筆，不同 %d 筆" % (total, diff))
sys.exit(1 if diff else 0)
