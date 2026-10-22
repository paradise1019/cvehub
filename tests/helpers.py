"""測試共用：暫存資料庫、假的 OSV 檔、設定覆寫"""
import io
import json
import os
import tarfile
import tempfile

from cvehub import db
from cvehub.config import Config


class TempEnv:
    """建立暫存目錄並把 Config 指過去；結束時還原"""

    def __init__(self, **overrides):
        self.overrides = overrides
        self.saved = {}

    def __enter__(self):
        self.dir = tempfile.TemporaryDirectory()
        d = self.dir.name
        base = {"DB_PATH": os.path.join(d, "t.sqlite3"), "OSV_INBOX_DIR": os.path.join(d, "inbox"),
                "OSV_ARCHIVE_DIR": os.path.join(d, "archive"),
                "VEX_INBOX_DIR": os.path.join(d, "vex-inbox"), "VEX_ARCHIVE_DIR": os.path.join(d, "vex-archive"),
                "VEX_KEEP_KERNEL_VARIANTS": [], "REPORT_DIR": os.path.join(d, "reports"),
                "UBUNTU_RELEASES": ["24.04"], "OSV_MIN_ROWS_PER_RELEASE": 1, "PRO_MODE": "auto",
                "INCLUDE_UNFIXED": False, "MIN_PRIORITY": "low", "CHECK_OLD_KERNELS": False,
                "KERNEL_API_URL": "", "KERNEL_API_MODE": "bulk", "HISTORY_KEEP_DAYS": 365,
                # 在已部署的容器裡跑測試時，Config 會讀到真實的 .env：外部連線一律清空，避免測試連到 Landscape／kernel API
                "LANDSCAPE_API_URI": "", "LANDSCAPE_API_KEY": "", "LANDSCAPE_API_SECRET": "", "KERNEL_API_TOKEN": "",
                "WEB_TLS_CERT": "", "WEB_SECRET_KEY": "", "WEB_COOKIE_SECURE": False}
        base.update(self.overrides)
        for k, v in base.items():
            self.saved[k] = getattr(Config, k)
            setattr(Config, k, v)
        self.con = db.connect()
        db.init(self.con)
        return self

    def __exit__(self, *a):
        self.con.close()
        for k, v in self.saved.items():
            setattr(Config, k, v)
        self.dir.cleanup()


def osv_record(cve, affected, priority="high", withdrawn=None, details=None):
    """affected: [(ecosystem, source, fixed_or_None, {binary: version})]"""
    d = {"schema_version": "1.7.0", "id": "UBUNTU-" + cve, "upstream": [cve],
         "severity": [{"type": "Ubuntu", "score": priority}], "published": "2026-01-01T00:00:00Z", "affected": []}
    if withdrawn:
        d["withdrawn"] = withdrawn
    if details:
        d["details"] = details
    for eco, src, fixed, bins in affected:
        ev = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
        d["affected"].append({"package": {"ecosystem": eco, "name": src},
                              "ranges": [{"type": "ECOSYSTEM", "events": ev}],
                              "ecosystem_specific": {"binaries": [{"binary_name": b, "binary_version": v} for b, v in bins.items()]}})
    return d


def usn_record(usn, published, cves, affected):
    """affected: [(ecosystem, source, fixed)]"""
    return {"id": usn, "published": published + "T00:00:00Z", "upstream": ["UBUNTU-" + c for c in cves],
            "affected": [{"package": {"ecosystem": e, "name": s}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": f}]}]}
                         for e, s, f in affected]}


def make_osv_tar(path, records, extra_files=None, usns=()):
    with tarfile.open(path, "w:xz") as t:
        for r in records:
            data = json.dumps(r).encode()
            ti = tarfile.TarInfo("osv/cve/2026/%s.json" % r["id"])
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
        for u in usns:
            data = json.dumps(u).encode()
            ti = tarfile.TarInfo("osv/usn/%s.json" % u["id"])
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
        for name, data in (extra_files or {}).items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return path


# VEX 說明文字（取自真實資料）
NOTE = {
    "fixed": ("fixed", None, "This package (for the given release) was vulnerable, but an update has been uploaded and published."),
    "vulnerable": ("affected", None, "This package (for the given release) is vulnerable to the CVE and needs fixing. CVE Notes / justification: x"),
    "vulnerable-wip": ("affected", None, "This package (for the given release) is vulnerable to the CVE, needs fixing, and it is being actively worked on."),
    "deferred": ("under_investigation", None, "This package (for the given release) is vulnerable to the CVE, the problem is understood, but it is currently deferred."),
    "ignored": ("affected", None, "This package (for the given release) is vulnerable to the CVE, the problem is understood, but the Ubuntu Security Team decided to not fix it."),
    "eol": ("affected", None, "This package (for the given release) is no longer supported. Please upgrade your system."),
    "needs-evaluation": ("under_investigation", None, "Ubuntu Security Team classified this CVE as of Medium priority."),
    "not-affected": ("not_affected", "vulnerable_code_not_present", "This package (for the given release), while related to the CVE in some way, is not affected by the issue."),
    "not-in-release": ("not_affected", "component_not_present", "This package (for the given release) does not exist in the archive."),
}


def make_vex_tar(path, docs):
    """docs: {cve: [(NOTE 的鍵, [(source, distro), ...])]}"""
    with tarfile.open(path, "w:xz") as t:
        for cve, stmts in docs.items():
            st = []
            for key, prods in stmts:
                status, just, note = NOTE[key]
                s = {"vulnerability": {"name": cve}, "status": status,
                     "products": [{"@id": "pkg:deb/ubuntu/%s@1.0?arch=source&distro=%s" % p} for p in prods] +
                                 [{"@id": "pkg:deb/ubuntu/%s-bin@1.0?arch=amd64&distro=%s" % p} for p in prods]}
                if just:
                    s["justification"] = just
                s["impact_statement" if status == "not_affected" else "action_statement"] = note
                st.append(s)
            data = json.dumps({"statements": st}).encode()
            ti = tarfile.TarInfo("vex/cve/2026/%s.json" % cve)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return path


E = "Ubuntu:24.04:LTS"
P = "Ubuntu:Pro:24.04:LTS"

# 一份小型、可預期的 OSV 資料
RECORDS = [
    osv_record("CVE-2026-0001", [(E, "openssl", "3.0.13-0ubuntu3.4", {"openssl": "3.0.13-0ubuntu3.4", "libssl3t64": "3.0.13-0ubuntu3.4"})], "high"),
    osv_record("CVE-2026-0002", [(E, "openssl", "3.0.13-0ubuntu3.16", {"openssl": "3.0.13-0ubuntu3.16", "libssl3t64": "3.0.13-0ubuntu3.16"})], "medium"),
    osv_record("CVE-2026-0003", [(E, "curl", None, {"curl": "8.5.0-2ubuntu10"})], "low"),                       # 尚未修正
    osv_record("CVE-2026-0004", [(P, "nodejs", "18.19.1+dfsg-6ubuntu5+esm1", {"nodejs": "18.19.1+dfsg-6ubuntu5+esm1"})], "high"),  # 只有 Pro 修正
    osv_record("CVE-2026-0005", [(E, "linux", "6.8.0-147.147", {"linux-image-6.8.0-147-generic": "6.8.0-147.147",
                                                                  "linux-modules-6.8.0-147-generic": "6.8.0-147.147"})], "critical"),
    osv_record("CVE-2026-0006", [(E, "openssl", "3.0.13-0ubuntu3.20", {})], "high", withdrawn="2026-02-01T00:00:00Z"),  # 已撤回
    osv_record("CVE-2026-0007", [("Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.20", {"openssl": "3.0.2-0ubuntu1.20"})], "high"),  # 其他版本
]
