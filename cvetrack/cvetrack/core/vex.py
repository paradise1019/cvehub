"""匯入 Canonical VEX（vex-all.tar.xz）：每個 CVE × source 套件 × Ubuntu 版本的官方處理狀態

OSV 只有「有沒有修正版本」，分不出 Vulnerable／Deferred／Ignored／Needs evaluation／Not affected。
VEX 的 status 只有 4 種（fixed／affected／not_affected／under_investigation），
細分要看每個 statement 的說明文字；認不出的說明會記在匯入紀錄，狀態顯示成 unknown。
VEX 的版本號是「目前最新版本」，不是第一個修正版本，所以比對主機仍以 OSV 為準。
"""
import fnmatch
import json
import logging
import os
import re
import tarfile
import urllib.parse

from django.db import connection, transaction
from django.utils import timezone

from ..conf import conf
from ..models import VexImport
from .kernel import kernel_variant
from .osv import file_mtime, purge_rows, sha256

log = logging.getLogger(__name__)

CODENAMES = {"16.04": "xenial", "18.04": "bionic", "20.04": "focal", "22.04": "jammy", "24.04": "noble",
             "25.04": "plucky", "25.10": "questing", "26.04": "resolute"}
PRO_PREFIXES = ("esm-infra/", "esm-apps/")

# 狀態代碼：順序＝「最需要注意」在前（一個 CVE 有多個套件時，統計取最前面的那個）
# (代碼, Ubuntu 官方名稱, 畫面／報表用的繁體中文, 說明)
STATUSES = [
    ("needs-evaluation", "Needs evaluation", "待評估", "官方還沒判斷是否受影響"),
    ("vulnerable", "Vulnerable", "受影響", "受影響，需要修正"),
    ("vulnerable-wip", "Vulnerable, work in progress", "修正中", "受影響，官方正在修正"),
    ("deferred", "Vulnerable, fix deferred", "延後修正", "受影響，官方延後修正"),
    ("ignored", "Ignored", "不修正", "官方不修正（不再支援、已撤回或修正會破壞其他功能）"),
    # 只用在輸出報表（截至期末）：修正的 USN 在報表期末之後才發布
    ("fixed-after", "Fixed after period end", "期末後修正", "報表期末時還沒有修正，期末之後才釋出修正（依 USN 發布日）"),
    ("unknown", "Unknown", "無法辨識", "VEX 說明文字無法辨識（見資料匯入頁）"),
    # 只用在輸出報表：有修正版本但沒有對應的 USN，無法判斷修正日期
    ("fixed-nodate", "Fixed (date unknown)", "已修正（日期不明）", "有修正版本，但沒有對應的 USN，無法確認是否在期末前修正"),
    ("fixed", "Fixed", "已修正", "已有修正版本（報表中：期末前已發布）"),
    ("not-affected", "Not affected", "不受影響", "相關但不受影響"),
    ("not-in-release", "Not in release", "版本無此套件", "這個版本沒有這個套件"),
    ("none", "—", "無紀錄", "官方資料沒有這個套件／版本的紀錄"),
]
LABEL = {c: zh for c, _, zh, _ in STATUSES}          # 繁體中文（畫面、Excel）
LABEL_EN = {c: en for c, en, _, _ in STATUSES}       # Ubuntu 官方名稱（說明、滑鼠提示）
RANK = {c: i for i, (c, _, _, _) in enumerate(STATUSES)}
UNRESOLVED = ("needs-evaluation", "vulnerable", "vulnerable-wip", "deferred", "ignored", "unknown")

PURL = re.compile(r"^pkg:deb/ubuntu/([^@]+)@([^?]+)\?(.*)$")


def classify(status, justification, note):
    """VEX status＋說明文字 → 狀態代碼（認不出回傳 None）"""
    n = (note or "").lower()
    if status == "fixed":
        return "fixed"
    if status == "not_affected":
        return "not-in-release" if justification == "component_not_present" or "does not exist in the archive" in n \
            else "not-affected"
    if "deferred" in n:
        return "deferred"
    if status == "under_investigation":
        return "needs-evaluation" if ("classified this cve" in n or "needs to be evaluated" in n) else None
    if status == "affected":
        if "actively worked on" in n:
            return "vulnerable-wip"
        if "decided to not fix" in n or "no longer supported" in n:
            return "ignored"
        if "needs fixing" in n:
            return "vulnerable"
    return None


def _note(s):
    return s.get("action_statement") or s.get("impact_statement") or s.get("status_notes") or ""


def _kernel_variant(src):
    """雲端／OEM kernel 變體：佔 VEX 約 87% 的資料量，預設不匯入；主機有用到的話把名稱（可用 *）加進 VEX_KEEP_KERNEL_VARIANTS"""
    return kernel_variant(src) and not any(fnmatch.fnmatch(src, p) for p in conf.VEX_KEEP_KERNEL_VARIANTS)


def _distros(releases):
    """{distro: (release, is_pro)}"""
    out = {}
    for rel in releases:
        c = CODENAMES.get(rel)
        if not c:
            continue
        out[c] = (rel, False)
        for p in PRO_PREFIXES:
            out[p + c] = (rel, True)
    return out


def _better(a, b):
    """同一個 (CVE, 版本, 套件, 通道) 出現多次時保留的那個：fixed 優先，其次最需要注意的"""
    if a is None:
        return b
    if b == "fixed" or (a != "fixed" and RANK[b] < RANK[a]):
        return b
    return a


def iter_vex(path, releases, unknown):
    """逐個 CVE 產生 [(cve, release, source, base 狀態|None, pro 狀態|None)]"""
    distros = _distros(releases)
    with tarfile.open(path, "r:xz") as tar:
        for m in tar:
            if not (m.isfile() and m.name.startswith("vex/cve/") and m.name.endswith(".json")):
                continue
            d = json.load(tar.extractfile(m))
            got = {}                                  # (cve, rel, src) -> [base, pro]
            for s in d.get("statements", []):
                cve = (s.get("vulnerability") or {}).get("name") or os.path.basename(m.name)[:-5]
                code = classify(s.get("status"), s.get("justification"), _note(s))
                if code is None:
                    code = "unknown"
                    key = "%s｜%s" % (s.get("status"), _note(s)[:120])
                    unknown[key] = unknown.get(key, 0) + 1
                for p in s.get("products", []):
                    pid = p.get("@id", "")
                    # 只看 source 套件（binary 的狀態跟 source 相同）；kernel CVE 的 binary 清單很長，先用字串過濾
                    i = pid.find("?arch=source&distro=")
                    if i < 0:
                        continue
                    dist = distros.get(pid[i + 20:])
                    if not dist:
                        continue
                    mm = PURL.match(pid)
                    if not mm:
                        continue
                    rel, is_pro = dist
                    src = urllib.parse.unquote(mm.group(1))
                    if _kernel_variant(src):
                        continue
                    slot = got.setdefault((cve, rel, src), [None, None])
                    slot[is_pro] = _better(slot[is_pro], code)
            if got:
                yield [(k[0], k[1], k[2], v[0], v[1]) for k, v in got.items()]


SQL = "INSERT OR REPLACE INTO cvetrack_vexstatus(imp,cve,release,source,base_status,pro_status) VALUES (%s,%s,%s,%s,%s,%s)"


def active_import():
    return VexImport.objects.filter(active=True).first()


def _write(imp, rows):
    with transaction.atomic(), connection.cursor() as c:
        c.executemany(SQL, [(imp,) + r for r in rows])


def import_file(path, filename=None):
    """匯入一個 VEX 檔；成功回傳 VexImport，失敗丟例外（舊資料不動）"""
    for stale in VexImport.objects.filter(status="loading"):      # 之前被中斷的匯入（呼叫端拿著 job_lock）
        purge_rows(stale.id, ("cvetrack_vexstatus",))
        VexImport.objects.filter(pk=stale.pk).update(status="failed", message="中斷（程序沒有正常結束）", purged=True)
    sha = sha256(path)
    releases = list(conf.UBUNTU_RELEASES)
    imp = VexImport.objects.create(filename=filename or os.path.basename(path), sha256=sha, file_mtime=file_mtime(path),
                                   imported_at=timezone.now(), releases=",".join(releases), status="loading")
    log.info("VEX 匯入開始：%s（sha256 %s…，版本 %s）", path, sha[:12], ",".join(releases))
    unknown = {}
    try:
        per_release = {r: 0 for r in releases}
        cves = set()
        buf = []
        for rows in iter_vex(path, releases, unknown):
            for cve, rel, src, base, pro in rows:
                cves.add(cve)
                per_release[rel] += 1
                buf.append((cve, rel, src, base, pro))
            if len(buf) >= conf.IMPORT_BATCH:
                _write(imp.id, buf)
                buf.clear()
        if buf:
            _write(imp.id, buf)
        if not cves:
            raise ValueError("檔案中沒有任何 %s 的資料，可能不是正確的 vex-all.tar.xz" % ",".join(releases))
        short = {r: n for r, n in per_release.items() if n < conf.OSV_MIN_ROWS_PER_RELEASE}
        if short:
            raise ValueError("以下版本的資料筆數不足 %d：%s（VEX 格式可能改變，或 UBUNTU_RELEASES 設錯）"
                             % (conf.OSV_MIN_ROWS_PER_RELEASE, ", ".join("%s=%d" % kv for kv in sorted(short.items()))))
        msg = ""
        if unknown:
            top = sorted(unknown.items(), key=lambda kv: -kv[1])[:5]
            msg = "無法辨識的說明 %d 種（狀態顯示 unknown）：%s" % (len(unknown), "；".join("%s（%d）" % kv for kv in top))
            log.warning(msg)
        with transaction.atomic():
            VexImport.objects.filter(active=True).update(active=False)
            imp.status, imp.active, imp.message = "ok", True, msg
            imp.cve_count, imp.row_count, imp.release_counts = len(cves), sum(per_release.values()), per_release
            imp.unknown_count = sum(unknown.values())
            imp.save()
        log.info("VEX 匯入完成：CVE %d、紀錄 %d", len(cves), sum(per_release.values()))
    except BaseException as e:
        log.exception("VEX 匯入失敗：%s", path)
        purge_rows(imp.id, ("cvetrack_vexstatus",))
        VexImport.objects.filter(pk=imp.pk).update(status="failed", message=str(e)[:500], purged=True)
        raise
    for old in VexImport.objects.filter(active=False, purged=False).exclude(status="loading"):
        purge_rows(old.id, ("cvetrack_vexstatus",))
        VexImport.objects.filter(pk=old.pk).update(purged=True)
    return imp


def status_for(row, release, osv_fixed=None):
    """一個 vex_status 列 → (狀態代碼, 是否靠 Pro, 修正版本)。
    20.04 標準支援已結束，以 Pro（esm）為準；其他版本以一般套件庫為準，只有 Pro 才修正時標 Pro。
    修正版本用 OSV 的（VEX 的版本號是目前最新版，不是第一個修正版本）"""
    osv_fixed = osv_fixed or {}
    if row is None:
        return "none", False, ""
    base, pro = row["base_status"], row["pro_status"]
    if release == "20.04":
        if pro:
            return pro, True, osv_fixed.get("pro") or ""
        return base or "none", False, osv_fixed.get("base") or ""
    if base == "fixed":
        return "fixed", False, osv_fixed.get("base") or ""
    if pro == "fixed":
        return "fixed", True, osv_fixed.get("pro") or ""
    if base:
        return base, False, ""
    return pro or "none", bool(pro), ""
