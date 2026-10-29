"""主機 × OSV 比對（規則與 cvehub 0.8 的 evaluate_host 相同，結果要完全一致）"""
import json
import re

from django.db import connection

from ..conf import conf
from .vercmp import vercmp

KERNEL_ABI = re.compile(r"^linux-(?:hwe-[0-9.]+-)?(?:image|image-unsigned|modules|modules-extra|headers|tools|cloud-tools|buildinfo)"
                        r"-(\d+\.\d+\.\d+)-(\d+)(?:-[a-z0-9-]+)?$")
KERNEL_NAME = re.compile(r"^(linux-(?:image|image-unsigned|modules))-(\d+\.\d+\.\d+)-\d+-([a-z0-9-]+)$")


def old_kernels(pk):
    """同一個 kernel 系列裡較舊的 ABI（已被新 kernel 取代，預設不比對）"""
    newest = {}
    for n in pk:
        m = KERNEL_ABI.match(n)
        if m:
            newest[m.group(1)] = max(newest.get(m.group(1), 0), int(m.group(2)))
    return {n for n in pk if (m := KERNEL_ABI.match(n)) and int(m.group(2)) < newest[m.group(1)]}


def newest_kernel_version(pk, release):
    m = KERNEL_ABI.match("linux-image-" + release)
    best = None
    for n, v in pk.items():
        mm = KERNEL_ABI.match(n)
        if m and mm and mm.group(1) == m.group(1) and n.startswith("linux-image-"):
            if best is None or vercmp(v, best) > 0:
                best = v
    return best


def _kernel_source_by_series(cur, imp, eco, name):
    """例：linux-image-6.8.0-139-generic → 找 binmap 裡 linux-image-6.8.0-*-generic 最常對到的 source"""
    m = KERNEL_NAME.match(name)
    if not m:
        return None
    prefix, series, flavor = m.groups()
    rx = re.compile(r"^%s-%s-\d+-%s$" % (re.escape(prefix), re.escape(series), re.escape(flavor)))
    counts = {}
    cur.execute("SELECT binary, source FROM cvetrack_binmap WHERE imp=%s AND ecosystem=%s AND binary LIKE %s",
                [imp, eco, "%s-%s-%%-%s" % (prefix, series, flavor)])
    for b, s in cur.fetchall():
        if rx.match(b):
            counts[s] = counts.get(s, 0) + 1
    return max(counts, key=counts.get) if counts else None


def has_pro(host, pk):
    if conf.PRO_MODE == "auto":
        return bool(host.pro_attached) if host.pro_attached is not None else any("+esm" in v for v in pk.values())
    return conf.PRO_MODE == "yes"


def evaluate(host, pk, imp):
    """回傳 (結果 {(cve, package, location): row}, 比對時略過的舊 kernel 套件名稱)

    host：Host（用到 release、pro_attached、kernel_*）；pk：{套件: 版本}；imp：使用中的 OSV 匯入編號
    """
    rel = host.release
    base, proe = "Ubuntu:%s:LTS" % rel, "Ubuntu:Pro:%s:LTS" % rel
    pro = has_pro(host, pk)

    items = []     # (binary, version, location)
    # error／stale／missing：沿用上一次可信的執行中 kernel（runs._kernel_fields 保留了 release／版本）；
    # 從來沒有可信資料時欄位是空的，改比對已安裝的 kernel 套件（同 cvehub）
    running_kernel = host.kernel_status in ("ok", "error", "stale", "missing") and host.kernel_version and host.kernel_release
    if running_kernel:
        skip = {n for n in pk if KERNEL_ABI.match(n)}
        for n in ("linux-image-", "linux-image-unsigned-", "linux-modules-"):
            items.append((n + host.kernel_release, host.kernel_version, "running-kernel"))
        newest_k = newest_kernel_version(pk, host.kernel_release)
    else:
        skip = set() if conf.CHECK_OLD_KERNELS else old_kernels(pk)
        newest_k = None
    items += [(n, v, "installed") for n, v in pk.items() if n not in skip]

    out = {}
    with connection.cursor() as cur:
        names = sorted({i[0] for i in items})
        srcmap, pro_srcmap = {}, {}
        for i in range(0, len(names), 500):
            chunk = names[i:i + 500]
            cur.execute("SELECT ecosystem, binary, source FROM cvetrack_binmap WHERE imp=%%s AND ecosystem IN (%%s,%%s) AND binary IN (%s)"
                        % ",".join(["%s"] * len(chunk)), [imp, base, proe] + chunk)
            for e, b, s in cur.fetchall():
                (srcmap if e == base else pro_srcmap)[b] = s
        for b, s in pro_srcmap.items():      # 一般版本優先，沒有才用 Pro 的對應
            srcmap.setdefault(b, s)
        if running_kernel:
            # 執行中 kernel 的 ABI 名稱不一定出現在 OSV 裡：改用同系列、同 flavor 的其他 ABI 推回 source 套件
            for n in [i[0] for i in items if i[2] == "running-kernel" and i[0] not in srcmap]:
                src = _kernel_source_by_series(cur, imp, base, n) or _kernel_source_by_series(cur, imp, proe, n)
                if src:
                    srcmap[n] = src
        vul = {}
        srcs = sorted(set(srcmap.values()))
        for i in range(0, len(srcs), 500):
            chunk = srcs[i:i + 500]
            cur.execute("SELECT a.ecosystem, a.source, a.cve, a.fixed, a.introduced, a.binaries, v.priority FROM cvetrack_affected a "
                        "LEFT JOIN cvetrack_vuln v ON v.imp=a.imp AND v.cve=a.cve "
                        "WHERE a.imp=%%s AND a.ecosystem IN (%%s,%%s) AND a.source IN (%s) ORDER BY a.id"
                        % ",".join(["%s"] * len(chunk)), [imp, base, proe] + chunk)
            for e, s, cve, fixed, introduced, binaries, prio in cur.fetchall():
                vul.setdefault(s, []).append((e, cve, fixed, introduced, binaries, prio))

    for binname, ver, loc in items:
        src = srcmap.get(binname)
        if not src:
            continue
        for eco, cve, vfixed, introduced, binaries, prio in vul.get(src, []):
            label = "base" if eco == base else "pro"
            if introduced and vercmp(ver, introduced) < 0:
                continue
            if vfixed:
                fixed = json.loads(binaries or "{}").get(binname) or vfixed
                if vercmp(ver, fixed) >= 0:
                    continue
                status = "fix-available" if (label == "base" or pro) else "fix-in-pro"
                repo = "ubuntu" if label == "base" else "esm"
            else:
                if not conf.INCLUDE_UNFIXED or label == "pro":
                    continue
                status, fixed, repo = "no-fix", "", ""
            if loc == "running-kernel":
                action = "reboot" if (fixed and newest_k and vercmp(newest_k, fixed) >= 0) else "upgrade+reboot"
                pkgname = "kernel " + host.kernel_release
            else:
                action, pkgname = "upgrade", binname
            if status == "no-fix":
                action = ""
            key = (cve, pkgname, loc)
            old = out.get(key)
            if old and not (old["status"] == "no-fix" or (old["repo"] != "ubuntu" and repo == "ubuntu")):
                continue
            out[key] = {"cve": cve, "package": pkgname, "source": src, "installed": pk.get(binname, ""),
                        "running": ver if loc == "running-kernel" else "", "fixed": fixed, "status": status, "repo": repo,
                        "location": loc, "action": action, "priority": prio or "", "binary": binname}
    return out, skip
