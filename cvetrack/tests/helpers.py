"""測試共用：產生小型 OSV 檔、主機資料、執行 Run"""
import io
import json
import tarfile

from cvetrack.core import osv, runs

ECO = "Ubuntu:24.04:LTS"
PRO = "Ubuntu:Pro:24.04:LTS"


def osv_record(cve, affected, priority="high", published="2026-01-01T00:00:00Z"):
    """affected: [(ecosystem, source, fixed_or_None, {binary: version})]"""
    d = {"schema_version": "1.7.0", "id": "UBUNTU-" + cve, "upstream": [cve],
         "severity": [{"type": "Ubuntu", "score": priority}], "published": published, "affected": [],
         "details": "details of " + cve}
    for eco, src, fixed, bins in affected:
        ev = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
        d["affected"].append({"package": {"ecosystem": eco, "name": src},
                              "ranges": [{"type": "ECOSYSTEM", "events": ev}],
                              "ecosystem_specific": {"binaries": [{"binary_name": b, "binary_version": v} for b, v in bins.items()]}})
    return d


def write_osv(path, records):
    with tarfile.open(path, "w:xz") as tar:
        for d in records:
            data = json.dumps(d).encode()
            ti = tarfile.TarInfo("osv/cve/%s.json" % d["id"])
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    return str(path)


def import_osv(tmp_path, name, records):
    return osv.import_file(write_osv(tmp_path / name, records))


def host(lid, packages, hostname=None, kernel=None, pro=False, release="24.04"):
    return {"landscape_id": lid, "hostname": hostname or "host%d.example.com" % lid, "ip": "", "title": "",
            "release": release, "pro_attached": pro, "packages": dict(packages), "kernel": kernel, "kernel_error": False}


def do_run(hosts, trigger="manual"):
    return runs.run(trigger=trigger, source=[dict(h, packages=dict(h["packages"])) for h in hosts])
