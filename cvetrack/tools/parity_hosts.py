"""產生一致性測試用的主機（JSON，格式同 cvetrack 的 file_hosts）

來源：cvehub 資料庫裡的真實主機套件，以及 OSV 的 binmap／affected 隨機抽樣（各版本），
把部分套件版本改成比修正版本舊，製造大量弱點；kernel、Pro 狀態也各種組合都有。
用法：python parity_hosts.py <cvehub.sqlite3> <輸出.json> [台數/版本]
"""
import json
import random
import sqlite3
import sys

db, out = sys.argv[1], sys.argv[2]
per = int(sys.argv[3]) if len(sys.argv) > 3 else 8
rnd = random.Random(20261029)
c = sqlite3.connect(db)
c.row_factory = sqlite3.Row


def older(v):
    """比 v 舊的版本：去掉最後一段，或在前面加 ~"""
    if "-" in v and rnd.random() < 0.5:
        up, rev = v.rsplit("-", 1)
        return up + "-" + (rev[:-1] if len(rev) > 1 else "0") if rnd.random() < 0.5 else up + "~0-0"
    return v + "~0" if rnd.random() < 0.5 else "0:0.1"


hosts = []
lid = 1000
for h in c.execute("SELECT * FROM host"):
    pk = {r["name"]: r["version"] for r in c.execute("SELECT name,version FROM host_package WHERE host_id=?", (h["id"],))}
    for variant in range(per):
        p = dict(pk)
        for n in rnd.sample(sorted(p), int(len(p) * 0.3)):
            p[n] = older(p[n])
        lid += 1
        k = None
        if variant % 3 == 0:
            k = {"release": h["kernel_release"], "version": h["kernel_version"], "collected_at": "auto"}
        elif variant % 3 == 1:
            # 執行中的是較舊的 kernel
            olds = [n[len("linux-image-"):] for n in p if n.startswith("linux-image-") and n[len("linux-image-"):][:1].isdigit()]
            if olds:
                rel = sorted(olds)[0]
                k = {"release": rel, "version": p["linux-image-" + rel], "collected_at": "auto"}
        hosts.append({"landscape_id": lid, "hostname": "real%02d-%s.example.com" % (variant, h["release"]),
                      "release": h["release"], "pro_attached": [None, True, False][variant % 3 - 1 if variant else 0],
                      "packages": p, "kernel": k})

for rel in ("20.04", "22.04", "24.04", "26.04"):
    eco = "Ubuntu:%s:LTS" % rel
    # kernel 套件只在真實清單那批測（隨機抽會抽到大量雲端／OEM kernel 變體，不像真實主機）
    bins = c.execute("SELECT binary, source FROM binmap WHERE ecosystem=? AND source NOT LIKE 'linux%' "
                     "ORDER BY random() LIMIT 6000", (eco,)).fetchall()
    rows = []
    for b in bins:
        a = c.execute("SELECT fixed, binaries FROM affected WHERE ecosystem=? AND source=? AND fixed IS NOT NULL LIMIT 1",
                      (eco, b["source"])).fetchone()
        if a:
            rows.append({"binary": b["binary"], "fixed": a["fixed"], "binaries": a["binaries"]})
    for i in range(per):
        p = {}
        for r in rnd.sample(rows, min(1500, len(rows))):
            fixed = json.loads(r["binaries"] or "{}").get(r["binary"]) or r["fixed"]
            x = rnd.random()
            p[r["binary"]] = fixed if x < 0.3 else older(fixed) if x < 0.8 else fixed + "+1"
        if i % 2:
            # 幾個 +esm 版本（PRO_MODE=auto 且 pro_attached 不明時用來判斷有 Pro）
            for n in rnd.sample(sorted(p), 3):
                p[n] = p[n] + "+esm1"
        lid += 1
        hosts.append({"landscape_id": lid, "hostname": "syn%02d-%s.example.com" % (i, rel), "release": rel,
                      "pro_attached": [None, True, False][i % 3], "packages": p, "kernel": None})

json.dump(hosts, open(out, "w"), indent=0)
print("主機 %d 台，套件合計 %d" % (len(hosts), sum(len(h["packages"]) for h in hosts)))
