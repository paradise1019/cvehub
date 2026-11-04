#!/usr/bin/env bash
# 從離線安裝包載入基礎 image（install.sh 全新安裝、scripts/upgrade.sh 更新時呼叫）
#   用法：bash scripts/bundle-base.sh <安裝包目錄> <要用的基礎 image 名稱>
#   結束碼：0＝已載入；1＝名稱不同，不載入（原因印在 stderr）；2＝安裝包有問題或不安全，不載入
#
#   安裝包是 root 執行 docker load 的來源，所以（能改安裝包上一層目錄的人也能直接改 root 執行的 install.sh，
#   那種情況不在這裡防；這裡擋的是傳壞的檔案、權限放太寬的目錄、會覆寫別的 tag 的 image 檔）：
#     - 安裝包目錄與檔案的擁有者要是 root 或執行 sudo 的人，而且別人不能寫入（例如別人先建好同名目錄）
#     - 先複製到只有 root 能讀寫的暫存目錄，之後的檢查與 docker load 都用這份（檢查完才被換掉也沒用）
#     - base-image.tar.gz、base-image.txt 要和 SHA256SUMS 相符（檔案傳壞了會擋下）
#     - image 檔裡的名稱（manifest.json 與 index.json 的全部項目）只能是要用的那一個：docker load 會覆寫同名的 tag
#     - 架構和這台主機相同
#   同名的 image 本機已經有也重新載入：安裝包裡的較新時（例如每季更新的基礎 image）才會換上
set -Eeuo pipefail

dir="${1:?用法：bundle-base.sh <安裝包目錄> <基礎 image>}"
want="${2:?用法：bundle-base.sh <安裝包目錄> <基礎 image>}"
note() { printf '   %s\n' "$*" >&2; }

dir="$(realpath -e -- "$dir")" || exit 1
[[ -f "$dir/base-image.tar.gz" && -f "$dir/base-image.txt" ]] || exit 1

if [[ "$want" == *@* ]]; then
    note "BASE_IMAGE 是 digest 形式（$want）：docker load 進來的 image 沒有 digest，請改用 tag（例：python:3.12-slim）"
    exit 1
fi
# 名稱比較：docker.io/library/python:3.12-slim 和 python:3.12-slim 算同一個
canon() {
    local n="$1"
    n="${n#docker.io/}"; n="${n#index.docker.io/}"; n="${n#library/}"
    [[ "${n##*/}" == *:* ]] || n="$n:latest"
    printf '%s' "$n"
}
name="$(sed -n 1p "$dir/base-image.txt")"
if [[ "$(canon "$name")" != "$(canon "$want")" ]]; then
    note "離線安裝包裡的基礎 image 是 $name，和要用的 $want（.env 的 BASE_IMAGE）不同，不載入"
    note "請把 .env 的 BASE_IMAGE 改成 $name，或用 BASE_IMAGE=$want 重新產生安裝包"
    exit 1
fi

# 擁有者與寫入權限（目錄本身與兩個檔案；上一層是有 sticky 的公用目錄如 /tmp 時沒關係，只要這一層是自己的）
# 群組可寫只在群組是 root 或自己的主要群組（Ubuntu 預設每個人有自己的群組、umask 002）時允許
owner_ok() {
    local f="$1" uid gid mode
    uid="$(stat -L -c %u -- "$f")"; gid="$(stat -L -c %g -- "$f")"; mode="$(stat -L -c %a -- "$f")"
    [[ "$uid" == 0 || "$uid" == "${SUDO_UID:-0}" ]] || return 1
    (( (8#$mode & 8#002) == 0 )) || return 1
    (( (8#$mode & 8#020) == 0 )) || [[ "$gid" == 0 || "$gid" == "${SUDO_GID:-0}" ]]
}
for f in "$dir" "$dir/base-image.tar.gz" "$dir/base-image.txt" "$dir/SHA256SUMS"; do
    [[ -e "$f" ]] || { note "安裝包缺少 $(basename "$f")"; exit 2; }
    if ! owner_ok "$f"; then
        note "$f 的擁有者不是 root 或你、或別人可以寫入，不從這裡載入 image（請解開到自己的目錄：mkdir ~/cvehub-install && tar -xzf … -C ~/cvehub-install）"
        exit 2
    fi
done

tmp="$(mktemp -d)"
trap 'rm -rf -- "${tmp:?}"' EXIT
chmod 700 "$tmp"
cp -- "$dir/base-image.tar.gz" "$dir/base-image.txt" "$dir/SHA256SUMS" "$tmp/"

case "$(uname -m)" in x86_64) here=amd64 ;; aarch64) here=arm64 ;; *) here="$(uname -m)" ;; esac
arch="$(sed -n 's/^arch=//p' "$tmp/base-image.txt")"
if [[ -n "$arch" && "$arch" != "$here" ]]; then
    note "離線安裝包的基礎 image 是 $arch，這台主機是 $here：請在 $here 的機器上產生安裝包"
    exit 2
fi
sums_ok() {   # 兩個檔案各有剛好一行，而且相符
    local f
    for f in base-image.tar.gz base-image.txt; do
        [[ "$(grep -cF "  ./$f" "$tmp/SHA256SUMS" | head -1)" == 1 ]] || return 1
        (cd "$tmp" && grep -F "  ./$f" SHA256SUMS | sha256sum -c --quiet --strict - >/dev/null 2>&1) || return 1
    done
}
if ! sums_ok; then
    note "base-image.tar.gz 和 SHA256SUMS 不符（檔案可能傳壞了），不載入"
    exit 2
fi
if ! python3 - "$tmp/base-image.tar.gz" "$(canon "$want")" <<'PY'
import json, posixpath, sys, tarfile
path, want = sys.argv[1], sys.argv[2]

def strict(pairs):
    """JSON 的鍵不分大小寫也不能重複（docker 讀 JSON 時不分大小寫、後面的蓋掉前面的）"""
    low = [k.lower() for k, _ in pairs]
    if len(set(low)) != len(low):
        sys.exit("JSON 有重複的鍵")
    return {k.lower(): v for k, v in pairs}

def canon(n):
    n = n.split("@", 1)[0]
    for p in ("docker.io/", "index.docker.io/", "library/"):
        if n.startswith(p):
            n = n[len(p):]
    return n if ":" in n.rsplit("/", 1)[-1] else n + ":latest"

seen, names = {}, set()
with tarfile.open(path, "r:gz") as t:
    for m in t:
        key = posixpath.normpath("/" + m.name).lstrip("/")      # docker 解開時也會整理路徑（./、../、開頭的 /）
        if key.lower() in ("manifest.json", "index.json"):
            key = key.lower()
            if key in seen:
                sys.exit("%s 出現兩次" % key)        # docker 用哪一份無法確定
            if not m.isfile():
                sys.exit("%s 不是一般檔案" % key)
            seen[key] = json.load(t.extractfile(m), object_pairs_hook=strict)
for e in seen.get("manifest.json") or []:
    names.update(e.get("repotags") or [])
for e in (seen.get("index.json") or {}).get("manifests") or []:
    a = e.get("annotations") or {}
    for k in ("io.containerd.image.name", "org.opencontainers.image.ref.name"):     # strict() 已把鍵轉小寫
        v = a.get(k)
        if v and (k != "org.opencontainers.image.ref.name" or "/" in v or ":" in v):   # ref.name 只有 tag 時不是完整名稱
            names.add(v)
if not names or {canon(n) for n in names} != {want}:
    sys.exit("image 名稱：%s" % (", ".join(sorted(names)) or "（沒有）"))
PY
then
    note "base-image.tar.gz 裡的 image 名稱不是只有 $want，不載入"
    exit 2
fi
note "從離線安裝包載入基礎 image $want（約 1 分鐘）…"
docker load -i "$tmp/base-image.tar.gz" >/dev/null || { note "docker load 失敗"; exit 2; }
docker image inspect "$want" >/dev/null 2>&1 || { note "載入後還是找不到 $want"; exit 2; }
