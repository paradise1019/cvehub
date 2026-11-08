#!/usr/bin/env bash
# cvehub 安裝／更新（一支腳本處理兩種情況）
#
#   1. 解開 zip（GitHub 下載的 cvehub-main.zip）：python3 -m zipfile -e /tmp/cvehub-main.zip /tmp/cvehub-src
#   2. 執行：    sudo bash /tmp/cvehub-src/*/install.sh
#
#   安裝目錄預設 /opt/cvehub（CVEHUB_DIR=/其他/路徑 可改）
#   - 目錄裡還沒有 cvehub → 全新安裝：問幾個問題、寫 .env、建 image、跑測試、建管理員、啟動
#   - 上次安裝中途失敗   → 沿用已寫好的 .env，從建 image 接著做（改過 .env 再重跑即可）
#   - 已經裝過           → 交給 scripts/upgrade.sh 更新（自動備份、測試，失敗還原；.env 與資料不動）
#   -y：不詢問，全部用預設值（或事先設定的環境變數，見下方 ask 的變數名稱，例：sudo WEB_HOST_PORT=8081 bash install.sh -y）
#
# 主機不需要能 docker pull：基礎 image（預設 python:3.12-slim）要先 docker load 進來，
# Python 套件從 PIP_INDEX_URL（例如內部 Nexus）安裝。
# 完全離線（沒有套件來源、也拉不到 image）：用離線安裝包（scripts/make-offline.sh 產生），解開後一樣執行這支：
#   基礎 image 從包裡的 base-image.tar.gz 自動 docker load，Python 套件從程式目錄的 wheels/ 安裝，不連任何網路
set -Eeuo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$(realpath -m -s -- "${CVEHUB_DIR:-/opt/cvehub}")"     # 絕對路徑（相對路徑會依目前目錄而不同）
YES=0
[[ "${1:-}" == "-y" ]] && YES=1

say()  { printf '%s\n' "$*"; }
step() { printf '\n▶ %s\n' "$*"; }
die()  { printf '❌ %s\n' "$*" >&2; exit 1; }

# 問一個問題：ask 變數名 "說明" 預設值 [secret]；環境變數已有值就直接用
ask() {
    local var="$1" prompt="$2" def="$3" secret="${4:-}" ans
    if [[ -n "${!var:-}" ]]; then return; fi
    if [[ $YES == 1 ]]; then printf -v "$var" '%s' "$def"; return; fi
    if [[ -n "$secret" ]]; then
        read -r -s -p "$prompt: " ans; echo
    else
        read -r -p "$prompt [$def]: " ans
    fi
    printf -v "$var" '%s' "${ans:-$def}"
}

# 寫入設定檔（$ENV_FILE）的一個設定。含 $、#、空白等字元時加單引號（docker compose 讀 .env 時不會再解讀）
set_env() {
    KEY="$1" VAL="$2" python3 - "$ENV_FILE" <<'PY'
import os, re, sys
p, k, v = sys.argv[1], os.environ["KEY"], os.environ["VAL"]
if "'" in v or "\n" in v:
    sys.exit("%s 的值不能包含單引號或換行" % k)
if v and not re.fullmatch(r"[A-Za-z0-9_./:,@+=%-]*", v):
    v = "'" + v + "'"
lines = open(p, encoding="utf-8").read().splitlines()
for i, l in enumerate(lines):
    if l.startswith(k + "="):
        lines[i] = k + "=" + v
        break
else:
    lines.append(k + "=" + v)
open(p, "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY
}

# 讀 .env 的一個設定（去掉引號）；續裝時用
get_env() {
    KEY="$1" python3 - "$APP_DIR/.env" <<'PY'
import os, re, sys
k = os.environ["KEY"]
val = None
for l in open(sys.argv[1], encoding="utf-8"):     # 和 docker compose 一樣：同一個設定寫了好幾行時用最後一行
    l = l.strip()
    l = re.sub(r"^export\s+", "", l)
    if l.startswith(k + "="):
        v = l.split("=", 1)[1].strip()
        if len(v) >= 2 and v[0] in "'\"" and v[0] in v[1:]:
            v = v[1:v.index(v[0], 1)]               # 引號內的值（後面的註解不算）
        else:
            v = v.split(" #", 1)[0].strip()         # 和 docker compose 一樣：沒有引號時「 #」之後是註解
        val = v
if val is not None:
    print(val, end="")
PY
}

# 主機 port 是否已被其他程式使用（接受 8081 或 127.0.0.1:8081）
port_busy() {
    # 這個 port 是否已被使用：主機上在聽的程式，或 docker 容器發布的 port（userland-proxy 關掉時 ss 看不到）
    # 指定了 IP 時，只有同一個 IP 或「全部位址」上的才算衝突
    [[ "$1" == \[* ]] && return 1                   # IPv6（更新時從舊設定搬來的）：不檢查，啟動失敗時會提示
    local p=$((10#${1##*:})) ip="" addr
    [[ "$1" == *:* ]] && ip="${1%:*}"
    conflict() {   # $1＝已在使用的位址（IP:port）
        local a="${1%:*}"
        [[ -z "$ip" || "$ip" == 0.0.0.0 || "$a" == "$ip" || "$a" == 0.0.0.0 || "$a" == "*" || "$a" == "[::]" || "$a" == "::" ]]
    }
    if command -v ss >/dev/null; then
        while read -r addr; do conflict "$addr" && return 0; done < <(ss -ltnH "sport = :$p" 2>/dev/null | awk '{print $4}')
    fi
    while read -r addr; do
        [[ "${addr##*:}" == "$p" ]] && conflict "$addr" && return 0
    done < <(docker ps --format '{{.Ports}}' 2>/dev/null | tr ',' '\n' | sed -nE 's#^ *([^ ]+:[0-9]+)->[0-9]+/tcp.*#\1#p')
    return 1
}

valid_port() {
    # 8081 或 <這台主機的 IPv4>:8081（0.0.0.0、127.x.x.x 也可以）
    [[ "$1" =~ ^(([0-9]{1,3}\.){3}[0-9]{1,3}:)?[0-9]{1,5}$ ]] || return 1
    (( 10#${1##*:} >= 1 && 10#${1##*:} <= 65535 )) || return 1
    [[ "$1" == *:* ]] || return 0
    local ip="${1%:*}" o
    for o in ${ip//./ }; do (( 10#$o <= 255 )) || return 1; done
    [[ "$ip" == 0.0.0.0 || "$ip" == 127.* ]] && return 0
    command -v ip >/dev/null || return 0                       # 沒有 ip 指令：無法檢查，交給 docker
    ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qxF "$ip"
}

# 瀏覽器（Chrome、Edge、Firefox）不讓網頁連的 port（Fetch 規格的 bad ports）：連過去只會看到 ERR_UNSAFE_PORT／此網址受到限制
UNSAFE_PORTS=" 1 7 9 11 13 15 17 19 20 21 22 23 25 37 42 43 53 69 77 79 87 95 101 102 103 104 109 110 111 113 115 117 119 123 135 137 139 143 161 179 389 427 465 512 513 514 515 526 530 531 532 540 548 554 556 563 587 601 636 989 990 993 995 1719 1720 1723 2049 3659 4045 4190 5060 5061 6000 6566 6665 6666 6667 6668 6669 6679 6697 10080 "
unsafe_port() {   # $1＝WEB_HOST_PORT；只聽 127.x（給本機反向代理連）時瀏覽器不會直接連，不算
    [[ "$1" == \[* || "$1" == 127.*:* ]] && return 1
    [[ "$UNSAFE_PORTS" == *" $((10#${1##*:})) "* ]]
}

# Docker Compose 的專案名稱：預設是安裝目錄的最後一段（和 compose 相同的規則：小寫、只留 a-z 0-9 _ -、去掉開頭的 _ -）
# 兩套的目錄最後一段相同（/opt/cvehub 與 /srv/cvehub）時專案名稱相同，docker compose 會把對方的容器當成自己的（重建、停止）
norm_project() { printf '%s' "$1" | LC_ALL=C tr '[:upper:]' '[:lower:]' | LC_ALL=C tr -cd 'a-z0-9_-' | sed 's/^[_-]*//'; }
compose_project() {   # 在安裝目錄問 docker compose（含 .env 的 COMPOSE_PROJECT_NAME）；問不到時用目錄名稱推算
    local n
    n="$( (docker compose config --format json 2>/dev/null || true) | python3 -c 'import json, sys
try:
    print(json.load(sys.stdin).get("name") or "", end="")
except Exception:
    pass' )"
    if [[ -n "$n" ]]; then printf '%s' "$n"; else norm_project "$(basename "$APP_DIR")"; fi
}
other_instance() {   # 專案名稱是 $1、但在別的目錄的容器：印出那些目錄
    local me d
    me="$(realpath -m -- "$APP_DIR")"
    while IFS= read -r d; do
        if [[ -n "$d" && "$(realpath -m -- "$d")" != "$me" ]]; then printf '%s\n' "$d"; fi
    done < <(docker ps -a --filter "label=com.docker.compose.project=$1" --format '{{.Label "com.docker.compose.project.working_dir"}}' 2>/dev/null | sort -u)
}
check_project() {   # $1＝專案名稱，$2＝要怎麼處理的說明
    local others
    others="$(other_instance "$1")"
    [[ -z "$others" ]] || die "這台主機已經有另一套 cvehub 使用相同的 Docker 專案名稱「$1」（$(printf '%s' "$others" | tr '\n' ' ')）。
   安裝目錄的最後一段相同時（例如 /opt/cvehub 與 /srv/cvehub），docker compose 會把兩套當成同一套、互相重建或停止對方的容器。
   $2
   （那一套已經不用、只剩容器的話：sudo docker ps -a --filter label=com.docker.compose.project=$1 找出來刪掉）"
}
# 這一套的 image 名稱（不含版本）：同一台的每一套各用各的，重新建置、更新失敗還原時不會改到別套用的 image
image_repo_for() {   # 專案名稱 → cvehub（預設的 /opt/cvehub）、cvehub-test（/opt/cvehub-test）、cvehub-<名稱>（其他）
    local s
    s="$(printf '%s' "$1" | LC_ALL=C tr -cs 'a-z0-9' '-' | sed 's/^-*//; s/-*$//')"
    case "$s" in ""|cvehub) echo cvehub ;; cvehub*) echo "$s" ;; *) echo "cvehub-$s" ;; esac
}
# 別套的容器在用 image $1（$2＝自己的專案名稱）：印出那些目錄。自己目錄的容器（例如改過 COMPOSE_PROJECT_NAME 留下的舊容器）不算
# 用建立容器時寫的名稱（Config.Image）：tag 被改指到別的 image 之後，docker ps 只顯示 ID
image_users() {
    local me i p d
    me="$(realpath -m -- "$APP_DIR")"
    while IFS='|' read -r i p d; do
        [[ "$i" == "$1" && "$p" != "$2" ]] || continue
        if [[ -n "$d" && "$(realpath -m -- "$d")" == "$me" ]]; then continue; fi
        printf '%s\n' "${d:-不是 docker compose 建的容器}"
    done < <(docker ps -aq 2>/dev/null | xargs -r docker inspect --format \
        '{{.Config.Image}}|{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.project.working_dir"}}' 2>/dev/null | sort -u)
}
check_image() {   # .env 寫好之後：專案名稱以 docker compose 為準再檢查一次，image 名稱不能和別套相同
    local img users
    PROJECT="$(compose_project)"
    check_project "$PROJECT" "請在 $APP_DIR/.env 加一行 COMPOSE_PROJECT_NAME=<別的名稱>（例：cvehub-test），或刪除 $APP_DIR 改裝到別的目錄（sudo CVEHUB_DIR=/opt/cvehub-test bash $0）"
    img="$(docker compose config --images cvehub 2>/dev/null | head -1 || true)"
    [[ -n "$img" ]] || die "無法解析 $APP_DIR 的 docker compose 設定；修正後重新執行：$RERUN"
    users="$(image_users "$img" "$PROJECT")"
    [[ -z "$users" ]] || die "另一套 cvehub（$(printf '%s' "$users" | tr '\n' ' ')）也使用 image $img，重新建置會改到它用的 image。
   請把 $APP_DIR/.env 的 CVEHUB_IMAGE 改成別的名稱（例：CVEHUB_IMAGE=$(image_repo_for "$PROJECT")-2）後重新執行：$RERUN"
}

# 安裝目錄裡屬於使用者的設定、資料與安裝狀態：複製程式、打包更新檔時都不碰（只有這一份清單）
KEEP_EXCLUDES=(.env .env.new .install-incomplete data config backups docker-compose.override.yml)

# 複製程式到安裝目錄（不含使用者的設定與資料）
copy_code() {
    [[ "$SRC" == "$APP_DIR" ]] && return
    mkdir -p "$APP_DIR"
    tar -C "$SRC" "${KEEP_EXCLUDES[@]/#/--exclude=./}" -cf - . | tar -C "$APP_DIR" -xf -
}

[[ $EUID -eq 0 ]] || die "請用 sudo 執行：sudo bash $0"
# docker compose 內插時殼層的變數會蓋過 .env：專案名稱一律以安裝目錄（或 .env）為準，之後手動執行 docker compose 才會是同一套
for _v in COMPOSE_PROJECT_NAME CVEHUB_IMAGE; do
    if [[ -v $_v ]]; then say "⚠️  不使用環境變數 $_v（要自訂請寫在 .env）"; unset "$_v"; fi
done
[[ -f "$SRC/docker-compose.yml" && -f "$SRC/cvehub/__init__.py" ]] || die "$SRC 不是 cvehub 的程式目錄"
command -v python3 >/dev/null || die "需要 python3（Ubuntu 內建）"
command -v docker >/dev/null || die "需要 Docker：sudo apt install docker.io docker-compose-v2"
docker compose version >/dev/null 2>&1 || die "需要 Docker Compose v2：sudo apt install docker-compose-v2"
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$SRC/cvehub/__init__.py")"

# 離線安裝包：程式目錄的 wheels/ 有套件；基礎 image 放在程式目錄的上一層（base-image.tar.gz＋base-image.txt 寫 image 名稱）
OFFLINE=0
compgen -G "$SRC/wheels/*.whl" >/dev/null && OFFLINE=1
BUNDLE_DIR="$(dirname "$SRC")"
BUNDLE_BASE=""
[[ -f "$BUNDLE_DIR/base-image.tar.gz" && -f "$BUNDLE_DIR/base-image.txt" ]] && BUNDLE_BASE="$(head -n 1 "$BUNDLE_DIR/base-image.txt")"

# 失敗後要重新執行的指令：離線安裝包要從包裡的 install.sh 執行（安裝目錄裡的找不到包裡的基礎 image）
# 用 CVEHUB_DIR 裝到別的目錄時要帶著它，否則會變成在 /opt/cvehub 重新安裝
q_app="$(printf '%q' "$APP_DIR")"
RERUN="sudo ${CVEHUB_DIR:+CVEHUB_DIR=$q_app }bash $q_app/install.sh"
[[ -n "$BUNDLE_BASE" ]] && RERUN="sudo ${CVEHUB_DIR:+CVEHUB_DIR=$q_app }bash $(printf '%q' "$SRC")/install.sh"

# 安裝狀態：.install-incomplete＝install.sh 寫好 .env 但還沒成功啟動過（成功後刪除）
# 有 .env 與程式、沒有這個標記＝已安裝（包含 0.8.x 以前手動安裝的）→ 更新
INCOMPLETE="$APP_DIR/.install-incomplete"

# ---------------------------------------------------------------- 已安裝 → 更新
if [[ -f "$APP_DIR/.env" && -f "$APP_DIR/cvehub/__init__.py" && ! -e "$INCOMPLETE" ]]; then
    say "$APP_DIR 已經安裝 cvehub，改用更新流程（→ $VERSION）"
    [[ -n "$BUNDLE_BASE" ]] && export CVEHUB_BUNDLE_DIR="$BUNDLE_DIR"     # 離線安裝包：更新腳本從這裡載入基礎 image
    tmp="$(mktemp -d)"
    trap 'rm -rf -- "$tmp"' EXIT
    # 只打包程式（不含 .env、data、backups、config）
    SRC_DIR="$SRC" SKIP="${KEEP_EXCLUDES[*]}" python3 - "$tmp/cvehub-$VERSION.zip" <<'PY'
import os, sys, zipfile
src = os.environ["SRC_DIR"]
skip = set(os.environ["SKIP"].split())
top = "cvehub-src"
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        if rel == ".":
            dirs[:] = [d for d in dirs if d not in skip]
            files = [f for f in files if f not in skip]
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for f in files:
            full = os.path.join(root, f)
            z.write(full, os.path.join(top, os.path.relpath(full, src)))
PY
    args=("$tmp/cvehub-$VERSION.zip"); [[ $YES == 1 ]] && args+=(-y)
    rc=0
    CVEHUB_DIR="$APP_DIR" bash "$SRC/scripts/upgrade.sh" "${args[@]}" || rc=$?
    exit $rc
fi

# ---------------------------------------------------------------- 上次安裝沒做完 → 沿用 .env 接著做
if [[ -f "$APP_DIR/.env" && -e "$INCOMPLETE" ]]; then
    say "cvehub $VERSION：$APP_DIR 上次安裝沒有完成，沿用現有的 .env 繼續（要重新回答問題：先刪掉 $APP_DIR/.env）"
    copy_code
    cd "$APP_DIR"
    touch "$INCOMPLETE"
    BASE_IMAGE="$(get_env BASE_IMAGE)"; BASE_IMAGE="${BASE_IMAGE:-python:3.12-slim}"
    PIP_INDEX_URL="$(get_env PIP_INDEX_URL)"
    HOST_SOURCE="$(get_env HOST_SOURCE)"
    WEB_HOST_PORT="$(get_env WEB_HOST_PORT)"; WEB_HOST_PORT="${WEB_HOST_PORT:-8080}"
    [[ "$WEB_HOST_PORT" == \[* ]] || valid_port "$WEB_HOST_PORT" || die ".env 的 WEB_HOST_PORT 不正確：$WEB_HOST_PORT（例：8081、127.0.0.1:8081）；修正後重新執行：$RERUN"
    unsafe_port "$WEB_HOST_PORT" && die ".env 的 WEB_HOST_PORT（${WEB_HOST_PORT##*:}）會被瀏覽器拒絕連線（Chrome、Edge 顯示 ERR_UNSAFE_PORT）；改成別的 port（例：8081）後重新執行：$RERUN"
    PROJECT="$(compose_project)"
    check_project "$PROJECT" "請先處理再重新執行：在 $APP_DIR/.env 加一行 COMPOSE_PROJECT_NAME=<別的名稱>（例：cvehub-test），或刪除 $APP_DIR 改裝到別的目錄（sudo CVEHUB_DIR=/opt/cvehub-test bash $0）"
    if [[ -z "$(get_env CVEHUB_IMAGE)" ]]; then           # 0.9.8 以前寫的 .env 沒有：依專案名稱決定
        ENV_FILE="$APP_DIR/.env"
        set_env CVEHUB_IMAGE "$(image_repo_for "$PROJECT")"
    fi
    mkdir -p config data
    chown -R 10001 data
else
    # ------------------------------------------------------------ 全新安裝
    say "cvehub $VERSION 全新安裝 → $APP_DIR"
    if [[ -d "$APP_DIR" ]] && [[ -n "$(ls -A "$APP_DIR" 2>/dev/null)" ]] && [[ "$SRC" != "$APP_DIR" ]] \
            && [[ ! -f "$APP_DIR/cvehub/__init__.py" ]]; then
        die "$APP_DIR 已存在且不是空的（也不是 cvehub 安裝目錄）；請換目錄：sudo CVEHUB_DIR=/其他/路徑 bash $0"
    fi
    PROJECT="$(norm_project "$(basename "$APP_DIR")")"
    [[ -n "$PROJECT" ]] || die "安裝目錄的名稱 $(basename "$APP_DIR") 不能當 Docker 專案名稱（要有英文字母或數字）；請換目錄：sudo CVEHUB_DIR=/opt/cvehub-test bash $0"
    check_project "$PROJECT" "請換一個目錄名稱，例：sudo CVEHUB_DIR=/opt/cvehub-test bash $0（目前沒有做任何變更）"
    users="$(image_users "$(image_repo_for "$PROJECT"):$VERSION" "$PROJECT")"
    [[ -z "$users" ]] || die "另一套 cvehub（$(printf '%s' "$users" | tr '\n' ' ')）已經使用 image $(image_repo_for "$PROJECT"):$VERSION（依安裝目錄名稱決定）。
   請換一個目錄名稱，例：sudo CVEHUB_DIR=/opt/cvehub-test2 bash $0（目前沒有做任何變更）"
    if [[ -n "$(docker ps -aq --filter label=com.docker.compose.service=cvehub 2>/dev/null || true)" ]]; then
        say "   這台主機已經有其他 cvehub：建議設定「網站標示」（例：測試），畫面上才分得出是哪一套"
    fi

    step "1/7 設定（直接按 Enter 用括號內的預設值）"
    ask HOST_SOURCE      "主機來源：file＝匯入主機清單 CSV、landscape＝接 Landscape API" "file"
    [[ "$HOST_SOURCE" == file || "$HOST_SOURCE" == landscape ]] || die "主機來源只能是 file 或 landscape"
    ask UBUNTU_RELEASES  "要比對的 Ubuntu 版本（逗號分隔）" "20.04,22.04,24.04"
    ask TZ_SET           "時區" "Asia/Taipei"
    while :; do
        ask WEB_HOST_PORT "網頁的 port（瀏覽器連 http://<主機>:<port>/；只給本機反向代理連時寫 127.0.0.1:8080）" "8080"
        if valid_port "$WEB_HOST_PORT"; then                      # 08081 → 8081（先正規化再檢查）
            p=$((10#${WEB_HOST_PORT##*:}))
            [[ "$WEB_HOST_PORT" == *:* ]] && WEB_HOST_PORT="${WEB_HOST_PORT%:*}:$p" || WEB_HOST_PORT="$p"
        fi
        if ! valid_port "$WEB_HOST_PORT"; then
            say "   ❌ 格式不對，或 IP 不是這台主機的：$WEB_HOST_PORT（例：8081、127.0.0.1:8081）"
        elif unsafe_port "$WEB_HOST_PORT"; then
            say "   ❌ port ${WEB_HOST_PORT##*:} 會被瀏覽器拒絕連線（Chrome、Edge 顯示 ERR_UNSAFE_PORT，Firefox 顯示「此網址受到限制」），請換一個，例：8081"
        elif port_busy "$WEB_HOST_PORT"; then
            say "   ❌ port ${WEB_HOST_PORT##*:} 已經被其他程式使用（sudo ss -ltnp 'sport = :${WEB_HOST_PORT##*:}' 可以看是誰），請換一個"
        else
            break
        fi
        [[ $YES == 1 ]] && die "請用環境變數指定可以用的 port（沒被使用、瀏覽器不會封鎖），例：sudo WEB_HOST_PORT=<port> bash $0 -y"
        WEB_HOST_PORT=""
    done
    ask SITE_LABEL "網站標示（同一台有兩套時用來分辨，顯示在每一頁最上方，例：測試；不需要就留空）" ""
    if [[ -n "$BUNDLE_BASE" ]]; then
        ask BASE_IMAGE   "基礎 image（離線安裝包裡附的）" "$BUNDLE_BASE"
    else
        ask BASE_IMAGE   "基礎 image（要先 docker load 進來）" "python:3.12-slim"
    fi
    if [[ $OFFLINE == 1 ]]; then
        say "   Python 套件：用離線安裝包裡的（wheels/），不需要套件來源"
        PIP_INDEX_URL="${PIP_INDEX_URL:-https://pypi.org/simple}"; PIP_TRUSTED_HOST="${PIP_TRUSTED_HOST:-}"
    else
        ask PIP_INDEX_URL    "Python 套件來源（內部 Nexus 的 PyPI proxy，或 pypi.org）" "https://pypi.org/simple"
        ask PIP_TRUSTED_HOST "套件來源是自簽憑證時填它的主機名稱（否則留空）" ""
    fi
    if [[ "$HOST_SOURCE" == landscape ]]; then
        ask LANDSCAPE_API_URI    "Landscape API 網址" "https://landscape.example.com/api/"
        ask LANDSCAPE_API_KEY    "Landscape API key" ""
        ask LANDSCAPE_API_SECRET "Landscape API secret（不顯示）" "" secret
        ask LANDSCAPE_CA         "Landscape 自簽 CA 憑證檔路徑（公開憑證留空）" ""
    fi

    step "2/7 複製程式、寫 .env"
    copy_code
    cd "$APP_DIR"
    ENV_FILE="$APP_DIR/.env.new"               # 全部寫完才改名成 .env：中途失敗不會留下寫一半的設定
    install -m 600 .env.example "$ENV_FILE"
    set_env HOST_SOURCE "$HOST_SOURCE"
    set_env UBUNTU_RELEASES "$UBUNTU_RELEASES"
    set_env TZ "$TZ_SET"
    set_env WEB_HOST_PORT "$WEB_HOST_PORT"
    set_env BASE_IMAGE "$BASE_IMAGE"
    set_env PIP_INDEX_URL "$PIP_INDEX_URL"
    set_env PIP_TRUSTED_HOST "$PIP_TRUSTED_HOST"
    set_env CVEHUB_IMAGE "$(image_repo_for "$PROJECT")"
    set_env SITE_LABEL "$SITE_LABEL"
    set_env KERNEL_API_URL ""                  # 沒有 kernel API：用 CSV 的 kernel 欄位或最新安裝的 kernel
    mkdir -p config data
    if [[ "$HOST_SOURCE" == landscape ]]; then
        set_env LANDSCAPE_API_URI "$LANDSCAPE_API_URI"
        set_env LANDSCAPE_API_KEY "$LANDSCAPE_API_KEY"
        set_env LANDSCAPE_API_SECRET "$LANDSCAPE_API_SECRET"
        if [[ -n "$LANDSCAPE_CA" ]]; then
            install -m 644 "$LANDSCAPE_CA" config/landscape_server_ca.crt
            set_env LANDSCAPE_CA_FILE /config/landscape_server_ca.crt
        else
            set_env LANDSCAPE_CA_FILE ""
        fi
    fi
    chown -R 10001 data                        # 容器內以 UID 10001 執行
    touch "$INCOMPLETE"
    mv -f "$ENV_FILE" .env
    say "   .env 已建立（權限 600）；其他設定的說明在 .env 裡，之後要改：sudo nano $APP_DIR/.env 再 sudo docker compose up -d"
fi

check_image

step "3/7 檢查基礎 image：$BASE_IMAGE"
rc=1
if [[ -n "$BUNDLE_BASE" ]]; then
    bash "$SRC/scripts/bundle-base.sh" "$BUNDLE_DIR" "$BASE_IMAGE" || rc=$?
    [[ $rc == 0 || $rc == 1 ]] || die "離線安裝包的基礎 image 不能用（原因如上）；處理後重新執行：$RERUN"
fi
if [[ $rc != 0 ]] && ! docker image inspect "$BASE_IMAGE" >/dev/null 2>&1; then
    say "   本機沒有，試著 docker pull…"
    if [[ -n "$BUNDLE_BASE" ]]; then
        docker pull "$BASE_IMAGE" >/dev/null 2>&1 || die "拿不到 $BASE_IMAGE：離線安裝包附的是 $BUNDLE_BASE，請把 $APP_DIR/.env 的 BASE_IMAGE 改成它，再執行：$RERUN"
    else
        docker pull "$BASE_IMAGE" >/dev/null 2>&1 || die "拿不到 $BASE_IMAGE。在能上網的機器執行
     docker pull $BASE_IMAGE && docker save $BASE_IMAGE | gzip > base-image.tar.gz
   帶進來後：sudo docker load -i base-image.tar.gz，再重新執行：$RERUN
   （完全離線的主機請改用離線安裝包，見 README「完全離線」）"
    fi
fi

if [[ $OFFLINE == 1 ]]; then
    step "4/7 建立 image（Python 套件來自離線安裝包，不連網路）"
    docker compose build -q || die "建置失敗（訊息如上）。離線安裝包的套件和基礎 image 不合時（例如 .env 的 BASE_IMAGE 換過），
   請在能上網的地方用同一個 BASE_IMAGE 重新執行 scripts/make-offline.sh；處理後重新執行：$RERUN"
else
    step "4/7 建立 image（Python 套件來自 $PIP_INDEX_URL）"
    docker compose build -q || die "建置失敗：檢查 .env 的 PIP_INDEX_URL、PIP_TRUSTED_HOST（套件來源連得到、有 requirements.txt 裡的版本）
   修正後重新執行：$RERUN"
fi

step "5/7 自動化測試"
docker compose run --rm --no-deps -T cvehub python -m unittest discover -s tests -t . </dev/null >/tmp/cvehub-test.log 2>&1 \
    || die "測試失敗，記錄在 /tmp/cvehub-test.log"
say "   $(grep -E '^Ran ' /tmp/cvehub-test.log)，全部通過"

step "6/7 建立管理員帳號"
users="$(docker compose run --rm --no-deps -T cvehub python -c "from cvehub import db; c = db.connect(); db.init(c); print(c.execute('SELECT COUNT(*) FROM users').fetchone()[0])" </dev/null 2>/tmp/cvehub-db.log | tail -1 || true)"
[[ "$users" =~ ^[0-9]+$ ]] || die "無法讀取資料庫（訊息在 /tmp/cvehub-db.log）；修正後重新執行：$RERUN"
if [[ "$users" -gt 0 ]]; then
    say "   已有 $users 個帳號，略過"
elif [[ $YES == 1 ]]; then
    say "   （-y 模式略過）之後執行：cd $APP_DIR && sudo docker compose run --rm --no-deps cvehub python -m cvehub.cli user-add admin admin"
else
    ask ADMIN_USER "管理員帳號名稱" "admin"
    say "   輸入兩次密碼（至少 12 個字元）"
    docker compose run --rm --no-deps cvehub python -m cvehub.cli user-add "$ADMIN_USER" admin \
        || say "   ⚠️ 沒有建立成功；之後可執行：cd $APP_DIR && sudo docker compose run --rm --no-deps cvehub python -m cvehub.cli user-add admin admin"
fi

step "7/7 啟動（port $WEB_HOST_PORT）"
if [[ -z "$(docker compose ps -q cvehub 2>/dev/null)" ]] && port_busy "$WEB_HOST_PORT"; then
    die "port ${WEB_HOST_PORT##*:} 已經被其他程式使用；改 $APP_DIR/.env 的 WEB_HOST_PORT（例：WEB_HOST_PORT=8081）後重新執行：$RERUN"
fi
docker compose up -d || die "啟動失敗（訊息如上）。port 的問題（被佔用、IP 不對）請改 $APP_DIR/.env 的 WEB_HOST_PORT 後重新執行：$RERUN"
for _ in $(seq 1 60); do
    st="$(docker inspect --format '{{.State.Health.Status}}' "$(docker compose ps -q cvehub)" 2>/dev/null || true)"
    [[ "$st" == healthy ]] && break
    sleep 3
done
[[ "${st:-}" == healthy ]] || die "容器 3 分鐘內沒有變成 healthy，請看：cd $APP_DIR && sudo docker compose logs"
rm -f -- "$INCOMPLETE"                        # 之後再執行 install.sh 就是更新

port="$(docker compose port cvehub 8080 2>/dev/null | head -1 | sed 's/.*://' || true)"      # 實際發布的 port（含 override）
# 網址的主機部分：WEB_HOST_PORT 指定了 IPv4（不是 0.0.0.0）就用它，否則用這台主機的第一個 IP
if [[ "$WEB_HOST_PORT" == *:* && "${WEB_HOST_PORT%:*}" != 0.0.0.0 && "$WEB_HOST_PORT" != \[* ]]; then
    web_host="${WEB_HOST_PORT%:*}"
else
    web_host="$(hostname -I | awk '{print $1}')"
fi
cat <<EOF

✅ cvehub $VERSION 已安裝並啟動
   網頁：http://$web_host:${port:-${WEB_HOST_PORT##*:}}/

接下來（都在網頁「資料匯入」頁，用管理員登入）：
   1. 上傳 osv-all.tar.xz 與 vex-all.tar.xz（在能上網的電腦下載）
        https://security-metadata.canonical.com/osv/osv-all.tar.xz
        https://security-metadata.canonical.com/vex/vex-all.tar.xz
EOF
if [[ "$HOST_SOURCE" == file ]]; then
    say "   2. 上傳主機清單 CSV（用 ansible/collect-hosts.yml 產生，格式見 README「主機清單」）"
else
    say "   2. 按「立即同步」從 Landscape 取得主機"
fi
say "   正式使用前請改成 HTTPS（README「HTTPS」）"
