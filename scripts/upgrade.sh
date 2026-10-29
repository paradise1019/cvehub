#!/usr/bin/env bash
# cvehub 更新／回復
#
#   更新：sudo bash scripts/upgrade.sh <新版的 zip>          （例：cvehub-0.6.0.zip，GitHub 的 Download ZIP 也可以）
#   回復：sudo bash scripts/upgrade.sh --rollback backups/<時間-舊版本>
#   不詢問：加 -y
#   安裝目錄：預設是這支腳本的上一層；從解開的新版執行時用 CVEHUB_DIR=/opt/cvehub 指定
#   備份：backups/ 只保留最近 5 份（CVEHUB_KEEP_BACKUPS 可改）
#
# 只替換程式檔；.env、data/、config/、backups/、docker-compose.override.yml 不會動。
# 流程：備份程式與設定 → 換程式 → 建 image → 跑測試（失敗就自動還原程式，舊版容器照常運作）
#       → 停容器 → 備份資料庫 → 啟動新版 → 健康檢查
set -Eeuo pipefail

CODE_ITEMS=(cvehub tests scripts django-kernel-view mock-kernel-api Dockerfile docker-compose.yml requirements.txt
            README.md MAINTENANCE.md CHANGELOG.md .env.example .dockerignore .gitignore)

rollback_hint() {   # 回復指令：用備份目錄裡的腳本副本（就是建立這份備份的腳本，安裝目錄的 scripts/ 可能是別的版本或不完整）
    if [[ -f "$1/upgrade.sh" ]]; then
        printf '%s\n' "sudo CVEHUB_DIR=$APP_DIR bash $1/upgrade.sh --rollback $1"
    else
        printf '%s\n' "sudo bash $APP_DIR/scripts/upgrade.sh --rollback backups/$(basename "$1")"
    fi
}

LOG=""                                  # 設定後，所有訊息也附加到這個檔案（SSH 斷線後仍可查結果）
logf() { if [[ -n "$LOG" ]]; then printf '%s %s\n' "$(date '+%F %T')" "$*" >> "$LOG" 2>/dev/null || true; fi; }
out() { printf '%s\n' "$*" 2>/dev/null || true; logf "$*"; }   # 終端機／pipe 已斷時也不會讓腳本中止
die() {
    printf '%s\n' "❌ $*" 1>&2 2>/dev/null || true
    logf "❌ $*"
    if [[ "${PHASE:-}" == service && -n "${ACTIVE_BK:-}" ]]; then
        printf '%s\n' "   回復：$(rollback_hint "$ACTIVE_BK")" 1>&2 2>/dev/null || true
        logf "   回復：$(rollback_hint "$ACTIVE_BK")"
    fi
    exit 1
}
info() { out "▶ $*"; }

YES=0
ARGS=()
for a in "$@"; do
    if [[ "$a" == "-y" ]]; then
        YES=1
    elif [[ -e "$a" ]]; then
        ARGS+=("$(cd "$(dirname "$a")" && pwd)/$(basename "$a")")    # 相對路徑先轉成絕對路徑（後面會 cd 到安裝目錄）
    else
        ARGS+=("$a")
    fi
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

APP_DIR="${CVEHUB_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
APP_DIR="$(cd "$APP_DIR" 2>/dev/null && pwd)" || die "找不到安裝目錄"
[[ "$APP_DIR" == /* && "$APP_DIR" != "/" ]] || die "安裝目錄不正確：$APP_DIR"
if [[ "${1:-}" == --rollback ]]; then              # 回復：安裝目錄可能已被中斷的更新刪掉一半，只要有備份目錄就好
    [[ -d "$APP_DIR/backups" ]] || die "$APP_DIR 沒有 backups/，不是 cvehub 安裝目錄"
else
    [[ -f "$APP_DIR/docker-compose.yml" && -f "$APP_DIR/cvehub/__init__.py" ]] || die "$APP_DIR 不是 cvehub 安裝目錄"
fi
[[ -f "$APP_DIR/.env" ]] || die "$APP_DIR/.env 不存在：從解開的新版執行時，請用 CVEHUB_DIR=/opt/cvehub 指定安裝目錄"
docker info >/dev/null 2>&1 || die "無法使用 docker（請用 sudo 執行）"

# 更新時會替換 scripts/（包括這支腳本本身）：先複製到暫存檔再從那裡執行
if [[ -z "${CVEHUB_UPGRADE_COPY:-}" ]]; then
    self="$(mktemp)"
    cp -- "$0" "$self"
    if [[ $YES == 1 ]]; then set -- "$@" -y; fi
    CVEHUB_UPGRADE_COPY="$self" CVEHUB_DIR="$APP_DIR" exec bash "$self" "$@"
fi
TMP_DIRS=()
cleanup() {
    local d
    for d in "${TMP_DIRS[@]+"${TMP_DIRS[@]}"}"; do rm -rf -- "${d:?}"; done
    rm -f -- "${CVEHUB_UPGRADE_COPY:?}"
}
trap cleanup EXIT
cd "$APP_DIR"

# 記錄與鎖：結果都寫到 backups/upgrade.log；同時只能有一個更新／回復在跑
mkdir -p "$APP_DIR/backups"
chmod 700 "$APP_DIR/backups"
LOG="$APP_DIR/backups/upgrade.log"
if [[ -z "${CVEHUB_UPGRADE_LOCKED:-}" ]]; then
    exec 9>"$APP_DIR/backups/.upgrade.lock"
    flock -n 9 || die "另一個更新或回復正在執行（看 $LOG）"
fi
logf "===== upgrade.sh $* ====="


confirm() {
    [[ $YES == 1 ]] && return 0
    read -r -p "$1 [y/N] " ans
    [[ "$ans" == "y" || "$ans" == "Y" ]] || die "已取消"
}

base_image() {   # 要用的基礎 image：在安裝目錄直接問 docker compose（和實際建置同一套 .env、override、COMPOSE_FILE 規則）；失敗回傳非零
    local json
    json="$(docker compose config --format json)" || return 1
    printf '%s' "$json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(((d["services"]["cvehub"].get("build") or {}).get("args") or {}).get("BASE_IMAGE", ""), end="")'
}

# 程式指紋：cvehub/（不含 __pycache__）＋requirements.txt＋Dockerfile＋基礎 image 與 Dockerfile 設定
# （proxy、Nexus 位址這類不影響 image 內容的設定不算）。compose 的設定含 .env 的秘密：只經 stdin 傳給 python，不放命令列
read -r -d '' FP_PY <<'PY' || true
import hashlib, json, os, sys
root = sys.argv[1]
h = hashlib.sha256()
def add(path):
    h.update(os.path.relpath(path, root).replace(os.sep, "/").encode() + b"\0")
    with open(path, "rb") as f:
        h.update(f.read())
    h.update(b"\0")
for dirpath, dirnames, filenames in os.walk(os.path.join(root, "cvehub")):
    dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
    for name in sorted(filenames):
        if not name.endswith((".pyc", ".pyo")):
            add(os.path.join(dirpath, name))
for name in ("requirements.txt", "Dockerfile"):
    if os.path.exists(os.path.join(root, name)):
        add(os.path.join(root, name))
try:
    build = json.load(sys.stdin)["services"]["cvehub"].get("build") or {}
    keep = {"base_image": (build.get("args") or {}).get("BASE_IMAGE", ""),
            "dockerfile": build.get("dockerfile", ""), "target": build.get("target", "")}
except Exception:
    keep = {"base_image": "?"}
h.update(json.dumps(keep, sort_keys=True).encode())
print(h.hexdigest(), end="")
PY

code_fp() {
    (cd "$1" && docker compose config --format json 2>/dev/null || true) | python3 -c "$FP_PY" "$1"
}

image_fp() { docker image inspect --format '{{index .Config.Labels "org.cvehub.code-fp"}}' "$1" 2>/dev/null || true; }

# 中途失敗時的處理：換程式到測試完成之間（PHASE=code）自動還原程式；停機之後（PHASE=service）提示回復指令
PHASE=""
ACTIVE_BK=""
OLD_IMG=""
OLD_IMG_ID=""
restore_tag() {   # 失敗時：新版沿用同一個 image 名稱、而且建置真的把它改指到別的 image，才指回更新前的（要在 restore_code 之前呼叫）
    [[ -n "$OLD_IMG" && -n "$OLD_IMG_ID" ]] || return 0
    [[ "$(compose_image || true)" == "$OLD_IMG" ]] || return 0
    [[ "$(docker image inspect --format '{{.Id}}' "$OLD_IMG" 2>/dev/null || true)" != "$OLD_IMG_ID" ]] || return 0
    if docker image inspect "$OLD_IMG_ID" >/dev/null 2>&1; then
        docker tag "$OLD_IMG_ID" "$OLD_IMG"
    elif [[ -f "$ACTIVE_BK/image_ref" ]]; then
        docker tag "$(cat "$ACTIVE_BK/image_ref")" "$OLD_IMG"
    fi
}

say() { printf '%s\n' "$*" 1>&2 2>/dev/null || true; logf "$*"; }   # 終端機／pipe 已斷時也不會讓腳本中止

on_err() {
    # set -E 讓 $(…)／<(…) 子 shell 也會觸發 ERR：只在主 shell 處理，避免背景子 shell 去還原程式
    [[ "$BASHPID" == "$$" ]] || return 0
    trap - ERR
    # 先處理、後印訊息：SSH 斷線或 pipe 已關時，印訊息可能失敗
    if [[ "$PHASE" == backup && -n "$ACTIVE_BK" ]]; then
        # 程式還沒換、容器沒動：只要清掉做到一半的備份（不完整的 code.tgz 不能留給 --rollback 用）
        docker rmi "$(rollback_tag "$ACTIVE_BK")" >/dev/null 2>&1 || true
        [[ "$ACTIVE_BK" == "$APP_DIR"/backups/?* ]] && rm -rf -- "$ACTIVE_BK"
        PHASE=""
        say "❌ 備份程式時失敗或被中斷（第 $1 行），已清掉做到一半的備份，沒有做任何變更"
    elif [[ "$PHASE" == code && -n "$ACTIVE_BK" ]]; then
        PHASE=restoring
        restore_tag || true
        if restore_code "$ACTIVE_BK"; then
            PHASE=""
            say "❌ 更新中途失敗或被中斷（第 $1 行），已還原成更新前的程式；容器沒有動到"
            drop_backup "$ACTIVE_BK"
        else
            say "❌ 更新中途失敗，自動還原也失敗（磁碟滿？）。處理後執行：$(rollback_hint "$ACTIVE_BK")"
        fi
    elif [[ "$PHASE" == restoring && -n "$ACTIVE_BK" ]]; then
        say "❌ 還原程式時被中斷。重新執行：$(rollback_hint "$ACTIVE_BK")"
    elif [[ "$PHASE" == dbbackup && -n "$ACTIVE_BK" ]]; then
        recover_before_start "❌ 備份資料庫時失敗或被中斷（第 $1 行，磁碟滿？）" || true
    elif [[ "$PHASE" == service && -n "$ACTIVE_BK" ]]; then
        say "❌ 啟動新版時失敗或被中斷（第 $1 行）。回復：$(rollback_hint "$ACTIVE_BK")"
    elif [[ "$PHASE" == rollback && -n "$ACTIVE_BK" ]]; then
        say "❌ 回復失敗或被中斷（第 $1 行），服務可能停止中。重新執行：$(rollback_hint "$ACTIVE_BK")"
    fi
}
trap 'on_err $LINENO' ERR
trap 'on_err $LINENO; exit 130' INT TERM HUP QUIT
trap '' PIPE

stop_all() {   # 停掉這個安裝目錄的所有 cvehub 容器（含 docker compose run 的一次性容器）；還有在跑的就回傳非零
    local cids
    if [[ -f "$APP_DIR/docker-compose.yml" ]]; then
        docker compose stop >/dev/null 2>&1 || true    # 用專案名稱找（安裝路徑是 symlink 時 label 可能對不上）
    fi
    cids="$(docker ps -q --filter "label=com.docker.compose.project.working_dir=$APP_DIR" --filter "label=com.docker.compose.service=cvehub")"
    if [[ -n "$cids" ]]; then
        docker stop $cids >/dev/null || true
    fi
    [[ -z "$(docker ps -q --filter "label=com.docker.compose.project.working_dir=$APP_DIR" --filter "label=com.docker.compose.service=cvehub")" ]] \
        && [[ -z "$(service_cid)" || "$(docker inspect --format '{{.State.Running}}' "$(service_cid)" 2>/dev/null)" != "true" ]]
}

drop_backup() {
    docker rmi "$(rollback_tag "$1")" >/dev/null 2>&1 || true
    if [[ "$1" == "$APP_DIR"/backups/?* && -f "$1/code.tgz" && ! -f "$1/db.ok" ]]; then
        rm -rf -- "$1"
    fi
}

recover_before_start() {   # 停機後、啟動新版前出問題：資料庫沒被新版用過 → 指回 tag、還原程式、啟動舊版並確認健康
    PHASE=restoring
    rm -f -- "$ACTIVE_BK"/cvehub.sqlite3.part
    restore_tag || true
    if restore_code "$ACTIVE_BK" && docker compose up -d && healthy_within; then
        PHASE=""
        say "$1；已還原並重新啟動更新前的版本（healthy）"
        drop_backup "$ACTIVE_BK"
        return 0
    fi
    PHASE=""
    say "$1；自動恢復也失敗，服務可能停止中（${HEALTH_STATE:-}）。處理後執行：$(rollback_hint "$ACTIVE_BK")"
    return 1
}

abort_code() {   # 換程式後、測試完成前失敗：指回 tag、還原程式，再結束
    PHASE=restoring
    restore_tag || true
    if restore_code "$ACTIVE_BK"; then
        PHASE=""
        say "❌ $1；已還原成更新前的程式，容器沒有動到"
        drop_backup "$ACTIVE_BK"            # 什麼都沒變（程式已還原、資料庫沒動），這份備份不需要
        exit 1
    fi
    PHASE=""
    die "$1；自動還原程式也失敗（磁碟滿？）。處理後執行：$(rollback_hint "$ACTIVE_BK")"
}

rollback_tag() {   # 保留更新前 image 用的 tag（docker tag 只接受 A-Z a-z 0-9 _ . -）
    echo "cvehub-rollback:$(basename "$1" | tr -c 'A-Za-z0-9_.\n-' '_')"
}

compose_image() {   # 實際會用的 image 名稱（含 docker-compose.override.yml 的覆寫）
    docker compose config --images cvehub 2>/dev/null | head -1
}

version_of() { sed -n 's/^__version__ = "\(.*\)"/\1/p' "$1/cvehub/__init__.py" 2>/dev/null || true; }

remove_code() {
    local it
    for it in "${CODE_ITEMS[@]}"; do
        rm -rf -- "${APP_DIR:?}/$it"
    done
}

restore_code() {   # $1＝備份目錄；.env 與 config/ 不還原（可能在更新後改過）
    remove_code
    tar -xzf "$1/code.tgz" -C "$APP_DIR" --exclude=./.env --exclude=./config
}

service_cid() {   # cvehub 服務容器（不含 docker compose run 的一次性容器）
    local c
    for c in $(docker compose ps -q cvehub 2>/dev/null || true); do
        if [[ "$(docker inspect --format '{{index .Config.Labels "com.docker.compose.oneoff"}}' "$c" 2>/dev/null)" != "True" ]]; then
            printf '%s' "$c"
            return 0
        fi
    done
}

healthy_within() {   # 3 分鐘內 healthy 回傳 0；HEALTH_STATE 是最後看到的狀態
    local cid i
    HEALTH_STATE=""
    cid="$(service_cid)"
    [[ -n "$cid" ]] || { HEALTH_STATE="沒有啟動"; return 1; }
    for i in $(seq 1 60); do
        HEALTH_STATE="$(docker inspect --format '{{.State.Health.Status}}' "$cid" 2>/dev/null || true)"
        [[ "$HEALTH_STATE" == "healthy" ]] && return 0
        sleep 3
    done
    return 1
}

wait_healthy() {
    local st
    healthy_within || true
    st="$HEALTH_STATE"
    [[ "$st" == "healthy" ]] || die "容器 3 分鐘內沒有變成 healthy（目前：${st:-未知}），請看 docker compose logs；要回復請用 --rollback"
    info "容器狀態 healthy；/healthz："
    docker compose exec -T cvehub python - <<'PY' || true
import json, os, ssl, urllib.request
scheme = "https" if os.environ.get("WEB_TLS_CERT") else "http"
url = "%s://127.0.0.1:%s/healthz" % (scheme, os.environ.get("WEB_PORT") or "8080")
ctx = ssl._create_unverified_context()          # 只連容器自己
try:
    r = urllib.request.urlopen(url, context=ctx, timeout=10)
    print(r.read().decode())
except urllib.error.HTTPError as e:
    print(e.read().decode())
PY
}

KEEP_BACKUPS="${CVEHUB_KEEP_BACKUPS:-5}"

prune_backups() {   # 只保留最近 KEEP_BACKUPS 份（每份含資料庫，約數百 MB）
    local old
    ls -1d "$APP_DIR"/backups/*/ 2>/dev/null | sort | head -n -"$KEEP_BACKUPS" | while read -r old; do
        if [[ "$old" == "$APP_DIR"/backups/?*/ ]]; then
            rm -rf -- "$old"
            docker rmi "$(rollback_tag "$old")" >/dev/null 2>&1 || true
            out "   已刪除舊備份：$(basename "$old")"
        fi
    done || true
}

upgrade() {
    local zip="$1" tmp src old new ts bk
    [[ -f "$zip" ]] || die "找不到檔案：$zip"
    tmp="$(mktemp -d)"
    TMP_DIRS+=("$tmp")
    python3 -m zipfile -e "$zip" "$tmp/x" || die "無法解開 $zip"
    src="$(find "$tmp/x" -maxdepth 2 -name docker-compose.yml -printf '%h\n' | head -1)"
    [[ -n "$src" && -f "$src/cvehub/__init__.py" ]] || die "$zip 不是 cvehub 的程式包"
    # 新版的更新腳本不一樣：改用新版的（更新流程以新版為準），舊的這支到此為止
    if [[ -z "${CVEHUB_UPGRADE_HANDOVER:-}" && -f "$src/scripts/upgrade.sh" ]] && ! cmp -s "$src/scripts/upgrade.sh" "$CVEHUB_UPGRADE_COPY"; then
        info "改用新版的更新腳本"
        local next
        next="$(mktemp)"
        cp -- "$src/scripts/upgrade.sh" "$next"
        rm -rf -- "${tmp:?}"
        rm -f -- "${CVEHUB_UPGRADE_COPY:?}"
        if [[ $YES == 1 ]]; then
            CVEHUB_UPGRADE_LOCKED=1 CVEHUB_UPGRADE_HANDOVER=1 CVEHUB_UPGRADE_COPY="$next" CVEHUB_DIR="$APP_DIR" exec bash "$next" "$zip" -y
        fi
        CVEHUB_UPGRADE_LOCKED=1 CVEHUB_UPGRADE_HANDOVER=1 CVEHUB_UPGRADE_COPY="$next" CVEHUB_DIR="$APP_DIR" exec bash "$next" "$zip"
    fi
    old="$(version_of "$APP_DIR")"
    new="$(version_of "$src")"
    out "安裝目錄：$APP_DIR"
    out "目前版本：$old → 新版本：$new"
    if [[ -f "$src/CHANGELOG.md" ]]; then
        out "------ 更新說明（CHANGELOG.md 開頭）------"
        out "$(head -n 30 "$src/CHANGELOG.md")"
        out "-----------------------------------------"
    fi
    confirm "開始更新？（約 5–10 分鐘；中間會停機約 1 分鐘）"

    ts="$(date +%Y%m%d-%H%M%S)"
    bk="$APP_DIR/backups/$ts-$old"
    ACTIVE_BK="$bk"
    PHASE=backup
    mkdir -p "$bk"
    chmod 700 "$APP_DIR/backups" "$bk"
    info "1/6 備份程式與設定 → $bk/code.tgz"
    cp -- "$CVEHUB_UPGRADE_COPY" "$bk/upgrade.sh"     # 回復用：安裝目錄的 scripts/ 在還原途中可能不存在
    # 先寫 .part，完成才改名：中斷時不會留下看起來完整、其實被截斷的 code.tgz
    tar -czf "$bk/code.tgz.part" --exclude=./data --exclude=./backups -C "$APP_DIR" .
    mv -- "$bk/code.tgz.part" "$bk/code.tgz"
    # 目前容器用的 image 另外加一個 tag 保留下來：回復時用它，不必重建，同版本號重新升級也不會拿錯 image
    # （containerd 的 image store 會把沒有 tag 的舊 image 立刻清掉，只記 ID 不夠）
    # 以「正在跑的容器」實際使用的 image 為準（tag 可能已被失敗的建置改指到別的 image）
    # 只認「正在跑的服務容器」（不含 docker compose run 的一次性容器）；沒在跑就不保留，回復時重建
    local cur_img="" keep_ref c
    c="$(service_cid)"
    [[ -n "$c" ]] && cur_img="$(docker inspect --format '{{.Image}}' "$c" 2>/dev/null || true)"
    keep_ref="$(rollback_tag "$bk")"
    if [[ -n "$cur_img" ]] && docker image inspect "$cur_img" >/dev/null 2>&1 && docker tag "$cur_img" "$keep_ref"; then
        echo "$keep_ref" > "$bk/image_ref"
    else
        out "ℹ️  cvehub 容器沒有在跑，不保留目前的 image（回復時會重建）"
    fi
    OLD_IMG="$(compose_image || true)"          # 換程式前的 image 名稱與 ID（同版本號建置失敗時指回去）
    OLD_IMG_ID=""
    if [[ -n "$OLD_IMG" ]]; then
        OLD_IMG_ID="$(docker image inspect --format '{{.Id}}' "$OLD_IMG" 2>/dev/null || true)"
    fi
    PHASE=code

    info "2/6 替換程式檔（.env、data/、config/ 不動）"
    remove_code
    local it
    for it in "${CODE_ITEMS[@]}"; do
        if [[ -e "$src/$it" ]]; then
            cp -a "$src/$it" "$APP_DIR/$it"
        fi
    done

    local missing
    missing="$(comm -23 <(grep -oE '^[A-Z_][A-Z0-9_]*=' "$APP_DIR/.env.example" 2>/dev/null | sort -u || true) \
                        <(grep -oE '^[A-Z_][A-Z0-9_]*=' "$APP_DIR/.env" | sort -u || true) | tr -d '=' | tr '\n' ' ')"
    if [[ -n "$missing" ]]; then
        out "ℹ️  .env 沒有的新設定（目前使用預設值，說明見 .env.example）：$missing"
    fi

    # 主機不能 docker pull：基礎 image 必須已經 docker load 進來；用和建置相同的 compose 設定判斷，拿不到就還原程式
    local base
    base="$(base_image)" || abort_code "無法解析新版的 docker compose 設定（訊息如上）"
    base="${base:-python:3.12-slim}"
    if ! docker image inspect "$base" >/dev/null 2>&1; then
        info "本機沒有基礎 image「$base」，嘗試 docker pull（主機不能連外時會失敗，請改用 docker load）"
        docker pull "$base" >/dev/null 2>&1 \
            || abort_code "拿不到基礎 image「$base」（.env 的 BASE_IMAGE）。請先載入：sudo docker load -i <檔案>（做法見 README 步驟 3）"
    fi

    info "3/6 建立新版 image、跑自動化測試（舊版容器仍在運作）"
    if ! CODE_FP="$(code_fp "$APP_DIR")" docker compose build || ! docker compose run --rm --no-deps cvehub python -m unittest discover -s tests -t . </dev/null; then
        abort_code "建立 image 或測試失敗"
    fi

    trap '' HUP                         # 開始停機後 SSH 斷線不中止：讓腳本把新版啟動完成（先忽略、再進入停機階段）
    info "4/6 停止容器、備份資料庫"
    PHASE=dbbackup
    if ! stop_all; then
        recover_before_start "❌ cvehub 容器停不下來，無法安全備份資料庫" || true
        exit 1
    fi
    # 用 SQLite 的線上備份產生「單一個完整檔案」（含 WAL 內容）：先寫 .part，完成才改名並寫 db.ok
    if [[ -f "$APP_DIR/data/cvehub.sqlite3" ]]; then
        python3 -c 'import sqlite3, sys
s = sqlite3.connect(sys.argv[1]); d = sqlite3.connect(sys.argv[2]); s.backup(d); d.close(); s.close()' \
            "$APP_DIR/data/cvehub.sqlite3" "$bk/cvehub.sqlite3.part"
        mv -- "$bk/cvehub.sqlite3.part" "$bk/cvehub.sqlite3"
        : > "$bk/db.ok"
    fi
    PHASE=service

    info "5/6 啟動 $new（第一次啟動可能會自動升級資料庫或重新匯入資料，請稍候）"
    docker compose up -d
    info "6/6 健康檢查"
    wait_healthy
    PHASE=""
    prune_backups
    out "✅ 已更新到 $new。"
    out "   有問題要回復：$(rollback_hint "$bk")"
    out "   （回復會把資料庫還原成更新前的狀態；更新後的同步結果會重新產生）"
}

rollback() {
    local bk="$1" ver
    [[ "$bk" == /* ]] || bk="$APP_DIR/$bk"
    bk="$(cd "$bk" 2>/dev/null && pwd)" || die "找不到備份目錄：$1"
    [[ "$bk" == "$APP_DIR"/backups/* && -f "$bk/code.tgz" ]] || die "$bk 不是 upgrade.sh 產生的備份"
    ver="$(tar -xzOf "$bk/code.tgz" ./cvehub/__init__.py | sed -n 's/^__version__ = "\(.*\)"/\1/p')"
    out "目前版本：$(version_of "$APP_DIR") → 回復成：$ver（備份 $bk）"
    # 資料庫備份：有 db.ok 才確定完整；0.6.x／0.7.0 腳本的備份沒有 db.ok，改用 SQLite 完整性檢查判斷（主檔被截斷會失敗）
    local db_ok=0
    if [[ -f "$bk/cvehub.sqlite3" ]] && { [[ -f "$bk/db.ok" ]] || ! compgen -G "$bk/*.part" >/dev/null; }; then
        if python3 -c 'import sqlite3, sys
c = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro&immutable=1", uri=True)
sys.exit(0 if c.execute("pragma quick_check").fetchone()[0] == "ok" else 1)' "$bk/cvehub.sqlite3" 2>/dev/null; then
            db_ok=1
            out "資料庫也會還原成更新前的狀態"
            if [[ ! -f "$bk/db.ok" ]]; then
                out "ℹ️  這是舊版腳本的備份：主檔通過完整性檢查，但無法確認當時的 WAL 是否複製完整"
            fi
        else
            out "⚠️  備份裡的資料庫沒有通過完整性檢查（可能複製到一半），不還原資料庫"
        fi
    else
        out "ℹ️  這份備份沒有完整的資料庫備份（更新在備份資料庫時就停了），不還原資料庫。"
        out "    如果之後曾手動啟動過新版，資料庫可能已被新版改過，請先確認再回復"
    fi
    confirm "確定回復？"
    rm -f -- "$bk"/*.part                # 不完整的副本：判斷已做完，刪掉騰出空間
    ACTIVE_BK="$bk"
    PHASE=rollback
    trap '' HUP                         # 回復期間 SSH 斷線不中止
    # 停容器：用 compose 的 label 找出這個目錄的所有容器（compose 檔不在或壞掉也找得到）；確定都停了才往下
    stop_all || die "cvehub 容器停不下來，無法安全還原資料庫；請先手動停止再執行一次"
    restore_code "$bk"
    if [[ $db_ok == 1 ]]; then
        rm -f -- "$APP_DIR"/data/cvehub.sqlite3-wal "$APP_DIR"/data/cvehub.sqlite3-shm
        local f
        for f in "$bk"/cvehub.sqlite3 "$bk"/cvehub.sqlite3-wal "$bk"/cvehub.sqlite3-shm; do   # 舊版腳本的備份可能有 WAL
            if [[ -f "$f" ]]; then
                cp -- "$f" "$APP_DIR/data/$(basename "$f")"
                chown --reference="$APP_DIR/data" "$APP_DIR/data/$(basename "$f")"   # 容器以 data/ 的擁有者（UID 10001）寫入
            fi
        done
    fi
    # 更新前容器用的 image 通常還在：用它（不必重建；回復時 Nexus 或基礎 image 不一定拿得到）
    local img ref="" fp_img="" fp_code
    img="$(compose_image || true)"
    if [[ -f "$bk/image_ref" ]]; then
        ref="$(cat "$bk/image_ref")"
    fi
    if [[ -n "$img" && -n "$ref" ]] && docker image inspect "$ref" >/dev/null 2>&1; then
        docker tag "$ref" "$img"
        info "使用更新前保留的 image $ref（不重建）"
    elif fp_code="$(code_fp "$APP_DIR")" && [[ -n "$img" ]] && fp_img="$(image_fp "$img")" && [[ -n "$fp_img" && "$fp_img" == "$fp_code" ]]; then
        # 程式指紋相同（兩邊都有、而且一樣）：這個 image 就是還原後這份程式建的，可以沿用
        info "使用本機既有的 image $img（${ref:+保留的 $ref 已不在；}程式指紋相符，不重建）"
    elif ! CODE_FP="$fp_code" docker compose build; then
        die "找不到可用的舊版 image（${img:-未知}），重建也失敗（基礎 image 或 Nexus 拿不到）；程式與資料庫已還原，但服務目前停止。處理後再執行一次 --rollback"
    fi
    docker compose up -d
    wait_healthy
    PHASE=""
    out "✅ 已回復成 $ver。"
}

case "${1:-}" in
    --rollback) [[ -n "${2:-}" ]] || die "用法：upgrade.sh --rollback backups/<時間-版本>"; rollback "$2" ;;
    ""|-h|--help) sed -n '2,12p' "$0" ;;    # $0 是暫存的複本，內容相同
    *) upgrade "$1" ;;
esac
