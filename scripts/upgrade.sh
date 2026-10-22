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
set -euo pipefail

CODE_ITEMS=(cvehub tests scripts django-kernel-view mock-kernel-api Dockerfile docker-compose.yml requirements.txt
            README.md MAINTENANCE.md CHANGELOG.md .env.example .dockerignore .gitignore)

die() { echo "❌ $*" >&2; exit 1; }
info() { echo "▶ $*"; }

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
[[ -f "$APP_DIR/docker-compose.yml" && -f "$APP_DIR/cvehub/__init__.py" ]] || die "$APP_DIR 不是 cvehub 安裝目錄"
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


confirm() {
    [[ $YES == 1 ]] && return 0
    read -r -p "$1 [y/N] " ans
    [[ "$ans" == "y" || "$ans" == "Y" ]] || die "已取消"
}

version_of() { sed -n 's/^__version__ = "\(.*\)"/\1/p' "$1/cvehub/__init__.py"; }

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

wait_healthy() {
    local cid i st=""
    cid="$(docker compose ps -q cvehub)"
    [[ -n "$cid" ]] || die "容器沒有啟動，請看 docker compose logs"
    for i in $(seq 1 60); do
        st="$(docker inspect --format '{{.State.Health.Status}}' "$cid" 2>/dev/null || true)"
        [[ "$st" == "healthy" ]] && break
        sleep 3
    done
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
        [[ "$old" == "$APP_DIR"/backups/?*/ ]] && rm -rf -- "$old" && echo "   已刪除舊備份：$(basename "$old")"
    done
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
            CVEHUB_UPGRADE_HANDOVER=1 CVEHUB_UPGRADE_COPY="$next" CVEHUB_DIR="$APP_DIR" exec bash "$next" "$zip" -y
        fi
        CVEHUB_UPGRADE_HANDOVER=1 CVEHUB_UPGRADE_COPY="$next" CVEHUB_DIR="$APP_DIR" exec bash "$next" "$zip"
    fi
    old="$(version_of "$APP_DIR")"
    new="$(version_of "$src")"
    echo "安裝目錄：$APP_DIR"
    echo "目前版本：$old → 新版本：$new"
    [[ -f "$src/CHANGELOG.md" ]] && { echo "------ 更新說明（CHANGELOG.md 開頭）------"; head -n 30 "$src/CHANGELOG.md"; echo "-----------------------------------------"; }
    # 主機不能 docker pull：基礎 image 必須已經 docker load 進來（在動任何東西之前先檢查）
    local base
    base="$(sed -n 's/^BASE_IMAGE=//p' "$APP_DIR/.env" | tail -1)"
    base="${base:-python:3.12-slim}"
    if ! docker image inspect "$base" >/dev/null 2>&1; then
        info "本機沒有基礎 image「$base」，嘗試 docker pull（主機不能連外時會失敗，請改用 docker load）"
        docker pull "$base" >/dev/null 2>&1 \
            || die "拿不到基礎 image「$base」（.env 的 BASE_IMAGE）。請先載入：sudo docker load -i <檔案>（做法見 README 步驟 3）；沒有改任何東西"
    fi
    confirm "開始更新？（約 5–10 分鐘；中間會停機約 1 分鐘）"

    ts="$(date +%Y%m%d-%H%M%S)"
    bk="$APP_DIR/backups/$ts-$old"
    mkdir -p "$bk"
    chmod 700 "$APP_DIR/backups" "$bk"
    info "1/6 備份程式與設定 → $bk/code.tgz"
    tar -czf "$bk/code.tgz" --exclude=./data --exclude=./backups -C "$APP_DIR" .

    info "2/6 替換程式檔（.env、data/、config/ 不動）"
    remove_code
    local it
    for it in "${CODE_ITEMS[@]}"; do
        [[ -e "$src/$it" ]] && cp -a "$src/$it" "$APP_DIR/$it"
    done

    local missing
    missing="$(comm -23 <(grep -oE '^[A-Z_][A-Z0-9_]*=' "$APP_DIR/.env.example" | sort -u) \
                        <(grep -oE '^[A-Z_][A-Z0-9_]*=' "$APP_DIR/.env" | sort -u) | tr -d '=' | tr '\n' ' ')"
    [[ -n "$missing" ]] && echo "ℹ️  .env 沒有的新設定（目前使用預設值，說明見 .env.example）：$missing"

    info "3/6 建立新版 image、跑自動化測試（舊版容器仍在運作）"
    if ! docker compose build || ! docker compose run --rm --no-deps cvehub python -m unittest discover -s tests -t . </dev/null; then
        restore_code "$bk"
        die "建立 image 或測試失敗，已還原成 $old 的程式；容器沒有動到"
    fi

    info "4/6 停止容器、備份資料庫"
    docker compose stop
    if compgen -G "$APP_DIR/data/cvehub.sqlite3*" >/dev/null; then
        cp -a "$APP_DIR"/data/cvehub.sqlite3* "$bk/"
    fi

    info "5/6 啟動 $new（第一次啟動可能會自動升級資料庫或重新匯入資料，請稍候）"
    docker compose up -d
    info "6/6 健康檢查"
    wait_healthy
    prune_backups
    echo "✅ 已更新到 $new。"
    echo "   有問題要回復：sudo bash $APP_DIR/scripts/upgrade.sh --rollback backups/$(basename "$bk")"
    echo "   （回復會把資料庫還原成更新前的狀態；更新後的同步結果會重新產生）"
}

rollback() {
    local bk="$1" ver
    [[ "$bk" == /* ]] || bk="$APP_DIR/$bk"
    bk="$(cd "$bk" 2>/dev/null && pwd)" || die "找不到備份目錄：$1"
    [[ "$bk" == "$APP_DIR"/backups/* && -f "$bk/code.tgz" ]] || die "$bk 不是 upgrade.sh 產生的備份"
    ver="$(tar -xzOf "$bk/code.tgz" ./cvehub/__init__.py | sed -n 's/^__version__ = "\(.*\)"/\1/p')"
    echo "目前版本：$(version_of "$APP_DIR") → 回復成：$ver（備份 $bk）"
    [[ -f "$bk/cvehub.sqlite3" ]] && echo "資料庫也會還原成更新前的狀態"
    confirm "確定回復？"
    docker compose stop
    restore_code "$bk"
    if [[ -f "$bk/cvehub.sqlite3" ]]; then
        rm -f -- "$APP_DIR"/data/cvehub.sqlite3-wal "$APP_DIR"/data/cvehub.sqlite3-shm
        cp -a "$bk"/cvehub.sqlite3* "$APP_DIR/data/"
    fi
    docker compose build
    docker compose up -d
    wait_healthy
    echo "✅ 已回復成 $ver。"
}

case "${1:-}" in
    --rollback) [[ -n "${2:-}" ]] || die "用法：upgrade.sh --rollback backups/<時間-版本>"; rollback "$2" ;;
    ""|-h|--help) sed -n '2,12p' "$0" ;;    # $0 是暫存的複本，內容相同
    *) upgrade "$1" ;;
esac
