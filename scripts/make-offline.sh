#!/usr/bin/env bash
# 產生離線安裝包：給完全沒有網路的主機（沒有 Python 套件來源、也不能 docker pull），只能傳檔案進去時用
#
#   在「能上網（或連得到 Nexus）、有 Docker」的機器上，從解開的程式目錄執行：
#     sudo bash scripts/make-offline.sh [輸出目錄，預設目前目錄]
#   產生 cvehub-<版本>-offline.tar.gz（約 50 MB），內容：
#     cvehub-<版本>/          程式（wheels/ 裡放好 Python 套件）
#     base-image.tar.gz       基礎 image（docker save）
#     base-image.txt          基礎 image 的名稱與架構（正式機要相同架構，例：都是 amd64）
#     SHA256SUMS              檢查檔案有沒有傳壞：sha256sum -c SHA256SUMS
#   正式機：tar -xzf cvehub-<版本>-offline.tar.gz && sudo bash cvehub-<版本>-offline/cvehub-<版本>/install.sh
#   （全新安裝或更新都一樣；基礎 image 自動 docker load，套件從 wheels/ 安裝，全程不連網路）
#
#   環境變數：
#     BASE_IMAGE     基礎 image（預設 python:3.12-slim；正式機 .env 的 BASE_IMAGE 要和它相同）
#     PIP_INDEX_URL  下載套件的來源（預設 https://pypi.org/simple；可填內部 Nexus）
#     PIP_TRUSTED_HOST  套件來源是自簽憑證時填它的主機名稱
set -Eeuo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mkdir -p "${1:-.}" && cd "${1:-.}" && pwd)"
BASE_IMAGE="${BASE_IMAGE:-python:3.12-slim}"
PIP_INDEX_URL="${PIP_INDEX_URL:-https://pypi.org/simple}"
PIP_TRUSTED_HOST="${PIP_TRUSTED_HOST:-}"

say()  { printf '%s\n' "$*"; }
step() { printf '\n▶ %s\n' "$*"; }
die()  { printf '❌ %s\n' "$*" >&2; exit 1; }

[[ -f "$SRC/docker-compose.yml" && -f "$SRC/cvehub/__init__.py" ]] || die "$SRC 不是 cvehub 的程式目錄"
[[ "$BASE_IMAGE" != *@* ]] || die "BASE_IMAGE 要用 tag（例：python:3.12-slim），不能用 digest：docker save 之後不會保留 digest"
command -v docker >/dev/null || die "需要 Docker"
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$SRC/cvehub/__init__.py")"
[[ -n "$VERSION" ]] || die "讀不到版本"
NAME="cvehub-$VERSION-offline"
WORK="$OUT/$NAME"
PKG="$WORK/cvehub-$VERSION"
[[ ! -e "$WORK" && ! -e "$OUT/$NAME.tar.gz" ]] || die "$WORK 或 $OUT/$NAME.tar.gz 已經存在，請先移走"

cleanup() {
    [[ -n "${WORK:-}" && -d "$WORK" ]] && rm -rf -- "${WORK:?}"
    rm -f -- "$OUT/$NAME.tar.gz.part"
}
trap cleanup EXIT

step "1/5 複製程式 → $PKG"
mkdir -p "$PKG"
# 只帶程式檔：和更新時替換的是同一份清單（scripts/upgrade.sh 的 CODE_ITEMS），使用者的設定與資料、其他檔案都不帶
eval "$(sed -n '/^CODE_ITEMS=(/,/)/p' "$SRC/scripts/upgrade.sh")"
[[ ${#CODE_ITEMS[@]} -gt 5 ]] || die "讀不到 scripts/upgrade.sh 的 CODE_ITEMS"
for it in "${CODE_ITEMS[@]}"; do
    [[ "$it" == wheels ]] && continue
    if [[ -e "$SRC/$it" ]]; then
        tar -C "$SRC" --exclude=__pycache__ --exclude='*.pyc' -cf - "./$it" | tar -C "$PKG" -xf -
    fi
done
mkdir -p "$PKG/wheels"
[[ -f "$SRC/wheels/README.md" ]] && cp -- "$SRC/wheels/README.md" "$PKG/wheels/"

step "2/5 基礎 image：$BASE_IMAGE（先 docker pull 取得最新的安全更新）"
if ! docker pull -q "$BASE_IMAGE" >/dev/null; then
    docker image inspect "$BASE_IMAGE" >/dev/null 2>&1 || die "拿不到 $BASE_IMAGE"
    say "   ⚠️ docker pull 失敗，使用本機現有的 $BASE_IMAGE（可能不是最新的）"
fi
ARCH="$(docker image inspect --format '{{.Architecture}}' "$BASE_IMAGE")"

step "3/5 下載 Python 套件（用基礎 image 裡的 Python，版本與平台才會和正式機建置時相同）"
docker run --rm -e PIP_ROOT_USER_ACTION=ignore -v "$PKG/requirements.txt:/req.txt:ro" -v "$PKG/wheels:/w" "$BASE_IMAGE" \
    pip download --disable-pip-version-check --only-binary=:all: --dest /w --index-url "$PIP_INDEX_URL" \
    ${PIP_TRUSTED_HOST:+--trusted-host "$PIP_TRUSTED_HOST"} -r /req.txt \
    || die "下載套件失敗（檢查 PIP_INDEX_URL）"
# 確認不連網路也裝得起來（和正式機建置時的指令相同）
docker run --rm --network none -e PIP_ROOT_USER_ACTION=ignore -v "$PKG/requirements.txt:/req.txt:ro" -v "$PKG/wheels:/w:ro" "$BASE_IMAGE" \
    pip install --disable-pip-version-check --no-index --find-links /w -r /req.txt >/dev/null \
    || die "套件不完整：不連網路時裝不起來"
chown -R --reference="$SRC" "$PKG/wheels"
say "   $(find "$PKG/wheels" -name '*.whl' | wc -l) 個套件，$(du -sh "$PKG/wheels" | cut -f1)"

step "4/5 匯出基礎 image"
docker save "$BASE_IMAGE" | gzip > "$WORK/base-image.tar.gz"
printf '%s\narch=%s\n' "$BASE_IMAGE" "$ARCH" > "$WORK/base-image.txt"
say "   $(du -sh "$WORK/base-image.tar.gz" | cut -f1)"

step "5/5 打包"
sums="$(cd "$WORK" && find . -type f -print0 | sort -z | xargs -0 sha256sum)"
printf '%s\n' "$sums" > "$WORK/SHA256SUMS"
tar -C "$OUT" -czf "$OUT/$NAME.tar.gz.part" "$NAME"
mv -- "$OUT/$NAME.tar.gz.part" "$OUT/$NAME.tar.gz"
say "
✅ $OUT/$NAME.tar.gz（$(du -sh "$OUT/$NAME.tar.gz" | cut -f1)）
   正式機：
     tar -xzf $NAME.tar.gz
     (cd $NAME && sha256sum -c --quiet SHA256SUMS)
     sudo bash $NAME/cvehub-$VERSION/install.sh"
