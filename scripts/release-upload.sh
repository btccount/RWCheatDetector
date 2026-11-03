#!/usr/bin/env bash
# Загрузка файла в релиз GitHub.
#
# Без аргументов: берёт последний релиз репозитория и открывает диалог выбора файла.
# Примеры:
#   ./scripts/release-upload.sh
#   ./scripts/release-upload.sh v1.0.0 ./dist/package.tar.gz
#   ./scripts/release-upload.sh --tag v1.0.0 --file ./report.json --clobber
#   ./scripts/release-upload.sh --dry-run --file README.md

set -euo pipefail

REPO_DEFAULT="btccount/RWCheatDetector"

usage() {
    cat <<'EOF'
Использование: release-upload.sh [тег] [файл] [опции]

Опции:
  -t, --tag ТЕГ       тег релиза (по умолчанию — последний релиз)
  -f, --file ФАЙЛ     файл для загрузки (без него откроется диалог выбора)
  -r, --repo РЕПО     owner/repo (по умолчанию — текущий репозиторий)
  -c, --clobber       заменить файл с тем же именем
  -n, --dry-run       показать команду, ничего не загружать
  -h, --help          эта справка

Примеры:
  release-upload.sh
  release-upload.sh v1.0.0 ./dist/package.tar.gz
  release-upload.sh --file ./report.json --clobber
EOF
}

TAG=""
FILE=""
REPO=""
DRY_RUN=0
CLOBBER=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--tag)     TAG="${2:?не указан тег}"; shift 2 ;;
        -f|--file)    FILE="${2:?не указан файл}"; shift 2 ;;
        -r|--repo)    REPO="${2:?не указан репозиторий}"; shift 2 ;;
        -c|--clobber) CLOBBER=1; shift ;;
        -n|--dry-run) DRY_RUN=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        --)           shift; break ;;
        -*)           echo "Неизвестная опция: $1" >&2; usage >&2; exit 2 ;;
        *)
            if [[ -z "$TAG" ]]; then
                TAG="$1"
            elif [[ -z "$FILE" ]]; then
                FILE="$1"
            else
                echo "Лишний аргумент: $1" >&2
                usage >&2
                exit 2
            fi
            shift
            ;;
    esac
done

command -v gh >/dev/null 2>&1 || { echo "Ошибка: gh не установлен (brew install gh)." >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Ошибка: gh не авторизован (gh auth login)." >&2; exit 1; }

if [[ -z "$REPO" ]]; then
    if REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null)"; then
        :
    else
        REPO="$REPO_DEFAULT"
    fi
fi

if [[ -z "$TAG" ]]; then
    TAG="$(gh release list --repo "$REPO" --limit 1 --json tagName -q '.[0].tagName' 2>/dev/null || true)"
fi

if [[ -z "$TAG" ]]; then
    echo "В репозитории $REPO пока нет релизов."
    read -r -p "Тег нового релиза [v1.0.0]: " TAG
    TAG="${TAG:-v1.0.0}"
    CREATE_RELEASE=1
else
    CREATE_RELEASE=0
fi

pick_file() {
    local picked=""
    case "$(uname -s)" in
        Darwin)
            picked="$(osascript -e 'POSIX path of (choose file with prompt "Выберите файл для загрузки в релиз")' 2>/dev/null || true)"
            ;;
        *)
            if command -v zenity >/dev/null 2>&1; then
                picked="$(zenity --file-selection --title="Выберите файл для загрузки в релиз" 2>/dev/null || true)"
            elif command -v kdialog >/dev/null 2>&1; then
                picked="$(kdialog --getopenfilename "$PWD" 2>/dev/null || true)"
            fi
            ;;
    esac
    printf '%s' "$picked"
}

if [[ -z "$FILE" ]]; then
    FILE="$(pick_file)"
    if [[ -z "$FILE" ]]; then
        read -r -p "Путь к файлу: " FILE
    fi
fi

[[ -n "$FILE" ]] || { echo "Файл не выбран." >&2; exit 1; }
[[ -f "$FILE" ]] || { echo "Ошибка: файл не найден: $FILE" >&2; exit 1; }

NAME="$(basename "$FILE")"
SIZE="$(wc -c < "$FILE" | tr -d ' ')"
echo "Репозиторий: $REPO"
echo "Релиз:       $TAG"
echo "Файл:        $NAME ($SIZE байт)"

UPLOAD=(gh release upload "$TAG" "$FILE" --repo "$REPO")
[[ "$CLOBBER" -eq 1 ]] && UPLOAD+=(--clobber)

if [[ "$CREATE_RELEASE" -eq 1 ]]; then
    CREATE=(gh release create "$TAG" --repo "$REPO" --title "$TAG" --generate-notes)
else
    CREATE=()
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
    [[ ${#CREATE[@]} -gt 0 ]] && printf '%q ' "${CREATE[@]}" && echo
    printf '%q ' "${UPLOAD[@]}"
    echo
    exit 0
fi

if [[ ${#CREATE[@]} -gt 0 ]]; then
    "${CREATE[@]}"
fi

"${UPLOAD[@]}"

echo "Готово: https://github.com/$REPO/releases/tag/$TAG"
if command -v shasum >/dev/null 2>&1; then
    echo "SHA-256: $(shasum -a 256 "$FILE" | awk '{print $1}')"
fi