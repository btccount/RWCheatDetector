#!/usr/bin/env bash
# Двойной клик в Finder: открывает выбор файла и загружает его в релиз.
cd "$(dirname "$0")/.." || exit 1
exec ./scripts/release-upload.sh "$@"