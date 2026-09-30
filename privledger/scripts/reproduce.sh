#!/usr/bin/env sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODE=${1:-smoke}
if [ "$#" -gt 0 ]; then shift; fi
exec "${PYTHON_BINARY:-python3}" "$SCRIPT_DIR/reproduce.py" --mode "$MODE" "$@"
