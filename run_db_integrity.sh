#!/bin/sh
set -e

# Resolve repository or script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 1. Activate virtual environment if present (.venv or venv) - host dev environment
if [ -f "$SCRIPT_DIR/.venv/bin/activate" ]; then
    # shellcheck source=/dev/null
    . "$SCRIPT_DIR/.venv/bin/activate"
elif [ -f "$SCRIPT_DIR/venv/bin/activate" ]; then
    # shellcheck source=/dev/null
    . "$SCRIPT_DIR/venv/bin/activate"
fi

# 2. Source environment configuration if present (.env) - host dev environment
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    # shellcheck source=/dev/null
    . "$SCRIPT_DIR/.env"
    set +a
fi

# 3. Execute database integrity tool (handles host repository layout vs container /app layout)
if [ -d "$SCRIPT_DIR/app" ]; then
    PYTHONPATH="${SCRIPT_DIR}/app" python3 -m db.integrity "$@"
else
    python3 -m db.integrity "$@"
fi
