#!/usr/bin/env bash
set -eo pipefail

# Resolve repository root directory
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

# 1. Activate virtual environment (.venv)
if [ -f "$REPO_DIR/.venv/bin/activate" ]; then
    source "$REPO_DIR/.venv/bin/activate"
elif [ -f "$REPO_DIR/venv/bin/activate" ]; then
    source "$REPO_DIR/venv/bin/activate"
fi

# 2. Source environment configuration (.env)
if [ -f "$REPO_DIR/.env" ]; then
    set -a
    source "$REPO_DIR/.env"
    set +a
fi

REFRESH_SCREENS=false
PASSTHROUGH_ARGS=()

# Parse wrapper-specific options
while [ $# -gt 0 ]; do
    case "$1" in
        --refresh-screens)
            REFRESH_SCREENS=true
            shift
            ;;
        *)
            PASSTHROUGH_ARGS+=("$1")
            shift
            ;;
    esac
done

# 3. Execute mock data generator
PYTHONPATH="${REPO_DIR}/app" python3 "${REPO_DIR}/scripts/generate_mock_data.py" "${PASSTHROUGH_ARGS[@]}"

# 4. Optional: Refresh screen captures
if [ "$REFRESH_SCREENS" = true ]; then
    echo ""
    echo "--> Refreshing documentation screenshots (capture_ui_screens.py)..."
    python3 "${REPO_DIR}/scripts/capture_ui_screens.py"
    echo "--> Screenshots refreshed successfully in Documentation/screenshots/"
fi
