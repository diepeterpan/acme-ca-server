#!/usr/bin/env bash

# Resolve repository root directory
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

echo "=========================================="
echo " ACME CA Server - Code Quality & Lint Checks"
echo "=========================================="

# 1. Activate virtual environment if available (.venv or venv)
if [ -f "$REPO_DIR/.venv/bin/activate" ]; then
    echo "--> Activating virtualenv (.venv)..."
    # shellcheck source=/dev/null
    source "$REPO_DIR/.venv/bin/activate"
elif [ -f "$REPO_DIR/venv/bin/activate" ]; then
    echo "--> Activating virtualenv (venv)..."
    # shellcheck source=/dev/null
    source "$REPO_DIR/venv/bin/activate"
else
    echo "--> Warning: No virtualenv (.venv or venv) found. Using current Python environment."
fi

# 2. Install / ensure required lint tools are available
echo "--> Installing / verifying lint tools (ruff, pylint, flake8 + plugins, mypy)..."
pip install -q ruff pylint flake8 flake8-bandit flake8-bugbear flake8-builtins flake8-comprehensions flake8-deprecated flake8-isort flake8-print flake8-quotes flake8-todo mypy

# 3. Ruff Check
echo ""
echo "--> [1/5] Running ruff check on 'app'..."
RUFF_TMP=$(mktemp)
ruff check app > "$RUFF_TMP" 2>&1
RUFF_EXIT=$?
cat "$RUFF_TMP"

if [ $RUFF_EXIT -ne 0 ]; then
    if grep -q "fixable with" "$RUFF_TMP"; then
        echo ""
        USER_REPLY=""
        if [ -t 0 ]; then
            read -r -p "Fixable errors found by ruff. Would you like to run 'ruff check --fix app'? [y/N]: " USER_REPLY
        elif [ -c /dev/tty ] && [ ! -p /dev/stdin ]; then
            read -r -p "Fixable errors found by ruff. Would you like to run 'ruff check --fix app'? [y/N]: " USER_REPLY </dev/tty
        elif [ -p /dev/stdin ]; then
            read -r USER_REPLY || USER_REPLY="N"
        fi

        if [[ "$USER_REPLY" =~ ^[Yy]$ ]]; then
            echo "--> Applying fixes with 'ruff check --fix app'..."
            ruff check --fix app
            echo "--> Re-checking with ruff..."
            ruff check app > "$RUFF_TMP" 2>&1
            RUFF_EXIT=$?
            cat "$RUFF_TMP"
        fi
    fi
fi

# Count Ruff errors
if [ $RUFF_EXIT -eq 0 ]; then
    RUFF_ERRORS=0
else
    RUFF_ERR_PARSED=$(grep -oE "Found [0-9]+ errors?" "$RUFF_TMP" | awk '{print $2}')
    if [ -n "$RUFF_ERR_PARSED" ]; then
        RUFF_ERRORS="$RUFF_ERR_PARSED"
    else
        RUFF_ERRORS=$(grep -cE "^\s*-->\s*app/" "$RUFF_TMP")
        [ "$RUFF_ERRORS" -eq 0 ] && RUFF_ERRORS=1
    fi
fi
rm -f "$RUFF_TMP"

# 4. Ruff Format Check
echo ""
echo "--> [2/5] Running ruff format --check on 'app'..."
RUFF_FMT_TMP=$(mktemp)
ruff format --check app > "$RUFF_FMT_TMP" 2>&1
RUFF_FMT_EXIT=$?
cat "$RUFF_FMT_TMP"

if [ $RUFF_FMT_EXIT -ne 0 ]; then
    echo ""
    USER_FMT_REPLY=""
    if [ -t 0 ]; then
        read -r -p "Files need formatting. Would you like to run 'ruff format app'? [y/N]: " USER_FMT_REPLY
    elif [ -c /dev/tty ] && [ ! -p /dev/stdin ]; then
        read -r -p "Files need formatting. Would you like to run 'ruff format app'? [y/N]: " USER_FMT_REPLY </dev/tty
    elif [ -p /dev/stdin ]; then
        read -r USER_FMT_REPLY || USER_FMT_REPLY="N"
    fi

    if [[ "$USER_FMT_REPLY" =~ ^[Yy]$ ]]; then
        echo "--> Formatting with 'ruff format app'..."
        ruff format app
        RUFF_FMT_ERRORS=0
    else
        FMT_COUNT=$(grep -oE "[0-9]+ files? would be reformatted" "$RUFF_FMT_TMP" | awk '{print $1}')
        RUFF_FMT_ERRORS="${FMT_COUNT:-1}"
    fi
else
    RUFF_FMT_ERRORS=0
fi
rm -f "$RUFF_FMT_TMP"

# 5. Mypy Type Check
echo ""
echo "--> [3/5] Running mypy on 'app'..."
MYPY_TMP=$(mktemp)
mypy app > "$MYPY_TMP" 2>&1
MYPY_EXIT=$?
cat "$MYPY_TMP"

if [ $MYPY_EXIT -eq 0 ]; then
    MYPY_ERRORS=0
else
    MYPY_COUNT=$(grep -oE "Found [0-9]+ errors?" "$MYPY_TMP" | awk '{print $2}')
    if [ -n "$MYPY_COUNT" ]; then
        MYPY_ERRORS="$MYPY_COUNT"
    else
        MYPY_ERRORS=$(grep -c ": error:" "$MYPY_TMP")
        [ "$MYPY_ERRORS" -eq 0 ] && MYPY_ERRORS=1
    fi
fi
rm -f "$MYPY_TMP"

# 6. Flake8 (Matching CI Workflow)
echo ""
echo "--> [4/5] Running flake8 on 'app'..."
FLAKE8_TMP=$(mktemp)
python -m flake8 --max-line-length 179 --ignore=F722,B008,I001,I004,I005 app > "$FLAKE8_TMP" 2>&1
FLAKE8_EXIT=$?
cat "$FLAKE8_TMP"

if [ $FLAKE8_EXIT -eq 0 ]; then
    FLAKE8_ERRORS=0
else
    FLAKE8_ERRORS=$(grep -cE "^[^:]+:[0-9]+:[0-9]+:" "$FLAKE8_TMP")
    if [ "$FLAKE8_ERRORS" -eq 0 ]; then
        FLAKE8_ERRORS=$(grep -c . "$FLAKE8_TMP")
    fi
    [ "$FLAKE8_ERRORS" -eq 0 ] && FLAKE8_ERRORS=1
fi
rm -f "$FLAKE8_TMP"

# 7. Pylint (Matching CI Workflow)
echo ""
echo "--> [5/5] Running pylint on 'app'..."
PYLINT_TMP=$(mktemp)
pylint app > "$PYLINT_TMP" 2>&1
PYLINT_EXIT=$?
cat "$PYLINT_TMP"

if [ $PYLINT_EXIT -eq 0 ]; then
    PYLINT_ERRORS=0
else
    PYLINT_ERRORS=$(grep -cE "^[a-zA-Z0-9_/.]+\.py:[0-9]+:[0-9]+:" "$PYLINT_TMP")
    [ "$PYLINT_ERRORS" -eq 0 ] && PYLINT_ERRORS=1
fi
rm -f "$PYLINT_TMP"

# Summary Report
TOTAL_ISSUES=$((RUFF_ERRORS + RUFF_FMT_ERRORS + MYPY_ERRORS + FLAKE8_ERRORS + PYLINT_ERRORS))

echo ""
echo "=========================================="
echo "          LINT SUMMARY REPORT"
echo "=========================================="
printf "  %-30s : %s\n" "[1/5] Ruff Check" "$RUFF_ERRORS error(s)"
printf "  %-30s : %s\n" "[2/5] Ruff Format Check" "$RUFF_FMT_ERRORS file(s) to reformat"
printf "  %-30s : %s\n" "[3/5] Mypy Type Check" "$MYPY_ERRORS error(s)"
printf "  %-30s : %s\n" "[4/5] Flake8" "$FLAKE8_ERRORS error(s)"
printf "  %-30s : %s\n" "[5/5] Pylint" "$PYLINT_ERRORS issue(s)"
echo "------------------------------------------"
printf "  %-30s : %s\n" "TOTAL ISSUES" "$TOTAL_ISSUES"
echo "=========================================="

if [ "$TOTAL_ISSUES" -eq 0 ]; then
    echo " ✓ All pre-commit lint checks passed!"
    echo "=========================================="
    exit 0
else
    echo " ✗ One or more lint checks failed ($TOTAL_ISSUES total issue(s))."
    echo "   Please fix the errors above before checking in."
    echo "=========================================="
    exit 1
fi
