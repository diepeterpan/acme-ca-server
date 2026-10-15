#!/usr/bin/env bash

# ACME CA Server - Test Suites Runner
# Mimics GitHub Actions .github/workflows/tests.yml locally.
# Exits with 0 on success, non-zero on failure for consumption in other scripts.

# Resolve repository root directory
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

# Defaults
TARGET="all"
FAIL_FAST=false
DO_CLEANUP=true
SUDO_OVERRIDE=""

# Usage / Help
show_help() {
    cat <<EOF
Usage: $(basename "$0") [TARGET] [OPTIONS]

Mimics the GitHub Actions tests.yml workflow locally, running the ACME CA Server test suites.

Targets:
  all               Run all test suites (pytest, e2e) [default]
  pytest            Run only the Pytest suite (tests/pytest/run.sh)
  e2e               Run only the End-to-End test suite (tests/e2e/run.sh)

Options:
  -f, --fail-fast   Stop immediately if a test suite fails
  --no-cleanup      Skip cleanup of test Docker containers and networks on exit
  --sudo            Force execution using sudo for container runner scripts
  --no-sudo         Force execution without sudo
  -h, --help        Show this help message and exit

Environment Variables:
  USE_SUDO          Set to "true" / "1" to use sudo, or "false" / "0" to omit sudo

Exit Codes:
  0                 All executed test suites passed successfully
  1                 One or more test suites failed
  2                 Invalid argument or missing prerequisite
EOF
}

# Parse command line arguments
while [ $# -gt 0 ]; do
    case "$1" in
        all|pytest|e2e)
            TARGET="$1"
            shift
            ;;
        -f|--fail-fast)
            FAIL_FAST=true
            shift
            ;;
        --no-cleanup)
            DO_CLEANUP=false
            shift
            ;;
        --sudo)
            SUDO_OVERRIDE="sudo"
            shift
            ;;
        --no-sudo)
            SUDO_OVERRIDE="none"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Error: Unknown argument '$1'" >&2
            echo "Run '$(basename "$0") --help' for usage." >&2
            exit 2
            ;;
    esac
done

echo "=========================================="
echo " ACME CA Server - Test Suite Runner"
echo "=========================================="
echo "--> Target:       $TARGET"
echo "--> Fail-fast:    $FAIL_FAST"
echo "--> Cleanup:      $DO_CLEANUP"

# 1. Determine sudo requirements
SUDO_CMD=""
if [ "$SUDO_OVERRIDE" = "sudo" ]; then
    SUDO_CMD="sudo"
elif [ "$SUDO_OVERRIDE" = "none" ]; then
    SUDO_CMD=""
elif [ -n "${USE_SUDO:-}" ]; then
    if [ "$USE_SUDO" = "true" ] || [ "$USE_SUDO" = "1" ]; then
        SUDO_CMD="sudo"
    fi
elif [ "$EUID" -ne 0 ]; then
    # If not running as root, check if current user can run docker without sudo
    if ! docker info >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
        SUDO_CMD="sudo"
    fi
fi

if [ -n "$SUDO_CMD" ]; then
    echo "--> Privileges:   Using '$SUDO_CMD' for runner commands"
else
    echo "--> Privileges:   Direct (no sudo)"
fi

# 2. Pre-flight checks
if ! command -v docker &>/dev/null; then
    echo "" >&2
    echo "Error: 'docker' command was not found in PATH." >&2
    echo "Please install Docker (or Podman with docker alias) to run the tests." >&2
    exit 2
fi

if ! $SUDO_CMD docker info >/dev/null 2>&1; then
    echo "" >&2
    echo "Error: Docker daemon is not accessible ($SUDO_CMD docker info failed)." >&2
    echo "Please ensure the Docker service is running and permissions are configured." >&2
    exit 2
fi

if [ "$TARGET" = "all" ] || [ "$TARGET" = "e2e" ]; then
    if ! command -v openssl &>/dev/null; then
        echo "" >&2
        echo "Error: 'openssl' command was not found in PATH (required by e2e tests)." >&2
        echo "Please install OpenSSL (e.g., sudo apt install openssl)." >&2
        exit 2
    fi
fi

# 3. Cleanup handler
cleanup() {
    local sig_exit=$?
    trap - EXIT INT TERM
    if [ "$DO_CLEANUP" = "true" ]; then
        echo ""
        echo "--> Cleaning up lingering test containers and networks..."
        $SUDO_CMD docker rm -f -v test_db test_server test_mail test_runner 2>/dev/null || true
        $SUDO_CMD docker network rm -f test_net 2>/dev/null || true
    fi
    exit "$sig_exit"
}
trap cleanup EXIT INT TERM

# 4. Define test suites to run
SUITES=()
case "$TARGET" in
    pytest)
        SUITES=("pytest")
        ;;
    e2e)
        SUITES=("e2e")
        ;;
    all)
        SUITES=("pytest" "e2e")
        ;;
esac

declare -A SUITE_STATUS
declare -A SUITE_DURATION
OVERALL_EXIT=0
TOTAL_START=$(date +%s)

# 5. Execute test suites
TOTAL_COUNT=${#SUITES[@]}
CURRENT_INDEX=1

for suite in "${SUITES[@]}"; do
    suite_dir="$REPO_DIR/tests/$suite"
    echo ""
    echo "------------------------------------------"
    echo "--> [$CURRENT_INDEX/$TOTAL_COUNT] Running test suite: $suite"
    echo "--> Path: $suite_dir"
    echo "------------------------------------------"

    if [ ! -d "$suite_dir" ] || [ ! -f "$suite_dir/run.sh" ]; then
        echo "Error: Runner script '$suite_dir/run.sh' not found." >&2
        SUITE_STATUS["$suite"]="MISSING"
        SUITE_DURATION["$suite"]="0s"
        OVERALL_EXIT=1
        if [ "$FAIL_FAST" = "true" ]; then
            break
        fi
        CURRENT_INDEX=$((CURRENT_INDEX + 1))
        continue
    fi

    # Ensure run.sh is executable
    [ -x "$suite_dir/run.sh" ] || chmod +x "$suite_dir/run.sh"

    START_TIME=$(date +%s)
    SUITE_EXIT=0

    # Execute the suite from its directory (matching GHA step: cd tests/<suite> && sudo ./run.sh)
    (
        cd "$suite_dir" || exit 1
        if [ -n "$SUDO_CMD" ]; then
            $SUDO_CMD ./run.sh
        else
            ./run.sh
        fi
    ) || SUITE_EXIT=$?

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    SUITE_DURATION["$suite"]="${DURATION}s"

    if [ $SUITE_EXIT -eq 0 ]; then
        SUITE_STATUS["$suite"]="PASSED"
        echo "--> Test suite '$suite' PASSED (${DURATION}s)"
    else
        SUITE_STATUS["$suite"]="FAILED (exit code $SUITE_EXIT)"
        echo "--> Test suite '$suite' FAILED with exit code $SUITE_EXIT (${DURATION}s)" >&2
        OVERALL_EXIT=1
        if [ "$FAIL_FAST" = "true" ]; then
            echo "--> Stopping test execution due to --fail-fast flag." >&2
            break
        fi
    fi

    CURRENT_INDEX=$((CURRENT_INDEX + 1))
done

TOTAL_END=$(date +%s)
TOTAL_DURATION=$((TOTAL_END - TOTAL_START))

# 6. Summary Report
echo ""
echo "=========================================="
echo " ACME CA Server - Test Run Summary"
echo "=========================================="
for suite in "${SUITES[@]}"; do
    status="${SUITE_STATUS[$suite]:-SKIPPED}"
    duration="${SUITE_DURATION[$suite]:--}"
    printf " %-12s : %s (%s)\n" "$suite" "$status" "$duration"
done
echo "------------------------------------------"
echo " Total Duration: ${TOTAL_DURATION}s"
echo "=========================================="

if [ $OVERALL_EXIT -eq 0 ]; then
    echo "--> All tests PASSED successfully."
    exit 0
else
    echo "--> Tests FAILED! Exiting with code 1." >&2
    if [ "$DO_CLEANUP" = "true" ]; then
        echo "Tip: Run with '--no-cleanup' to inspect leftover test containers upon failure." >&2
    fi
    exit 1
fi
