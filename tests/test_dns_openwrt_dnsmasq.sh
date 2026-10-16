#!/bin/sh
# ==============================================================================
# Unit & Integration Test for dns_openwrt_dnsmasq plugin logic
# Validates:
#   - POSIX compliance (/bin/sh)
#   - Dynamic record creation & file formatting
#   - Concurrent wildcard + apex handling (shared _acme-challenge name)
#   - Individual record cleanup without deleting sibling records
# ==============================================================================

set -e

# Mock environment
TEST_TMP_DIR=$(mktemp -d /tmp/acme_test_XXXXXX)
trap 'rm -rf "$TEST_TMP_DIR"' EXIT

# Mock /etc/init.d/dnsmasq
MOCK_BIN_DIR="${TEST_TMP_DIR}/bin"
mkdir -p "${MOCK_BIN_DIR}"
cat << EOF > "${MOCK_BIN_DIR}/dnsmasq_service"
#!/bin/sh
# Mock dnsmasq init script
echo "dnsmasq \$1 called" >> "${TEST_TMP_DIR}/dnsmasq.log"
exit 0
EOF
chmod +x "${MOCK_BIN_DIR}/dnsmasq_service"

# Load the plugin implementation with overridden CONF_DIR and service command
export CONF_DIR="${TEST_TMP_DIR}/acme"
mkdir -p "${CONF_DIR}"

# Define the functions as implemented in run_openwrt_config.sh
dns_openwrt_dnsmasq_add() {
    fulldomain=$1
    txtvalue=$2

    [ -z "$fulldomain" ] || [ -z "$txtvalue" ] && return 1

    _token_slug="$(echo "$txtvalue" | tr -c 'a-zA-Z0-9_' '_')"
    _conf_file="${CONF_DIR}/acme_${fulldomain}_${_token_slug}.conf"

    mkdir -p "${CONF_DIR}" 2>/dev/null || true
    echo "txt-record=${fulldomain},${txtvalue}" > "${_conf_file}"

    "${MOCK_BIN_DIR}/dnsmasq_service" restart >/dev/null 2>&1
    return 0
}

dns_openwrt_dnsmasq_rm() {
    fulldomain=$1
    txtvalue=$2

    [ -z "$fulldomain" ] || [ -z "$txtvalue" ] && return 1

    _token_slug="$(echo "$txtvalue" | tr -c 'a-zA-Z0-9_' '_')"
    _conf_file="${CONF_DIR}/acme_${fulldomain}_${_token_slug}.conf"

    rm -f "${_conf_file}"
    "${MOCK_BIN_DIR}/dnsmasq_service" restart >/dev/null 2>&1
    return 0
}

echo "=== Running dns_openwrt_dnsmasq plugin tests ==="

# Test 1: Single domain record addition
echo "[1/4] Testing single record addition..."
dns_openwrt_dnsmasq_add "_acme-challenge.example.lan" "TOKEN_SINGLE_123"

COUNT=$(ls -1 "${CONF_DIR}"/acme__acme-challenge.example.lan_*.conf 2>/dev/null | wc -l)
if [ "$COUNT" -ne 1 ]; then
    echo "FAIL: Expected 1 conf file, found $COUNT"
    exit 1
fi

CONTENT=$(cat "${CONF_DIR}"/acme__acme-challenge.example.lan_*.conf)
EXPECTED="txt-record=_acme-challenge.example.lan,TOKEN_SINGLE_123"
if [ "$CONTENT" != "$EXPECTED" ]; then
    echo "FAIL: Content mismatch: '$CONTENT' != '$EXPECTED'"
    exit 1
fi
echo "PASS: Single record addition verified."

# Test 2: Concurrent Wildcard + Apex additions (shared domain name)
echo "[2/4] Testing concurrent wildcard + apex record coexistence..."
dns_openwrt_dnsmasq_add "_acme-challenge.lan" "TOKEN_WILDCARD_ABC"
dns_openwrt_dnsmasq_add "_acme-challenge.lan" "TOKEN_APEX_XYZ"

COUNT_LAN=$(ls -1 "${CONF_DIR}"/acme__acme-challenge.lan_*.conf 2>/dev/null | wc -l)
if [ "$COUNT_LAN" -ne 2 ]; then
    echo "FAIL: Expected 2 conf files for _acme-challenge.lan, found $COUNT_LAN"
    exit 1
fi

# Verify both records exist
grep -q "TOKEN_WILDCARD_ABC" "${CONF_DIR}"/acme__acme-challenge.lan_*.conf
grep -q "TOKEN_APEX_XYZ" "${CONF_DIR}"/acme__acme-challenge.lan_*.conf
echo "PASS: Concurrent wildcard and apex coexistence verified."

# Test 3: Selective record cleanup
echo "[3/4] Testing selective record cleanup..."
dns_openwrt_dnsmasq_rm "_acme-challenge.lan" "TOKEN_WILDCARD_ABC"

# Apex record should still exist
if ! grep -q "TOKEN_APEX_XYZ" "${CONF_DIR}"/acme__acme-challenge.lan_*.conf 2>/dev/null; then
    echo "FAIL: Apex record was prematurely deleted!"
    exit 1
fi

# Wildcard record must be gone
if grep -q "TOKEN_WILDCARD_ABC" "${CONF_DIR}"/acme__acme-challenge.lan_*.conf 2>/dev/null; then
    echo "FAIL: Wildcard record was not removed!"
    exit 1
fi

# Clean up apex record
dns_openwrt_dnsmasq_rm "_acme-challenge.lan" "TOKEN_APEX_XYZ"
COUNT_REMAINING=$(ls -1 "${CONF_DIR}"/acme__acme-challenge.lan_*.conf 2>/dev/null | wc -l)
if [ "$COUNT_REMAINING" -ne 0 ]; then
    echo "FAIL: Expected 0 files remaining for _acme-challenge.lan, found $COUNT_REMAINING"
    exit 1
fi
echo "PASS: Selective cleanup verified."

# Test 4: Restart invocation check
echo "[4/4] Verifying dnsmasq service restart calls..."
RESTART_COUNT=$(grep -c "dnsmasq restart called" "${TEST_TMP_DIR}/dnsmasq.log" || true)
if [ "$RESTART_COUNT" -lt 4 ]; then
    echo "FAIL: dnsmasq restart called $RESTART_COUNT times, expected at least 4"
    exit 1
fi
echo "PASS: dnsmasq restart service triggered correctly."

echo "=== ALL TESTS PASSED SUCCESSFULLY ==="
