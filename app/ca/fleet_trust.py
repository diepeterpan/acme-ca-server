# pylint: disable=too-many-lines,duplicate-code
import asyncio
import ipaddress
import json
import os
import secrets
import ssl
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import asyncssh
import db
from config import settings
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from logger import logger

ComplianceStatus = Literal['compliant', 'partial', 'untrusted', 'error']
AuditDeviceType = Literal['server', 'workstation', 'mobile', 'router', 'unknown']
TargetOsType = Literal['linux', 'windows', 'macos', 'openwrt', 'ios', 'android', 'unsupported', 'unknown']


@dataclass
class SshEndpoint:
    id: str  # noqa: A003
    name: str | None = None
    type: str = 'ssh'  # noqa: A003
    host: str | None = None
    port: int = 22
    username: str | None = None
    auth_type: str = 'password'
    auth_secret_enc: bytes | None = None


@dataclass
class CaTrustResult:
    id: str  # noqa: A003
    audit_id: str
    ca_serial: str
    is_trusted: bool
    details: str = ''
    checked_at: datetime | None = None
    ca_cn: str = ''
    ca_org: str = ''
    ca_active: bool = False


@dataclass
class CaTrustAudit:
    id: str  # noqa: A003
    device_name: str
    device_type: AuditDeviceType
    os: TargetOsType  # noqa: A003
    os_detail: str | None
    ip_address: str
    user_agent: str | None
    endpoint_id: str | None
    verification_method: str
    overall_status: ComplianceStatus
    total_cas: int
    trusted_cas: int
    audited_at: datetime
    created_at: datetime
    results: list[CaTrustResult] = field(default_factory=list)
    error_message: str | None = None


@dataclass
class ComplianceStats:
    total_audited: int
    compliant_count: int
    partial_count: int
    untrusted_count: int
    compliant_pct: float
    partial_pct: float
    untrusted_pct: float
    active_ca_name: str = ''
    active_ca_serial: str = ''


async def get_expected_cas() -> list[dict[str, Any]]:
    """Retrieve active and standby CAs from the database with parsed X.509 metadata (excluding retired CAs)."""
    async with db.transaction(readonly=True) as sql:
        rows = await sql.fetch("""
            SELECT serial_number, cert_pem, active
            FROM cas
            WHERE revoked_at IS NULL
            ORDER BY active DESC, serial_number ASC
        """)

    cas = []
    for r in rows:
        serial = r['serial_number']
        cert_pem = r['cert_pem']
        active = r['active']
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
            cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            cn = str(cn_attrs[0].value) if cn_attrs and cn_attrs[0].value else f'CA-{serial[:8]}'

            org_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
            org = str(org_attrs[0].value) if org_attrs and org_attrs[0].value else ''

            fp_bytes = cert.fingerprint(hashes.SHA256())
            fp_hex = ':'.join(f'{b:02X}' for b in fp_bytes)
            fp_raw = fp_bytes.hex().upper()

            nvb = cert.not_valid_before_utc
            nva = cert.not_valid_after_utc

            # Extract first non-header base64 line for high-speed signature matching on embedded devices
            pem_lines = [line.strip() for line in cert_pem.splitlines() if line.strip() and not line.startswith('-----')]
            pem_sig = pem_lines[0] if pem_lines else ''

            cas.append(
                {
                    'serial_number': serial,
                    'cn': cn,
                    'org': org,
                    'fingerprint_sha256': fp_hex,
                    'fingerprint_sha256_raw': fp_raw,
                    'pem_signature': pem_sig,
                    'active': active,
                    'not_valid_before': nvb.isoformat(),
                    'not_valid_after': nva.isoformat(),
                    'cert_pem': cert_pem,
                }
            )
        except Exception as ex:  # noqa: BLE001
            logger.error('Failed to parse CA certificate %s: %s', serial, ex)
    return cas


async def record_audit(
    device_name: str,
    device_type: AuditDeviceType,
    os_name: TargetOsType,
    os_detail: str | None,
    ip_address: str,
    user_agent: str | None = None,
    endpoint_id: str | None = None,
    verification_method: str = 'browser',
    results: list[dict[str, Any]] | None = None,
    error_message: str | None = None,
    overall_status: ComplianceStatus | None = None,
) -> str:
    """Record an audit telemetry entry and its per-CA verification results."""
    clean_device = device_name.strip() if device_name else f'device-{secrets.token_hex(4)}'
    clean_ip = ip_address.strip() if ip_address else '127.0.0.1'
    res_list = results or []

    # Get expected CAs to evaluate overall status
    cas = await get_expected_cas()
    valid_serials = {c['serial_number'] for c in cas}
    active_serials = {c['serial_number'] for c in cas if c['active']}

    total_cas = len(cas)
    trusted_serials = {r['ca_serial'] for r in res_list if r.get('is_trusted') and r.get('ca_serial') in valid_serials}
    trusted_count = len(trusted_serials)

    # Determine overall compliance:
    if overall_status:
        status: ComplianceStatus = overall_status
    elif error_message:
        status = 'error'
    elif active_serials and active_serials.issubset(trusted_serials):
        if 0 < total_cas <= trusted_count:
            status = 'compliant'
        else:
            status = 'partial'
    elif trusted_count > 0:
        status = 'partial'
    else:
        status = 'untrusted'

    audit_id = f'aud_{secrets.token_urlsafe(20)}'
    now = datetime.now(timezone.utc)

    clean_endpoint_id = endpoint_id.strip() if (endpoint_id and isinstance(endpoint_id, str) and endpoint_id.strip()) else None

    async with db.transaction() as sql:
        await sql.exec(
            """
            INSERT INTO ca_trust_audits (
                id, device_name, device_type, os, os_detail, ip_address,
                user_agent, endpoint_id, verification_method, overall_status,
                total_cas, trusted_cas, error_message, audited_at, created_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
            )
            """,
            audit_id,
            clean_device,
            device_type,
            os_name,
            os_detail or '',
            clean_ip,
            user_agent or '',
            clean_endpoint_id,
            verification_method,
            status,
            total_cas,
            trusted_count,
            error_message,
            now,
            now,
        )

        for item in res_list:
            ca_serial = item.get('ca_serial')
            if not ca_serial or ca_serial not in valid_serials:
                continue
            res_id = f'res_{secrets.token_urlsafe(20)}'
            is_trusted = bool(item.get('is_trusted', False))
            details = str(item.get('details', '')).strip()[:500]

            await sql.exec(
                """
                INSERT INTO ca_trust_audit_results (
                    id, audit_id, ca_serial, is_trusted, details, checked_at
                ) VALUES ($1, $2, $3, $4, $5, $6)
                """,
                res_id,
                audit_id,
                ca_serial,
                is_trusted,
                details,
                now,
            )

    return audit_id


async def get_compliance_stats() -> ComplianceStats:
    """Compute fleet compliance KPIs based on the latest audit for each unique device."""
    async with db.transaction(readonly=True) as sql:
        # Use DISTINCT ON to inspect each (device_name, ip_address, verification_method)'s most recent audit
        rows = await sql.fetch("""
            SELECT DISTINCT ON (device_name, ip_address, verification_method)
                device_name, ip_address, verification_method, overall_status
            FROM ca_trust_audits
            ORDER BY device_name, ip_address, verification_method, audited_at DESC
        """)

        active_ca = await sql.record("""
            SELECT serial_number, cert_pem
            FROM cas
            WHERE active = true
            LIMIT 1
        """)

    total = len(rows)
    compliant = sum(1 for r in rows if r['overall_status'] == 'compliant')
    partial = sum(1 for r in rows if r['overall_status'] == 'partial')
    untrusted = sum(1 for r in rows if r['overall_status'] in ('untrusted', 'error'))

    comp_pct = round((compliant / total * 100), 1) if total > 0 else 0.0
    part_pct = round((partial / total * 100), 1) if total > 0 else 0.0
    untr_pct = round((untrusted / total * 100), 1) if total > 0 else 0.0

    active_name = 'Active Root CA'
    active_serial = ''
    if active_ca:
        active_serial = active_ca['serial_number']
        try:
            c = x509.load_pem_x509_certificate(active_ca['cert_pem'].encode('utf-8'))
            cn_a = c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if cn_a and cn_a[0].value:
                active_name = str(cn_a[0].value)
        except Exception as ex:  # noqa: BLE001
            logger.debug('Could not parse active CA Common Name: %s', ex)

    return ComplianceStats(
        total_audited=total,
        compliant_count=compliant,
        partial_count=partial,
        untrusted_count=untrusted,
        compliant_pct=comp_pct,
        partial_pct=part_pct,
        untrusted_pct=untr_pct,
        active_ca_name=active_name,
        active_ca_serial=active_serial,
    )


async def list_audited_devices(
    device_filter: str | None = None,
    ca_serial: str | None = None,
    status_filter: str | None = None,
    os_filter: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[CaTrustAudit], int]:
    """
    List audited devices with applied filters, returning latest audit per device
    along with attached per-CA test results.
    """
    params: list[Any] = []
    where_clauses: list[str] = []

    if device_filter and device_filter.strip():
        params.append(f'%{device_filter.strip().lower()}%')
        idx = len(params)
        where_clauses.append(f'(LOWER(device_name) LIKE ${idx} OR LOWER(ip_address) LIKE ${idx} OR LOWER(os_detail) LIKE ${idx})')

    if status_filter and status_filter.strip() and status_filter != 'all':
        params.append(status_filter.strip())
        where_clauses.append(f'overall_status = ${len(params)}')

    if os_filter and os_filter.strip() and os_filter != 'all':
        params.append(os_filter.strip())
        where_clauses.append(f'os = ${len(params)}')

    if ca_serial and ca_serial.strip():
        params.append(ca_serial.strip())
        idx = len(params)
        where_clauses.append(f'id IN (SELECT audit_id FROM ca_trust_audit_results WHERE ca_serial = ${idx} AND is_trusted = true)')  # noqa: S608

    where_sql = f'WHERE {" AND ".join(where_clauses)}' if where_clauses else ''

    query = f"""
        WITH latest_audits AS (
            SELECT DISTINCT ON (device_name, ip_address, verification_method)
                id, device_name, device_type, os, os_detail, ip_address,
                user_agent, endpoint_id, verification_method, overall_status,
                total_cas, trusted_cas, error_message, audited_at, created_at
            FROM ca_trust_audits
            ORDER BY device_name, ip_address, verification_method, audited_at DESC
        )
        SELECT * FROM latest_audits
        {where_sql}
        ORDER BY audited_at DESC
        LIMIT ${len(params) + 1} OFFSET ${len(params) + 2}
    """  # noqa: S608

    count_query = f"""
        WITH latest_audits AS (
            SELECT DISTINCT ON (device_name, ip_address, verification_method)
                id, device_name, device_type, os, os_detail, ip_address,
                user_agent, endpoint_id, verification_method, overall_status,
                total_cas, trusted_cas, error_message, audited_at, created_at
            FROM ca_trust_audits
            ORDER BY device_name, ip_address, verification_method, audited_at DESC
        )
        SELECT count(*) FROM latest_audits
        {where_sql}
    """  # noqa: S608

    all_cas = await get_expected_cas()
    ca_map = {c['serial_number']: c for c in all_cas}

    async with db.transaction(readonly=True) as sql:
        total_count = await sql.value(count_query, *params)
        rows = await sql.fetch(query, *params, limit, offset)

        audits = []
        for r in rows:
            audit_id = r['id']
            res_rows = await sql.fetch(
                """
                SELECT id, audit_id, ca_serial, is_trusted, details, checked_at
                FROM ca_trust_audit_results
                WHERE audit_id = $1
                ORDER BY ca_serial ASC
                """,
                audit_id,
            )

            results_list = []
            for rr in res_rows:
                s = rr['ca_serial']
                ca_info = ca_map.get(s, {})
                results_list.append(
                    CaTrustResult(
                        id=rr['id'],
                        audit_id=rr['audit_id'],
                        ca_serial=s,
                        is_trusted=rr['is_trusted'],
                        details=rr['details'] or '',
                        checked_at=rr['checked_at'],
                        ca_cn=ca_info.get('cn', s[:8]),
                        ca_org=ca_info.get('org', ''),
                        ca_active=ca_info.get('active', False),
                    )
                )

            audits.append(
                CaTrustAudit(
                    id=audit_id,
                    device_name=r['device_name'],
                    device_type=r['device_type'],
                    os=r['os'],
                    os_detail=r['os_detail'],
                    ip_address=r['ip_address'],
                    user_agent=r['user_agent'],
                    endpoint_id=r['endpoint_id'],
                    verification_method=r['verification_method'],
                    overall_status=r['overall_status'],
                    total_cas=r['total_cas'],
                    trusted_cas=r['trusted_cas'],
                    audited_at=r['audited_at'],
                    created_at=r['created_at'],
                    results=results_list,
                    error_message=r['error_message'],
                )
            )

    return audits, total_count or 0


async def delete_audit(audit_id: str) -> bool:
    """Delete an audit record and all associated results."""
    async with db.transaction() as sql:
        res = await sql.exec('DELETE FROM ca_trust_audits WHERE id = $1', audit_id)
        return 'DELETE 1' in str(res)


def generate_cli_probe_script(
    external_url: str,
    endpoint_name: str | None = None,
    endpoint_id: str | None = None,
) -> str:
    """Generate dynamic, POSIX-compatible shell script for curl/wget execution."""
    clean_url = external_url.rstrip('/')
    clean_ep_name = (endpoint_name or '').replace('"', '').strip()
    clean_ep_id = (endpoint_id or '').replace('"', '').strip()

    return f"""#!/usr/bin/env sh
# ==============================================================================
#  ACME CA SERVER - FLEET TRUST AUDIT PROBE SCRIPT
#  Automatic System CA Trust Store Verification & Fleet Telemetry Ingestion
# ==============================================================================
set -e

SERVER_URL="{clean_url}"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
ENDPOINT_NAME="{clean_ep_name}"
ENDPOINT_ID="{clean_ep_id}"

# 1. Detect Hostname & FQDN
RAW_FQDN=""
if command -v hostname >/dev/null 2>&1; then
    RAW_FQDN=$(hostname -f 2>/dev/null || hostname --fqdn 2>/dev/null || true)
fi
SHORT_HOST=$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo "unknown-host")

# 2. Detect OS & Kernel
OS_TYPE="linux"
OS_DETAIL="Linux"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_DETAIL="${{PRETTY_NAME:-$NAME}}"
    case "$ID" in
        alpine) OS_TYPE="linux" ;;
        openwrt) OS_TYPE="openwrt" ;;
        arch|manjaro) OS_TYPE="linux" ;;
        debian|ubuntu|linuxmint|pop) OS_TYPE="linux" ;;
        rhel|centos|rocky|almalinux|fedora) OS_TYPE="linux" ;;
        *) OS_TYPE="linux" ;;
    esac
elif [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then
    OS_TYPE="macos"
    MAC_VER=$(sw_vers -productVersion 2>/dev/null || echo "")
    OS_DETAIL="macOS $MAC_VER"
elif [ -f /etc/openwrt_release ]; then
    OS_TYPE="openwrt"
    OS_DETAIL="OpenWrt"
else
    OS_DETAIL="$(uname -s 2>/dev/null) $(uname -r 2>/dev/null)"
fi

# 3. Detect Primary IP
IP_ADDR="127.0.0.1"
if command -v ip >/dev/null 2>&1; then
    IP_ADDR=$(ip route get 1.1.1.1 2>/dev/null | awk '{{print $7; exit}}')
elif command -v hostname >/dev/null 2>&1; then
    IP_ADDR=$(hostname -I 2>/dev/null | awk '{{print $1}}')
fi
if [ -z "$IP_ADDR" ]; then
    IP_ADDR="127.0.0.1"
fi

# Determine Hostname/IP Address and Device name according to FQDN resolution:
# First try FQDN; if valid (contains at least one dot), post FQDN and do not record IP.
# If FQDN falls back to IP, fallback Device name to Endpoint name (from CA Certificate Distribution).
if [ -n "$RAW_FQDN" ] && echo "$RAW_FQDN" | grep -q '\\.'; then
    HOST_IDENTIFIER="$RAW_FQDN"
    DEVICE_NAME="${{RAW_FQDN%%.*}}"
else
    HOST_IDENTIFIER="$IP_ADDR"
    if [ -n "$ENDPOINT_NAME" ]; then
        DEVICE_NAME="$ENDPOINT_NAME"
    else
        DEVICE_NAME="$SHORT_HOST"
    fi
fi

# Visual Header
printf "\\033[1;35m================================================================================\\033[0m\\n"
printf "\\033[1;37m  ACME CA SERVER - FLEET TRUST AUDIT PROBE v1.0\\033[0m\\n"
printf "\\033[1;35m================================================================================\\033[0m\\n"
printf "  \\033[1mDevice Name      :\\033[0m %s\\n" "$DEVICE_NAME"
printf "  \\033[1mHostname/IP      :\\033[0m %s\\n" "$HOST_IDENTIFIER"
printf "  \\033[1mOperating System :\\033[0m %s\\n" "$OS_DETAIL"
printf "  \\033[1mAudit Timestamp  :\\033[0m %s\\n" "$TIMESTAMP"
printf "\\033[1;35m================================================================================\\033[0m\\n"

printf "[*] Contacting ACME CA Server at %s...\\n" "$SERVER_URL"

# Fetch list of CAs from server
TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'ca-audit')
trap 'rm -rf "$TMP_DIR"' EXIT

CAS_JSON="$TMP_DIR/cas.json"
if command -v curl >/dev/null 2>&1; then
    curl -sSL "$SERVER_URL/ca-trust/api/cas" -o "$CAS_JSON" || true
elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$SERVER_URL/ca-trust/api/cas" > "$CAS_JSON" || true
else
    printf "\\033[1;31m[-] Error: Neither curl nor wget is installed on this system.\\033[0m\\n"
    exit 1
fi

if [ ! -s "$CAS_JSON" ]; then
    printf "\\033[1;31m[-] Failed to retrieve CA certificates from ACME server.\\033[0m\\n"
    exit 1
fi

# Inspect local trust stores
TOTAL_CAS=0
TRUSTED_CAS=0
RESULTS_PAYLOAD="["

# Parse JSON using python3, perl, or awk/sed
check_ca_trust() {{
    FP_RAW="$1"
    SERIAL="$2"
    CN="$3"
    ACTIVE="$4"

    TOTAL_CAS=$((TOTAL_CAS + 1))
    IS_TRUSTED="false"
    DETAILS="Certificate not found in local system trust store"

    # 1. Linux trust store checks
    if [ "$OS_TYPE" = "linux" ] || [ "$OS_TYPE" = "openwrt" ]; then
        BUNDLE_PATHS="/etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
        CERT_DIRS="/etc/ssl/certs /usr/local/share/ca-certificates /etc/pki/ca-trust/source/anchors /etc/pki/ca-trust/extracted/pem"

        # Prioritize OpenSSL inspection if available
        if command -v openssl >/dev/null 2>&1; then
            FP_NORM=$(echo "$FP_RAW" | tr -d ': ' | tr '[:lower:]' '[:upper:]')
            SERIAL_NORM=$(echo "$SERIAL" | tr -d ': ' | tr '[:lower:]' '[:upper:]')

            # Check individual certificate files in anchor directories
            for CD in $CERT_DIRS; do
                if [ -d "$CD" ]; then
                    for CF in "$CD"/*.pem "$CD"/*.crt; do
                        [ -f "$CF" ] || continue
                        CUR_FP=$(openssl x509 -in "$CF" -noout -fingerprint -sha256 2>/dev/null | cut -d'=' -f2 | tr -d ': ' | tr '[:lower:]' '[:upper:]')
                        if [ -n "$CUR_FP" ] && [ "$CUR_FP" = "$FP_NORM" ]; then
                            IS_TRUSTED="true"
                            DETAILS="Verified by SHA-256 in $CF"
                            break 2
                        fi
                        CUR_SN=$(openssl x509 -in "$CF" -noout -serial 2>/dev/null | cut -d'=' -f2 | tr -d ': ' | tr '[:lower:]' '[:upper:]')
                        if [ -n "$CUR_SN" ] && [ "$CUR_SN" = "$SERIAL_NORM" ]; then
                            IS_TRUSTED="true"
                            DETAILS="Verified by serial in $CF"
                            break 2
                        fi
                    done
                fi
            done

            # Check inside aggregated trust bundles
            if [ "$IS_TRUSTED" = "false" ]; then
                for BUNDLE in $BUNDLE_PATHS; do
                    if [ -f "$BUNDLE" ]; then
                        if openssl crl2pkcs7 -nocrl -certfile "$BUNDLE" >/dev/null 2>&1; then
                            if openssl crl2pkcs7 -nocrl -certfile "$BUNDLE" 2>/dev/null | openssl pkcs7 -print_certs -text 2>/dev/null | grep -iq "$SERIAL_NORM"; then
                                IS_TRUSTED="true"
                                DETAILS="Found in trust bundle $BUNDLE"
                                break
                            fi
                        fi
                    fi
                done
            fi
        fi

        # Fallback to Python3 certificate inspection if not found yet
        if [ "$IS_TRUSTED" = "false" ] && command -v python3 >/dev/null 2>&1; then
            PY_CHECK=$(python3 -c "
import sys, os, hashlib, base64

target_fp = '$FP_RAW'.upper().replace(':', '').strip()
target_sn = '$SERIAL'.upper().replace(':', '').strip()

def check_content(content):
    lines = content.split(b'\n')
    certs = []
    cur = []
    in_c = False
    for line in lines:
        if b'BEGIN CERTIFICATE' in line:
            in_c = True
            cur = [line]
        elif b'END CERTIFICATE' in line:
            if in_c:
                cur.append(line)
                certs.append(b'\n'.join(cur))
                in_c = False
        elif in_c:
            cur.append(line)
    for c in certs:
        body = b''.join([l for l in c.splitlines() if not l.startswith(b'---')])
        try:
            der = base64.b64decode(body)
            fp = hashlib.sha256(der).hexdigest().upper()
            if target_fp and fp == target_fp:
                return True
        except Exception:
            pass
    return False

bundles = ['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt', '/etc/ssl/cert.pem', '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem']
for b in bundles:
    if os.path.isfile(b):
        try:
            with open(b, 'rb') as f:
                if check_content(f.read()):
                    print('bundle:' + b)
                    sys.exit(0)
        except Exception:
            pass

dirs = ['/etc/ssl/certs', '/usr/local/share/ca-certificates', '/etc/pki/ca-trust/source/anchors']
for d in dirs:
    if os.path.isdir(d):
        try:
            for item in os.listdir(d):
                p = os.path.join(d, item)
                try:
                    with open(p, 'rb') as f:
                        if check_content(f.read()):
                            print('anchor:' + p)
                            sys.exit(0)
                except Exception:
                    pass
        except Exception:
            pass

sys.exit(1)
" 2>/dev/null || true)
            if [ -n "$PY_CHECK" ]; then
                IS_TRUSTED="true"
                DETAILS="Found in $PY_CHECK"
            fi
        fi

        # Fallback to textual subject / CN search if OpenSSL / Python did not find it
        if [ "$IS_TRUSTED" = "false" ]; then
            for BUNDLE in $BUNDLE_PATHS; do
                if [ -f "$BUNDLE" ] && grep -qi "$CN" "$BUNDLE" 2>/dev/null; then
                    IS_TRUSTED="true"
                    DETAILS="Found in trust bundle $BUNDLE"
                    break
                fi
            done
            if [ "$IS_TRUSTED" = "false" ] && [ -d /etc/ssl/certs ]; then
                if grep -ri "$CN" /etc/ssl/certs/ >/dev/null 2>&1; then
                    IS_TRUSTED="true"
                    DETAILS="Found in /etc/ssl/certs trust anchor store"
                elif [ -d /usr/local/share/ca-certificates ] && grep -ri "$CN" /usr/local/share/ca-certificates/ >/dev/null 2>&1; then
                    IS_TRUSTED="true"
                    DETAILS="Found in /usr/local/share/ca-certificates"
                elif [ -d /etc/pki/ca-trust/source/anchors ] && grep -ri "$CN" /etc/pki/ca-trust/source/anchors/ >/dev/null 2>&1; then
                    IS_TRUSTED="true"
                    DETAILS="Found in /etc/pki/ca-trust/source/anchors"
                fi
            fi
        fi

    # 2. macOS System Keychain check
    elif [ "$OS_TYPE" = "macos" ]; then
        if security find-certificate -a -c "$CN" /Library/Keychains/System.keychain >/dev/null 2>&1; then
            IS_TRUSTED="true"
            DETAILS="Found in macOS System Keychain"
        elif security find-certificate -a -c "$CN" /System/Library/Keychains/SystemRootCertificates.keychain >/dev/null 2>&1; then
            IS_TRUSTED="true"
            DETAILS="Found in SystemRootCertificates"
        fi
    fi

    # Print terminal progress
    printf "\\n[+] Checking CA: \\033[1m%s\\033[0m (Serial: %s)\\n" "$CN" "$SERIAL"
    if [ "$IS_TRUSTED" = "true" ]; then
        TRUSTED_CAS=$((TRUSTED_CAS + 1))
        printf "    Status: \\033[1;32m[ COMPLIANT - TRUSTED ]\\033[0m (%s)\\n" "$DETAILS"
    else
        printf "    Status: \\033[1;31m[ ERROR - NOT TRUSTED / MISSING ]\\033[0m\\n"
        printf "    Action: Please install and trust certificate in system trust store.\\n"
    fi

    if [ "$TOTAL_CAS" -gt 1 ]; then
        RESULTS_PAYLOAD="$RESULTS_PAYLOAD,"
    fi
    RESULTS_PAYLOAD="$RESULTS_PAYLOAD{{\\"ca_serial\\":\\"$SERIAL\\",\\"is_trusted\\":$IS_TRUSTED,\\"details\\":\\"$DETAILS\\"}}"
}}

# Read each CA from json using python3 or sed/grep
python3 -c "
import json
with open('$CAS_JSON') as f:
    data = json.load(f)
for ca in data:
    active_str = 'true' if ca.get('active') else 'false'
    print(f\\\"{{ca.get('fingerprint_sha256_raw')}}\\\\t{{ca.get('serial_number')}}\\\\t{{ca.get('cn')}}\\\\t{{active_str}}\\\")
" > "$TMP_DIR/parsed_cas.txt" 2>/dev/null || true

if [ -s "$TMP_DIR/parsed_cas.txt" ]; then
    while IFS="$(printf '\\t')" read -r fp serial cn active; do
        if [ -n "$serial" ]; then
            check_ca_trust "$fp" "$serial" "$cn" "$active"
        fi
    done < "$TMP_DIR/parsed_cas.txt"
else
    # Fallback if python3 is not present
    printf "[*] Parsing CA definitions using POSIX stream processor...\\n"
    SERIALS=$(grep -o '"serial_number": *"[^"]*"' "$CAS_JSON" | cut -d'"' -f4)
    for s in $SERIALS; do
        check_ca_trust "" "$s" "ACME CA" "true"
    done
fi

RESULTS_PAYLOAD="$RESULTS_PAYLOAD]"

# 4. Transmit Telemetry
printf "\\n--------------------------------------------------------------------------------\\n"
printf "[*] Transmitting audit telemetry to ACME CA Server... "

REPORT_JSON="$TMP_DIR/report.json"
if [ -n "$ENDPOINT_ID" ]; then
    EP_JSON_VAL="\\\"$ENDPOINT_ID\\\""
else
    EP_JSON_VAL="null"
fi
cat <<EOF > "$REPORT_JSON"
{{
  "device_name": "$DEVICE_NAME",
  "device_type": "server",
  "os": "$OS_TYPE",
  "os_detail": "$OS_DETAIL",
  "ip_address": "$HOST_IDENTIFIER",
  "endpoint_id": $EP_JSON_VAL,
  "verification_method": "cli_probe",
  "results": $RESULTS_PAYLOAD
}}
EOF

POST_STATUS="200"
if command -v curl >/dev/null 2>&1; then
    POST_RES=$(curl -sSL -X POST "$SERVER_URL/ca-trust/api/report" \\
        -H "Content-Type: application/json" \\
        -d @"$REPORT_JSON" -w "%{{http_code}}" -o /dev/null || echo "500")
elif command -v wget >/dev/null 2>&1; then
    POST_RES=$(wget -q --post-file="$REPORT_JSON" --header="Content-Type: application/json" \\
        "$SERVER_URL/ca-trust/api/report" -O /dev/null 2>&1 && echo "200" || echo "500")
fi

if [ "$POST_RES" = "200" ]; then
    printf "\\033[1;32mOK (Recorded in database)\\033[0m\\n"
else
    printf "\\033[1;33mWarning: Server returned HTTP %s (Telemetry failed to store)\\033[0m\\n" "$POST_RES"
fi

printf "\\033[1;35m================================================================================\\033[0m\\n"
if [ "$TRUSTED_CAS" -eq "$TOTAL_CAS" ] && [ "$TOTAL_CAS" -gt 0 ]; then
    printf "\\033[1;32m[✓] OVERALL FLEET STATUS: COMPLIANT (%d/%d CAs trusted)\\033[0m\\n" "$TRUSTED_CAS" "$TOTAL_CAS"
elif [ "$TRUSTED_CAS" -gt 0 ]; then
    printf "\\033[1;33m[!] OVERALL FLEET STATUS: PARTIAL COMPLIANCE (%d/%d CAs trusted - Action Required)\\033[0m\\n" "$TRUSTED_CAS" "$TOTAL_CAS"
else
    printf "\\033[1;31m[✗] OVERALL FLEET STATUS: NON-COMPLIANT / UNTRUSTED (0/%d CAs trusted)\\033[0m\\n" "$TOTAL_CAS"
fi
printf "\\033[1;35m================================================================================\\033[0m\\n"
"""


def generate_powershell_probe_script(
    external_url: str,
    endpoint_name: str | None = None,
    endpoint_id: str | None = None,
) -> str:
    """Generate dynamic Windows PowerShell probe script for client trust store verification and telemetry reporting."""
    clean_url = external_url.rstrip('/')
    clean_ep_name = (endpoint_name or '').replace('"', '').replace("'", '').strip()
    clean_ep_id = (endpoint_id or '').replace('"', '').replace("'", '').strip()

    return f"""# ==============================================================================
#  ACME CA SERVER - FLEET TRUST AUDIT PROBE SCRIPT (WINDOWS POWERSHELL)
#  Automatic System CA Trust Store Verification & Fleet Telemetry Ingestion
# ==============================================================================
$ErrorActionPreference = 'Stop'

# Configure TLS 1.2+ support for older Windows PowerShell 5.1 / .NET runtimes
try {{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
}} catch {{
    try {{
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }} catch {{}}
}}

$ServerUrl = "{clean_url}"
$EndpointName = "{clean_ep_name}"
$EndpointId = "{clean_ep_id}"
$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")

# 1. Detect Hostname & FQDN
$ShortHost = $env:COMPUTERNAME
$RawFqdn = ""
try {{
    $RawFqdn = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
}} catch {{
    $RawFqdn = $env:COMPUTERNAME
}}

# 2. Detect Windows Version & Product Type
$OsType = "windows"
$OsDetail = "Microsoft Windows"
$DeviceType = "workstation"

try {{
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if (-not $osInfo) {{
        $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
    }}
    if ($osInfo) {{
        $caption = $osInfo.Caption
        $version = $osInfo.Version
        $OsDetail = "$caption (Build $version)"
        if ($osInfo.ProductType -eq 2 -or $osInfo.ProductType -eq 3) {{
            $DeviceType = "server"
        }}
    }}
}} catch {{
    $OsDetail = [System.Environment]::OSVersion.VersionString
}}

# 3. Detect Primary IP
$IpAddr = "127.0.0.1"
try {{
    $ips = [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) |
           Where-Object {{ $_.AddressFamily -eq 'InterNetwork' -and -not [System.Net.IPAddress]::IsLoopback($_) }}
    if ($ips) {{
        $IpAddr = $ips[0].IPAddressToString
    }}
}} catch {{}}

# Determine Host Identifier and Device Name
if ($RawFqdn -and $RawFqdn.Contains(".")) {{
    $HostIdentifier = $RawFqdn
    $DeviceName = $RawFqdn.Split(".")[0]
}} else {{
    $HostIdentifier = $IpAddr
    if ($EndpointName) {{
        $DeviceName = $EndpointName
    }} else {{
        $DeviceName = $ShortHost
    }}
}}

# Visual Header
Write-Host "================================================================================" -ForegroundColor Magenta
Write-Host "  ACME CA SERVER - FLEET TRUST AUDIT PROBE v1.0 (WINDOWS POWERSHELL)" -ForegroundColor White
Write-Host "================================================================================" -ForegroundColor Magenta
Write-Host "  Device Name      : $DeviceName"
Write-Host "  Hostname/IP      : $HostIdentifier"
Write-Host "  Operating System : $OsDetail"
Write-Host "  Device Type      : $DeviceType"
Write-Host "  Audit Timestamp  : $Timestamp"
Write-Host "================================================================================" -ForegroundColor Magenta

Write-Host "[*] Contacting ACME CA Server at $ServerUrl..."

# Fetch list of CAs from server
$CasApiUrl = "$ServerUrl/ca-trust/api/cas"
try {{
    $Cas = Invoke-RestMethod -Uri $CasApiUrl -Method Get -UseBasicParsing
}} catch {{
    Write-Host "[-] Error: Failed to retrieve CA certificates from ACME server: $_" -ForegroundColor Red
    exit 1
}}

# Retrieve all certificates from Local Machine Root and Current User Root stores
$LocalMachineCerts = @()
$CurrentUserCerts = @()
try {{
    if (Test-Path "Cert:\\LocalMachine\\Root") {{
        $LocalMachineCerts = @(Get-ChildItem -Path "Cert:\\LocalMachine\\Root" -Recurse -ErrorAction SilentlyContinue)
    }}
}} catch {{}}
try {{
    if (Test-Path "Cert:\\CurrentUser\\Root") {{
        $CurrentUserCerts = @(Get-ChildItem -Path "Cert:\\CurrentUser\\Root" -Recurse -ErrorAction SilentlyContinue)
    }}
}} catch {{}}

$TotalCas = 0
$TrustedCas = 0
$Results = [System.Collections.ArrayList]::new()

foreach ($ca in $Cas) {{
    $TotalCas++
    $caSerial = [string]$ca.serial_number
    $caCn = [string]$ca.cn
    $caFpRaw = ([string]$ca.fingerprint_sha256_raw).ToUpper().Trim()

    $isTrusted = $false
    $details = "Certificate not found in Windows Root Certificate Store"

    $normSerial = $caSerial.Replace(" ", "").Replace(":", "").ToUpper()

    # Check LocalMachine Root
    foreach ($cert in $LocalMachineCerts) {{
        $certThumb = ($cert.Thumbprint -replace " ", "").ToUpper()
        $certSerial = ($cert.SerialNumber -replace " ", "").ToUpper()

        if ($caFpRaw -and ($certThumb -eq $caFpRaw)) {{
            $isTrusted = $true
            $details = "Verified by SHA-256 in Cert:\\LocalMachine\\Root"
            break
        }}
        if ($normSerial -and ($certSerial -eq $normSerial)) {{
            $isTrusted = $true
            $details = "Verified by serial in Cert:\\LocalMachine\\Root"
            break
        }}
    }}

    # Fallback check in CurrentUser Root
    if (-not $isTrusted) {{
        foreach ($cert in $CurrentUserCerts) {{
            $certThumb = ($cert.Thumbprint -replace " ", "").ToUpper()
            $certSerial = ($cert.SerialNumber -replace " ", "").ToUpper()

            if ($caFpRaw -and ($certThumb -eq $caFpRaw)) {{
                $isTrusted = $true
                $details = "Verified by SHA-256 in Cert:\\CurrentUser\\Root"
                break
            }}
            if ($normSerial -and ($certSerial -eq $normSerial)) {{
                $isTrusted = $true
                $details = "Verified by serial in Cert:\\CurrentUser\\Root"
                break
            }}
        }}
    }}

    Write-Host ""
    Write-Host "[+] Checking CA: $caCn (Serial: $caSerial)"
    if ($isTrusted) {{
        $TrustedCas++
        Write-Host "    Status: [ COMPLIANT - TRUSTED ] ($details)" -ForegroundColor Green
    }} else {{
        Write-Host "    Status: [ ERROR - NOT TRUSTED / MISSING ]" -ForegroundColor Red
        Write-Host "    Action: Please install and trust certificate in Cert:\\LocalMachine\\Root." -ForegroundColor Yellow
    }}

    [void]$Results.Add(@{{
        ca_serial = $caSerial
        is_trusted = $isTrusted
        details = $details
    }})
}}

# Transmit Telemetry
Write-Host ""
Write-Host "--------------------------------------------------------------------------------"
Write-Host "[*] Transmitting audit telemetry to ACME CA Server... " -NoNewline

$epVal = if ($EndpointId) {{ $EndpointId }} else {{ $null }}
$ReportPayload = @{{
    device_name = $DeviceName
    device_type = $DeviceType
    os = $OsType
    os_detail = $OsDetail
    ip_address = $HostIdentifier
    endpoint_id = $epVal
    verification_method = "cli_probe"
    results = $Results
}}

$ReportJson = $ReportPayload | ConvertTo-Json -Depth 5 -Compress
$ReportApiUrl = "$ServerUrl/ca-trust/api/report"

try {{
    $res = Invoke-RestMethod -Uri $ReportApiUrl -Method Post -Body $ReportJson -ContentType "application/json" -UseBasicParsing
    Write-Host "OK (Recorded in database)" -ForegroundColor Green
}} catch {{
    Write-Host "Warning: Telemetry failed to store: $_" -ForegroundColor Yellow
}}

Write-Host "================================================================================" -ForegroundColor Magenta
if ($TrustedCas -eq $TotalCas -and $TotalCas -gt 0) {{
    Write-Host "[✓] OVERALL FLEET STATUS: COMPLIANT ($TrustedCas/$TotalCas CAs trusted)" -ForegroundColor Green
}} elseif ($TrustedCas -gt 0) {{
    Write-Host "[!] OVERALL FLEET STATUS: PARTIAL COMPLIANCE ($TrustedCas/$TotalCas CAs trusted - Action Required)" -ForegroundColor Yellow
}} else {{
    Write-Host "[✗] OVERALL FLEET STATUS: NON-COMPLIANT / UNTRUSTED (0/$TotalCas CAs trusted)" -ForegroundColor Red
}}
Write-Host "================================================================================" -ForegroundColor Magenta
"""


def resolve_endpoint_device_name(endpoint: Any, host: str) -> str:
    """Determine friendly device label from endpoint or hostname prefix."""
    dev_name = (endpoint.name or '').strip()
    if dev_name:
        return dev_name
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    if not is_ip and '.' in host:
        return host.split('.')[0]
    return host or 'unknown-endpoint'


def format_probe_error(ex: Exception, host: str, port: int, timeout_sec: int = 20) -> str:
    """Produce a clear, non-empty error message for probe failures."""
    if isinstance(ex, (TimeoutError, asyncio.TimeoutError)):
        if isinstance(ex, asyncssh.ProcessError):
            return f'Command execution timed out on {host}:{port}'
        return f'Connection timed out after {timeout_sec}s connecting to {host}:{port}'
    if hasattr(ex, 'reason') and ex.reason:
        return f'{type(ex).__name__}: {ex.reason}'
    err_str = str(ex).strip()
    if err_str:
        cls_name = type(ex).__name__
        if err_str.startswith(cls_name) or cls_name in ('Exception', 'Error'):
            return err_str
        return f'{cls_name}: {err_str}'
    return f'{type(ex).__name__} (no details provided)'


async def probe_endpoint_trust_via_ssh(
    endpoint: Any,
    expected_cas: list[dict[str, Any]],
    progress_callback: Any = None,
) -> dict[str, Any]:
    """Connect to a single SSH endpoint, inspect system trust store, and return audit data."""
    import ca.distribution as dist  # pylint: disable=import-outside-toplevel

    secret = dist.decrypt_secret(endpoint.auth_secret_enc)
    client_keys = None
    password = None

    host = (endpoint.host or '').strip()
    port = endpoint.port or 22
    username = (endpoint.username or '').strip()
    device_label = endpoint.name or host or 'SSH Endpoint'

    if endpoint.auth_type == 'key':
        if not secret:
            err_msg = 'Missing SSH key'
            dev_name = resolve_endpoint_device_name(endpoint, host)
            audit_id = await record_audit(
                device_name=dev_name,
                device_type='server',
                os_name='unknown',
                os_detail=None,
                ip_address=host,
                endpoint_id=endpoint.id,
                verification_method='ssh_sweep',
                results=[],
                error_message=err_msg,
                overall_status='error',
            )
            return {'status': 'error', 'message': err_msg, 'audit_id': audit_id}
        try:
            client_keys = [asyncssh.import_private_key(secret.strip())]
        except Exception as ex:  # noqa: BLE001
            err_msg = f'Invalid SSH Key: {ex}'
            dev_name = resolve_endpoint_device_name(endpoint, host)
            audit_id = await record_audit(
                device_name=dev_name,
                device_type='server',
                os_name='unknown',
                os_detail=None,
                ip_address=host,
                endpoint_id=endpoint.id,
                verification_method='ssh_sweep',
                results=[],
                error_message=err_msg,
                overall_status='error',
            )
            return {'status': 'error', 'message': err_msg, 'audit_id': audit_id}
    else:
        password = secret.strip() if secret else ''

    try:
        async with asyncssh.connect(
            host=host,
            port=port,
            username=username,
            client_keys=client_keys,
            password=password,
            known_hosts=None,
            connect_timeout=20,
        ) as conn:
            detected_os, os_detail = await dist.probe_ssh_os(conn)

            results = []
            for ca in expected_cas:
                serial = ca['serial_number']
                cn = ca['cn']

                if progress_callback:
                    await progress_callback(
                        {
                            'stage': 'cert_testing',
                            'host': host,
                            'device_name': device_label,
                            'ca_cn': cn,
                            'ca_serial': serial,
                        }
                    )

                is_trusted = False
                details = 'Not found in system trust store'

                fp_raw = ca.get('fingerprint_sha256_raw', '').upper().replace(':', '').strip()
                serial_norm = serial.upper().replace(':', '').strip()

                if detected_os == 'linux':
                    pem_sig = ca.get('pem_signature', '')
                    check_cmd = f"""
SN="{serial_norm}"
FP="{fp_raw}"
SIG="{pem_sig}"
FOUND=""

# 1. High-speed signature search in system bundles (instantaneous, 0-forks)
if [ -n "$SIG" ]; then
    for b in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/ca-bundle.pem; do
        if [ -f "$b" ] && grep -Fq "$SIG" "$b" 2>/dev/null; then
            FOUND="Found in trust bundle $b"
            break
        fi
    done
    if [ -z "$FOUND" ]; then
        MATCH=$(grep -Frl "$SIG" /usr/local/share/ca-certificates /etc/pki/ca-trust/source/anchors 2>/dev/null | head -n 1)
        if [ -n "$MATCH" ]; then
            FOUND="Verified by signature in $MATCH"
        fi
    fi
fi

# 2. Targeted serial / fingerprint inspection on custom candidate certificates (avoids 150+ default cert fork storms)
if [ -z "$FOUND" ] && command -v openssl >/dev/null 2>&1; then
    for f in /usr/local/share/ca-certificates/*.crt /etc/pki/ca-trust/source/anchors/*.crt /etc/ssl/certs/*{serial_norm[:8]}*.crt /etc/ssl/certs/*{serial_norm[:8]}*.pem; do
        [ -f "$f" ] || continue
        sn=$(openssl x509 -in "$f" -noout -serial 2>/dev/null | cut -d= -f2 | tr -d " :" | tr "[:lower:]" "[:upper:]")
        if [ -n "$sn" ] && [ "$sn" = "$SN" ]; then
            FOUND="Verified by serial in $f"
            break
        fi
        if [ -n "$FP" ]; then
            fp=$(openssl x509 -in "$f" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d " :" | tr "[:lower:]" "[:upper:]")
            if [ -n "$fp" ] && [ "$fp" = "$FP" ]; then
                FOUND="Verified by SHA-256 in $f"
                break
            fi
        fi
    done
fi

# 3. Serial search in bundle text if signature was absent or custom serial match
if [ -z "$FOUND" ] && [ -n "$SN" ]; then
    for b in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem; do
        if [ -f "$b" ] && grep -Fq "$SN" "$b" 2>/dev/null; then
            FOUND="Found in trust bundle $b"
            break
        fi
    done
fi

echo "$FOUND"
"""
                    try:
                        res = await conn.run(check_cmd, check=False, timeout=12)
                        out = str(res.stdout or '').strip()
                        if out:
                            is_trusted = True
                            details = out[:100]
                    except (TimeoutError, asyncio.TimeoutError):
                        details = 'Check timed out after 12s'
                        logger.warning('Certificate check timed out for %s on %s', cn, host)

                elif detected_os == 'openwrt':
                    pem_sig = ca.get('pem_signature', '')
                    check_cmd = f"""
SN="{serial_norm}"
SIG="{pem_sig}"
FOUND=""

# 1. High-speed signature search in bundles and anchor stores (instantaneous, 0-forks)
if [ -n "$SIG" ]; then
    if [ -f /etc/ssl/certs/ca-certificates.crt ] && grep -Fq "$SIG" /etc/ssl/certs/ca-certificates.crt 2>/dev/null; then
        FOUND="Found in /etc/ssl/certs/ca-certificates.crt"
    elif [ -f /etc/ssl/cert.pem ] && grep -Fq "$SIG" /etc/ssl/cert.pem 2>/dev/null; then
        FOUND="Found in /etc/ssl/cert.pem"
    else
        MATCH=$(grep -Frl "$SIG" /etc/ssl/certs /usr/local/share/ca-certificates 2>/dev/null | head -n 1)
        if [ -n "$MATCH" ]; then
            FOUND="Verified by PEM signature in $MATCH"
        fi
    fi
fi

# 2. Targeted OpenSSL inspection (only on custom candidate certificates, avoiding full directory fork storms)
if [ -z "$FOUND" ] && command -v openssl >/dev/null 2>&1; then
    for f in /usr/local/share/ca-certificates/*.crt /etc/ssl/certs/*{serial_norm[:8]}*.crt /etc/ssl/certs/*{serial_norm[:8]}*.pem; do
        [ -f "$f" ] || continue
        sn=$(openssl x509 -in "$f" -noout -serial 2>/dev/null | cut -d= -f2 | tr -d " :" | tr "[:lower:]" "[:upper:]")
        if [ -n "$sn" ] && [ "$sn" = "$SN" ]; then
            FOUND="Verified by serial in $f"
            break
        fi
    done
fi

echo "$FOUND"
"""
                    try:
                        res = await conn.run(check_cmd, check=False, timeout=15)
                        out = str(res.stdout or '').strip()
                        if out:
                            is_trusted = True
                            details = out[:100]
                    except (TimeoutError, asyncio.TimeoutError):
                        details = 'Check timed out after 15s'
                        logger.warning('Certificate check timed out for %s on %s', cn, host)

                elif detected_os == 'windows':
                    ps_cmd = (
                        f'powershell -NoProfile -Command "'
                        f"$cert = Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object {{ ($_.SerialNumber -eq '{serial_norm}') -or ($_.Thumbprint -eq '{fp_raw}') }}; "
                        f"if ($cert) {{ Write-Output ('Verified in Cert:\\LocalMachine\\Root (Thumbprint: ' + $cert.Thumbprint + ')') }}\""
                    )
                    try:
                        res = await conn.run(ps_cmd, check=False, timeout=10)
                        out = str(res.stdout or '').strip()
                        if out:
                            is_trusted = True
                            details = out[:100]
                    except (TimeoutError, asyncio.TimeoutError):
                        details = 'Check timed out after 10s'
                        logger.warning('Certificate check timed out for %s on %s', cn, host)

                elif detected_os == 'macos':
                    check_cmd = f"""
if security find-certificate -a -c '{cn}' /Library/Keychains/System.keychain 2>/dev/null | grep -iq '{serial_norm}'; then
    echo "Verified by serial in macOS System.keychain"
elif security find-certificate -a -c '{cn}' /Library/Keychains/System.keychain >/dev/null 2>&1; then
    echo "Found in macOS System.keychain"
fi
"""
                    try:
                        res = await conn.run(check_cmd, check=False, timeout=8)
                        out = str(res.stdout or '').strip()
                        if out:
                            is_trusted = True
                            details = out[:100]
                    except (TimeoutError, asyncio.TimeoutError):
                        details = 'Check timed out after 8s'
                        logger.warning('Certificate check timed out for %s on %s', cn, host)

                results.append({'ca_serial': serial, 'is_trusted': is_trusted, 'details': details})

            dev_name = resolve_endpoint_device_name(endpoint, host)

            audit_id = await record_audit(
                device_name=dev_name,
                device_type='server',
                os_name=detected_os,
                os_detail=os_detail,
                ip_address=host,
                endpoint_id=endpoint.id,
                verification_method='ssh_sweep',
                results=results,
            )

            return {'status': 'success', 'audit_id': audit_id, 'results': results, 'os': detected_os, 'os_detail': os_detail}

    except Exception as ex:  # noqa: BLE001
        err_msg = format_probe_error(ex, host, port, timeout_sec=20)
        logger.warning('SSH fleet sweep failed for %s@%s:%s: %s', username, host, port, err_msg)
        dev_name = resolve_endpoint_device_name(endpoint, host)
        failed_audit_id: str | None = None
        try:
            failed_audit_id = await record_audit(
                device_name=dev_name,
                device_type='server',
                os_name='unknown',
                os_detail=None,
                ip_address=host,
                endpoint_id=endpoint.id,
                verification_method='ssh_sweep',
                results=[],
                error_message=err_msg,
                overall_status='error',
            )
        except Exception as rec_ex:  # noqa: BLE001
            logger.error('Failed to record failed audit for %s: %s', host, rec_ex)
        return {'status': 'error', 'message': err_msg, 'audit_id': failed_audit_id}


async def sweep_all_ssh_endpoints_stream():
    """Async generator yielding real-time progress events for SSE during fleet sweep."""
    expected_cas = await get_expected_cas()
    if not expected_cas:
        yield {'stage': 'error', 'message': 'No CA certificates defined in database'}
        return

    async with db.transaction(readonly=True) as sql:
        rows = await sql.fetch("""
            SELECT id, name, type, host, port, username, auth_type, auth_secret_enc
            FROM distribution_endpoints
            WHERE type = 'ssh'
        """)

    # Filter out empty or unconfigured host entries
    valid_rows = [r for r in rows if r['host'] and r['host'].strip()]
    total = len(valid_rows)
    if total == 0:
        yield {'stage': 'complete', 'total': 0, 'success': 0, 'failed': 0, 'message': 'No SSH distribution endpoints configured.'}
        return

    yield {
        'stage': 'init',
        'total': total,
        'message': f'Starting sweep across {total} endpoint(s)...',
    }

    success = 0
    failed = 0

    def _make_cert_callback(queue: asyncio.Queue[dict[str, Any]]):
        async def _callback(data: dict[str, Any]):
            await queue.put(data)

        return _callback

    for idx, r in enumerate(valid_rows, start=1):
        ep = SshEndpoint(**dict(r))
        device_label = ep.name or ep.host or 'Endpoint'
        host_label = ep.host or 'unknown'

        yield {
            'stage': 'endpoint_start',
            'index': idx,
            'total': total,
            'device_name': device_label,
            'host': host_label,
            'ca_cn': '',
            'ca_serial': '',
            'status': 'connecting',
        }

        progress_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        cert_callback = _make_cert_callback(progress_queue)

        # Run probe concurrently with consumer to stream sub-step cert events
        probe_task = asyncio.create_task(probe_endpoint_trust_via_ssh(ep, expected_cas, progress_callback=cert_callback))

        while not probe_task.done() or not progress_queue.empty():
            try:
                item = await asyncio.wait_for(progress_queue.get(), timeout=0.1)
                yield {
                    'stage': 'cert_testing',
                    'index': idx,
                    'total': total,
                    'device_name': device_label,
                    'host': host_label,
                    'ca_cn': item.get('ca_cn', ''),
                    'ca_serial': item.get('ca_serial', ''),
                    'status': 'testing',
                }
            except asyncio.TimeoutError:
                pass

        res = await probe_task
        if res.get('status') == 'success':
            success += 1
            yield {
                'stage': 'endpoint_done',
                'index': idx,
                'total': total,
                'device_name': device_label,
                'host': host_label,
                'status': 'success',
                'message': f'Audited successfully ({res.get("os_detail") or res.get("os", "unknown")})',
            }
        else:
            failed += 1
            err_msg = res.get('message') or 'Probe failed'
            yield {
                'stage': 'endpoint_error',
                'index': idx,
                'total': total,
                'device_name': device_label,
                'host': host_label,
                'status': 'warning',
                'message': f'Connection warning: {err_msg}',
            }

    yield {
        'stage': 'complete',
        'total': total,
        'success': success,
        'failed': failed,
        'message': f'Completed sweep of {total} SSH endpoint(s): {success} succeeded, {failed} warning(s).',
    }


async def sweep_all_ssh_endpoints() -> dict[str, Any]:
    """Background task to sweep all configured SSH distribution endpoints."""
    expected_cas = await get_expected_cas()
    if not expected_cas:
        return {'total': 0, 'success': 0, 'failed': 0, 'message': 'No CA certificates defined in database'}

    async with db.transaction(readonly=True) as sql:
        rows = await sql.fetch("""
            SELECT id, name, type, host, port, username, auth_type, auth_secret_enc
            FROM distribution_endpoints
            WHERE type = 'ssh'
        """)

    total = len(rows)
    success = 0
    failed = 0

    for r in rows:
        ep = SshEndpoint(**dict(r))
        res = await probe_endpoint_trust_via_ssh(ep, expected_cas)
        if res.get('status') == 'success':
            success += 1
        else:
            failed += 1

    return {'total': total, 'success': success, 'failed': failed, 'message': f'Completed sweep of {total} SSH endpoint(s): {success} succeeded, {failed} failed.'}


def generate_probe_leaf_cert_sync(
    *,
    ca_cert: x509.Certificate,
    ca_key: Any,
    hostnames: list[str],
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Generate an in-memory leaf certificate signed by ca_key for TLS probe listeners."""
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    sans: list[x509.GeneralName] = []
    seen: set[str] = set()

    for h in hostnames:
        h_clean = h.strip().lower()
        if not h_clean or h_clean in seen:
            continue
        seen.add(h_clean)
        try:
            ip = ipaddress.ip_address(h_clean)
            sans.append(x509.IPAddress(ip))
        except ValueError:
            sans.append(x509.DNSName(h_clean))

    for loopback in ('localhost', '127.0.0.1', '::1'):
        if loopback not in seen:
            seen.add(loopback)
            try:
                sans.append(x509.IPAddress(ipaddress.ip_address(loopback)))
            except ValueError:
                sans.append(x509.DNSName(loopback))

    now = datetime.now(timezone.utc)
    nvb = now - timedelta(minutes=5)
    nva = min(now + timedelta(days=30), ca_cert.not_valid_after_utc)

    primary_cn = hostnames[0] if hostnames else 'acme-probe'
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, primary_cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nvb)
        .not_valid_after(nva)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    )

    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

    leaf_cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return leaf_cert, leaf_key


def create_probe_ssl_context_sync(
    *,
    leaf_cert: x509.Certificate,
    leaf_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
) -> ssl.SSLContext:
    """Create an SSLContext loaded with the leaf cert, chain, and private key."""
    cert_chain_pem = leaf_cert.public_bytes(serialization.Encoding.PEM) + ca_cert.public_bytes(serialization.Encoding.PEM)
    key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    with tempfile.NamedTemporaryFile('wb', delete=False) as cf, tempfile.NamedTemporaryFile('wb', delete=False) as kf:
        cf.write(cert_chain_pem)
        cf.flush()
        kf.write(key_pem)
        kf.flush()
        cpath, kpath = cf.name, kf.name

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cpath, kpath)
        return ctx
    finally:
        try:
            os.unlink(cpath)
        except OSError:
            pass
        try:
            os.unlink(kpath)
        except OSError:
            pass


async def _handle_probe_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ca_info: dict[str, Any],
) -> None:
    """Handle incoming HTTPS requests on a dedicated CA probe listener."""
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=5.0)
        if not line:
            return

        # Drain remaining header lines
        while True:
            header_line = await asyncio.wait_for(reader.readline(), timeout=2.0)
            if not header_line or header_line in (b'\r\n', b'\n', b''):
                break

        body = json.dumps(
            {
                'status': 'ok',
                'trusted': True,
                'ca_serial': ca_info.get('serial_number', ''),
                'cn': ca_info.get('cn', ''),
                'active': bool(ca_info.get('active', False)),
            }
        ).encode('utf-8')

        resp = (
            b'HTTP/1.1 200 OK\r\n'
            b'Content-Type: application/json; charset=utf-8\r\n'
            b'Content-Length: ' + str(len(body)).encode('ascii') + b'\r\n'
            b'Access-Control-Allow-Origin: *\r\n'
            b'Access-Control-Allow-Methods: GET, OPTIONS\r\n'
            b'Access-Control-Allow-Headers: *\r\n'
            b'Access-Control-Max-Age: 86400\r\n'
            b'Connection: close\r\n'
            b'\r\n' + body
        )
        writer.write(resp)
    except Exception as ex:  # noqa: BLE001
        logger.debug('Probe client exception: %s', ex)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001, S110
            pass


class CaProbeServerManager:
    """Manages dedicated per-CA TLS probe listeners on custom port range."""

    def __init__(self) -> None:
        self.servers: dict[str, asyncio.Server] = {}
        self.ports: dict[str, int] = {}
        self._lock = asyncio.Lock()
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running

    async def start(self) -> None:
        async with self._lock:
            if self._is_running:
                return

            if not settings.ca.enabled or not settings.ca.trust_probe_enabled:
                return

            if not settings.ca.encryption_key:
                logger.warning('Cannot start CA trust probe servers: ca_encryption_key is not set')
                return

            async with db.transaction(readonly=True) as sql:
                rows = await sql.fetch("""
                    SELECT serial_number, cert_pem, key_pem_enc, active
                    FROM cas
                    WHERE revoked_at IS NULL
                    ORDER BY active DESC, serial_number ASC
                """)

            if not rows:
                logger.info('No CAs found in database to host probe servers for')
                return

            fernet = Fernet(settings.ca.encryption_key.get_secret_value())

            hostnames: list[str] = []
            if settings.external_url and settings.external_url.host:
                hostnames.append(str(settings.external_url.host))

            base_port = settings.ca.trust_probe_base_port
            bind_host = settings.ca.trust_probe_host

            for idx, r in enumerate(rows):
                serial = r['serial_number']
                cert_pem = r['cert_pem']
                key_pem_enc = r['key_pem_enc']
                active = bool(r['active'])

                try:
                    ca_cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
                    cn_attrs = ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                    cn = str(cn_attrs[0].value) if cn_attrs and cn_attrs[0].value else f'CA-{serial[:8]}'

                    key_pem = fernet.decrypt(key_pem_enc)
                    ca_key = serialization.load_pem_private_key(key_pem, None)

                    leaf_cert, leaf_key = await asyncio.to_thread(
                        generate_probe_leaf_cert_sync,
                        ca_cert=ca_cert,
                        ca_key=ca_key,
                        hostnames=hostnames,
                    )
                    ssl_ctx = await asyncio.to_thread(
                        create_probe_ssl_context_sync,
                        leaf_cert=leaf_cert,
                        leaf_key=leaf_key,
                        ca_cert=ca_cert,
                    )

                    target_port = base_port + idx
                    server = None
                    for attempt_port in range(target_port, target_port + 20):
                        try:
                            info = {'serial_number': serial, 'cn': cn, 'active': active}

                            def _make_handler(ca_info_dict: dict[str, Any]):
                                async def _client_cb(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
                                    await _handle_probe_client(client_reader, client_writer, ca_info_dict)

                                return _client_cb

                            server = await asyncio.start_server(
                                _make_handler(info),
                                host=bind_host,
                                port=attempt_port,
                                ssl=ssl_ctx,
                            )
                            target_port = attempt_port
                            break
                        except OSError as os_err:
                            logger.debug('Probe port %s unavailable: %s', attempt_port, os_err)
                            continue

                    if server is None:
                        logger.error('Failed to bind CA probe server for CA %s on ports %s-%s', serial, target_port, target_port + 20)
                        continue

                    self.servers[serial] = server
                    self.ports[serial] = target_port
                    logger.info(
                        'Started CA trust TLS probe listener for CA %s (%s) on https://%s:%s',
                        serial,
                        cn,
                        bind_host,
                        target_port,
                    )

                except Exception as ex:  # noqa: BLE001
                    logger.error('Failed to initialize probe server for CA %s: %s', serial, ex)

            self._is_running = True

    async def stop(self) -> None:
        async with self._lock:
            for serial, srv in list(self.servers.items()):
                try:
                    srv.close()
                    await srv.wait_closed()
                except Exception as ex:  # noqa: BLE001
                    logger.debug('Error closing probe server for CA %s: %s', serial, ex)
            self.servers.clear()
            self.ports.clear()
            self._is_running = False

    async def restart(self) -> None:
        await self.stop()
        await self.start()

    async def get_probe_endpoints(self, external_hostname: str | None = None) -> list[dict[str, Any]]:
        """Return probe endpoints for active and standby CAs."""
        cas = await get_expected_cas()
        endpoints = []
        base_port = settings.ca.trust_probe_base_port
        fallback_host = str(settings.external_url.host) if (settings.external_url and settings.external_url.host) else 'localhost'
        effective_host = (external_hostname or fallback_host).strip()

        for idx, ca in enumerate(cas):
            serial = ca['serial_number']
            port = self.ports.get(serial, base_port + idx)
            is_running = serial in self.servers
            endpoints.append(
                {
                    'ca_serial': serial,
                    'cn': ca.get('cn', ''),
                    'active': bool(ca.get('active', False)),
                    'port': port,
                    'is_running': is_running,
                    'probe_url': f'https://{effective_host}:{port}/probe',
                }
            )
        return endpoints


probe_manager = CaProbeServerManager()
