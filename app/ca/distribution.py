# pylint: disable=too-many-lines,duplicate-code
import asyncio
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Literal

import asyncssh
import db
import mail.service
from aiosmtplib import SMTP, SMTPException
from config import settings
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from logger import logger

EndpointType = Literal['ssh', 'email']
TargetOsType = Literal['linux', 'windows', 'macos', 'openwrt', 'ios', 'android', 'unsupported', 'unknown']
SshAuthType = Literal['key', 'password']


@dataclass
class Endpoint:
    id: str  # noqa: A003
    name: str
    type: EndpointType  # noqa: A003
    host: str | None = None
    port: int = 22
    username: str | None = None
    auth_type: SshAuthType = 'key'
    target_dir: str | None = None
    email_addresses: list[str] | None = None
    target_os_list: list[TargetOsType] | None = None
    detected_os: TargetOsType = 'unknown'
    os_detail: str | None = None
    last_test_at: datetime | None = None
    last_test_status: bool | None = None
    last_test_message: str | None = None
    has_secret: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None


@dataclass
class DistributionResult:
    endpoint_id: str
    endpoint_name: str
    endpoint_type: EndpointType
    status: bool
    message: str
    filename: str
    detected_os: TargetOsType = 'unknown'


def _get_fernet() -> Fernet:
    if not settings.ca.encryption_key:
        raise RuntimeError('CA encryption key is not configured (env var CA_ENCRYPTION_KEY)')
    return Fernet(settings.ca.encryption_key.get_secret_value())


def encrypt_secret(secret: str) -> bytes:
    if not secret:
        return b''
    return _get_fernet().encrypt(secret.strip().encode('utf-8'))


def decrypt_secret(secret_enc: bytes | None) -> str:
    if not secret_enc:
        return ''
    try:
        return _get_fernet().decrypt(secret_enc).decode('utf-8')
    except Exception as ex:  # noqa: BLE001
        logger.error('Failed to decrypt endpoint secret: %s', ex)
        return ''


def format_ca_filename(ca_cert: x509.Certificate, ext: str = '') -> str:
    """
    Formulate a certificate filename consisting of:
    Subject DN Organization first word (sanitized) and '_' valid from yyyymmddHHmm.
    Fallback to Common Name first word or 'CA'.
    """
    org_attrs = ca_cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    org_str = ''
    if org_attrs and org_attrs[0].value:
        org_str = str(org_attrs[0].value).strip()

    if not org_str:
        cn_attrs = ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn_attrs and cn_attrs[0].value:
            org_str = str(cn_attrs[0].value).strip()

    first_word = 'CA'
    if org_str:
        clean_words = [re.sub(r'[^a-zA-Z0-9]', '', w) for w in org_str.split()]
        valid_words = [w for w in clean_words if w]
        if valid_words:
            first_word = valid_words[0]

    nvb = ca_cert.not_valid_before_utc
    ts_str = nvb.strftime('%Y%m%d%H%M')

    base_name = f'{first_word}_{ts_str}'
    if ext:
        clean_ext = ext if ext.startswith('.') else f'.{ext}'
        return f'{base_name}{clean_ext}'
    return base_name


def format_ca_subdirectory(ca_cert: x509.Certificate) -> str:
    """
    Formulate a subdirectory name for SSH target distribution:
    CACert_{Sanitized_Common_Name}_{First6HexOfSerial}
    e.g., CACert_RootCA_4A1B2C
    """
    cn_attrs = ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    raw_name = str(cn_attrs[0].value).strip() if cn_attrs and cn_attrs[0].value else 'RootCA'
    clean_name = re.sub(r'[^a-zA-Z0-9]+', '', raw_name) or 'RootCA'
    serial_hex = f'{ca_cert.serial_number:X}'.zfill(6)[:6]
    return f'CACert_{clean_name}_{serial_hex}'


def generate_readme(
    base_name: str,
    os_target: TargetOsType,
    ca_name: str,
    serial: str,
    subdir: str = '',
    endpoint_id: str | None = None,
) -> str:
    subdir_line = f'Subdirectory          : {subdir}\n' if subdir else ''
    header = f"""================================================================================
  ACME CA SERVER - ROOT CA CERTIFICATE INSTALLATION GUIDE
================================================================================
Certificate Authority : {ca_name}
Serial Number         : {serial}
Base Filename         : {base_name}
{subdir_line}Target Operating Sys  : {os_target.upper()}
Generated At          : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
================================================================================
"""

    ext_url = str(settings.external_url).rstrip('/')
    probe_param = f'?endpoint_id={endpoint_id}' if endpoint_id else ''
    verify_section = f"""[AUTOMATED TRUST VERIFICATION & FLEET AUDITING]
After completing the installation above, verify that this system trusts
the newly installed CA certificate by running the automated audit probe:

Option 1: Using cURL (Recommended)
   curl -sSL {ext_url}/ca-trust/probe.sh{probe_param} | sudo bash

Option 2: Using Wget
   wget -qO- {ext_url}/ca-trust/probe.sh{probe_param} | sudo bash
================================================================================
"""

    ps_bootstrap = (
        f'[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; '
        f'[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}; '
        f"Invoke-Expression (Invoke-RestMethod -Uri '{ext_url}/ca-trust/probe.ps1{probe_param}')"
    )

    windows_verify_section = f"""[AUTOMATED TRUST VERIFICATION & FLEET AUDITING]
After completing the installation above, verify that this system trusts
the newly installed CA certificate by running the automated audit probe:

Option 1: Using PowerShell (Automated Fleet Audit)
   {ps_bootstrap}

Option 2: Using Command Prompt / cmd.exe (Automated Fleet Audit)
   powershell -NoProfile -ExecutionPolicy Bypass -Command "{ps_bootstrap}"

Option 3: Local CLI Verification (Built-in Tools - No Remote Probe)
   certutil -verifystore Root "{serial}"
   -or-
   powershell -Command "Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object {{ $_.SerialNumber -eq '{serial}' }}"

Option 4: Interactive Web Browser Verification
   {ext_url}/ca-trust/verify{probe_param}
================================================================================
"""

    if os_target == 'linux':
        return f"""{header}
[DEBIAN / UBUNTU / LINUX MINT]
1. Copy the certificate file to the system trust anchors directory:
   sudo cp {base_name}.crt /usr/local/share/ca-certificates/{base_name}.crt
2. Update the system CA trust store:
   sudo update-ca-certificates

[RHEL / CENTOS / ROCKY / ALMALINUX / FEDORA]
1. Copy the certificate file to the system trust anchors directory:
   sudo cp {base_name}.crt /etc/pki/ca-trust/source/anchors/{base_name}.crt
2. Update the system CA trust store:
   sudo update-ca-trust extract

[ALPINE LINUX]
1. Copy certificate:
   sudo cp {base_name}.crt /usr/local/share/ca-certificates/{base_name}.crt
2. Update system store:
   sudo update-ca-certificates

[ARCH LINUX / MANJARO]
1. Copy certificate:
   sudo trust anchor --store {base_name}.crt
================================================================================
{verify_section}"""

    if os_target == 'openwrt':
        return f"""{header}
[OPENWRT SYSTEM-WIDE INSTALLATION]
1. Ensure OpenWrt CA certificates package is installed:
   opkg update && opkg install ca-certificates ca-bundle
2. Copy the certificate into the SSL certificates directory:
   cp {base_name}.crt /etc/ssl/certs/{base_name}.crt
3. Re-hash the certificate directory or append to ca-certificates bundle:
   c_rehash /etc/ssl/certs/ 2>/dev/null || cat {base_name}.crt >> /etc/ssl/certs/ca-certificates.crt
================================================================================
{verify_section}"""

    if os_target == 'windows':
        return f"""{header}
[WINDOWS SYSTEM-WIDE INSTALLATION]
Certificate Formats Provided:
  - {base_name}.cer (DER Binary Format)
  - {base_name}.crt (PEM Format)

Option A: Command Prompt (Run as Administrator)
   certutil -addstore -f "Root" "{base_name}.cer"

Option B: PowerShell (Run as Administrator)
   Import-Certificate -FilePath "{base_name}.cer" -CertStoreLocation "Cert:\\LocalMachine\\Root"

Option C: Graphical Interface (Certmgr)
   1. Press Win + R, type 'certlm.msc' (Local Computer) and press Enter.
   2. Navigate to 'Trusted Root Certification Authorities' -> 'Certificates'.
   3. Right-click 'Certificates' -> 'All Tasks' -> 'Import...'.
   4. Browse and select '{base_name}.cer'.
   5. Select 'Place all certificates in the following store: Trusted Root Certification Authorities'.
   6. Click Finish.
================================================================================
{windows_verify_section}"""

    if os_target == 'macos':
        return f"""{header}
[MACOS SYSTEM-WIDE INSTALLATION]
Certificate Format Provided: {base_name}.crt

Option A: Terminal (CLI - Recommended)
   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "{base_name}.crt"

Option B: Keychain Access (GUI)
   1. Open 'Keychain Access' app.
   2. Select 'System' keychain on the left sidebar.
   3. Drag and drop '{base_name}.crt' into the list.
   4. Double-click the newly imported '{ca_name}' certificate.
   5. Expand the 'Trust' section.
   6. Set 'When using this certificate:' to 'Always Trust'.
   7. Close the window and enter your administrator credentials when prompted.
================================================================================
{verify_section}"""

    # Default / Generic instructions
    return f"""{header}
[GENERIC SYSTEM-WIDE INSTALLATION]
Certificate File: {base_name}.crt

Please copy '{base_name}.crt' to your operating system's root certificate trust store
and update the trust cache according to your platform guidelines.
================================================================================
{verify_section}"""


def _to_str(val: bytes | str | None) -> str:
    if val is None:
        return ''
    if isinstance(val, bytes):
        return val.decode('utf-8', errors='replace')
    return str(val)


WINDOWS_BUILD_NAMES: dict[str, str] = {
    '26100': 'Windows Server 2025 / Windows 11 24H2',
    '22631': 'Windows 11 23H2',
    '22621': 'Windows 11 22H2',
    '22000': 'Windows 11 21H2',
    '20348': 'Windows Server 2022',
    '19045': 'Windows 10 22H2',
    '19044': 'Windows 10 21H2',
    '19043': 'Windows 10 21H1',
    '19042': 'Windows 10 20H2',
    '19041': 'Windows 10 2004',
    '17763': 'Windows Server 2019 / Windows 10 1809',
    '17134': 'Windows 10 1803',
    '16299': 'Windows 10 1709',
    '15063': 'Windows 10 1703',
    '14393': 'Windows Server 2016 / Windows 10 1607',
    '10586': 'Windows 10 1511',
    '10240': 'Windows 10 1507',
    '9600': 'Windows Server 2012 R2 / Windows 8.1',
    '9200': 'Windows Server 2012 / Windows 8',
    '7601': 'Windows Server 2008 R2 / Windows 7 SP1',
    '7600': 'Windows Server 2008 R2 / Windows 7',
    '6002': 'Windows Server 2008 SP2 / Windows Vista SP2',
}


def _format_windows_version(raw: str) -> str:
    """Format Windows version using friendly name (Option B) with fallback to raw banner (Option A)."""
    clean_raw = raw.strip()
    match = re.search(r'(?:Version\s+)?(\d+(?:\.\d+)*)', clean_raw, re.IGNORECASE)
    if match:
        full_ver = match.group(1)
        parts = full_ver.split('.')
        build = parts[2] if len(parts) >= 3 else parts[-1]
        if build in WINDOWS_BUILD_NAMES:
            return f'{WINDOWS_BUILD_NAMES[build]} (Build {full_ver})'
        return f'Microsoft Windows [Version {full_ver}]'
    return clean_raw if clean_raw else 'Microsoft Windows'


async def probe_ssh_os(conn: asyncssh.SSHClientConnection) -> tuple[TargetOsType, str]:
    """Execute non-intrusive probe commands over SSH connection to determine remote OS."""
    try:
        # Step 1: Clean POSIX uname probe (no compound pipe or shell redirection)
        uname_res = await conn.run('uname -s', check=False, timeout=6)
        uname_out = _to_str(uname_res.stdout).strip()

        if 'Darwin' in uname_out:
            mac_ver = await conn.run('sw_vers -productVersion 2>/dev/null', check=False, timeout=5)
            v = _to_str(mac_ver.stdout).strip()
            return 'macos', f'macOS {v}' if v else 'Apple macOS'

        if 'Linux' in uname_out:
            # Check if OpenWrt
            ow_cmd = 'test -f /etc/openwrt_release && cat /etc/openwrt_release 2>/dev/null'
            ow_check = await conn.run(ow_cmd, check=False, timeout=5)
            ow_out = _to_str(ow_check.stdout).strip()
            if 'OpenWrt' in ow_out or 'DISTRIB_ID' in ow_out:
                desc_match = re.search(r"DISTRIB_DESCRIPTION=['\"]([^'\"]+)['\"]", ow_out)
                detail = desc_match.group(1) if desc_match else 'OpenWrt'
                return 'openwrt', detail

            # Standard Linux: check /etc/os-release
            os_rel = await conn.run('cat /etc/os-release 2>/dev/null', check=False, timeout=5)
            rel_out = _to_str(os_rel.stdout).strip()
            name_match = re.search(r'PRETTY_NAME=["\']?([^"\']+)["\']?', rel_out)
            detail = name_match.group(1) if name_match else 'Linux'
            return 'linux', detail

        if any(u in uname_out for u in ('FreeBSD', 'OpenBSD', 'NetBSD', 'SunOS', 'AIX')):
            return 'unsupported', f'Unsupported Unix ({uname_out})'

        # Step 2: Universal Windows probe via cmd.exe /c ver
        # cmd.exe is available on all Windows installations and callable from both cmd and powershell default shells
        win_res = await conn.run('cmd.exe /c ver', check=False, timeout=6)
        win_out = (_to_str(win_res.stdout) + ' ' + _to_str(win_res.stderr)).strip()

        if 'Windows' in win_out or 'Microsoft' in win_out:
            return 'windows', _format_windows_version(win_out)

        # Step 3: Windows PowerShell .NET environment fallback (works in all PS versions: 2.0 to 7+)
        ps_cmd = 'powershell -NoProfile -Command "[System.Environment]::OSVersion.VersionString"'
        ps_res = await conn.run(ps_cmd, check=False, timeout=6)
        ps_out = (_to_str(ps_res.stdout) + ' ' + _to_str(ps_res.stderr)).strip()

        if 'Windows' in ps_out or 'Microsoft' in ps_out:
            return 'windows', _format_windows_version(ps_out)

        # Step 4: Windows environment variable check (%OS% or $env:OS returns Windows_NT)
        env_res = await conn.run('cmd.exe /c echo %OS%', check=False, timeout=5)
        env_out = _to_str(env_res.stdout).strip()
        if 'Windows' in env_out:
            return 'windows', 'Microsoft Windows'

        ps_env = await conn.run('powershell -NoProfile -Command "$env:OS"', check=False, timeout=5)
        ps_env_out = _to_str(ps_env.stdout).strip()
        if 'Windows' in ps_env_out:
            return 'windows', 'Microsoft Windows'

        # Step 5: Check combined output of initial uname probe in case server greeting had banner
        combined_initial = (_to_str(uname_res.stdout) + ' ' + _to_str(uname_res.stderr)).strip()
        if 'Microsoft Windows' in combined_initial or '[Version ' in combined_initial:
            return 'windows', _format_windows_version(combined_initial)

        if uname_out:
            return 'unsupported', f'Unsupported OS ({uname_out[:40]})'

        return 'unknown', 'Unable to identify remote OS'

    except Exception as ex:  # noqa: BLE001
        logger.warning('Error probing remote OS over SSH: %s', ex)
        return 'unknown', f'Probe error: {ex}'


async def test_and_probe_ssh(
    host: str,
    port: int,
    username: str,
    auth_type: SshAuthType,
    secret: str,
    target_dir: str | None = None,
) -> tuple[bool, str, TargetOsType, str]:
    """Test SSH connection and probe OS."""
    if not host or not host.strip():
        return False, 'Host is required', 'unknown', ''
    if not username or not username.strip():
        return False, 'Username is required', 'unknown', ''

    client_keys = None
    password = None

    if auth_type == 'key':
        if not secret or not secret.strip():
            return False, 'SSH Private Key is required', 'unknown', ''
        try:
            client_keys = [asyncssh.import_private_key(secret.strip())]
        except Exception as ex:  # noqa: BLE001
            return False, f'Invalid SSH Private Key format: {ex}', 'unknown', ''
    else:
        password = secret.strip() if secret else ''

    try:
        async with asyncssh.connect(
            host=host.strip(),
            port=port or 22,
            username=username.strip(),
            client_keys=client_keys,
            password=password,
            known_hosts=None,
            connect_timeout=10,
        ) as conn:
            detected_os, os_detail = await probe_ssh_os(conn)

            # Test target directory if provided
            dir_msg = ''
            if target_dir and target_dir.strip():
                try:
                    async with conn.start_sftp_client() as sftp:
                        clean_dir = target_dir.strip()
                        try:
                            attrs = await sftp.stat(clean_dir)
                            if not attrs.permissions:
                                dir_msg = f' Directory {clean_dir} verified.'
                            else:
                                dir_msg = f' Directory {clean_dir} verified.'
                        except asyncssh.SFTPNoSuchFile:
                            dir_msg = f' Note: Directory {clean_dir} does not exist yet; will be created on distribution.'
                except Exception as ex:  # noqa: BLE001
                    dir_msg = f' Warning: SFTP check failed: {ex}'

            if detected_os == 'unsupported':
                msg = f'Connected successfully to {host}:{port}. Warning: Remote OS is unsupported ({os_detail}).{dir_msg}'
            else:
                msg = f'Connection verified! Detected {os_detail}.{dir_msg}'

            return True, msg, detected_os, os_detail

    except asyncssh.PermissionDenied as ex:
        return False, f'SSH Authentication failed for user {username}: {ex}', 'unknown', ''
    except asyncssh.DisconnectError as ex:
        return False, f'SSH Disconnected: {ex}', 'unknown', ''
    except (TimeoutError, asyncio.TimeoutError):
        return False, f'Connection timed out after 10 seconds connecting to {host}:{port}', 'unknown', ''
    except Exception as ex:  # noqa: BLE001
        return False, f'SSH Connection failed: {ex}', 'unknown', ''


async def test_email_endpoint(email_addresses: list[str]) -> tuple[bool, str]:
    """Validate email endpoint recipient list and check SMTP server configuration."""
    if not email_addresses:
        return False, 'At least one recipient email address is required.'

    invalid_emails = [e for e in email_addresses if not re.match(r'^[^@]+@[^@]+\.[^@]+$', e.strip())]
    if invalid_emails:
        return False, f'Invalid email address format: {", ".join(invalid_emails)}'

    mail_cfg = await mail.service.get_mail_settings()
    if not mail_cfg.enabled:
        return True, f'{len(email_addresses)} recipient(s) validated. Note: System SMTP delivery is currently disabled in Mail Settings.'

    if not mail_cfg.host or not mail_cfg.sender:
        return False, 'System SMTP settings are incomplete (missing SMTP Host or Sender).'

    return True, f'Email endpoint verified: {len(email_addresses)} valid recipient(s). Ready for distribution via {mail_cfg.host}.'


async def get_endpoints(endpoint_type: EndpointType | None = None) -> list[Endpoint]:
    """Retrieve distribution endpoints from the database."""
    query = """
        SELECT
            id, name, type, host, port, username, auth_type, target_dir,
            email_addresses, target_os_list, detected_os, os_detail,
            last_test_at, last_test_status, last_test_message,
            (auth_secret_enc IS NOT NULL AND length(auth_secret_enc) > 0) AS has_secret,
            created_at, updated_at
        FROM distribution_endpoints
    """
    args = []
    if endpoint_type:
        query += ' WHERE type = $1'
        args.append(endpoint_type)
    query += ' ORDER BY created_at ASC'

    async with db.transaction(readonly=True) as sql:
        rows = [r async for r in sql(query, *args)]

    return [
        Endpoint(
            id=r['id'],
            name=r['name'],
            type=r['type'],
            host=r['host'],
            port=r['port'] or 22,
            username=r['username'],
            auth_type=r['auth_type'] or 'key',
            target_dir=r['target_dir'],
            email_addresses=list(r['email_addresses']) if r['email_addresses'] else [],
            target_os_list=list(r['target_os_list']) if r['target_os_list'] else [],
            detected_os=r['detected_os'] or 'unknown',
            os_detail=r['os_detail'],
            last_test_at=r['last_test_at'],
            last_test_status=r['last_test_status'],
            last_test_message=r['last_test_message'],
            has_secret=bool(r['has_secret']),
            created_at=r['created_at'],
            updated_at=r['updated_at'],
        )
        for r in rows
    ]


async def get_endpoint(endpoint_id: str) -> Endpoint | None:
    """Retrieve single distribution endpoint."""
    async with db.transaction(readonly=True) as sql:
        r = await sql.record(
            """
            SELECT
                id, name, type, host, port, username, auth_type, target_dir,
                email_addresses, target_os_list, detected_os, os_detail,
                last_test_at, last_test_status, last_test_message,
                (auth_secret_enc IS NOT NULL AND length(auth_secret_enc) > 0) AS has_secret,
                created_at, updated_at
            FROM distribution_endpoints
            WHERE id = $1
            """,
            endpoint_id,
        )
    if not r:
        return None

    return Endpoint(
        id=r['id'],
        name=r['name'],
        type=r['type'],
        host=r['host'],
        port=r['port'] or 22,
        username=r['username'],
        auth_type=r['auth_type'] or 'key',
        target_dir=r['target_dir'],
        email_addresses=list(r['email_addresses']) if r['email_addresses'] else [],
        target_os_list=list(r['target_os_list']) if r['target_os_list'] else [],
        detected_os=r['detected_os'] or 'unknown',
        os_detail=r['os_detail'],
        last_test_at=r['last_test_at'],
        last_test_status=r['last_test_status'],
        last_test_message=r['last_test_message'],
        has_secret=bool(r['has_secret']),
        created_at=r['created_at'],
        updated_at=r['updated_at'],
    )


async def find_endpoint_by_host_or_name(*identifiers: str | None) -> Endpoint | None:
    """Find a configured distribution endpoint matching any candidate hostnames, IPs, or names."""
    clean_ids = [i.strip() for i in identifiers if i and isinstance(i, str) and i.strip()]
    if not clean_ids:
        return None
    async with db.transaction(readonly=True) as sql:
        for ident in clean_ids:
            r = await sql.record(
                """
                SELECT
                    id, name, type, host, port, username, auth_type, target_dir,
                    email_addresses, target_os_list, detected_os, os_detail,
                    last_test_at, last_test_status, last_test_message,
                    (auth_secret_enc IS NOT NULL AND length(auth_secret_enc) > 0) AS has_secret,
                    created_at, updated_at
                FROM distribution_endpoints
                WHERE LOWER(host) = LOWER($1) OR LOWER(name) = LOWER($1)
                LIMIT 1
                """,
                ident,
            )
            if r:
                return Endpoint(
                    id=r['id'],
                    name=r['name'],
                    type=r['type'],
                    host=r['host'],
                    port=r['port'] or 22,
                    username=r['username'],
                    auth_type=r['auth_type'] or 'key',
                    target_dir=r['target_dir'],
                    email_addresses=list(r['email_addresses']) if r['email_addresses'] else [],
                    target_os_list=list(r['target_os_list']) if r['target_os_list'] else [],
                    detected_os=r['detected_os'] or 'unknown',
                    os_detail=r['os_detail'],
                    last_test_at=r['last_test_at'],
                    last_test_status=r['last_test_status'],
                    last_test_message=r['last_test_message'],
                    has_secret=bool(r['has_secret']),
                    created_at=r['created_at'],
                    updated_at=r['updated_at'],
                )
    return None


async def create_endpoint(
    *,
    name: str,
    endpoint_type: EndpointType,
    host: str | None = None,
    port: int = 22,
    username: str | None = None,
    auth_type: SshAuthType = 'key',
    auth_secret: str | None = None,
    target_dir: str | None = None,
    email_addresses: list[str] | None = None,
    target_os_list: list[TargetOsType] | None = None,
) -> str:
    """Create a new distribution endpoint in Postgres."""
    endpoint_id = f'dist_{secrets.token_urlsafe(20)}'
    secret_enc = encrypt_secret(auth_secret) if auth_secret else None

    clean_emails = [e.strip() for e in (email_addresses or []) if e and e.strip()]
    clean_os_list = [os.strip() for os in (target_os_list or []) if os and os.strip()]

    async with db.transaction() as sql:
        await sql.exec(
            """
            INSERT INTO distribution_endpoints (
                id, name, type, host, port, username, auth_type, auth_secret_enc,
                target_dir, email_addresses, target_os_list, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now()
            )
            """,
            endpoint_id,
            name.strip(),
            endpoint_type,
            host.strip() if host else None,
            port or 22,
            username.strip() if username else None,
            auth_type,
            secret_enc,
            target_dir.strip() if target_dir else None,
            clean_emails,
            clean_os_list,
        )
    return endpoint_id


async def update_endpoint(
    *,
    endpoint_id: str,
    name: str,
    host: str | None = None,
    port: int = 22,
    username: str | None = None,
    auth_type: SshAuthType = 'key',
    auth_secret: str | None = None,
    target_dir: str | None = None,
    email_addresses: list[str] | None = None,
    target_os_list: list[TargetOsType] | None = None,
) -> bool:
    """Update existing endpoint."""
    clean_emails = [e.strip() for e in (email_addresses or []) if e and e.strip()]
    clean_os_list = [os.strip() for os in (target_os_list or []) if os and os.strip()]

    async with db.transaction() as sql:
        if auth_secret and auth_secret.strip():
            secret_enc = encrypt_secret(auth_secret.strip())
            await sql.exec(
                """
                UPDATE distribution_endpoints SET
                    name = $2, host = $3, port = $4, username = $5, auth_type = $6,
                    auth_secret_enc = $7, target_dir = $8, email_addresses = $9,
                    target_os_list = $10, updated_at = now()
                WHERE id = $1
                """,
                endpoint_id,
                name.strip(),
                host.strip() if host else None,
                port or 22,
                username.strip() if username else None,
                auth_type,
                secret_enc,
                target_dir.strip() if target_dir else None,
                clean_emails,
                clean_os_list,
            )
        else:
            await sql.exec(
                """
                UPDATE distribution_endpoints SET
                    name = $2, host = $3, port = $4, username = $5, auth_type = $6,
                    target_dir = $7, email_addresses = $8, target_os_list = $9, updated_at = now()
                WHERE id = $1
                """,
                endpoint_id,
                name.strip(),
                host.strip() if host else None,
                port or 22,
                username.strip() if username else None,
                auth_type,
                target_dir.strip() if target_dir else None,
                clean_emails,
                clean_os_list,
            )
    return True


async def delete_endpoint(endpoint_id: str) -> bool:
    """Delete distribution endpoint."""
    async with db.transaction() as sql:
        await sql.exec('DELETE FROM distribution_endpoints WHERE id = $1', endpoint_id)
    return True


async def test_endpoint(endpoint_id: str) -> tuple[bool, str, TargetOsType, str]:
    """Run connection test and OS detection for specified endpoint and save results."""
    async with db.transaction() as sql:
        row = await sql.record(
            """
            SELECT id, name, type, host, port, username, auth_type, auth_secret_enc, target_dir, email_addresses
            FROM distribution_endpoints WHERE id = $1
            """,
            endpoint_id,
        )
    if not row:
        return False, 'Endpoint not found', 'unknown', ''

    now_utc = datetime.now(timezone.utc)
    if row['type'] == 'ssh':
        secret = decrypt_secret(row['auth_secret_enc'])
        success, msg, detected_os, os_detail = await test_and_probe_ssh(
            host=row['host'] or '',
            port=row['port'] or 22,
            username=row['username'] or '',
            auth_type=row['auth_type'] or 'key',
            secret=secret,
            target_dir=row['target_dir'],
        )
        async with db.transaction() as sql:
            await sql.exec(
                """
                UPDATE distribution_endpoints SET
                    last_test_at = $2, last_test_status = $3, last_test_message = $4,
                    detected_os = $5, os_detail = $6, updated_at = now()
                WHERE id = $1
                """,
                endpoint_id,
                now_utc,
                success,
                msg,
                detected_os,
                os_detail,
            )
        return success, msg, detected_os, os_detail

    # Email endpoint
    emails = list(row['email_addresses']) if row['email_addresses'] else []
    success, msg = await test_email_endpoint(emails)
    async with db.transaction() as sql:
        await sql.exec(
            """
            UPDATE distribution_endpoints SET
                last_test_at = $2, last_test_status = $3, last_test_message = $4, updated_at = now()
            WHERE id = $1
            """,
            endpoint_id,
            now_utc,
            success,
            msg,
        )
    return success, msg, 'unknown', ''


async def log_distribution(
    *,
    ca_serial: str,
    endpoint_id: str | None,
    endpoint_name: str,
    endpoint_type: EndpointType,
    filename: str,
    status: bool,
    status_message: str,
) -> None:
    """Record an audit log entry for CA distribution."""
    log_id = f'distlog_{secrets.token_urlsafe(18)}'
    async with db.transaction() as sql:
        await sql.exec(
            """
            INSERT INTO ca_distribution_logs (
                id, ca_serial, endpoint_id, endpoint_name, endpoint_type, filename, status, status_message, distributed_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, now()
            )
            """,
            log_id,
            ca_serial,
            endpoint_id,
            endpoint_name,
            endpoint_type,
            filename,
            status,
            status_message,
        )


async def get_distribution_logs(ca_serial: str | None = None, limit: int = 50) -> list[dict]:
    """Fetch distribution audit logs."""
    query = """
        SELECT id, ca_serial, endpoint_id, endpoint_name, endpoint_type, filename, status, status_message, distributed_at
        FROM ca_distribution_logs
    """
    args: list[Any] = []
    if ca_serial:
        query += ' WHERE ca_serial = $1'
        args.append(ca_serial)
    query += ' ORDER BY distributed_at DESC LIMIT $' + str(len(args) + 1)
    args.append(limit)

    async with db.transaction(readonly=True) as sql:
        rows = [r async for r in sql(query, *args)]

    return [
        {
            'id': r['id'],
            'ca_serial': r['ca_serial'],
            'endpoint_id': r['endpoint_id'],
            'endpoint_name': r['endpoint_name'],
            'endpoint_type': r['endpoint_type'],
            'filename': r['filename'],
            'status': r['status'],
            'status_message': r['status_message'],
            'distributed_at': r['distributed_at'],
        }
        for r in rows
    ]


async def distribute_to_ssh_endpoint(
    endpoint: Endpoint,
    ca_cert: x509.Certificate,
    cert_pem: str,
) -> DistributionResult:
    """Transfer CA certificate file(s) and README.TXT to remote SSH endpoint via SFTP."""
    base_name = format_ca_filename(ca_cert)

    async with db.transaction(readonly=True) as sql:
        row = await sql.record('SELECT auth_secret_enc FROM distribution_endpoints WHERE id = $1', endpoint.id)
    secret = decrypt_secret(row['auth_secret_enc']) if row else ''

    client_keys = None
    password = None
    if endpoint.auth_type == 'key':
        try:
            client_keys = [asyncssh.import_private_key(secret.strip())]
        except Exception as ex:  # noqa: BLE001
            msg = f'Invalid private key: {ex}'
            await log_distribution(
                ca_serial=f'{ca_cert.serial_number:X}',
                endpoint_id=endpoint.id,
                endpoint_name=endpoint.name,
                endpoint_type='ssh',
                filename=base_name,
                status=False,
                status_message=msg,
            )
            return DistributionResult(endpoint.id, endpoint.name, 'ssh', False, msg, base_name)
    else:
        password = secret.strip() if secret else ''

    target_base = (endpoint.target_dir or '/tmp').rstrip('/\\')  # noqa: S108
    subdir_name = format_ca_subdirectory(ca_cert)
    dest_dir = f'{target_base}/{subdir_name}'

    try:
        async with asyncssh.connect(
            host=(endpoint.host or '').strip(),
            port=endpoint.port or 22,
            username=(endpoint.username or '').strip(),
            client_keys=client_keys,
            password=password,
            known_hosts=None,
            connect_timeout=15,
        ) as conn:
            # Probe OS to update detected OS if unknown
            detected_os, os_detail = await probe_ssh_os(conn)
            endpoint.detected_os = detected_os
            endpoint.os_detail = os_detail

            # Get Common Name
            cn_attr = ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            ca_name = str(cn_attr[0].value) if cn_attr else 'Root CA'
            serial_hex = f'{ca_cert.serial_number:X}'

            readme_content = generate_readme(
                base_name,
                detected_os,
                ca_name,
                serial_hex,
                subdir=subdir_name,
                endpoint_id=endpoint.id,
            )

            async with conn.start_sftp_client() as sftp:
                # Ensure destination subdirectory exists or create it
                try:
                    await sftp.stat(dest_dir)
                except asyncssh.SFTPNoSuchFile:
                    try:
                        await sftp.makedirs(dest_dir)
                    except Exception as ex:  # noqa: BLE001
                        logger.debug('Could not create directory %s: %s', dest_dir, ex)

                uploaded_files = []

                # Always upload .crt
                crt_path = f'{dest_dir}/{base_name}.crt'
                async with sftp.open(crt_path, 'w') as f:
                    await f.write(cert_pem)
                uploaded_files.append(f'{base_name}.crt')

                # Upload .pem
                pem_path = f'{dest_dir}/{base_name}.pem'
                async with sftp.open(pem_path, 'w') as f:
                    await f.write(cert_pem)
                uploaded_files.append(f'{base_name}.pem')

                # If Windows, upload DER .cer
                if detected_os == 'windows':
                    cer_path = f'{dest_dir}/{base_name}.cer'
                    der_bytes = ca_cert.public_bytes(serialization.Encoding.DER)
                    async with sftp.open(cer_path, 'wb') as f:
                        await f.write(der_bytes)
                    uploaded_files.append(f'{base_name}.cer')

                # Upload README.TXT
                readme_path = f'{dest_dir}/README.TXT'
                async with sftp.open(readme_path, 'w') as f:
                    await f.write(readme_content)
                uploaded_files.append('README.TXT')

            msg = f'Successfully deployed {len(uploaded_files)} files ({", ".join(uploaded_files)}) to {dest_dir}'
            await log_distribution(
                ca_serial=serial_hex,
                endpoint_id=endpoint.id,
                endpoint_name=endpoint.name,
                endpoint_type='ssh',
                filename=base_name,
                status=True,
                status_message=msg,
            )
            return DistributionResult(endpoint.id, endpoint.name, 'ssh', True, msg, base_name, detected_os)

    except Exception as ex:  # noqa: BLE001
        err_msg = f'SSH/SFTP transfer failed: {ex}'
        logger.error('Failed to distribute CA to SSH endpoint %s: %s', endpoint.name, ex)
        await log_distribution(
            ca_serial=f'{ca_cert.serial_number:X}',
            endpoint_id=endpoint.id,
            endpoint_name=endpoint.name,
            endpoint_type='ssh',
            filename=base_name,
            status=False,
            status_message=err_msg,
        )
        return DistributionResult(endpoint.id, endpoint.name, 'ssh', False, err_msg, base_name, endpoint.detected_os)


async def distribute_to_email_endpoint(
    endpoint: Endpoint,
    ca_cert: x509.Certificate,
    cert_pem: str,
) -> DistributionResult:
    """Send CA certificate in 3 formats (.crt, .pem, .cer) along with OS installation instructions via email."""
    base_name = format_ca_filename(ca_cert)
    serial_hex = f'{ca_cert.serial_number:X}'

    recipients = endpoint.email_addresses or []
    if not recipients:
        msg = 'No recipients specified in email endpoint.'
        await log_distribution(
            ca_serial=serial_hex,
            endpoint_id=endpoint.id,
            endpoint_name=endpoint.name,
            endpoint_type='email',
            filename=base_name,
            status=False,
            status_message=msg,
        )
        return DistributionResult(endpoint.id, endpoint.name, 'email', False, msg, base_name)

    mail_cfg = await mail.service.get_mail_settings()
    if not mail_cfg.enabled:
        msg = 'System SMTP delivery is disabled in Mail Settings. Email distribution skipped.'
        await log_distribution(
            ca_serial=serial_hex,
            endpoint_id=endpoint.id,
            endpoint_name=endpoint.name,
            endpoint_type='email',
            filename=base_name,
            status=False,
            status_message=msg,
        )
        return DistributionResult(endpoint.id, endpoint.name, 'email', False, msg, base_name)

    cn_attr = ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    ca_name = str(cn_attr[0].value) if cn_attr else 'Root CA'
    org_attr = ca_cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    org_name = str(org_attr[0].value) if org_attr else 'Internal Organization'

    nvb = ca_cert.not_valid_before_utc
    nva = ca_cert.not_valid_after_utc
    nvb_str = nvb.strftime('%Y-%m-%d %H:%M UTC')
    nva_str = nva.strftime('%Y-%m-%d %H:%M UTC')
    fingerprint = ca_cert.fingerprint(hashes.SHA256()).hex().upper()
    fingerprint_formatted = ':'.join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2))  # noqa: E203

    # Formulate OS instruction blocks
    target_oses = endpoint.target_os_list or ['ios', 'android', 'windows', 'macos', 'linux', 'openwrt']

    # Build HTML email
    html_sections = []
    text_sections = []

    # Shared SVG icon badges matching ca-distribution.html
    svg_ios = (
        '<span style="display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; '
        'border-radius: 6px; border: 1px solid #cbd5e1; background: #f8fafc; color: #0f172a; margin-right: 6px; vertical-align: middle;">'
        '<svg viewBox="0 0 170 170" width="13" height="13" fill="currentColor">'
        '<path d="M150.37 130.25c-2.45 5.66-5.35 10.87-8.71 15.66-4.58 6.53-8.33 11.05-11.22 13.56-4.48 4.12-9.28 6.23-14.42 6.35-3.69 0-8.14-1.05-13.32-3.18-5.19-2.12-9.97-3.17'
        '-14.34-3.17-4.58 0-9.49 1.05-14.75 3.17-5.26 2.13-9.5 3.24-12.74 3.35-4.35.13-9.16-1.9-14.42-6.08-3.7-3.04-7.59-7.71-11.66-14-5.33-8.2-9.61-17.76-12.83-28.67-3.21-10.91'
        '-4.83-21.43-4.83-31.55 0-16.19 4.35-29.42 13.06-39.7 8.71-10.28 19.32-15.54 31.84-15.79 4.9 0 10.42 1.37 16.58 4.11 6.16 2.74 10.36 4.16 12.61 4.26 1.9-.1 6.27-1.57 '
        '13.12-4.42 6.84-2.85 12.74-4.14 17.69-3.87 13.48 1.05 24.16 6.3 32.04 15.74-11.96 7.22-17.83 17.1-17.62 29.63.21 9.87 4.04 18.06 11.47 24.58 7.44 6.51 16.32 10.23 '
        '26.65 11.16-2.54 7.74-5.71 15.22-9.52 22.45zM119.22 31.83c0-7.39 2.67-14.33 8.01-20.82 5.34-6.49 11.96-10.46 19.86-11.91.43 1.9.64 3.7.64 5.4 0 7.39-2.78 14.49-8.34 '
        '21.3-5.56 6.82-12.33 10.74-20.31 11.76-.22-1.9-.33-3.8-.33-5.73z"/>'
        '</svg></span>'
    )
    svg_android = (
        '<span style="display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; '
        'border-radius: 6px; border: 1px solid #bbf7d0; background: #f0fdf4; color: #16a34a; margin-right: 6px; vertical-align: middle;">'
        '<svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor">'
        '<path d="M17.52 15.34c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1m-11.04 0c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1'
        'm11.4-6.02l2-3.46a.42.42 0 00-.15-.57.42.42 0 00-.57.15l-2.02 3.5A11.7 11.7 0 0012 8.08c-1.86 0-3.59.33-5.14.87L4.84 5.45'
        'a.42.42 0 00-.57-.15.42.42 0 00-.15.57l2 3.46C2.69 11.19.34 14.66 0 18.76h24c-.34-4.1-2.69-7.57-6.12-9.44"/>'
        '</svg></span>'
    )
    svg_windows = (
        '<span style="display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; '
        'border-radius: 6px; border: 1px solid #bae6fd; background: #f0f9ff; color: #0078d4; margin-right: 6px; vertical-align: middle;">'
        '<svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor">'
        '<path d="M0 3.45L9.75 2.1v9.45H0m10.95-9.6L24 0v11.4H10.95M0 12.6h9.75v9.45L0 20.7m10.95-8.1H24V24l-12.9-1.8"/>'
        '</svg></span>'
    )
    svg_macos = (
        '<span style="display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; '
        'border-radius: 6px; border: 1px solid #cbd5e1; background: #f8fafc; color: #0f172a; margin-right: 6px; vertical-align: middle;">'
        '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line>'
        '</svg></span>'
    )
    svg_linux = (
        '<span style="display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; '
        'border-radius: 6px; border: 1px solid #fde68a; background: #fffbeb; color: #d97706; margin-right: 6px; vertical-align: middle;">'
        '<svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor">'
        '<path d="M12 2C9.5 2 8 3.8 8 6.5v2.8C6.9 10 6 11.8 6 14.2c0 2.5 1.2 4.6 3.1 5.3-.2.8-.7 1.5-1.6 1.8-.4.1-.6.6-.4 1 .2.4.6.6 1 .4 '
        '1.8-.7 2.8-2.1 3-3.7h1.8c.2 1.6 1.2 3 3 3.7.4.2.8 0 1-.4.2-.4 0-.9-.4-1-.9-.3-1.4-1-1.6-1.8 1.9-.7 3.1-2.8 3.1-5.3 0-2.4-.9-4.2-2-4.9V6.5'
        'C16 3.8 14.5 2 12 2zm-1.8 5.2c.4 0 .8.3.8.8s-.4.8-.8.8-.8-.4-.8-.8.4-.8.8-.8zm3.6 0c.4 0 .8.3.8.8s-.4.8-.8.8-.8-.4-.8-.8.4-.8.8-.8zm-1.8 2.3'
        'c1.2 0 2.2.5 2.2 1.2s-1 1.2-2.2 1.2-2.2-.5-2.2-1.2 1-1.2 2.2-1.2z"/>'
        '</svg></span>'
    )
    svg_openwrt = (
        '<span style="display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; '
        'border-radius: 6px; border: 1px solid #a7f3d0; background: #ecfdf5; color: #0284c7; margin-right: 6px; vertical-align: middle;">'
        '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M5 12.55a11 11 0 0 1 14.08 0"></path><path d="M1.42 9a16 16 0 0 1 21.16 0"></path><path d="M8.53 16.11a6 6 0 0 1 6.95 0"></path>'
        '<line x1="12" y1="20" x2="12.01" y2="20"></line>'
        '</svg></span>'
    )

    if 'ios' in target_oses:
        html_sections.append(
            f"""
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 12px;">
                <h4 style="margin: 0 0 6px 0; color: #1e1b4b; font-size: 14px; display: flex; align-items: center;">
                    {svg_ios} Apple iOS / iPadOS
                </h4>
                <ol style="margin: 0; padding-left: 18px; font-size: 13px; color: #334155; line-height: 1.5;">
                    <li>Download <code>{base_name}.crt</code> in Safari.</li>
                    <li>Open <strong>Settings</strong> &rarr; tap <strong>Profile Downloaded</strong> &rarr; tap <strong>Install</strong>.</li>
                    <li>Go to <strong>Settings &gt; General &gt; About &gt; Certificate Trust Settings</strong>.</li>
                    <li>Under 'Enable Full Trust for Root Certificates', toggle <strong>ON</strong> for <em>{ca_name}</em>.</li>
                </ol>
            </div>
            """
        )
        text_sections.append(
            f"""[Apple iOS / iPadOS]
1. Download {base_name}.crt in Safari.
2. Open Settings -> tap Profile Downloaded -> Install.
3. Open Settings > General > About > Certificate Trust Settings.
4. Toggle ON Full Trust for {ca_name}.
"""
        )

    if 'android' in target_oses:
        html_sections.append(
            f"""
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 12px;">
                <h4 style="margin: 0 0 6px 0; color: #1e1b4b; font-size: 14px; display: flex; align-items: center;">
                    {svg_android} Android
                </h4>
                <ol style="margin: 0; padding-left: 18px; font-size: 13px; color: #334155; line-height: 1.5;">
                    <li>Download <code>{base_name}.crt</code> to your device.</li>
                    <li>Open <strong>Settings &gt; Security & Privacy &gt; More security settings &gt; Encryption & credentials</strong>.</li>
                    <li>Tap <strong>Install a certificate &gt; CA certificate</strong> (select 'Install anyway' if warned).</li>
                    <li>Browse and select <code>{base_name}.crt</code>. Verify that <em>{ca_name}</em> appears under User credentials.</li>
                </ol>
            </div>
            """
        )
        text_sections.append(
            f"""[Android]
1. Download {base_name}.crt to your device.
2. Open Settings > Security & Privacy > Encryption & credentials.
3. Tap Install a certificate > CA certificate.
4. Select {base_name}.crt to install.
"""
        )

    if 'windows' in target_oses:
        html_sections.append(
            f"""
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 12px;">
                <h4 style="margin: 0 0 6px 0; color: #1e1b4b; font-size: 14px; display: flex; align-items: center;">
                    {svg_windows} Microsoft Windows
                </h4>
                <ol style="margin: 0; padding-left: 18px; font-size: 13px; color: #334155; line-height: 1.5;">
                    <li>Download <code>{base_name}.cer</code> or <code>{base_name}.crt</code>.</li>
                    <li>Open Command Prompt as Administrator and run:<br/>
                        <code style="background: #ede9fe; color: #7c3aed; padding: 2px 6px; border-radius: 4px; display: inline-block; margin-top: 4px;">
                            certutil -addstore -f "Root" "{base_name}.cer"
                        </code>
                    </li>
                    <li>Alternatively, double-click the file &rarr; click <strong>Install Certificate...</strong> &rarr;
                        select <strong>Local Machine</strong> &rarr; place in <strong>Trusted Root Certification Authorities</strong>.</li>
                </ol>
            </div>
            """
        )
        text_sections.append(
            f"""[Microsoft Windows]
1. Download {base_name}.cer.
2. Run cmd as Admin: certutil -addstore -f "Root" "{base_name}.cer"
"""
        )

    if 'macos' in target_oses:
        html_sections.append(
            f"""
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 12px;">
                <h4 style="margin: 0 0 6px 0; color: #1e1b4b; font-size: 14px; display: flex; align-items: center;">
                    {svg_macos} Apple macOS
                </h4>
                <ol style="margin: 0; padding-left: 18px; font-size: 13px; color: #334155; line-height: 1.5;">
                    <li>Download <code>{base_name}.crt</code>.</li>
                    <li>Open Terminal and execute:<br/>
                        <code style="background: #ede9fe; color: #7c3aed; padding: 2px 6px; border-radius: 4px; display: inline-block; margin-top: 4px;">
                            sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "{base_name}.crt"
                        </code>
                    </li>
                </ol>
            </div>
            """
        )
        text_sections.append(
            f"""[Apple macOS]
1. Download {base_name}.crt.
2. In Terminal run: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "{base_name}.crt"
"""
        )

    if 'linux' in target_oses:
        html_sections.append(
            f"""
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 12px;">
                <h4 style="margin: 0 0 6px 0; color: #1e1b4b; font-size: 14px; display: flex; align-items: center;">
                    {svg_linux} Linux (Debian / Ubuntu / RHEL / Alpine)
                </h4>
                <p style="margin: 0 0 4px 0; font-size: 13px; color: #334155;"><strong>Debian / Ubuntu:</strong></p>
                <code style="background: #ede9fe; color: #7c3aed; padding: 2px 6px; border-radius: 4px; display: block; margin-bottom: 6px; font-size: 12px;">
                    sudo cp {base_name}.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates
                </code>
                <p style="margin: 0 0 4px 0; font-size: 13px; color: #334155;"><strong>RHEL / Fedora:</strong></p>
                <code style="background: #ede9fe; color: #7c3aed; padding: 2px 6px; border-radius: 4px; display: block; font-size: 12px;">
                    sudo cp {base_name}.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust extract
                </code>
            </div>
            """
        )
        text_sections.append(
            f"""[Linux]
Debian/Ubuntu: sudo cp {base_name}.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates
RHEL/Fedora: sudo cp {base_name}.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust extract
"""
        )

    if 'openwrt' in target_oses:
        html_sections.append(
            f"""
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 12px;">
                <h4 style="margin: 0 0 6px 0; color: #1e1b4b; font-size: 14px; display: flex; align-items: center;">
                    {svg_openwrt} OpenWrt
                </h4>
                <code style="background: #ede9fe; color: #7c3aed; padding: 2px 6px; border-radius: 4px; display: block; font-size: 12px;">
                    opkg update && opkg install ca-certificates && cp {base_name}.crt /etc/ssl/certs/ && c_rehash /etc/ssl/certs/
                </code>
            </div>
            """
        )
        text_sections.append(
            f"""[OpenWrt]
opkg update && opkg install ca-certificates && cp {base_name}.crt /etc/ssl/certs/ && c_rehash /etc/ssl/certs/
"""
        )

    ext_url = str(settings.external_url).rstrip('/')
    verify_url = f'{ext_url}/ca-trust/verify?endpoint_id={endpoint.id}'

    instructions_html = '\n'.join(html_sections)
    instructions_text = '\n'.join(text_sections)

    full_html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
             color: #1e1b4b; background-color: #f8fafc; padding: 20px; margin: 0;">
    <div style="max-width: 640px; margin: 0 auto; background: #ffffff; border: 1px solid #ede9fe;
                border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(124, 58, 237, 0.08);">
        <div style="background: linear-gradient(135deg, #7c3aed 0%, #4f46e5 100%); padding: 24px 28px; color: #ffffff;">
            <div style="font-size: 12px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase;
                        opacity: 0.85; margin-bottom: 4px;">Certificate Authority Distribution</div>
            <h2 style="margin: 0; font-size: 20px; font-weight: 700;">Action Required: Install Root CA Certificate</h2>
            <p style="margin: 6px 0 0 0; font-size: 13px; opacity: 0.9;">{ca_name} ({org_name})</p>
        </div>
        <div style="padding: 24px 28px;">
            <div style="background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 14px;
                        margin-bottom: 20px; font-size: 14px; color: #1e40af; line-height: 1.5;">
                A new Root Certificate Authority certificate has been generated.
                To prevent security warnings and maintain trusted connectivity to internal services,
                please install and trust this certificate on your devices.
            </div>

            <div style="background: #f5f3ff; border: 1px solid #ddd6fe; border-radius: 8px; padding: 16px; margin-bottom: 20px;">
                <table style="width: 100%; border-collapse: collapse; font-size: 13px; color: #334155;">
                    <tr><td style="padding: 4px 0; font-weight: 600; width: 140px;">Common Name:</td><td style="font-weight: 600; color: #1e1b4b;">{ca_name}</td></tr>
                    <tr><td style="padding: 4px 0; font-weight: 600;">Organization:</td><td>{org_name}</td></tr>
                    <tr><td style="padding: 4px 0; font-weight: 600;">Serial Number:</td><td style="font-family: monospace; font-size: 12px;">{serial_hex}</td></tr>
                    <tr><td style="padding: 4px 0; font-weight: 600;">Valid Period:</td><td>{nvb_str} &rarr; {nva_str}</td></tr>
                    <tr>
                        <td style="padding: 4px 0; font-weight: 600; vertical-align: top;">SHA-256 Fingerprint:</td>
                        <td style="font-family: monospace; font-size: 11px; word-break: break-all;">{fingerprint_formatted}</td>
                    </tr>
                </table>
            </div>

            <h3 style="color: #1e1b4b; font-size: 15px; margin: 0 0 12px 0;">Attached Certificate Formats:</h3>
            <div style="display: flex; gap: 8px; margin-bottom: 24px;">
                <span style="background: #f1f5f9; border: 1px solid #cbd5e1; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-family: monospace; color: #334155;">
                    📎 {base_name}.crt
                </span>
                <span style="background: #f1f5f9; border: 1px solid #cbd5e1; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-family: monospace; color: #334155;">
                    📎 {base_name}.pem
                </span>
                <span style="background: #f1f5f9; border: 1px solid #cbd5e1; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-family: monospace; color: #334155;">
                    📎 {base_name}.cer
                </span>
            </div>

            <h3 style="color: #1e1b4b; font-size: 15px; margin: 0 0 12px 0;">Installation Instructions by Operating System:</h3>
            {instructions_html}

            <div style="background: #f5f3ff; border: 1px solid #ddd6fe; border-radius: 8px; padding: 18px; margin: 24px 0; text-align: center;">
                <h4 style="margin: 0 0 8px 0; font-size: 15px; color: #1e1b4b; font-weight: 700;">Verify Your Installation</h4>
                <p style="margin: 0 0 14px 0; font-size: 13px; color: #4b5563;">
                    After installing the certificate, click the button below on your device to verify that the Root CA is properly trusted:
                </p>
                <a href="{verify_url}"
                   style="display: inline-block; background: #7c3aed; color: #ffffff;
                          text-decoration: none; font-weight: 700; font-size: 14px;
                          padding: 10px 22px; border-radius: 6px;">
                    ✓ Verify CA Trust on This Device
                </a>
                <div style="margin-top: 10px; font-size: 11px; color: #6b7280;">
                    Or visit directly: <a href="{verify_url}" style="color: #7c3aed;">{verify_url}</a>
                </div>
            </div>

            <div style="border-top: 1px solid #e2e8f0; margin-top: 24px; padding-top: 16px; font-size: 12px; color: #64748b; text-align: center;">
                Sent automatically by {settings.web.app_title} CA Distribution Engine.
            </div>
        </div>
    </div>
</body>
</html>
"""

    full_text = f"""Action Required: Install Root CA Certificate - {ca_name}

A new Root Certificate Authority certificate has been generated.
Please install and trust this certificate on your devices.

Certificate Details:
  Common Name: {ca_name}
  Organization: {org_name}
  Serial Number: {serial_hex}
  Valid: {nvb_str} to {nva_str}
  SHA-256 Fingerprint: {fingerprint_formatted}

Attached Files:
  - {base_name}.crt (PEM format)
  - {base_name}.pem (PEM bundle)
  - {base_name}.cer (DER binary format)

Instructions:
{instructions_text}

Verification:
After installing the certificate, verify your device's trust status at:
{verify_url}

Sent automatically by {settings.web.app_title}.
"""

    # Assemble MIME Message
    email_msg = MIMEMultipart('mixed')
    email_msg['From'] = mail_cfg.sender or 'ca-admin@example.org'
    email_msg['To'] = ', '.join(recipients)
    email_msg['Subject'] = f'[Action Required] Install Root CA Certificate - {ca_name}'

    alt_part = MIMEMultipart('alternative')
    alt_part.attach(MIMEText(full_text, 'plain', 'utf-8'))
    alt_part.attach(MIMEText(full_html, 'html', 'utf-8'))
    email_msg.attach(alt_part)

    # 1. Attach .crt (PEM)
    crt_attach = MIMEApplication(cert_pem.encode('utf-8'), _subtype='x-x509-ca-cert')
    crt_attach.add_header('Content-Disposition', 'attachment', filename=f'{base_name}.crt')
    email_msg.attach(crt_attach)

    # 2. Attach .pem
    pem_attach = MIMEApplication(cert_pem.encode('utf-8'), _subtype='x-pem-file')
    pem_attach.add_header('Content-Disposition', 'attachment', filename=f'{base_name}.pem')
    email_msg.attach(pem_attach)

    # 3. Attach .cer (DER binary format)
    der_bytes = ca_cert.public_bytes(serialization.Encoding.DER)
    cer_attach = MIMEApplication(der_bytes, _subtype='pkix-cert')
    cer_attach.add_header('Content-Disposition', 'attachment', filename=f'{base_name}.cer')
    email_msg.attach(cer_attach)

    # Dispatch via aiosmtplib
    auth = {}
    if mail_cfg.username and mail_cfg.password:
        auth = {'username': mail_cfg.username, 'password': mail_cfg.password}

    ctx = None
    if mail_cfg.encryption != 'plain' and mail_cfg.tls_non_strict:
        import ssl  # pylint: disable=import-outside-toplevel

        ctx = ssl.create_default_context()
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT

    try:
        async with SMTP(
            hostname=mail_cfg.host,
            port=mail_cfg.effective_port,
            **auth,  # type: ignore[arg-type]
            use_tls=mail_cfg.encryption.startswith('tls'),
            start_tls=mail_cfg.encryption.startswith('starttls'),
            tls_context=ctx,
            timeout=20,
        ) as client:
            await client.send_message(email_msg)

        success_msg = f'Email successfully sent to {len(recipients)} recipient(s) with .crt, .pem, and .cer attachments.'
        await log_distribution(
            ca_serial=serial_hex,
            endpoint_id=endpoint.id,
            endpoint_name=endpoint.name,
            endpoint_type='email',
            filename=base_name,
            status=True,
            status_message=success_msg,
        )
        return DistributionResult(endpoint.id, endpoint.name, 'email', True, success_msg, base_name)

    except SMTPException as ex:
        err = f'SMTP delivery error ({type(ex).__name__}): {ex}'
        logger.error('Failed to send CA distribution email to %s: %s', recipients, ex)
        await log_distribution(
            ca_serial=serial_hex,
            endpoint_id=endpoint.id,
            endpoint_name=endpoint.name,
            endpoint_type='email',
            filename=base_name,
            status=False,
            status_message=err,
        )
        return DistributionResult(endpoint.id, endpoint.name, 'email', False, err, base_name)
    except Exception as ex:  # noqa: BLE001
        err = f'Email delivery failed: {ex}'
        logger.error('Unexpected error dispatching CA distribution email: %s', ex, exc_info=True)
        await log_distribution(
            ca_serial=serial_hex,
            endpoint_id=endpoint.id,
            endpoint_name=endpoint.name,
            endpoint_type='email',
            filename=base_name,
            status=False,
            status_message=err,
        )
        return DistributionResult(endpoint.id, endpoint.name, 'email', False, err, base_name)
