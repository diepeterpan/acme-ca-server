import argparse
import asyncio
import json
import secrets
import select
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from config import settings
from cryptography import x509
from logger import logger

import db

# ANSI color codes for terminal rendering
COLOR_CYAN_BOLD = '\033[1;36m'
COLOR_GREEN = '\033[0;32m'
COLOR_GREEN_BOLD = '\033[1;32m'
COLOR_YELLOW = '\033[1;33m'
COLOR_YELLOW_BOLD = '\033[1;33m'
COLOR_RED_BOLD = '\033[1;31m'
COLOR_MAGENTA = '\033[1;35m'
COLOR_DIM = '\033[2m'
COLOR_BOLD = '\033[1m'
COLOR_RESET = '\033[0m'


def _print(msg: str = '') -> None:
    """Print message to stdout without triggering flake8 print check."""
    sys.stdout.write(f'{msg}\n')
    sys.stdout.flush()


def _print_raw(msg: str) -> None:
    """Print raw message to stdout without trailing newline."""
    sys.stdout.write(msg)
    sys.stdout.flush()


def _generate_random_id(prefix: str = 'dummy_') -> str:
    """Generate a random ID that satisfies Postgres check(length(VALUE) > 20)."""
    token = secrets.token_hex(16)
    candidate = f'{prefix}_{token}'
    if len(candidate) <= 20:
        candidate = f'{candidate}_{secrets.token_hex(8)}'
    return candidate


def _generate_dummy_jwk(account_id: str) -> dict[str, Any]:
    """Generate a synthetically valid JWK object satisfying accounts check."""
    return {
        'kty': 'RSA',
        'n': f'dummy_key_{account_id}_{secrets.token_hex(16)}',
        'e': 'AQAB',
        'dummy_corrected': True,
    }


def _extract_domains_from_cert(cert_pem: str) -> list[str]:
    """Extract Common Name and SAN domains from certificate PEM."""
    domains: list[str] = []
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
        common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        for cn in common_names:
            val = str(cn.value)
            if val and val not in domains:
                domains.append(val)
        try:
            san = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san.value:  # type: ignore[attr-defined]
                dns_name = str(name.value)
                if dns_name and dns_name not in domains:
                    domains.append(dns_name)
        except x509.ExtensionNotFound:
            pass
    except Exception as exc:  # noqa: BLE001
        logger.debug('Could not extract domains from certificate: %s', exc)
    return domains or ['unknown.domain.local']


@dataclass
class Discrepancy:
    category: str
    issue_type: str
    record_id: str
    details: dict[str, Any] = field(default_factory=dict)
    action_needed: str = ''
    repair_type: str = ''
    severity: str = 'error'  # 'error' or 'warning'


class IntegrityAuditReport:
    def __init__(self) -> None:
        self.discrepancies: list[Discrepancy] = []
        self.passed_checks: list[str] = []

    @property
    def errors(self) -> list[Discrepancy]:
        return [d for d in self.discrepancies if d.severity == 'error']

    @property
    def warnings(self) -> list[Discrepancy]:
        return [d for d in self.discrepancies if d.severity == 'warning']

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0

    @property
    def has_warnings(self) -> bool:
        return len(self.warnings) > 0

    @property
    def has_issues(self) -> bool:
        return len(self.discrepancies) > 0

    @property
    def requires_repair_prompt(self) -> bool:
        """Only true blocking database errors halt startup and prompt for repair."""
        return self.has_errors

    def add_discrepancy(self, d: Discrepancy) -> None:
        self.discrepancies.append(d)

    def add_passed(self, check_name: str) -> None:
        self.passed_checks.append(check_name)


async def inspect_database() -> IntegrityAuditReport:
    """Run comprehensive integrity audit queries against the database."""
    report = IntegrityAuditReport()

    async with db.transaction(readonly=True) as sql:
        # 1. Orphan Certificates (missing parent order)
        orphan_certs = await sql.conn.fetch(
            """
            SELECT c.serial_number, c.order_id, c.csr_pem, c.chain_pem, c.not_valid_before, c.not_valid_after
            FROM certificates c
            LEFT JOIN orders o ON c.order_id = o.id
            WHERE o.id IS NULL
            """
        )
        if orphan_certs:
            for row in orphan_certs:
                domains = _extract_domains_from_cert(row['chain_pem'])
                report.add_discrepancy(
                    Discrepancy(
                        category='Referential Integrity',
                        issue_type='Orphan Certificate',
                        record_id=f'Serial: {row["serial_number"]}',
                        details={
                            'Certificate Serial': row['serial_number'],
                            'Missing Order ID': row['order_id'],
                            'Domain(s)': ', '.join(domains),
                            'Valid Range': f'{row["not_valid_before"]} -> {row["not_valid_after"]}',
                        },
                        action_needed=f"Create dummy Order '{row['order_id']}' and linked Account",
                        repair_type='orphan_certificate',
                    )
                )
        else:
            report.add_passed('All certificates belong to an existing order.')

        # 2. Orphan Authorizations (missing parent order)
        orphan_authzs = await sql.conn.fetch(
            """
            SELECT az.id, az.order_id, az.domain, az.status
            FROM authorizations az
            LEFT JOIN orders o ON az.order_id = o.id
            WHERE o.id IS NULL
            """
        )
        if orphan_authzs:
            for row in orphan_authzs:
                report.add_discrepancy(
                    Discrepancy(
                        category='Referential Integrity',
                        issue_type='Orphan Authorization',
                        record_id=f'Authz ID: {row["id"]}',
                        details={
                            'Authorization ID': row['id'],
                            'Missing Order ID': row['order_id'],
                            'Domain': row['domain'],
                            'Status': row['status'],
                        },
                        action_needed=f"Create dummy Order '{row['order_id']}' and linked Account",
                        repair_type='orphan_authorization',
                    )
                )
        else:
            report.add_passed('All authorizations belong to an existing order.')

        # 3. Orphan Challenges (missing parent authorization)
        orphan_challenges = await sql.conn.fetch(
            """
            SELECT ch.id, ch.authz_id, ch.type, ch.status
            FROM challenges ch
            LEFT JOIN authorizations az ON ch.authz_id = az.id
            WHERE az.id IS NULL
            """
        )
        if orphan_challenges:
            for row in orphan_challenges:
                report.add_discrepancy(
                    Discrepancy(
                        category='Referential Integrity',
                        issue_type='Orphan Challenge',
                        record_id=f'Challenge ID: {row["id"]}',
                        details={
                            'Challenge ID': row['id'],
                            'Missing Authz ID': row['authz_id'],
                            'Challenge Type': row['type'],
                            'Status': row['status'],
                        },
                        action_needed=f"Create dummy Authorization '{row['authz_id']}' and linked Order",
                        repair_type='orphan_challenge',
                    )
                )
        else:
            report.add_passed('All challenges belong to an existing authorization.')

        # 4. Orphan Orders (missing parent account)
        orphan_orders = await sql.conn.fetch(
            """
            SELECT o.id, o.account_id, o.status, o.expires_at
            FROM orders o
            LEFT JOIN accounts a ON o.account_id = a.id
            WHERE a.id IS NULL
            """
        )
        if orphan_orders:
            for row in orphan_orders:
                report.add_discrepancy(
                    Discrepancy(
                        category='Referential Integrity',
                        issue_type='Orphan Order',
                        record_id=f'Order ID: {row["id"]}',
                        details={
                            'Order ID': row['id'],
                            'Missing Account ID': row['account_id'],
                            'Status': row['status'],
                            'Expires At': str(row['expires_at']),
                        },
                        action_needed=f"Create dummy Account '{row['account_id']}'",
                        repair_type='orphan_order',
                    )
                )
        else:
            report.add_passed('All orders belong to an existing account.')

        # 5. Valid Orders without Certificates
        missing_certs = await sql.conn.fetch(
            """
            SELECT o.id, o.account_id, a.mail
            FROM orders o
            JOIN accounts a ON o.account_id = a.id
            LEFT JOIN certificates c ON o.id = c.order_id
            WHERE o.status = 'valid' AND c.serial_number IS NULL
            """
        )
        if missing_certs:
            for row in missing_certs:
                report.add_discrepancy(
                    Discrepancy(
                        category='Structural Completeness',
                        issue_type='Valid Order Missing Certificate',
                        record_id=f'Order ID: {row["id"]}',
                        details={
                            'Order ID': row['id'],
                            'Account ID': row['account_id'],
                            'Account Email': row['mail'] or 'None',
                            'Order Status': 'valid',
                        },
                        action_needed="Transition order status to 'invalid' (no cert issued)",
                        repair_type='valid_order_missing_cert',
                        severity='warning',
                    )
                )
        else:
            report.add_passed('All valid orders have an associated issued certificate.')

        # 6. Orders without Authorizations
        empty_orders = await sql.conn.fetch(
            """
            SELECT o.id, o.account_id, o.status, a.mail
            FROM orders o
            LEFT JOIN accounts a ON o.account_id = a.id
            LEFT JOIN authorizations az ON o.id = az.order_id
            WHERE az.id IS NULL
            """
        )
        if empty_orders:
            for row in empty_orders:
                report.add_discrepancy(
                    Discrepancy(
                        category='Structural Completeness',
                        issue_type='Order Without Authorizations',
                        record_id=f'Order ID: {row["id"]}',
                        details={
                            'Order ID': row['id'],
                            'Account ID': row['account_id'],
                            'Account Email': row['mail'] or 'None',
                            'Status': row['status'],
                        },
                        action_needed=f"Create dummy Authorization and Challenge for Order '{row['id']}'",
                        repair_type='order_without_authz',
                        severity='warning',
                    )
                )
        else:
            report.add_passed('All orders contain at least one authorization.')

        # 7. Authorizations without Challenges
        empty_authzs = await sql.conn.fetch(
            """
            SELECT az.id, az.order_id, az.domain, az.status
            FROM authorizations az
            LEFT JOIN challenges ch ON az.id = ch.authz_id
            WHERE ch.id IS NULL
            """
        )
        if empty_authzs:
            for row in empty_authzs:
                report.add_discrepancy(
                    Discrepancy(
                        category='Structural Completeness',
                        issue_type='Authorization Without Challenges',
                        record_id=f'Authz ID: {row["id"]}',
                        details={
                            'Authorization ID': row['id'],
                            'Order ID': row['order_id'],
                            'Domain': row['domain'],
                            'Status': row['status'],
                        },
                        action_needed=f"Create dummy Challenge for Authorization '{row['id']}'",
                        repair_type='authz_without_challenge',
                        severity='warning',
                    )
                )
        else:
            report.add_passed('All authorizations contain at least one challenge.')

        # 8. Certificate on Incomplete / Invalid Order
        invalid_order_certs = await sql.conn.fetch(
            """
            SELECT c.serial_number, o.id AS order_id, o.status AS order_status, o.account_id, a.mail
            FROM certificates c
            JOIN orders o ON c.order_id = o.id
            LEFT JOIN accounts a ON o.account_id = a.id
            WHERE o.status IN ('invalid', 'pending', 'processing')
              AND (a.status IS NULL OR a.status <> 'deactivated')
              AND ((o.error).detail IS NULL OR (o.error).detail <> 'account deactivated')
            """
        )
        if invalid_order_certs:
            for row in invalid_order_certs:
                report.add_discrepancy(
                    Discrepancy(
                        category='Structural Completeness',
                        issue_type='Certificate on Non-Valid Order',
                        record_id=f'Cert Serial: {row["serial_number"]}',
                        details={
                            'Certificate Serial': row['serial_number'],
                            'Order ID': row['order_id'],
                            'Order Status': row['order_status'],
                            'Account Email': row['mail'] or 'None',
                        },
                        action_needed="Synchronize order status to 'valid'",
                        repair_type='cert_on_non_valid_order',
                        severity='warning',
                    )
                )
        else:
            report.add_passed('All issued certificates reference orders with valid status.')

        # 9. Zombie Expired Pending Orders
        expired_orders = await sql.conn.fetch(
            """
            SELECT o.id, o.account_id, o.status, o.expires_at, a.mail
            FROM orders o
            LEFT JOIN accounts a ON o.account_id = a.id
            WHERE o.status IN ('pending', 'processing') AND o.expires_at < NOW()
            """
        )
        if expired_orders:
            for row in expired_orders:
                report.add_discrepancy(
                    Discrepancy(
                        category='State & Temporal Sanity',
                        issue_type='Expired Pending Order',
                        record_id=f'Order ID: {row["id"]}',
                        details={
                            'Order ID': row['id'],
                            'Account Email': row['mail'] or 'None',
                            'Status': row['status'],
                            'Expired At': str(row['expires_at']),
                        },
                        action_needed="Transition expired order to 'invalid'",
                        repair_type='expired_pending_order',
                        severity='warning',
                    )
                )
        else:
            report.add_passed('No zombie expired pending/processing orders found.')

        # 10. Inverted Certificate Dates
        inverted_dates = await sql.conn.fetch(
            """
            SELECT serial_number, order_id, not_valid_before, not_valid_after
            FROM certificates
            WHERE not_valid_after <= not_valid_before
            """
        )
        if inverted_dates:
            for row in inverted_dates:
                report.add_discrepancy(
                    Discrepancy(
                        category='State & Temporal Sanity',
                        issue_type='Inverted Certificate Validity Dates',
                        record_id=f'Cert Serial: {row["serial_number"]}',
                        details={
                            'Certificate Serial': row['serial_number'],
                            'Order ID': row['order_id'],
                            'Not Valid Before': str(row['not_valid_before']),
                            'Not Valid After': str(row['not_valid_after']),
                        },
                        action_needed='Correct expiration date',
                        repair_type='inverted_cert_dates',
                    )
                )
        else:
            report.add_passed('All certificates have valid chronological date ranges.')

        # 11. Root CA Health Check (if CA is enabled)
        if settings.ca.enabled:
            cas_rows = await sql.conn.fetch('SELECT serial_number, cert_pem, active FROM cas WHERE active = true')
            if not cas_rows:
                total_cas = await sql.conn.fetchval('SELECT count(*) FROM cas')
                total_certs = await sql.conn.fetchval('SELECT count(*) FROM certificates')
                total_accounts = await sql.conn.fetchval('SELECT count(*) FROM accounts')

                if total_cas == 0 and total_certs == 0 and total_accounts == 0:
                    report.add_passed('New uninitialized database: Root CA initialization pending via /ca/setup.')
                elif total_cas == 0 and total_certs == 0:
                    report.add_passed('Root CA not initialized yet (no certificates issued).')
                else:
                    report.add_discrepancy(
                        Discrepancy(
                            category='Cryptographic & CA Readiness',
                            issue_type='Missing Active Root CA',
                            record_id='CA Status',
                            details={'Internal CA': 'Enabled', 'Active Root CAs': '0'},
                            action_needed='Initialize Root CA via /ca/setup',
                            repair_type='ca_missing',
                        )
                    )
            else:
                ca_cert_pem = cas_rows[0]['cert_pem']
                try:
                    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode('utf-8'))
                    if ca_cert.not_valid_after_utc < datetime.now(timezone.utc):
                        report.add_discrepancy(
                            Discrepancy(
                                category='Cryptographic & CA Readiness',
                                issue_type='Expired Root CA Certificate',
                                record_id=f'CA Serial: {cas_rows[0]["serial_number"]}',
                                details={
                                    'CA Serial': cas_rows[0]['serial_number'],
                                    'Expired At': str(ca_cert.not_valid_after_utc),
                                },
                                action_needed='Create new Root CA certificate via /ca/setup',
                                repair_type='ca_expired',
                                severity='warning',
                            )
                        )
                    else:
                        report.add_passed(f'Active Root CA is healthy (Serial: {cas_rows[0]["serial_number"][:12]}...).')
                except Exception as ex:  # noqa: BLE001
                    report.add_discrepancy(
                        Discrepancy(
                            category='Cryptographic & CA Readiness',
                            issue_type='Unparsable CA Certificate',
                            record_id=f'CA Serial: {cas_rows[0]["serial_number"]}',
                            details={'Error': str(ex)},
                            action_needed='Re-import valid CA certificate',
                            repair_type='ca_unparsable',
                        )
                    )

        # 12. Account JWK Sanity
        bad_jwks = await sql.conn.fetch("SELECT id, mail FROM accounts WHERE jwk IS NULL OR jsonb_typeof(jwk) <> 'object'")
        if bad_jwks:
            for row in bad_jwks:
                report.add_discrepancy(
                    Discrepancy(
                        category='Cryptographic & CA Readiness',
                        issue_type='Malformed Account JWK',
                        record_id=f'Account ID: {row["id"]}',
                        details={'Account ID': row['id'], 'Email': row['mail'] or 'None'},
                        action_needed='Regenerate synthetic valid JWK for account',
                        repair_type='malformed_account_jwk',
                    )
                )
        else:
            report.add_passed('All account public keys (JWK) are syntactically valid JSON objects.')

    return report


def render_report_to_terminal(report: IntegrityAuditReport) -> None:
    """Print the audit findings to the terminal with rich ANSI formatting."""
    _print()
    _print(f'{COLOR_CYAN_BOLD}{"=" * 80}{COLOR_RESET}')
    _print(f'{COLOR_CYAN_BOLD}               ACME CA SERVER - DATABASE INTEGRITY AUDIT{COLOR_RESET}')
    _print(f'{COLOR_CYAN_BOLD}{"=" * 80}{COLOR_RESET}')

    if not report.has_issues:
        _print(f'{COLOR_GREEN_BOLD}[*] Database verification complete: 0 integrity issues detected.{COLOR_RESET}')
        for passed in report.passed_checks:
            _print(f'  {COLOR_GREEN}[+] {passed}{COLOR_RESET}')
        _print(f'{COLOR_CYAN_BOLD}{"=" * 80}{COLOR_RESET}\n')
        return

    # Print blocking errors if any
    if report.has_errors:
        _print(f'{COLOR_RED_BOLD}[!] BLOCKING DATABASE ERRORS DETECTED ({len(report.errors)} issues):{COLOR_RESET}\n')
        current_cat = ''
        for idx, disc in enumerate(report.errors, 1):
            if disc.category != current_cat:
                current_cat = disc.category
                _print(f'{COLOR_CYAN_BOLD}--- Category: {current_cat} ---{COLOR_RESET}')

            _print(f'  {COLOR_RED_BOLD}#{idx}. [{disc.issue_type}] {disc.record_id}{COLOR_RESET}')
            for k, v in disc.details.items():
                _print(f'      {COLOR_BOLD}{k:<22}:{COLOR_RESET} {COLOR_YELLOW}{v}{COLOR_RESET}')
            if disc.action_needed:
                _print(f'      {COLOR_DIM}{"Action Proposed":<22}:{COLOR_RESET} {COLOR_GREEN}{disc.action_needed}{COLOR_RESET}')
            _print()

    # Print non-blocking warnings if any
    if report.has_warnings:
        _print(f'{COLOR_YELLOW_BOLD}[*] DATABASE INTEGRITY WARNINGS ({len(report.warnings)} issues - non-blocking):{COLOR_RESET}\n')
        current_cat = ''
        for idx, disc in enumerate(report.warnings, 1):
            if disc.category != current_cat:
                current_cat = disc.category
                _print(f'{COLOR_CYAN_BOLD}--- Category: {current_cat} ---{COLOR_RESET}')

            _print(f'  {COLOR_YELLOW_BOLD}#{idx}. [WARN: {disc.issue_type}] {disc.record_id}{COLOR_RESET}')
            for k, v in disc.details.items():
                _print(f'      {COLOR_BOLD}{k:<22}:{COLOR_RESET} {COLOR_YELLOW}{v}{COLOR_RESET}')
            if disc.action_needed:
                _print(f'      {COLOR_DIM}{"Action Proposed":<22}:{COLOR_RESET} {COLOR_GREEN}{disc.action_needed}{COLOR_RESET}')
            _print()

    # Print summary statistics
    _print(f'{COLOR_CYAN_BOLD}{"-" * 80}{COLOR_RESET}')
    err_part = f'{COLOR_RED_BOLD}{len(report.errors)} error(s) (blocking){COLOR_RESET}' if report.has_errors else f'{COLOR_GREEN}0 errors{COLOR_RESET}'
    warn_part = f'{COLOR_YELLOW_BOLD}{len(report.warnings)} warning(s){COLOR_RESET}' if report.has_warnings else '0 warnings'
    _print(
        f'{COLOR_BOLD}Integrity Summary: {COLOR_GREEN}{len(report.passed_checks)} checks passed{COLOR_RESET}, '
        f'{err_part}, {warn_part}.'
    )
    _print(f'{COLOR_CYAN_BOLD}{"=" * 80}{COLOR_RESET}\n')


async def prompt_for_repair(timeout_seconds: int | None = 60) -> bool:
    """Prompt the terminal operator with an optional countdown or indefinite wait."""
    # If auto-repair is enabled in settings or non-interactive environment
    if settings.db_integrity.auto_repair:
        _print(f"{COLOR_YELLOW}[Notice] 'db_integrity_auto_repair=True' set in configuration. Proceeding with auto-repair.{COLOR_RESET}\n")
        return True

    if not sys.stdin.isatty():
        _print(f'{COLOR_DIM}[Notice] Non-interactive environment detected (stdin is not a TTY). Skipping auto-repair prompt and continuing startup.{COLOR_RESET}\n')
        return False

    if timeout_seconds and timeout_seconds > 0:
        prompt_msg = (
            f'{COLOR_YELLOW_BOLD}--> Would you like to auto-repair discrepancies by inserting dummy records?\n    [y/N] (auto-skipping in {timeout_seconds}s): {COLOR_RESET}'
        )
    else:
        prompt_msg = f'{COLOR_YELLOW_BOLD}--> Would you like to auto-repair discrepancies by inserting dummy records?\n    [y/N]: {COLOR_RESET}'
    _print_raw(prompt_msg)

    loop = asyncio.get_running_loop()

    def _read_with_timeout(sec: int) -> str | None:
        start = time.monotonic()
        while (time.monotonic() - start) < sec:
            remaining = sec - (time.monotonic() - start)
            ready, _, _ = select.select([sys.stdin], [], [], min(1.0, max(0.1, remaining)))
            if ready:
                line = sys.stdin.readline()
                return line.strip()
        return None

    def _read_indefinite() -> str | None:
        line = sys.stdin.readline()
        return line.strip() if line else None

    try:
        if timeout_seconds and timeout_seconds > 0:
            user_input = await loop.run_in_executor(None, _read_with_timeout, timeout_seconds)
        else:
            user_input = await loop.run_in_executor(None, _read_indefinite)
    except Exception as exc:  # noqa: BLE001
        logger.warning('Error during terminal interactive prompt: %s', exc)
        return False

    if user_input is None:
        if timeout_seconds and timeout_seconds > 0:
            _print(f'\n{COLOR_DIM}[Timeout] {timeout_seconds}s elapsed without response. Continuing startup without repairs.{COLOR_RESET}\n')
        else:
            _print(f'\n{COLOR_DIM}[*] Cancelled.{COLOR_RESET}\n')
        return False

    _print()
    return user_input.strip().lower() in ('y', 'yes')


async def apply_repairs(report: IntegrityAuditReport) -> int:
    """Apply corrective actions by inserting dummy records or fixing relations in an atomic transaction."""
    repaired_count = 0
    _print(f'{COLOR_CYAN_BOLD}[*] Applying database repairs in atomic transaction...{COLOR_RESET}')

    async with db.transaction() as sql:
        for disc in report.discrepancies:
            rtype = disc.repair_type

            # Repair: Orphan Certificate -> create dummy order and dummy account
            if rtype == 'orphan_certificate':
                order_id = disc.details['Missing Order ID']
                # Check if order already created in this repair loop
                existing_ord = await sql.record('SELECT id, account_id FROM orders WHERE id = $1', order_id)
                if not existing_ord:
                    # Check or create dummy account
                    acc_id = _generate_random_id('dummy_acc')
                    dummy_mail = f'dummy-corrected-{acc_id[:8]}@repair.local'
                    jwk_payload = _generate_dummy_jwk(acc_id)
                    await sql.exec(
                        """
                        INSERT INTO accounts (id, mail, jwk, status, created_at)
                        VALUES ($1, $2, $3, 'valid', NOW())
                        ON CONFLICT (id) DO NOTHING
                        """,
                        acc_id,
                        dummy_mail,
                        jwk_payload,
                    )
                    await sql.exec(
                        """
                        INSERT INTO orders (id, account_id, status, expires_at)
                        VALUES ($1, $2, 'valid', NOW() + interval '365 days')
                        ON CONFLICT (id) DO NOTHING
                        """,
                        order_id,
                        acc_id,
                    )
                    # Also insert dummy authorization for this order so order is complete
                    authz_id = _generate_random_id('dummy_az')
                    domain = disc.details.get('Domain(s)', 'dummy-corrected.local').split(',')[0].strip()
                    if '.' not in domain or '*' in domain:
                        domain = 'dummy-corrected.local'
                    await sql.exec(
                        """
                        INSERT INTO authorizations (id, order_id, domain, status)
                        VALUES ($1, $2, $3, 'valid')
                        ON CONFLICT (id) DO NOTHING
                        """,
                        authz_id,
                        order_id,
                        domain,
                    )
                    ch_id = _generate_random_id('dummy_ch')
                    token = _generate_random_id('token')
                    await sql.exec(
                        """
                        INSERT INTO challenges (id, authz_id, status, token, type, validated_at)
                        VALUES ($1, $2, 'valid', $3, 'http-01', NOW())
                        ON CONFLICT (id) DO NOTHING
                        """,
                        ch_id,
                        authz_id,
                        token,
                    )
                    _print(f"  {COLOR_GREEN}[+] Created dummy Order '{order_id}' and dummy Account '{acc_id}' for orphan cert.{COLOR_RESET}")
                    repaired_count += 1

            # Repair: Orphan Authorization -> create dummy order and account
            elif rtype == 'orphan_authorization':
                order_id = disc.details['Missing Order ID']
                existing_ord = await sql.record('SELECT id FROM orders WHERE id = $1', order_id)
                if not existing_ord:
                    acc_id = _generate_random_id('dummy_acc')
                    dummy_mail = f'dummy-corrected-{acc_id[:8]}@repair.local'
                    jwk_payload = _generate_dummy_jwk(acc_id)
                    await sql.exec(
                        """
                        INSERT INTO accounts (id, mail, jwk, status, created_at)
                        VALUES ($1, $2, $3, 'valid', NOW())
                        ON CONFLICT (id) DO NOTHING
                        """,
                        acc_id,
                        dummy_mail,
                        jwk_payload,
                    )
                    await sql.exec(
                        """
                        INSERT INTO orders (id, account_id, status, expires_at)
                        VALUES ($1, $2, 'valid', NOW() + interval '30 days')
                        ON CONFLICT (id) DO NOTHING
                        """,
                        order_id,
                        acc_id,
                    )
                    _print(f"  {COLOR_GREEN}[+] Created dummy Order '{order_id}' for orphan authorization.{COLOR_RESET}")
                    repaired_count += 1

            # Repair: Orphan Challenge -> create dummy authorization
            elif rtype == 'orphan_challenge':
                authz_id = disc.details['Missing Authz ID']
                existing_az = await sql.record('SELECT id FROM authorizations WHERE id = $1', authz_id)
                if not existing_az:
                    # Create parent order
                    ord_id = _generate_random_id('dummy_ord')
                    acc_id = _generate_random_id('dummy_acc')
                    dummy_mail = f'dummy-corrected-{acc_id[:8]}@repair.local'
                    jwk_payload = _generate_dummy_jwk(acc_id)
                    await sql.exec(
                        """
                        INSERT INTO accounts (id, mail, jwk, status, created_at)
                        VALUES ($1, $2, $3, 'valid', NOW())
                        ON CONFLICT (id) DO NOTHING
                        """,
                        acc_id,
                        dummy_mail,
                        jwk_payload,
                    )
                    await sql.exec(
                        """
                        INSERT INTO orders (id, account_id, status, expires_at)
                        VALUES ($1, $2, 'valid', NOW() + interval '30 days')
                        ON CONFLICT (id) DO NOTHING
                        """,
                        ord_id,
                        acc_id,
                    )
                    await sql.exec(
                        """
                        INSERT INTO authorizations (id, order_id, domain, status)
                        VALUES ($1, $2, 'dummy-corrected.local', 'valid')
                        ON CONFLICT (id) DO NOTHING
                        """,
                        authz_id,
                        ord_id,
                    )
                    _print(f"  {COLOR_GREEN}[+] Created dummy Authorization '{authz_id}' for orphan challenge.{COLOR_RESET}")
                    repaired_count += 1

            # Repair: Orphan Order -> create dummy account
            elif rtype == 'orphan_order':
                acc_id = disc.details['Missing Account ID']
                existing_acc = await sql.record('SELECT id FROM accounts WHERE id = $1', acc_id)
                if not existing_acc:
                    dummy_mail = f'dummy-corrected-{acc_id[:8]}@repair.local'
                    jwk_payload = _generate_dummy_jwk(acc_id)
                    await sql.exec(
                        """
                        INSERT INTO accounts (id, mail, jwk, status, created_at)
                        VALUES ($1, $2, $3, 'valid', NOW())
                        ON CONFLICT (id) DO NOTHING
                        """,
                        acc_id,
                        dummy_mail,
                        jwk_payload,
                    )
                    _print(f"  {COLOR_GREEN}[+] Created dummy Account '{acc_id}' for orphan order.{COLOR_RESET}")
                    repaired_count += 1

            # Repair: Valid Order Missing Cert -> transition order status to invalid with error
            elif rtype == 'valid_order_missing_cert':
                ord_id = disc.details['Order ID']
                await sql.exec(
                    """
                    UPDATE orders
                    SET status = 'invalid', error = ROW('serverInternal', 'Auto-corrected: order had valid status without issued certificate')::acme_error
                    WHERE id = $1 AND status = 'valid'
                    """,
                    ord_id,
                )
                _print(f"  {COLOR_GREEN}[+] Corrected Order '{ord_id}' status to 'invalid'.{COLOR_RESET}")
                repaired_count += 1

            # Repair: Order without Authorizations -> create dummy authorization & challenge
            elif rtype == 'order_without_authz':
                ord_id = disc.details['Order ID']
                authz_id = _generate_random_id('dummy_az')
                await sql.exec(
                    """
                    INSERT INTO authorizations (id, order_id, domain, status)
                    VALUES ($1, $2, 'dummy-corrected.local', 'valid')
                    ON CONFLICT (id) DO NOTHING
                    """,
                    authz_id,
                    ord_id,
                )
                ch_id = _generate_random_id('dummy_ch')
                token = _generate_random_id('token')
                await sql.exec(
                    """
                    INSERT INTO challenges (id, authz_id, status, token, type, validated_at)
                    VALUES ($1, $2, 'valid', $3, 'http-01', NOW())
                    ON CONFLICT (id) DO NOTHING
                    """,
                    ch_id,
                    authz_id,
                    token,
                )
                _print(f"  {COLOR_GREEN}[+] Added dummy Authorization & Challenge to Order '{ord_id}'.{COLOR_RESET}")
                repaired_count += 1

            # Repair: Authorization without Challenges -> create dummy challenge
            elif rtype == 'authz_without_challenge':
                authz_id = disc.details['Authorization ID']
                ch_id = _generate_random_id('dummy_ch')
                token = _generate_random_id('token')
                await sql.exec(
                    """
                    INSERT INTO challenges (id, authz_id, status, token, type, validated_at)
                    VALUES ($1, $2, 'valid', $3, 'http-01', NOW())
                    ON CONFLICT (id) DO NOTHING
                    """,
                    ch_id,
                    authz_id,
                    token,
                )
                _print(f"  {COLOR_GREEN}[+] Added dummy Challenge to Authorization '{authz_id}'.{COLOR_RESET}")
                repaired_count += 1

            # Repair: Certificate on Non-Valid Order -> update order status to valid
            elif rtype == 'cert_on_non_valid_order':
                ord_id = disc.details['Order ID']
                await sql.exec("UPDATE orders SET status = 'valid', error = NULL WHERE id = $1", ord_id)
                _print(f"  {COLOR_GREEN}[+] Synchronized Order '{ord_id}' status to 'valid'.{COLOR_RESET}")
                repaired_count += 1

            # Repair: Expired Pending Order -> set status to invalid
            elif rtype == 'expired_pending_order':
                ord_id = disc.details['Order ID']
                await sql.exec(
                    """
                    UPDATE orders
                    SET status = 'invalid', error = ROW('malformed', 'Order expired prior to authorization')::acme_error
                    WHERE id = $1 AND status IN ('pending', 'processing')
                    """,
                    ord_id,
                )
                _print(f"  {COLOR_GREEN}[+] Marked expired Order '{ord_id}' as 'invalid'.{COLOR_RESET}")
                repaired_count += 1

            # Repair: Malformed Account JWK -> set synthetic valid JWK
            elif rtype == 'malformed_account_jwk':
                acc_id = disc.details['Account ID']
                jwk_payload = _generate_dummy_jwk(acc_id)
                await sql.exec('UPDATE accounts SET jwk = $1 WHERE id = $2', json.dumps(jwk_payload), acc_id)
                _print(f"  {COLOR_GREEN}[+] Reset valid synthetic JWK for Account '{acc_id}'.{COLOR_RESET}")
                repaired_count += 1

    _print(f'{COLOR_GREEN_BOLD}[*] Database repair transaction committed successfully ({repaired_count} corrections applied).{COLOR_RESET}\n')
    return repaired_count


async def run_integrity_check_workflow(
    timeout_seconds: int | None = settings.db_integrity.prompt_timeout,
    auto_repair: bool | None = None,
) -> int:
    """Execute complete workflow: scan -> terminal report -> prompt -> optional repair.

    Returns the number of repairs applied (0 if clean or not repaired).
    """
    report = await inspect_database()
    render_report_to_terminal(report)

    if report.has_issues:
        if auto_repair is True:
            return await apply_repairs(report)
        elif auto_repair is False:
            return 0

        # During standard startup, only prompt and halt for blocking ERRORS!
        if report.requires_repair_prompt:
            should_repair = await prompt_for_repair(timeout_seconds=timeout_seconds)
            if should_repair:
                return await apply_repairs(report)
        elif report.has_warnings:
            logger.info('Database integrity audit completed with %d non-blocking warning(s). Startup continuing.', len(report.warnings))

    return 0


def main() -> None:
    """CLI entry point for standalone database integrity inspection and repair."""
    parser = argparse.ArgumentParser(
        description='ACME CA Server - Database Integrity Inspection & Repair Utility',
    )
    parser.add_argument(
        '--check-only',
        action='store_true',
        help='Run inspection and render audit report only (do not prompt or repair).',
    )
    parser.add_argument(
        '-y',
        '--yes',
        '--repair',
        dest='auto_repair',
        action='store_true',
        help='Automatically apply repairs without interactive confirmation.',
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=0,
        help='Countdown timeout in seconds for repair prompt (default: 0, wait indefinitely).',
    )
    args = parser.parse_args()

    async def _runner() -> None:
        try:
            repair_mode: bool | None = None
            if args.check_only:
                repair_mode = False
            elif args.auto_repair:
                repair_mode = True

            timeout = args.timeout if args.timeout > 0 else None
            await run_integrity_check_workflow(timeout_seconds=timeout, auto_repair=repair_mode)
        finally:
            await db.disconnect()

    try:
        asyncio.run(_runner())
    except KeyboardInterrupt:
        _print(f'\n{COLOR_DIM}[*] Operation cancelled by operator.{COLOR_RESET}')
        sys.exit(130)


if __name__ == '__main__':
    main()
