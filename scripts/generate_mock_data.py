#!/usr/bin/env python3
"""
ACME CA Server - Mock Data Generation Utility
Generates realistic dummy data in PostgreSQL development database:
  - Accounts (>= 20) with RSA and ECDSA keys across valid, deactivated, and revoked states
  - Domains (>= 30) across single-domain and multi-SAN configurations
  - Orders (>= 100) across valid, pending, processing, and invalid states with ACME errors
  - Certificates (>= 90) across valid, expiring (<=20 days), expired, and revoked states

Preserves active Root CA and administrative user accounts.
"""

import argparse
import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import random
import secrets
import sys

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

REPO_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = REPO_DIR / '.env'

# Load environment configuration (.env)
if ENV_FILE.exists():
    with open(ENV_FILE) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                os.environ.setdefault(k, v)

try:
    import asyncpg
except ImportError:
    print("Error: 'asyncpg' is not installed. Ensure script is run inside .venv.")
    sys.exit(1)


# Sample domain names across various environments and root zones
DOMAINS_POOL = [
    'api.example.com',
    'auth.example.com',
    'admin.example.com',
    'cdn.example.com',
    'web.example.com',
    'cloud.example.org',
    'vpn.example.org',
    'metrics.example.org',
    'git.example.org',
    'vault.example.org',
    'app.internal.net',
    'db.internal.net',
    'k8s.internal.net',
    'registry.internal.net',
    'cluster.internal.net',
    'shop.platform.io',
    'checkout.platform.io',
    'pay.platform.io',
    'ws.platform.io',
    'events.platform.io',
    'status.network.dev',
    'monitor.network.dev',
    'logger.network.dev',
    'grafana.network.dev',
    'tracing.network.dev',
    'mail.corp.com',
    'smtp.corp.com',
    'imap.corp.com',
    'relay.corp.com',
    'portal.service.tech',
    'gateway.service.tech',
    'ingress.service.tech',
    'proxy.service.tech',
    'iot.device.local',
    'sensor.device.local',
    'edge.device.local',
    'hub.device.local',
    'staging.web.app',
    'test.web.app',
    'demo.web.app',
    'beta.web.app',
]

ACCOUNT_EMAILS = [
    'devops@example.com',
    'sre-team@example.com',
    'infra@example.org',
    'security@example.org',
    'platform@internal.net',
    'backend-leads@platform.io',
    'ops-automation@network.dev',
    'sysadmin@corp.com',
    'monitoring@service.tech',
    'edge-gateway@device.local',
    'cert-manager@web.app',
    'traefik-ingress@k8s.net',
    'caddy-proxy@cloud.org',
    'lego-bot@example.com',
    'uacme-router@openwrt.org',
    'cluster-operator@internal.net',
    'qa-lead@staging.io',
    'billing-service@platform.io',
    'iot-collector@device.local',
    'telemetry@network.dev',
    'auth-service@corp.com',
    'legacy-app@example.org',
    'compliance-audit@corp.com',
    'release-manager@web.app',
    'gateway-fleet@service.tech',
]

ACME_ERROR_TEMPLATES = [
    ('dns', "DNS record for domain '{domain}' not found: NXDOMAIN response from resolver"),
    ('connection', "Failed to connect to {domain}:80 (TCP connection timeout / firewall drop)"),
    ('unauthorized', "Key authorization does not match challenge token for '{domain}'"),
    ('incorrectResponse', "HTTP 404 Not Found returned when fetching /.well-known/acme-challenge/ for '{domain}'"),
    ('malformed', "Invalid identifier format or disallowed character in domain '{domain}'"),
    ('serverInternal', "Validation timeout after 3 retries against remote resolver for '{domain}'"),
    ('dns', "DNS SERVFAIL returned while resolving CAA record for '{domain}'"),
]


def generate_random_id() -> str:
    """Generate a high-entropy ACME random_id (>20 characters)."""
    return secrets.token_urlsafe(24)


def generate_hex_serial() -> str:
    """Generate an uppercase hex serial number."""
    val = secrets.randbits(128)
    return hex(val)[2:].upper()


def generate_jwk(key_type: str = 'RSA') -> dict:
    """Generate a valid JWK dictionary for an account."""
    if key_type == 'RSA':
        bits = random.choice([2048, 4096])
        n_len = (bits // 8)
        dummy_n = secrets.token_urlsafe(n_len)
        return {
            'kty': 'RSA',
            'n': dummy_n,
            'e': 'AQAB',
        }
    else:
        crv = random.choice(['P-256', 'P-384'])
        coord_len = 32 if crv == 'P-256' else 48
        return {
            'kty': 'EC',
            'crv': crv,
            'x': secrets.token_urlsafe(coord_len),
            'y': secrets.token_urlsafe(coord_len),
        }


def load_ca_key_and_cert(cert_pem_str: str, key_pem_enc: bytes, encryption_key: str):
    """Load active CA certificate and decrypted private key."""
    f = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)
    key_pem = f.decrypt(key_pem_enc)
    ca_key = serialization.load_pem_private_key(key_pem, password=None)
    ca_cert = x509.load_pem_x509_certificate(cert_pem_str.encode())
    return ca_cert, ca_key


def generate_leaf_cert(
    primary_domain: str,
    san_domains: list[str],
    not_valid_before: datetime,
    not_valid_after: datetime,
    ca_cert: x509.Certificate = None,
    ca_key = None,
) -> tuple[str, str, str]:
    """Generate CSR and X.509 certificate chain (PEM)."""
    # Generate leaf key
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Generate CSR
    san_names = [x509.DNSName(primary_domain)]
    for san in san_domains:
        if san != primary_domain:
            san_names.append(x509.DNSName(san))

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, primary_domain)]))
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .sign(leaf_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

    # Sign certificate using CA or self-sign
    issuer_name = ca_cert.subject if ca_cert else csr.subject
    signing_key = ca_key if ca_key else leaf_key

    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_name)
        .public_key(leaf_key.public_key())
        .serial_number(secrets.randbits(128))
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .sign(signing_key, hashes.SHA256())
    )

    leaf_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    serial_hex = hex(cert.serial_number)[2:].upper()

    if ca_cert:
        ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
        chain_pem = f"{leaf_pem.strip()}\n{ca_pem.strip()}\n"
    else:
        chain_pem = leaf_pem

    return serial_hex, csr_pem, chain_pem


async def populate_mock_data(
    dsn: str,
    clean: bool = True,
    target_accounts: int = 25,
    target_orders: int = 115,
    target_certs: int = 95,
    target_domains: int = 35,
):
    print("=" * 65)
    print(" ACME CA Server - Populating Development Database")
    print(f" Target: >={target_accounts} Accounts, >={target_orders} Orders, >={target_certs} Certs, >={target_domains} Domains")
    print("=" * 65)

    conn = await asyncpg.connect(dsn)

    # 1. Inspect existing CA
    ca_row = await conn.fetchrow("SELECT serial_number, cert_pem, key_pem_enc FROM cas WHERE active = true")
    ca_cert = None
    ca_key = None
    if ca_row:
        enc_key = os.environ.get('CA_ENCRYPTION_KEY', '')
        if enc_key:
            try:
                ca_cert, ca_key = load_ca_key_and_cert(ca_row['cert_pem'], ca_row['key_pem_enc'], enc_key)
                print(f"--> Found active Root CA: SN {ca_row['serial_number'][:8]}... (Certificates will be CA-signed)")
            except Exception as e:
                print(f"--> Notice: Could not decrypt active CA ({e}), self-signing fallback will be used.")
        else:
            print("--> Notice: CA_ENCRYPTION_KEY unset, self-signing fallback will be used.")
    else:
        print("--> Notice: No active Root CA found in DB, self-signing fallback will be used.")

    # 2. Clean previous mock data if requested
    if clean:
        print("--> Cleaning previous mock data (preserving Root CA and admin users)...")
        async with conn.transaction():
            await conn.execute("DELETE FROM certificates")
            await conn.execute("DELETE FROM challenges")
            await conn.execute("DELETE FROM authorizations")
            await conn.execute("DELETE FROM orders")
            await conn.execute("DELETE FROM nonces")
            await conn.execute("DELETE FROM accounts")
        print("    Clean complete!")

    now = datetime.now(timezone.utc)

    # 3. Insert Accounts
    print(f"--> Generating {target_accounts} accounts...")
    accounts = []
    account_statuses = ['valid'] * 18 + ['deactivated'] * 4 + ['revoked'] * 3
    random.shuffle(account_statuses)

    for i in range(target_accounts):
        acc_id = generate_random_id()
        email = ACCOUNT_EMAILS[i % len(ACCOUNT_EMAILS)]
        if i >= len(ACCOUNT_EMAILS):
            user, host = email.split('@')
            email = f"{user}+{i}@{host}"
        
        status = account_statuses[i % len(account_statuses)]
        key_type = 'RSA' if (i % 3 != 0) else 'EC'
        jwk_dict = generate_jwk(key_type)
        created_at = now - timedelta(days=random.randint(15, 300), hours=random.randint(1, 23))

        await conn.execute(
            """
            INSERT INTO accounts (id, mail, jwk, status, created_at)
            VALUES ($1, $2, $3, $4, $5)
            """,
            acc_id,
            email,
            json.dumps(jwk_dict),
            status,
            created_at,
        )
        accounts.append({'id': acc_id, 'email': email, 'status': status, 'created_at': created_at})

    # Select domain pool
    domains_subset = DOMAINS_POOL[:max(target_domains, len(DOMAINS_POOL))]
    random.shuffle(domains_subset)

    # 4. Generate Orders, Authorizations, Challenges, and Certificates
    print(f"--> Generating {target_orders} orders & {target_certs} certificates across all states...")

    # We distribute certificates into 4 categories:
    # - Valid active (e.g. 52): not_valid_after between now + 30d and now + 90d
    # - Expiring (e.g. 15): not_valid_after between now + 2d and now + 19d (<= 20 days)
    # - Expired (e.g. 16): not_valid_after in the past (now - 5d to now - 120d)
    # - Revoked (e.g. 12): revoked_at set to timestamp in past
    # Total certificates = 95
    cert_categories = (
        ['valid_active'] * 52 +
        ['expiring'] * 15 +
        ['expired'] * 16 +
        ['revoked'] * 12
    )
    random.shuffle(cert_categories)

    # Non-certificate orders (115 - 95 = 20 orders):
    # - 7 pending orders
    # - 3 processing / ready orders
    # - 10 invalid / failed orders
    order_categories = cert_categories + ['pending'] * 7 + ['processing'] * 3 + ['invalid'] * 10
    random.shuffle(order_categories)

    certs_created = 0
    orders_created = 0
    domains_covered = set()

    for idx, cat in enumerate(order_categories):
        order_id = generate_random_id()
        account = random.choice(accounts)
        
        # Pick 1 to 3 domains for this order
        primary_domain = domains_subset[idx % len(domains_subset)]
        domains_covered.add(primary_domain)
        san_list = [primary_domain]
        if random.random() < 0.35:  # Multi-SAN certificate
            extra_san = random.choice(domains_subset)
            if extra_san != primary_domain:
                san_list.append(extra_san)
                domains_covered.add(extra_san)

        authz_ids = []

        if cat in ('valid_active', 'expiring', 'expired', 'revoked'):
            # Valid order yielding certificate
            order_status = 'valid'
            order_error = None
            order_expires = now + timedelta(days=random.randint(1, 30))

            # Insert order
            await conn.execute(
                """
                INSERT INTO orders (id, account_id, status, error, expires_at)
                VALUES ($1, $2, $3, $4, $5)
                """,
                order_id,
                account['id'],
                order_status,
                order_error,
                order_expires,
            )

            # Insert authorizations & challenges
            for dom in san_list:
                authz_id = generate_random_id()
                await conn.execute(
                    """
                    INSERT INTO authorizations (id, order_id, status, domain)
                    VALUES ($1, $2, 'valid', $3)
                    """,
                    authz_id,
                    order_id,
                    dom,
                )
                chal_type = 'http-01' if random.random() < 0.7 else 'dns-01'
                await conn.execute(
                    """
                    INSERT INTO challenges (id, authz_id, type, status, token, validated_at, error)
                    VALUES ($1, $2, $3, 'valid', $4, $5, NULL)
                    """,
                    generate_random_id(),
                    authz_id,
                    chal_type,
                    generate_random_id(),
                    now - timedelta(days=random.randint(1, 30)),
                )

            # Determine certificate validity timelines
            if cat == 'valid_active':
                nvb = now - timedelta(days=random.randint(5, 60))
                nva = now + timedelta(days=random.randint(30, 90))
                revoked_at = None
            elif cat == 'expiring':
                nvb = now - timedelta(days=random.randint(40, 70))
                nva = now + timedelta(days=random.randint(2, 19), hours=random.randint(1, 23))  # <= 20 days!
                revoked_at = None
            elif cat == 'expired':
                nvb = now - timedelta(days=random.randint(100, 200))
                nva = now - timedelta(days=random.randint(2, 60))
                revoked_at = None
            else:  # revoked
                nvb = now - timedelta(days=random.randint(30, 80))
                nva = nvb + timedelta(days=90)
                revoked_at = nvb + timedelta(days=random.randint(5, 25))

            sn_hex, csr_pem, chain_pem = generate_leaf_cert(
                primary_domain=primary_domain,
                san_domains=san_list,
                not_valid_before=nvb,
                not_valid_after=nva,
                ca_cert=ca_cert,
                ca_key=ca_key,
            )

            await conn.execute(
                """
                INSERT INTO certificates (serial_number, csr_pem, chain_pem, order_id, not_valid_before, not_valid_after, revoked_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                sn_hex,
                csr_pem,
                chain_pem,
                order_id,
                nvb,
                nva,
                revoked_at,
            )
            certs_created += 1

        elif cat == 'pending':
            order_status = 'pending'
            order_error = None
            order_expires = now + timedelta(hours=random.randint(2, 72))

            await conn.execute(
                """
                INSERT INTO orders (id, account_id, status, error, expires_at)
                VALUES ($1, $2, $3, $4, $5)
                """,
                order_id,
                account['id'],
                order_status,
                order_error,
                order_expires,
            )

            for dom in san_list:
                authz_id = generate_random_id()
                await conn.execute(
                    """
                    INSERT INTO authorizations (id, order_id, status, domain)
                    VALUES ($1, $2, 'pending', $3)
                    """,
                    authz_id,
                    order_id,
                    dom,
                )
                await conn.execute(
                    """
                    INSERT INTO challenges (id, authz_id, type, status, token, validated_at, error)
                    VALUES ($1, $2, 'http-01', 'pending', $3, NULL, NULL)
                    """,
                    generate_random_id(),
                    authz_id,
                    generate_random_id(),
                )

        elif cat == 'processing':
            order_status = random.choice(['processing', 'ready'])
            order_error = None
            order_expires = now + timedelta(hours=random.randint(1, 24))

            await conn.execute(
                """
                INSERT INTO orders (id, account_id, status, error, expires_at)
                VALUES ($1, $2, $3, $4, $5)
                """,
                order_id,
                account['id'],
                order_status,
                order_error,
                order_expires,
            )

            for dom in san_list:
                authz_id = generate_random_id()
                await conn.execute(
                    """
                    INSERT INTO authorizations (id, order_id, status, domain)
                    VALUES ($1, $2, 'valid', $3)
                    """,
                    authz_id,
                    order_id,
                    dom,
                )
                await conn.execute(
                    """
                    INSERT INTO challenges (id, authz_id, type, status, token, validated_at, error)
                    VALUES ($1, $2, 'http-01', 'valid', $3, $4, NULL)
                    """,
                    generate_random_id(),
                    authz_id,
                    generate_random_id(),
                    now - timedelta(minutes=10),
                )

        else:  # invalid
            order_status = 'invalid'
            err_type, err_template = random.choice(ACME_ERROR_TEMPLATES)
            err_detail = err_template.format(domain=primary_domain)
            order_expires = now - timedelta(hours=random.randint(1, 48))

            await conn.execute(
                """
                INSERT INTO orders (id, account_id, status, error, expires_at)
                VALUES ($1, $2, $3, ROW($4, $5)::acme_error, $6)
                """,
                order_id,
                account['id'],
                order_status,
                err_type,
                err_detail,
                order_expires,
            )

            for dom in san_list:
                authz_id = generate_random_id()
                await conn.execute(
                    """
                    INSERT INTO authorizations (id, order_id, status, domain)
                    VALUES ($1, $2, 'invalid', $3)
                    """,
                    authz_id,
                    order_id,
                    dom,
                )
                await conn.execute(
                    """
                    INSERT INTO challenges (id, authz_id, type, status, token, validated_at, error)
                    VALUES ($1, $2, 'http-01', 'invalid', $3, NULL, ROW($4, $5)::acme_error)
                    """,
                    generate_random_id(),
                    authz_id,
                    generate_random_id(),
                    err_type,
                    err_detail,
                )

        orders_created += 1

    # 5. Summary Verification
    acc_count = await conn.fetchval("SELECT count(*) FROM accounts")
    ord_count = await conn.fetchval("SELECT count(*) FROM orders")
    cert_count = await conn.fetchval("SELECT count(*) FROM certificates")
    dom_count = await conn.fetchval("SELECT count(DISTINCT domain) FROM authorizations")

    valid_certs = await conn.fetchval("SELECT count(*) FROM certificates WHERE not_valid_after > now() AND revoked_at IS NULL")
    expiring_certs = await conn.fetchval("SELECT count(*) FROM certificates WHERE not_valid_after > now() AND revoked_at IS NULL AND not_valid_after - now() <= interval '20 days'")
    expired_certs = await conn.fetchval("SELECT count(*) FROM certificates WHERE not_valid_after <= now() AND revoked_at IS NULL")
    revoked_certs = await conn.fetchval("SELECT count(*) FROM certificates WHERE revoked_at IS NULL IS FALSE")

    valid_orders = await conn.fetchval("SELECT count(*) FROM orders WHERE status = 'valid'")
    pending_orders = await conn.fetchval("SELECT count(*) FROM orders WHERE status = 'pending'")
    proc_orders = await conn.fetchval("SELECT count(*) FROM orders WHERE status IN ('processing', 'ready')")
    invalid_orders = await conn.fetchval("SELECT count(*) FROM orders WHERE status = 'invalid'")

    await conn.close()

    print("\n" + "=" * 65)
    print("        MOCK DATA GENERATION COMPLETE")
    print("=" * 65)
    print(f" Accounts Total       : {acc_count} (Target: >= {target_accounts})")
    print(f" Domains Tracked      : {dom_count} (Target: >= {target_domains})")
    print(f" Orders Total         : {ord_count} (Target: >= {target_orders})")
    print(f"   - Valid            : {valid_orders}")
    print(f"   - Pending          : {pending_orders}")
    print(f"   - Ready/Processing : {proc_orders}")
    print(f"   - Invalid (Errors) : {invalid_orders}")
    print(f" Certificates Total   : {cert_count} (Target: >= {target_certs})")
    print(f"   - Active Valid     : {valid_certs}")
    print(f"   - Expiring (<=20d) : {expiring_certs}")
    print(f"   - Expired          : {expired_certs}")
    print(f"   - Revoked          : {revoked_certs}")
    print("=" * 65)


def main():
    parser = argparse.ArgumentParser(description="Generate realistic mock data for ACME CA Server")
    parser.add_argument('--dsn', default=os.environ.get('DB_DSN', 'postgresql://postgres:secret@localhost:5432/postgres'), help="PostgreSQL DSN")
    parser.add_argument('--accounts', type=int, default=25, help="Minimum accounts to generate (default: 25)")
    parser.add_argument('--orders', type=int, default=115, help="Minimum orders to generate (default: 115)")
    parser.add_argument('--certs', type=int, default=95, help="Minimum certificates to generate (default: 95)")
    parser.add_argument('--domains', type=int, default=35, help="Minimum domains to generate (default: 35)")
    parser.add_argument('--append', action='store_true', help="Append to existing data instead of cleaning mock tables first")

    args = parser.parse_args()

    asyncio.run(
        populate_mock_data(
            dsn=args.dsn,
            clean=not args.append,
            target_accounts=args.accounts,
            target_orders=args.orders,
            target_certs=args.certs,
            target_domains=args.domains,
        )
    )


if __name__ == '__main__':
    main()
