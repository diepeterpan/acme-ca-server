import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import db
from acme.certificate.service import SerialNumberConverter
from config import settings
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from logger import logger

from .model import SignedCertInfo


async def sign_csr(csr: x509.CertificateSigningRequest, subject_domain: str, san_domains: list[str]) -> SignedCertInfo:
    """
    csr: the parsed csr object
    subject_domain: the main requested domain name
    san_domains: the alternative (additional) requested domain names
    """
    if not settings.ca.enabled:
        raise RuntimeError('internal ca is not enabled (env var CA_ENABLED)! Please provide a custom ca implementation')

    ca_cert, ca_key = await load_active_ca()

    cert, cert_chain_pem = await asyncio.to_thread(generate_cert_sync, ca_key=ca_key, ca_cert=ca_cert, csr=csr, subject_domain=subject_domain, san_domains=san_domains)

    return SignedCertInfo(cert=cert, cert_chain_pem=cert_chain_pem)


async def revoke_cert(serial_number: str, revocations: set[tuple[str, datetime]]) -> None:  # pylint: disable=unused-argument
    if not settings.ca.enabled:
        raise RuntimeError('internal ca is not enabled (env var CA_ENABLED)! Please provide a custom ca implementation')
    ca_cert, ca_key = await load_active_ca()
    _, crl_pem = await asyncio.to_thread(build_crl_sync, ca_key=ca_key, ca_cert=ca_cert, revocations=revocations)
    async with db.transaction() as sql:
        await sql.exec("""update cas set crl_pem = $1 where active = true""", crl_pem)


async def load_active_ca():
    async with db.transaction(readonly=True) as sql:
        cert_pem, key_pem_enc = await sql.record("""select cert_pem, key_pem_enc from cas where active = true""")
    return await asyncio.to_thread(load_ca_sync, cert_pem=cert_pem, key_pem_enc=key_pem_enc)


def load_ca_sync(*, cert_pem, key_pem_enc):
    f = Fernet(settings.ca.encryption_key.get_secret_value())
    key_pem = f.decrypt(key_pem_enc)
    ca_key = serialization.load_pem_private_key(key_pem, None)
    ca_cert = x509.load_pem_x509_certificate(cert_pem.encode(), None)
    return ca_cert, ca_key


def generate_cert_sync(*, ca_key: PrivateKeyTypes, ca_cert: x509.Certificate, csr: x509.CertificateSigningRequest, subject_domain: str, san_domains: list[str]):
    ca_id = SerialNumberConverter.int2hex(ca_cert.serial_number)

    cert_builder = x509.CertificateBuilder(
        issuer_name=ca_cert.subject,
        subject_name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_domain)]),
        serial_number=x509.random_serial_number(),
        not_valid_before=datetime.now(timezone.utc),
        not_valid_after=datetime.now(timezone.utc) + settings.ca.cert_lifetime,
        public_key=csr.public_key(),
    ).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    if settings.ca.cert_cdp_enabled:
        cdp_uri = str(settings.external_url).lower().removesuffix('/') + f'/ca/{ca_id}/crl'
        if cdp_uri.startswith('https://'):
            # CDP URI should always be HTTP, not HTTPS:
            # https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.13
            # https://datatracker.ietf.org/doc/html/rfc5280#section-8
            cdp_uri = cdp_uri.replace('https://', 'http://', 1)
        cert_builder = cert_builder.add_extension(
            x509.CRLDistributionPoints(
                distribution_points=[
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(cdp_uri)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
    cert_builder = (
        cert_builder.add_extension(x509.SubjectAlternativeName(general_names=[x509.DNSName(domain) for domain in san_domains]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage(usages=[x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH, x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    )

    cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA512())  # type: ignore[arg-type]

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    cert_chain_pem = (cert_pem + ca_cert_pem).decode()

    return cert, cert_chain_pem


def build_crl_sync(*, ca_key: PrivateKeyTypes, ca_cert: x509.Certificate, revocations: set[tuple[str, datetime]]):
    now = datetime.now(timezone.utc)
    builder = x509.CertificateRevocationListBuilder(
        last_update=now,
        next_update=now + settings.ca.crl_lifetime,
        issuer_name=ca_cert.subject,
    )
    for serial_number, revoked_at in revocations:
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(SerialNumberConverter.hex2int(serial_number)).revocation_date(revoked_at).build()
        builder = builder.add_revoked_certificate(revoked_cert)
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA512())  # type: ignore[arg-type]
    crl_pem = crl.public_bytes(encoding=serialization.Encoding.PEM).decode()
    return crl, crl_pem


def generate_root_ca_sync(
    *,
    common_name: str,
    organization: str | None = None,
    organizational_unit: str | None = None,
    country: str | None = None,
    state: str | None = None,
    locality: str | None = None,
    key_type: str = 'RSA',
    key_size_or_curve: str = '4096',
    digest_algorithm: str = 'SHA-384',
    validity_years: int = 10,
):
    key_type = (key_type or 'RSA').strip().upper()
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    if key_type == 'RSA':
        key_size = int(key_size_or_curve or 4096)
        if key_size not in (2048, 3072, 4096):
            raise ValueError(f'Unsupported RSA key size: {key_size}')
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_type == 'ECDSA':
        curve_name = (key_size_or_curve or 'P-384').strip().upper()
        curve: ec.EllipticCurve
        if curve_name in ('P-256', 'SECP256R1'):
            curve = ec.SECP256R1()
        elif curve_name in ('P-384', 'SECP384R1'):
            curve = ec.SECP384R1()
        elif curve_name in ('P-521', 'SECP521R1'):
            curve = ec.SECP521R1()
        else:
            raise ValueError(f'Unsupported ECDSA curve: {key_size_or_curve}')
        private_key = ec.generate_private_key(curve)
    else:
        raise ValueError(f'Unsupported key type: {key_type}')

    digest_name = (digest_algorithm or 'SHA-384').strip().upper()
    hash_algo: hashes.HashAlgorithm
    if digest_name == 'SHA-256':
        hash_algo = hashes.SHA256()
    elif digest_name == 'SHA-384':
        hash_algo = hashes.SHA384()
    elif digest_name == 'SHA-512':
        hash_algo = hashes.SHA512()
    else:
        raise ValueError(f'Unsupported digest algorithm: {digest_algorithm}')

    name_attributes = [x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name.strip())]
    if organization and organization.strip():
        name_attributes.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization.strip()))
    if organizational_unit and organizational_unit.strip():
        name_attributes.append(x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit.strip()))
    if country and country.strip():
        c_code = country.strip().upper()
        if len(c_code) != 2 or not c_code.isalpha():
            raise ValueError(f'Country must be a 2-letter ISO code, not: {country}')
        name_attributes.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME, c_code))
    if state and state.strip():
        name_attributes.append(x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, state.strip()))
    if locality and locality.strip():
        name_attributes.append(x509.NameAttribute(x509.NameOID.LOCALITY_NAME, locality.strip()))

    subject = x509.Name(name_attributes)
    issuer = subject

    now = datetime.now(timezone.utc)
    not_valid_before = now
    not_valid_after = now + timedelta(days=int(validity_years) * 365)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False,
        )
    )

    cert = builder.sign(private_key=private_key, algorithm=hash_algo)
    cert_pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
    key_pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    _, crl_pem = build_crl_sync(ca_key=private_key, ca_cert=cert, revocations=set())

    return cert, cert_pem_bytes, key_pem_bytes, crl_pem


async def create_root_ca(
    *,
    common_name: str,
    organization: str | None = None,
    organizational_unit: str | None = None,
    country: str | None = None,
    state: str | None = None,
    locality: str | None = None,
    key_type: str = 'RSA',
    key_size_or_curve: str = '4096',
    digest_algorithm: str = 'SHA-384',
    validity_years: int = 10,
) -> str:
    import acme  # pylint: disable=import-outside-toplevel

    import ca  # pylint: disable=import-outside-toplevel

    cert, cert_pem_bytes, key_pem_bytes, crl_pem = await asyncio.to_thread(
        generate_root_ca_sync,
        common_name=common_name,
        organization=organization,
        organizational_unit=organizational_unit,
        country=country,
        state=state,
        locality=locality,
        key_type=key_type,
        key_size_or_curve=key_size_or_curve,
        digest_algorithm=digest_algorithm,
        validity_years=validity_years,
    )

    if not settings.ca.encryption_key:
        raise RuntimeError('CA encryption key is not configured')
    f = Fernet(settings.ca.encryption_key.get_secret_value())
    key_pem_enc = f.encrypt(key_pem_bytes)
    serial_number = SerialNumberConverter.int2hex(cert.serial_number)
    cert_pem = cert_pem_bytes.decode()

    async with db.transaction() as sql:
        await sql.exec('update cas set active = false')
        await sql.exec(
            """
            insert into cas (serial_number, cert_pem, key_pem_enc, active, crl_pem)
                values ($1, $2, $3, true, $4)
            on conflict (serial_number) do update set active = true, crl_pem = $4
            """,
            serial_number,
            cert_pem,
            key_pem_enc,
            crl_pem,
        )

    # Persist to disk import folder if writable
    try:
        import_dir = Path(settings.ca.import_dir)
        import_dir.mkdir(parents=True, exist_ok=True)
        (import_dir / 'ca.pem').write_bytes(cert_pem_bytes)
        (import_dir / 'ca.key').write_bytes(key_pem_bytes)
        logger.info('Saved newly generated CA certificate and key to %s', import_dir)
    except OSError as e:
        logger.warning('Could not save CA to import_dir %s: %s', settings.ca.import_dir, e)

    ca.is_initialized = True
    await ca.cronjob.start()
    await acme.start_cronjobs()

    return serial_number


def get_cert_dates(cert: x509.Certificate) -> tuple[datetime, datetime]:
    if hasattr(cert, 'not_valid_before_utc'):
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    return cert.not_valid_before.replace(tzinfo=timezone.utc), cert.not_valid_after.replace(tzinfo=timezone.utc)


async def get_active_ca_details() -> dict | None:
    if not settings.ca.enabled:
        return None
    async with db.transaction(readonly=True) as sql:
        record = await sql.record('select serial_number, cert_pem, crl_pem from cas where active = true')
    if not record:
        return None

    serial_number = record['serial_number']
    cert_pem = record['cert_pem']
    crl_pem = record['crl_pem']

    cert = await asyncio.to_thread(x509.load_pem_x509_certificate, cert_pem.encode(), None)
    nvb, nva = get_cert_dates(cert)
    now = datetime.now(timezone.utc)
    is_valid = nvb <= now <= nva
    days_remaining = max(0, (nva - now).days)

    fp_bytes = cert.fingerprint(hashes.SHA256())
    fingerprint = ':'.join(f'{b:02X}' for b in fp_bytes)

    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_info = f'RSA {pub_key.key_size}-bit'
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_info = f'ECDSA {pub_key.curve.name}'
    else:
        key_info = 'Public Key'

    sig_algo = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else 'SHA'

    return {
        'serial_number': serial_number,
        'cert_pem': cert_pem,
        'crl_pem': crl_pem,
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'not_valid_before': nvb.strftime('%Y-%m-%d %H:%M:%S UTC'),
        'not_valid_after': nva.strftime('%Y-%m-%d %H:%M:%S UTC'),
        'is_valid': is_valid,
        'days_remaining': days_remaining,
        'fingerprint_sha256': fingerprint,
        'key_info': f'{key_info} / {sig_algo}',
        'signature_algorithm': cert.signature_algorithm_oid._name,  # pylint: disable=protected-access
    }
