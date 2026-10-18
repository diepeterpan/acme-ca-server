from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID


def evaluate_ca_x509_strict_compliance(cert: x509.Certificate) -> dict[str, Any]:
    issues: list[str] = []
    checks: list[dict[str, Any]] = []

    # 1. Version Check
    is_v3 = cert.version == x509.Version.v3
    if not is_v3:
        issues.append(f'Certificate version is {cert.version.name}, but X.509 Version 3 (v3) is required for CA extensions.')
    checks.append(
        {
            'name': 'X.509 Version',
            'passed': is_v3,
            'detail': 'Version 3 (v3)' if is_v3 else f'{cert.version.name} (v3 required)',
        }
    )

    # 2. Basic Constraints Check
    bc_passed = False
    bc_detail = ''
    try:
        bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        bc: x509.BasicConstraints = bc_ext.value  # type: ignore[assignment]
        if not bc.ca:
            issues.append('Basic Constraints cA flag is False (must be True for a CA certificate).')
            bc_detail = 'cA: FALSE (must be TRUE)'
        elif not bc_ext.critical:
            issues.append('Basic Constraints extension is not marked critical (RFC 5280 §4.2.1.9 requires critical=True).')
            bc_detail = 'CA:TRUE (non-critical, RFC 5280 requires critical)'
        else:
            bc_passed = True
            path_info = f', pathlen:{bc.path_length}' if bc.path_length is not None else ''
            bc_detail = f'Critical, CA:TRUE{path_info}'
    except x509.ExtensionNotFound:
        issues.append('Basic Constraints extension is missing (must be present with cA=True and critical=True).')
        bc_detail = 'Missing'
    checks.append(
        {
            'name': 'Basic Constraints',
            'passed': bc_passed,
            'detail': bc_detail,
        }
    )

    # 3. Key Usage Check
    ku_passed = False
    ku_detail = ''
    try:
        ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        ku: x509.KeyUsage = ku_ext.value  # type: ignore[assignment]
        if not ku.key_cert_sign:
            issues.append('Key Usage does not include Certificate Signing (keyCertSign bit must be set).')
            ku_detail = 'keyCertSign bit missing'
        else:
            ku_passed = True
            flags = ['keyCertSign']
            if ku.crl_sign:
                flags.append('cRLSign')
            if ku.digital_signature:
                flags.append('digitalSignature')
            crit = 'Critical, ' if ku_ext.critical else ''
            ku_detail = f'{crit}{", ".join(flags)}'
    except x509.ExtensionNotFound:
        issues.append('Key Usage extension is missing (OpenSSL X509_STRICT error 92: CA cert does not include key usage extension).')
        ku_detail = 'Missing'
    checks.append(
        {
            'name': 'Key Usage',
            'passed': ku_passed,
            'detail': ku_detail,
        }
    )

    # 4. Subject Key Identifier Check
    skid_passed = False
    skid_detail = ''
    try:
        cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        skid_passed = True
        skid_detail = 'Present (RFC 5280 §4.2.1.2 conforming)'
    except x509.ExtensionNotFound:
        issues.append('Subject Key Identifier (SKID) extension is missing (RFC 5280 §4.2.1.2 requires SKID for all CA certificates).')
        skid_detail = 'Missing'
    checks.append(
        {
            'name': 'Subject Key Identifier',
            'passed': skid_passed,
            'detail': skid_detail,
        }
    )

    # 5. Authority Key Identifier Check
    akid_passed = True
    akid_detail = 'Not present (acceptable for self-signed root)'
    try:
        cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        akid_detail = 'Present'
    except x509.ExtensionNotFound:
        pass
    checks.append(
        {
            'name': 'Authority Key Identifier',
            'passed': akid_passed,
            'detail': akid_detail,
        }
    )

    # 6. Cryptographic Security & Digest Check
    algo_passed = True
    algo_detail = ''
    sig_hash = cert.signature_hash_algorithm
    if sig_hash and sig_hash.name.lower() in ('md5', 'sha1'):
        issues.append(f'Signature algorithm uses insecure digest {sig_hash.name.upper()} (SHA-256 or better required).')
        algo_passed = False
        algo_detail = f'{sig_hash.name.upper()} (insecure)'
    else:
        hash_name = sig_hash.name.upper() if sig_hash else 'Secure'
        algo_detail = f'{hash_name} / Valid'

    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey) and pub_key.key_size < 2048:
        issues.append(f'RSA key size is {pub_key.key_size}-bit (minimum 2048-bit required for strict compliance).')
        algo_passed = False
        algo_detail += f', RSA {pub_key.key_size}-bit (<2048)'
    checks.append(
        {
            'name': 'Cryptographic Security',
            'passed': algo_passed,
            'detail': algo_detail,
        }
    )

    is_compliant = len(issues) == 0

    return {
        'is_compliant': is_compliant,
        'badge_text': 'X.509 Strict Compliant' if is_compliant else 'X.509 Strict: Non-Compliant',
        'badge_class': 'badge-strict-valid' if is_compliant else 'badge-strict-warning',
        'home_badge_text': 'X.509 Strict' if is_compliant else 'Non-Strict',
        'summary': (
            'This certificate adheres to RFC 5280 requirements and OpenSSL strict validation rules for Certificate Authorities.'
            if is_compliant
            else 'This certificate does not satisfy RFC 5280 / OpenSSL X509_STRICT requirements. Modern TLS clients and tools may reject certificates issued by this CA.'
        ),
        'issues': issues,
        'checks': checks,
    }
