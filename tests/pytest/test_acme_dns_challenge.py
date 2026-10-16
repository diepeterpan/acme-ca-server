import base64
import hashlib
from unittest import mock

import dns.exception
import dns.resolver
import jwcrypto
from acme.challenge.service import compute_dns_key_authorization_digest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding


class MockDNSAnswer:
    def __init__(self, txt_values: list[str]):
        class MockRdata:
            def __init__(self, val: str):
                self.strings = (val.encode('utf-8'),)

        self._rdatas = [MockRdata(v) for v in txt_values]

    def __iter__(self):
        return iter(self._rdatas)


def test_dns_key_auth_digest_calculation(account_jwk):
    token = 'DGyRejmCefe7v4NfDGQgXXFuIgxCHhgLK5GJQ9QBQIg'
    thumbprint = account_jwk.thumbprint()
    expected = base64.urlsafe_b64encode(hashlib.sha256(f'{token}.{thumbprint}'.encode('ascii')).digest()).decode('ascii').rstrip('=')
    actual = compute_dns_key_authorization_digest(token, account_jwk)
    assert actual == expected


def test_should_offer_both_challenges_for_standard_domain(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    domain = 'std.example.org'
    response = signed_request(
        directory['newOrder'],
        response.headers['Replay-Nonce'],
        {'identifiers': [{'type': 'dns', 'value': domain}]},
        account_id,
    )
    assert response.status_code == 201
    authz_url = response.json()['authorizations'][0]

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    authz_data = response.json()
    assert authz_data['status'] == 'pending'
    assert 'wildcard' not in authz_data or authz_data['wildcard'] is None

    types = [c['type'] for c in authz_data['challenges']]
    assert 'http-01' in types
    assert 'dns-01' in types


def test_should_offer_only_dns_challenge_for_wildcard_domain(signed_request, directory):
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    domain = '*.wildcard.example.org'
    response = signed_request(
        directory['newOrder'],
        response.headers['Replay-Nonce'],
        {'identifiers': [{'type': 'dns', 'value': domain}]},
        account_id,
    )
    assert response.status_code == 201
    authz_url = response.json()['authorizations'][0]

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    authz_data = response.json()
    assert authz_data['status'] == 'pending'
    assert authz_data.get('wildcard') is True

    types = [c['type'] for c in authz_data['challenges']]
    assert types == ['dns-01']


def test_should_fulfill_dns_challenge_and_issue_cert(signed_request, directory, build_csr):
    domain = 'dns-ok.example.org'
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': ['mailto:dns@example.org']})
    account_id = response.headers['Location']

    response = signed_request(
        directory['newOrder'],
        response.headers['Replay-Nonce'],
        {'identifiers': [{'type': 'dns', 'value': domain}]},
        account_id,
    )
    authz_url = response.json()['authorizations'][0]
    finalize_url = response.json()['finalize']

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    dns_chal = next(c for c in response.json()['challenges'] if c['type'] == 'dns-01')
    challenge_url = dns_chal['url']
    token = dns_chal['token']

    expected_digest = compute_dns_key_authorization_digest(token, signed_request.account_jwk)

    with mock.patch('dns.asyncresolver.Resolver.resolve', return_value=MockDNSAnswer([expected_digest])) as mock_resolve:
        response = signed_request(challenge_url, response.headers['Replay-Nonce'], {}, account_id)

    mock_resolve.assert_called_once_with(f'_acme-challenge.{domain}', 'TXT')
    chal_data = response.json()
    assert chal_data['status'] == 'valid'
    assert chal_data['type'] == 'dns-01'

    # Check authorization is now valid
    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    assert response.json()['status'] == 'valid'

    # Finalize and download cert
    csr = build_csr([domain])
    response = signed_request(
        finalize_url,
        response.headers['Replay-Nonce'],
        {'csr': jwcrypto.common.base64url_encode(csr.public_bytes(Encoding.DER))},
        account_id,
    )
    cert_url = response.json()['certificate']
    response = signed_request(cert_url, response.headers['Replay-Nonce'], {}, account_id)
    signed_cert = x509.load_pem_x509_certificate(response.content)
    assert signed_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == domain


def test_should_fail_dns_challenge_on_mismatched_txt(signed_request, directory):
    domain = 'dns-mismatch.example.org'
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    response = signed_request(
        directory['newOrder'],
        response.headers['Replay-Nonce'],
        {'identifiers': [{'type': 'dns', 'value': domain}]},
        account_id,
    )
    authz_url = response.json()['authorizations'][0]

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    dns_chal = next(c for c in response.json()['challenges'] if c['type'] == 'dns-01')

    with mock.patch('dns.asyncresolver.Resolver.resolve', return_value=MockDNSAnswer(['incorrect-digest-value'])):
        response = signed_request(dns_chal['url'], response.headers['Replay-Nonce'], {}, account_id)

    chal_data = response.json()
    assert chal_data['status'] == 'invalid'
    assert chal_data['error']['type'] == 'urn:ietf:params:acme:error:incorrectResponse'


def test_should_fail_dns_challenge_on_nxdomain(signed_request, directory):
    domain = 'dns-nxdomain.example.org'
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    response = signed_request(
        directory['newOrder'],
        response.headers['Replay-Nonce'],
        {'identifiers': [{'type': 'dns', 'value': domain}]},
        account_id,
    )
    authz_url = response.json()['authorizations'][0]

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    dns_chal = next(c for c in response.json()['challenges'] if c['type'] == 'dns-01')

    with mock.patch('dns.asyncresolver.Resolver.resolve', side_effect=dns.resolver.NXDOMAIN()):
        response = signed_request(dns_chal['url'], response.headers['Replay-Nonce'], {}, account_id)

    chal_data = response.json()
    assert chal_data['status'] == 'invalid'
    assert chal_data['error']['type'] == 'urn:ietf:params:acme:error:dns'


def test_should_fail_dns_challenge_on_timeout(signed_request, directory):
    domain = 'dns-timeout.example.org'
    response = signed_request(directory['newAccount'], signed_request.nonce, {})
    account_id = response.headers['Location']

    response = signed_request(
        directory['newOrder'],
        response.headers['Replay-Nonce'],
        {'identifiers': [{'type': 'dns', 'value': domain}]},
        account_id,
    )
    authz_url = response.json()['authorizations'][0]

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    dns_chal = next(c for c in response.json()['challenges'] if c['type'] == 'dns-01')

    with mock.patch('dns.asyncresolver.Resolver.resolve', side_effect=dns.exception.Timeout()):
        response = signed_request(dns_chal['url'], response.headers['Replay-Nonce'], {}, account_id)

    chal_data = response.json()
    assert chal_data['status'] == 'invalid'
    assert chal_data['error']['type'] == 'urn:ietf:params:acme:error:connection'
