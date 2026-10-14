from unittest import mock

import httpx
import jwcrypto
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from .conftest import TestClient
from .utils import build_csr


def test_get_certificates_page(testclient: TestClient):
    response = testclient.get('/certificates')
    assert response.status_code == 200, response.text
    assert 'Certificates' in response.text
    assert 'revoke-dialog' in response.text
    assert 'filter-tabs' in response.text


def test_get_certificates_page_with_account_filter(testclient: TestClient):
    response = testclient.get('/certificates?account_id=nonexistent&certstatus=all')
    assert response.status_code == 200, response.text
    assert 'Filtered by Account:' in response.text
    assert 'nonexistent' in response.text
    assert 'No certificates found' in response.text


def test_get_domains_page(testclient: TestClient):
    response = testclient.get('/domains')
    assert response.status_code == 200, response.text


def test_download_non_existent_cert(testclient: TestClient):
    response = testclient.get('/certificates/DEADBEEF')
    assert response.status_code == 404, response.text


def test_revoke_non_existent_cert(testclient: TestClient):
    response = testclient.post('/certificates/DEADBEEF/revoke')
    assert response.status_code == 404, response.text


def test_download_and_revoke_certificate_web(signed_request, directory, testclient: TestClient, db):
    mail_address = 'mailto:webuser@example.com'
    host = 'web.example.com'

    # 1. Create account & order
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [mail_address]})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': host}]}, account_id)
    authz_url = response.json()['authorizations'][0]
    finalize_order_url = response.json()['finalize']

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
    challenge_token = response.json()['challenges'][0]['token']
    challenge_url = response.json()['challenges'][0]['url']

    mock_challenge_file_contents = f'{challenge_token}.{signed_request.account_jwk.thumbprint()}'.rstrip()

    with mock.patch(
        'app.acme.challenge.service.httpx.AsyncClient.get',
        return_value=httpx.Response(200, text=mock_challenge_file_contents),
    ):
        response = signed_request(challenge_url, response.headers['Replay-Nonce'], '', account_id)

    csr = build_csr([host])
    response = signed_request(finalize_order_url, response.headers['Replay-Nonce'], {'csr': jwcrypto.common.base64url_encode(csr.public_bytes(Encoding.DER))}, account_id)
    cert_url = response.json()['certificate']

    response = signed_request(cert_url, response.headers['Replay-Nonce'], {}, account_id)
    signed_cert = x509.load_pem_x509_certificate(response.content)
    serial_hex = format(signed_cert.serial_number, 'X')

    # 2. Test Download via Web endpoint
    dl_resp = testclient.get(f'/certificates/{serial_hex}')
    assert dl_resp.status_code == 200, dl_resp.text
    assert 'Content-Disposition' in dl_resp.headers
    assert f'{host}_{serial_hex[:8]}.crt' in dl_resp.headers['Content-Disposition']

    # 3. Test Revoke via Web endpoint (JSON request)
    revoke_resp = testclient.post(f'/certificates/{serial_hex}/revoke', headers={'Accept': 'application/json'})
    assert revoke_resp.status_code == 200, revoke_resp.text
    assert revoke_resp.json() == {'status': 'revoked', 'serial_number': serial_hex}

    # Verify database has revoked_at set
    cert_db = db.fetch_row('SELECT serial_number, revoked_at FROM certificates WHERE serial_number = $1', serial_hex)
    assert cert_db is not None
    assert cert_db['revoked_at'] is not None

    # 4. Attempting to revoke again should return 400
    duplicate_resp = testclient.post(f'/certificates/{serial_hex}/revoke')
    assert duplicate_resp.status_code == 400, duplicate_resp.text

    # 5. Check certificates list page contains revoked cert
    list_resp = testclient.get('/certificates?certstatus=revoked')
    assert list_resp.status_code == 200
    assert serial_hex in list_resp.text
    assert host in list_resp.text


def test_ca_view_and_download(testclient: TestClient):
    # 1. View CA Details Page
    ca_page_resp = testclient.get('/ca')
    assert ca_page_resp.status_code == 200, ca_page_resp.text
    assert 'Root Certificate Authority' in ca_page_resp.text
    assert 'SHA-256 Fingerprint' in ca_page_resp.text
    assert 'PEM Encoded CA Certificate' in ca_page_resp.text

    # 2. Download CA Certificate (.crt)
    cert_dl_resp = testclient.get('/ca/download')
    assert cert_dl_resp.status_code == 200, cert_dl_resp.text
    assert 'Content-Disposition' in cert_dl_resp.headers
    assert 'ca_' in cert_dl_resp.headers['Content-Disposition']
    assert '-----BEGIN CERTIFICATE-----' in cert_dl_resp.text

    # 3. Download CA CRL (.crl)
    crl_dl_resp = testclient.get('/ca/download/crl')
    assert crl_dl_resp.status_code == 200, crl_dl_resp.text
    assert 'Content-Disposition' in crl_dl_resp.headers
    assert 'ca_' in crl_dl_resp.headers['Content-Disposition']
    assert '-----BEGIN X509 CRL-----' in crl_dl_resp.text


def test_ca_setup_validation(testclient: TestClient):
    import ca

    # Temporarily set ca.is_initialized to False to test setup wizard validation
    ca.is_initialized = False
    try:
        # Accessing /ca/setup should return 200 with form
        setup_resp = testclient.get('/ca/setup')
        assert setup_resp.status_code == 200, setup_resp.text
        assert 'Create Root Certificate Authority (CA)' in setup_resp.text

        # 1. Missing Common Name
        resp_no_cn = testclient.post('/ca/setup', data={'common_name': ''})
        assert resp_no_cn.status_code == 200
        assert 'Common Name (CN) is required.' in resp_no_cn.text

        # 2. Invalid country code
        resp_bad_c = testclient.post('/ca/setup', data={'common_name': 'Valid CN', 'country': 'XYZ'})
        assert resp_bad_c.status_code == 200
        assert 'Country code must be a 2-letter ISO 3166-1 alpha-2 code' in resp_bad_c.text

        # 3. Invalid validity period
        resp_bad_val = testclient.post('/ca/setup', data={'common_name': 'Valid CN', 'validity_years': '99'})
        assert resp_bad_val.status_code == 200
        assert 'Validity period must be between 1 and 30 years.' in resp_bad_val.text

        # 4. Successful creation
        create_resp = testclient.post(
            '/ca/setup',
            data={
                'common_name': 'Fresh Root CA',
                'organization': 'Pytest Org',
                'country': 'DE',
                'key_type': 'RSA',
                'key_size_or_curve': '4096',
                'digest_algorithm': 'SHA-384',
                'validity_years': 5,
            },
            follow_redirects=False,
        )
        assert create_resp.status_code == 303
        assert '/ca?status_msg=ca_created' in create_resp.headers['Location']
        assert ca.is_initialized is True
    finally:
        ca.is_initialized = True


