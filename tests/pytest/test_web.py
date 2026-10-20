from unittest import mock

import httpx
import jwcrypto
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from fastapi.testclient import TestClient


def test_get_certificates_page(testclient: TestClient):
    response = testclient.get('/certificates')
    assert response.status_code == 200, response.text
    assert 'Certificates' in response.text
    assert 'revoke-dialog' in response.text
    assert 'cert-details-dialog' in response.text
    assert 'cert-modal-container' in response.text
    assert 'dialog.cert-details-dialog:not([open])' in response.text
    assert 'btn-action-details' in response.text
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


def test_details_non_existent_cert(testclient: TestClient):
    response = testclient.get('/certificates/DEADBEEF/details')
    assert response.status_code == 404, response.text


def test_revoke_non_existent_cert(testclient: TestClient):
    response = testclient.post('/certificates/DEADBEEF/revoke')
    assert response.status_code == 404, response.text


def test_download_and_revoke_certificate_web(signed_request, directory, testclient: TestClient, db, build_csr):
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

    # 2b. Test Certificate Details JSON via Web endpoint
    details_resp = testclient.get(f'/certificates/{serial_hex}/details')
    assert details_resp.status_code == 200, details_resp.text
    details_data = details_resp.json()
    assert details_data['serial_number'] == serial_hex
    assert details_data['primary_domain'] == host
    assert details_data['healthy'] is True
    assert len(details_data['capabilities']) > 0

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

    # 6. Delete revoked certificate via Web endpoint
    del_resp = testclient.post(f'/certificates/{serial_hex}/delete', headers={'Accept': 'application/json'})
    assert del_resp.status_code == 200, del_resp.text
    assert del_resp.json() == {'status': 'deleted', 'serial_number': serial_hex}

    # Verify certificate row is removed
    assert db.fetch_row('SELECT serial_number FROM certificates WHERE serial_number = $1', serial_hex) is None
    # Verify order, authorization, and challenges are deleted
    assert db.fetch_row('SELECT id FROM orders WHERE id = (SELECT order_id FROM certificates WHERE serial_number = $1)', serial_hex) is None


def test_batch_revoke_and_batch_delete_certificates(signed_request, directory, testclient: TestClient, db, build_csr):
    mail_address = 'mailto:batchuser@example.com'
    domains = ['batch1.example.com', 'batch2.example.com']
    serials = []

    # Create account
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [mail_address]})
    account_id = response.headers['Location']

    for domain in domains:
        response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': domain}]}, account_id)
        authz_url = response.json()['authorizations'][0]
        finalize_order_url = response.json()['finalize']

        response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_id)
        challenge_token = response.json()['challenges'][0]['token']
        challenge_url = response.json()['challenges'][0]['url']
        mock_contents = f'{challenge_token}.{signed_request.account_jwk.thumbprint()}'.rstrip()

        with mock.patch('app.acme.challenge.service.httpx.AsyncClient.get', return_value=httpx.Response(200, text=mock_contents)):
            response = signed_request(challenge_url, response.headers['Replay-Nonce'], '', account_id)

        csr = build_csr([domain])
        response = signed_request(finalize_order_url, response.headers['Replay-Nonce'], {'csr': jwcrypto.common.base64url_encode(csr.public_bytes(Encoding.DER))}, account_id)
        cert_url = response.json()['certificate']
        response = signed_request(cert_url, response.headers['Replay-Nonce'], {}, account_id)
        signed_cert = x509.load_pem_x509_certificate(response.content)
        serials.append(format(signed_cert.serial_number, 'X'))

    assert len(serials) == 2

    # Attempting batch delete before revocation should return 400
    bad_del_resp = testclient.post('/certificates/batch-delete', data={'serials': ','.join(serials)}, headers={'Accept': 'application/json'})
    assert bad_del_resp.status_code == 400

    # Batch revoke
    batch_rev_resp = testclient.post('/certificates/batch-revoke', data={'serials': ','.join(serials)}, headers={'Accept': 'application/json'})
    assert batch_rev_resp.status_code == 200
    assert batch_rev_resp.json() == {'status': 'revoked', 'count': 2}

    # Verify both are revoked in DB
    for sn in serials:
        row = db.fetch_row('SELECT serial_number, revoked_at FROM certificates WHERE serial_number = $1', sn)
        assert row is not None and row['revoked_at'] is not None

    # Batch delete
    batch_del_resp = testclient.post('/certificates/batch-delete', data={'serials': ','.join(serials)}, headers={'Accept': 'application/json'})
    assert batch_del_resp.status_code == 200
    assert batch_del_resp.json() == {'status': 'deleted', 'count': 2}

    # Verify both certificates are deleted from DB
    for sn in serials:
        assert db.fetch_row('SELECT serial_number FROM certificates WHERE serial_number = $1', sn) is None


def test_delete_invalid_domain_without_certs(signed_request, directory, testclient: TestClient, db):
    mail_address = 'mailto:domainuser@example.com'
    host = 'pending-del.example.com'

    # Create account & order without finalizing
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [mail_address]})
    account_id = response.headers['Location']

    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': host}]}, account_id)
    assert response.status_code == 201

    # Check domain appears in domains list
    dom_page = testclient.get('/domains?domainstatus=all')
    assert dom_page.status_code == 200
    assert host in dom_page.text

    # Delete domain
    del_dom_resp = testclient.post(f'/domains/{host}/delete', headers={'Accept': 'application/json'})
    assert del_dom_resp.status_code == 200, del_dom_resp.text
    assert del_dom_resp.json() == {'status': 'deleted', 'domain': host}

    # Verify domain authorization and order are gone
    assert db.fetch_row('SELECT id FROM authorizations WHERE domain = $1', host) is None


def test_delete_deactivated_account(signed_request, directory, testclient: TestClient, db):
    mail_address = 'mailto:deact-del@example.com'

    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [mail_address]})
    account_url = response.headers['Location']
    account_id = account_url.split('/')[-1]

    # Deleting active/valid account should be rejected
    del_active = testclient.post(f'/accounts/{account_id}/delete')
    assert del_active.status_code == 400

    # Deactivate account
    deact_resp = testclient.post(f'/accounts/{account_id}/status', data={'action': 'deactivate'})
    assert deact_resp.status_code in (200, 303)

    # Delete deactivated account
    del_resp = testclient.post(f'/accounts/{account_id}/delete', headers={'Accept': 'application/json'})
    assert del_resp.status_code == 200
    assert del_resp.json() == {'status': 'deleted', 'account_id': account_id}

    # Verify account is deleted from DB
    assert db.fetch_row('SELECT id FROM accounts WHERE id = $1', account_id) is None


def test_batch_delete_orders(signed_request, directory, testclient: TestClient, db):
    mail_address = 'mailto:orders-del@example.com'
    host_pending = 'ord-pending.example.com'

    # Create account
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [mail_address]})
    account_url = response.headers['Location']

    # Create pending order 1
    resp_order1 = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': host_pending}]}, account_url)
    assert resp_order1.status_code == 201
    order1_id = resp_order1.headers['Location'].split('/')[-1]

    # Create pending order 2
    resp_order2 = signed_request(directory['newOrder'], resp_order1.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': 'ord2.example.com'}]}, account_url)
    assert resp_order2.status_code == 201
    order2_id = resp_order2.headers['Location'].split('/')[-1]

    # Check orders appear in account list
    acc_page = testclient.get('/accounts')
    assert acc_page.status_code == 200
    assert order1_id in acc_page.text
    assert order2_id in acc_page.text

    # Batch delete empty list should return 400
    bad_req = testclient.post('/accounts/orders/batch-delete', json={'order_ids': []}, headers={'Accept': 'application/json'})
    assert bad_req.status_code == 400

    # Delete non-existent orders should return 404
    not_found = testclient.post('/accounts/orders/batch-delete', json={'order_ids': ['nonexistent123']}, headers={'Accept': 'application/json'})
    assert not_found.status_code == 404

    # Batch delete both orders via JSON
    del_resp = testclient.post('/accounts/orders/batch-delete', json={'order_ids': [order1_id, order2_id]}, headers={'Accept': 'application/json'})
    assert del_resp.status_code == 200
    assert del_resp.json()['status'] == 'deleted'
    assert set(del_resp.json()['deleted_order_ids']) == {order1_id, order2_id}

    # Verify orders are deleted from database
    assert db.fetch_row('SELECT id FROM orders WHERE id = $1', order1_id) is None
    assert db.fetch_row('SELECT id FROM orders WHERE id = $1', order2_id) is None
    # Verify authorizations are deleted
    assert db.fetch_row('SELECT id FROM authorizations WHERE order_id = $1', order1_id) is None
    assert db.fetch_row('SELECT id FROM authorizations WHERE order_id = $1', order2_id) is None


def test_batch_delete_orders_safeguard_active_cert(signed_request, directory, testclient: TestClient, db, build_csr):
    mail_address = 'mailto:orders-cert@example.com'
    domain = 'active-cert-ord.example.com'

    # Create account
    response = signed_request(directory['newAccount'], signed_request.nonce, {'contact': [mail_address]})
    account_url = response.headers['Location']

    # Create order & finalize cert
    response = signed_request(directory['newOrder'], response.headers['Replay-Nonce'], {'identifiers': [{'type': 'dns', 'value': domain}]}, account_url)
    order_id = response.headers['Location'].split('/')[-1]
    authz_url = response.json()['authorizations'][0]
    finalize_url = response.json()['finalize']

    response = signed_request(authz_url, response.headers['Replay-Nonce'], '', account_url)
    challenge_token = response.json()['challenges'][0]['token']
    challenge_url = response.json()['challenges'][0]['url']
    mock_contents = f'{challenge_token}.{signed_request.account_jwk.thumbprint()}'.rstrip()

    with mock.patch('app.acme.challenge.service.httpx.AsyncClient.get', return_value=httpx.Response(200, text=mock_contents)):
        response = signed_request(challenge_url, response.headers['Replay-Nonce'], '', account_url)

    csr = build_csr([domain])
    response = signed_request(finalize_url, response.headers['Replay-Nonce'], {'csr': jwcrypto.common.base64url_encode(csr.public_bytes(Encoding.DER))}, account_url)
    cert_url = response.json()['certificate']
    response = signed_request(cert_url, response.headers['Replay-Nonce'], {}, account_url)
    signed_cert = x509.load_pem_x509_certificate(response.content)
    serial_number = format(signed_cert.serial_number, 'X')

    # Deleting order with active certificate must be rejected with 400
    del_resp = testclient.post('/accounts/orders/batch-delete', json={'order_ids': [order_id]}, headers={'Accept': 'application/json'})
    assert del_resp.status_code == 400
    assert 'active valid certificates' in del_resp.json()['detail']

    # Revoke certificate
    rev_resp = testclient.post('/certificates/batch-revoke', data={'serials': serial_number}, headers={'Accept': 'application/json'})
    assert rev_resp.status_code == 200

    # Deleting order after revocation must succeed
    del_resp2 = testclient.post('/accounts/orders/batch-delete', json={'order_ids': [order_id]}, headers={'Accept': 'application/json'})
    assert del_resp2.status_code == 200
    assert del_resp2.json()['status'] == 'deleted'
    assert db.fetch_row('SELECT id FROM orders WHERE id = $1', order_id) is None
    assert db.fetch_row('SELECT serial_number FROM certificates WHERE serial_number = $1', serial_number) is None


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


def test_login_page_renders_version_and_github(anon_client: httpx.Client):
    response = anon_client.get('/login')
    assert response.status_code == 200, response.text
    assert 'login-footer' in response.text
    assert 'login-version-badge' in response.text
    assert 'v0.0.0' in response.text or 'edge' in response.text
    assert 'https://github.com/diepeterpan/acme-ca-server' in response.text
    assert 'justify-content: center' in response.text


def test_navbar_renders_version_and_github(testclient: TestClient):
    response = testclient.get('/certificates')
    assert response.status_code == 200, response.text
    assert 'navbar-version-badge' in response.text
    assert 'navbar-github-link' in response.text
    assert 'https://github.com/diepeterpan/acme-ca-server' in response.text


def test_ca_details_page_renders_strict_compliance(testclient: TestClient):
    response = testclient.get('/ca')
    assert response.status_code == 200, response.text
    assert 'btn-strict-pill' in response.text
    assert 'strictDetailsBanner' in response.text
    assert 'toggleStrictDetails()' in response.text


def test_home_page_renders_ca_strict_badge(testclient: TestClient):
    response = testclient.get('/')
    assert response.status_code == 200, response.text
    assert 'ca-strict-pill' in response.text
    assert 'X.509 Strict' in response.text or 'Non-Strict' in response.text


def test_x509_strict_evaluator():
    import datetime

    from ca.compliance import evaluate_ca_x509_strict_compliance
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa

    # 1. Compliant CA
    ca_key = rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Compliant Root CA')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
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
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
    )
    compliant_cert = cert_builder.sign(ca_key, hashes.SHA256())
    eval_res = evaluate_ca_x509_strict_compliance(compliant_cert)
    assert eval_res['is_compliant'] is True
    assert len(eval_res['issues']) == 0
    assert eval_res['badge_class'] == 'badge-strict-valid'

    # 2. Non-compliant CA (missing Key Usage and non-critical basic constraints)
    bad_cert_builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(2)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=False)
    )
    bad_cert = bad_cert_builder.sign(ca_key, hashes.SHA256())
    bad_res = evaluate_ca_x509_strict_compliance(bad_cert)
    assert bad_res['is_compliant'] is False
    assert any('Basic Constraints extension is not marked critical' in iss for iss in bad_res['issues'])
    assert any('Key Usage extension is missing' in iss for iss in bad_res['issues'])


def test_get_ca_distribution_page(testclient: TestClient):
    response = testclient.get('/ca-distribution')
    assert response.status_code == 200, response.text
    assert 'CA Certificate Distribution' in response.text
    assert 'SSH Endpoints' in response.text
    assert 'Email Endpoints' in response.text
    assert 'Add SSH Endpoint' in response.text
    assert 'Add Email Endpoint' in response.text


def test_get_ca_distribution_email_tab(testclient: TestClient):
    response = testclient.get('/ca-distribution?tab=email')
    assert response.status_code == 200, response.text
    assert 'Email Endpoints' in response.text
    assert 'Email Distribution Groups' in response.text
    assert 'Recipient Email Addresses' in response.text


def test_ca_distribution_list_active(testclient: TestClient):
    response = testclient.get('/ca-distribution/list-active')
    assert response.status_code == 200, response.text
    data = response.json()
    assert 'endpoints' in data
    assert isinstance(data['endpoints'], list)


def test_ca_distribution_ssh_endpoint_lifecycle(testclient: TestClient, db):
    # 1. Validation error on missing name
    resp_empty = testclient.post('/ca-distribution/endpoint/save', data={'endpoint_type': 'ssh', 'name': ''}, follow_redirects=False)
    assert resp_empty.status_code == 303
    assert 'error=' in resp_empty.headers['Location']

    # 2. Validation error on missing host or username
    resp_nohost = testclient.post('/ca-distribution/endpoint/save', data={'endpoint_type': 'ssh', 'name': 'Node No Host'}, follow_redirects=False)
    assert resp_nohost.status_code == 303
    assert 'error=' in resp_nohost.headers['Location']

    # 3. Create valid SSH endpoint
    resp_create = testclient.post(
        '/ca-distribution/endpoint/save',
        data={
            'endpoint_type': 'ssh',
            'name': 'Pytest Test Node',
            'host': '127.0.0.1',
            'port': '22',
            'username': 'root',
            'auth_type': 'password',
            'auth_secret': 'password123',
            'target_dir': '/etc/ssl/certs',
        },
        follow_redirects=False,
    )
    assert resp_create.status_code == 303
    assert 'status_msg=' in resp_create.headers['Location']

    # 4. Verify in active endpoints list
    resp_list = testclient.get('/ca-distribution/list-active')
    assert resp_list.status_code == 200
    eps = resp_list.json()['endpoints']
    created_ep = next((e for e in eps if e['name'] == 'Pytest Test Node'), None)
    assert created_ep is not None
    ep_id = created_ep['id']

    # 5. Test endpoint diagnostic AJAX route
    with mock.patch('ca.distribution.test_endpoint', return_value=(True, 'Connection OK', 'linux', 'Ubuntu 24.04')):
        resp_test = testclient.post(f'/ca-distribution/endpoint/{ep_id}/test')
        assert resp_test.status_code == 200
        test_data = resp_test.json()
        assert test_data['success'] is True
        assert 'Connection OK' in test_data['message']

    # 6. Delete endpoint
    resp_del = testclient.post(f'/ca-distribution/endpoint/{ep_id}/delete', follow_redirects=False)
    assert resp_del.status_code == 303

    # 7. Verify deletion
    resp_list2 = testclient.get('/ca-distribution/list-active')
    assert not any(e['id'] == ep_id for e in resp_list2.json()['endpoints'])


def test_ca_distribution_email_endpoint_lifecycle(testclient: TestClient, db):
    # 1. Validation error on missing email address
    resp_noemail = testclient.post(
        '/ca-distribution/endpoint/save',
        data={'endpoint_type': 'email', 'name': 'Alert Group', 'email_addresses_raw': ''},
        follow_redirects=False,
    )
    assert resp_noemail.status_code == 303
    assert 'error=' in resp_noemail.headers['Location']

    # 2. Create valid email endpoint
    resp_create = testclient.post(
        '/ca-distribution/endpoint/save',
        data={
            'endpoint_type': 'email',
            'name': 'Pytest Alerts Group',
            'email_addresses_raw': 'alerts@example.com, ops@example.org',
            'target_os': ['linux', 'windows'],
        },
        follow_redirects=False,
    )
    assert resp_create.status_code == 303
    assert 'status_msg=' in resp_create.headers['Location']

    # 3. Verify in active list
    resp_list = testclient.get('/ca-distribution/list-active')
    eps = resp_list.json()['endpoints']
    created_ep = next((e for e in eps if e['name'] == 'Pytest Alerts Group'), None)
    assert created_ep is not None
    ep_id = created_ep['id']

    # 4. Clean up / delete
    resp_del = testclient.post(f'/ca-distribution/endpoint/{ep_id}/delete', follow_redirects=False)
    assert resp_del.status_code == 303


def test_ca_distribute_empty_selection(testclient: TestClient):
    response = testclient.post('/ca/DEADBEEF/distribute', json={'endpoint_ids': []})
    assert response.status_code == 400, response.text
    assert 'No endpoints selected' in response.json()['detail']


def test_ca_distribute_nonexistent_ca(testclient: TestClient):
    response = testclient.post('/ca/NONEXISTENTSERIAL/distribute', json={'endpoint_ids': ['ep-1']})
    assert response.status_code == 404, response.text
    assert 'not found' in response.json()['detail']


def test_get_users_page(testclient: TestClient):
    response = testclient.get('/users')
    assert response.status_code == 200, response.text
    assert 'Users & Access' in response.text
    assert 'Registered Accounts' in response.text
    assert 'Add User' in response.text

