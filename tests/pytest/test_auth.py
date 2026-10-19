import httpx
import web.auth
from fastapi.testclient import TestClient


def test_password_hashing():
    pwd = 'SuperSecretPassword!2026'
    hashed = web.auth.hash_password(pwd)
    assert hashed.startswith('pbkdf2_sha256$600000$')
    assert web.auth.verify_password(pwd, hashed) is True
    assert web.auth.verify_password('WrongPassword', hashed) is False
    assert web.auth.verify_password('', hashed) is False


def test_session_cookie_signing():
    username = 'security_admin'
    cookie_val, max_age = web.auth.create_session_cookie(username, remember_me=False)
    assert max_age == 86400
    assert '.' in cookie_val

    # Valid verification
    payload = web.auth.verify_session_cookie(cookie_val)
    assert payload is not None
    assert payload['sub'] == username

    # Tampered payload
    parts = cookie_val.split('.')
    tampered_cookie = 'aW52YWxpZA.' + parts[1]
    assert web.auth.verify_session_cookie(tampered_cookie) is None

    # Tampered signature
    tampered_sig = parts[0] + '.ZmFrZXNpZw'
    assert web.auth.verify_session_cookie(tampered_sig) is None

    # Remember me cookie
    remember_cookie, remember_max_age = web.auth.create_session_cookie(username, remember_me=True)
    assert remember_cookie is not None
    assert remember_max_age == 14 * 86400


def test_unauthenticated_redirect_to_login(anon_client: httpx.Client):
    resp = anon_client.get('/certificates', follow_redirects=False)
    assert resp.status_code == 307
    assert '/login' in resp.headers['Location']
    assert 'next=%2Fcertificates' in resp.headers['Location']


def test_endpoints_protected_behind_login(testclient: TestClient, anon_client: httpx.Client):
    # /endpoints redirects unauthenticated users to login
    resp = anon_client.get('/endpoints', follow_redirects=False)
    assert resp.status_code == 307
    assert '/login' in resp.headers['Location']

    # /openapi.json returns 401 Unauthorized for unauthenticated users
    resp_api = anon_client.get('/openapi.json')
    assert resp_api.status_code == 401

    # Ensure testclient is authenticated
    token, _ = web.auth.create_session_cookie('admin', remember_me=True)
    testclient.cookies[web.auth.COOKIE_NAME] = token

    # Authenticated testclient can access both
    auth_resp = testclient.get('/endpoints')
    assert auth_resp.status_code == 200
    assert 'swagger' in auth_resp.text.lower() or 'openapi' in auth_resp.text.lower()


def test_acme_directory_is_public(anon_client: httpx.Client):
    # ACME machine-to-machine traffic must never be blocked by web authentication
    resp = anon_client.get('/directory')
    assert resp.status_code == 200
    assert 'newAccount' in resp.json()

    resp_acme = anon_client.get('/acme/directory')
    assert resp_acme.status_code == 200


def test_ca_download_is_public(anon_client: httpx.Client):
    # CA Certificate and CRL downloads must be publicly accessible without authentication
    resp = anon_client.get('/ca/download')
    assert resp.status_code == 200, resp.text
    assert 'Content-Disposition' in resp.headers
    assert 'ca_' in resp.headers['Content-Disposition']
    assert '-----BEGIN CERTIFICATE-----' in resp.text

    resp_pem = anon_client.get('/ca/download/pem')
    assert resp_pem.status_code == 200, resp_pem.text
    assert 'Content-Disposition' in resp_pem.headers
    assert '-----BEGIN CERTIFICATE-----' in resp_pem.text

    resp_crl = anon_client.get('/ca/download/crl')
    assert resp_crl.status_code == 200, resp_crl.text
    assert 'Content-Disposition' in resp_crl.headers
    assert '-----BEGIN X509 CRL-----' in resp_crl.text

    # Verify login page displays CA and CRL download options
    login_resp = anon_client.get('/login')
    assert login_resp.status_code == 200
    assert '/ca/download' in login_resp.text
    assert 'Download CA Certificate (.crt)' in login_resp.text
    assert '/ca/download/pem' in login_resp.text
    assert 'Download CA Certificate (.pem)' in login_resp.text
    assert '/ca/download-crl' in login_resp.text
    assert 'Download Revocation List (.crl)' in login_resp.text
    assert 'Root CA &amp; CRL' not in login_resp.text


def test_login_flow(anon_client: httpx.Client):
    client = anon_client
    # 1. Invalid credentials
    bad_resp = client.post('/login', data={'username': 'admin', 'password': 'wrongpassword'}, follow_redirects=False)
    assert bad_resp.status_code == 200
    assert 'Invalid username or password' in bad_resp.text

    # 2. Valid credentials
    good_resp = client.post(
        '/login',
        data={'username': 'admin', 'password': 'adminpassword123', 'next': '/certificates'},
        follow_redirects=False,
    )
    assert good_resp.status_code == 303
    assert good_resp.headers['Location'] == '/certificates'
    assert web.auth.COOKIE_NAME in good_resp.cookies

    # 3. Access protected view with returned cookie
    cert_page = client.get('/certificates')
    assert cert_page.status_code == 200
    assert 'Logged in as admin' in cert_page.text
    assert 'Sign out' in cert_page.text

    # 4. Logout
    logout_resp = client.get('/logout', follow_redirects=False)
    assert logout_resp.status_code == 303
    assert logout_resp.headers['Location'] == '/login'

    # After logout, accessing protected page redirects to login
    after_logout = client.get('/certificates', follow_redirects=False)
    assert after_logout.status_code == 307
    assert '/login' in after_logout.headers['Location']


def test_reset_user_password():
    import asyncio

    import tools.reset_password

    # Reset admin password to a new password
    success = asyncio.run(tools.reset_password.reset_user_password('admin', 'BrandNewPassword!2026'))
    assert success is True

    # Authenticate with new password
    auth_res = asyncio.run(web.auth.authenticate_user('admin', 'BrandNewPassword!2026'))
    assert auth_res is not None
    assert auth_res['username'] == 'admin'

    # Old password no longer works
    auth_old = asyncio.run(web.auth.authenticate_user('admin', 'adminpassword123'))
    assert auth_old is None

    # Reset back to original for subsequent tests
    asyncio.run(tools.reset_password.reset_user_password('admin', 'adminpassword123'))


def test_account_password_wrong_current(testclient: TestClient):
    token, _ = web.auth.create_session_cookie('admin', remember_me=True)
    testclient.cookies[web.auth.COOKIE_NAME] = token

    resp = testclient.post(
        '/account/password',
        json={
            'current_password': 'DefinitelyWrongPassword!',
            'new_password': 'BrandNewPassword!2026',
            'confirm_password': 'BrandNewPassword!2026',
        },
        headers={'Accept': 'application/json'},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data['ok'] is False
    assert 'Current password is incorrect' in data['error']


def test_account_password_mismatch(testclient: TestClient):
    token, _ = web.auth.create_session_cookie('admin', remember_me=True)
    testclient.cookies[web.auth.COOKIE_NAME] = token

    resp = testclient.post(
        '/account/password',
        json={
            'current_password': 'adminpassword123',
            'new_password': 'BrandNewPassword!2026',
            'confirm_password': 'DifferentPassword!2026',
        },
        headers={'Accept': 'application/json'},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data['ok'] is False
    assert 'New passwords do not match' in data['error']


def test_account_password_too_short(testclient: TestClient):
    token, _ = web.auth.create_session_cookie('admin', remember_me=True)
    testclient.cookies[web.auth.COOKIE_NAME] = token

    resp = testclient.post(
        '/account/password',
        json={
            'current_password': 'adminpassword123',
            'new_password': 'short',
            'confirm_password': 'short',
        },
        headers={'Accept': 'application/json'},
    )
    assert resp.status_code == 400
    data = resp.json()
    assert data['ok'] is False
    assert 'at least 8 characters' in data['error']


def test_account_password_success(testclient: TestClient):
    import asyncio
    import tools.reset_password

    token, _ = web.auth.create_session_cookie('admin', remember_me=True)
    testclient.cookies[web.auth.COOKIE_NAME] = token

    # Change password to new password
    resp = testclient.post(
        '/account/password',
        json={
            'current_password': 'adminpassword123',
            'new_password': 'BrandNewPassword!2026',
            'confirm_password': 'BrandNewPassword!2026',
        },
        headers={'Accept': 'application/json'},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data['ok'] is True
    assert 'successfully' in data['message'].lower()

    # Verify new password authenticates
    auth_res = asyncio.run(web.auth.authenticate_user('admin', 'BrandNewPassword!2026'))
    assert auth_res is not None
    assert auth_res['username'] == 'admin'

    # Verify old password no longer works
    auth_old = asyncio.run(web.auth.authenticate_user('admin', 'adminpassword123'))
    assert auth_old is None

    # Reset back to default password for subsequent tests
    asyncio.run(tools.reset_password.reset_user_password('admin', 'adminpassword123'))

