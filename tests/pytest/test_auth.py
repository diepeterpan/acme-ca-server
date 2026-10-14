import main
import web.auth
from fastapi.testclient import TestClient
from .conftest import TestClient as TC


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
    assert remember_max_age == 14 * 86400


def test_unauthenticated_redirect_to_login(testclient: TC):
    # Use unauthenticated client (no session cookie)
    with TestClient(main.app) as anon_client:
        resp = anon_client.get('/certificates', follow_redirects=False)
        assert resp.status_code == 307
        assert '/login' in resp.headers['Location']
        assert 'next=%2Fcertificates' in resp.headers['Location']


def test_endpoints_protected_behind_login(testclient: TC):
    with TestClient(main.app) as anon_client:
        # /endpoints redirects unauthenticated users to login
        resp = anon_client.get('/endpoints', follow_redirects=False)
        assert resp.status_code == 307
        assert '/login' in resp.headers['Location']

        # /openapi.json returns 401 Unauthorized for unauthenticated users
        resp_api = anon_client.get('/openapi.json')
        assert resp_api.status_code == 401

    # Authenticated testclient can access both
    auth_resp = testclient.get('/endpoints')
    assert auth_resp.status_code == 200
    assert 'swagger' in auth_resp.text.lower() or 'openapi' in auth_resp.text.lower()


def test_acme_directory_is_public(testclient: TC):
    # ACME machine-to-machine traffic must never be blocked by web authentication
    with TestClient(main.app) as anon_client:
        resp = anon_client.get('/directory')
        assert resp.status_code == 200
        assert 'newAccount' in resp.json()

        resp_acme = anon_client.get('/acme/directory')
        assert resp_acme.status_code == 200


def test_login_flow(testclient: TC):
    with TestClient(main.app) as client:
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
