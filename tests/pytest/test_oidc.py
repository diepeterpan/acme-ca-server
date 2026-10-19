import asyncio
import base64
import hashlib
import json
import ssl
from unittest.mock import AsyncMock, patch
from urllib.parse import unquote

import config
import httpx
import web.auth
import web.oidc
from fastapi.testclient import TestClient


def test_create_local_user_with_optional_email():
    """Verify local user can be created with password and optional email."""
    user_id = asyncio.run(web.auth.create_user('test_local_admin', 'SecurePassword123!', 'admin@example.com'))
    assert user_id is not None

    user = asyncio.run(web.auth.get_user_by_username('test_local_admin'))
    assert user is not None
    assert user['user_type'] == 'local'
    assert user['email'] == 'admin@example.com'

    # Local user authenticates with password
    auth_res = asyncio.run(web.auth.authenticate_user('test_local_admin', 'SecurePassword123!'))
    assert auth_res is not None
    assert auth_res['username'] == 'test_local_admin'

    # Clean up
    asyncio.run(web.auth.delete_user(user_id, current_username='admin'))


def test_create_oidc_user_mandatory_email():
    """Verify OIDC user is created without password and with mandatory email."""
    user_id = asyncio.run(web.auth.create_oidc_user('test_oidc_user', 'sso_user@example.com'))
    assert user_id is not None

    user = asyncio.run(web.auth.get_user_by_username('test_oidc_user'))
    assert user is not None
    assert user['user_type'] == 'oidc'
    assert user['email'] == 'sso_user@example.com'
    assert user.get('password_hash') is None

    # OIDC user CANNOT authenticate via local password form
    auth_local = asyncio.run(web.auth.authenticate_user('test_oidc_user', 'AnyPassword'))
    assert auth_local is None

    # OIDC user authenticates via verified email
    auth_oidc = asyncio.run(web.auth.authenticate_oidc_user('sso_user@example.com'))
    assert auth_oidc is not None
    assert auth_oidc['username'] == 'test_oidc_user'

    # Case insensitive email lookup
    auth_case = asyncio.run(web.auth.authenticate_oidc_user('SSO_USER@EXAMPLE.COM'))
    assert auth_case is not None

    # Clean up
    asyncio.run(web.auth.delete_user(user_id, current_username='admin'))


def test_user_delete_safeguards():
    """Verify deletion safeguards (cannot delete self, cannot delete sole local admin)."""
    # 1. Cannot delete active logged in account
    admin_user = asyncio.run(web.auth.get_user_by_username('admin'))
    assert admin_user is not None
    ok, err = asyncio.run(web.auth.delete_user(admin_user['id'], current_username='admin'))
    assert ok is False
    assert 'own active account' in err.lower()

    # 2. Cannot delete the only local administrator account
    ok_other, err_other = asyncio.run(web.auth.delete_user(admin_user['id'], current_username='another_admin'))
    assert ok_other is False
    assert 'only local administrator' in err_other.lower()


def test_oidc_disabled_by_default(anon_client: httpx.Client):
    """When OIDC is disabled, /oidc/login and /oidc/callback return 404."""
    config.settings.oidc.enabled = False

    resp_login = anon_client.get('/oidc/login')
    assert resp_login.status_code == 404

    resp_cb = anon_client.get('/oidc/callback')
    assert resp_cb.status_code == 404


def test_oidc_login_redirect_and_state_cookie(anon_client: httpx.Client):
    """When OIDC is enabled, /oidc/login sets signed state cookie and redirects to provider."""
    config.settings.oidc.enabled = True
    config.settings.oidc.issuer_url = 'https://auth.example.com/'  # type: ignore[assignment]
    config.settings.oidc.client_id = 'acme-test-client'
    config.settings.oidc.client_secret = config.SecretStr('test-secret')  # type: ignore[assignment]

    mock_discovery = {
        'authorization_endpoint': 'https://auth.example.com/api/oidc/authorization',
        'token_endpoint': 'https://auth.example.com/api/oidc/token',
        'jwks_uri': 'https://auth.example.com/api/oidc/jwks',
    }

    with patch('web.oidc.get_discovery_document', new=AsyncMock(return_value=mock_discovery)):
        resp = anon_client.get('/oidc/login?next=/certificates', follow_redirects=False)
        assert resp.status_code == 302
        assert 'https://auth.example.com/api/oidc/authorization' in resp.headers['Location']
        assert 'client_id=acme-test-client' in resp.headers['Location']
        assert 'state=' in resp.headers['Location']
        assert 'nonce=' in resp.headers['Location']
        assert 'code_challenge=' in resp.headers['Location']
        assert 'code_challenge_method=S256' in resp.headers['Location']
        assert 'acme_oidc_state' in resp.cookies

    config.settings.oidc.enabled = False


def test_oidc_callback_state_mismatch(anon_client: httpx.Client):
    """Callback with invalid or missing state parameter returns error."""
    config.settings.oidc.enabled = True
    config.settings.oidc.issuer_url = 'https://auth.example.com/'  # type: ignore[assignment]
    config.settings.oidc.client_id = 'acme-test-client'
    config.settings.oidc.client_secret = config.SecretStr('test-secret')  # type: ignore[assignment]

    resp = anon_client.get('/oidc/callback?code=fake_code&state=fake_state', follow_redirects=False)
    assert resp.status_code == 303
    assert '/login' in resp.headers['Location']
    assert 'error=' in resp.headers['Location']

    config.settings.oidc.enabled = False


def test_oidc_callback_unprovisioned_user_rejected(anon_client: httpx.Client):
    """Verified OIDC user whose email is not pre-provisioned in users table is rejected."""
    config.settings.oidc.enabled = True
    config.settings.oidc.issuer_url = 'https://auth.example.com/'  # type: ignore[assignment]
    config.settings.oidc.client_id = 'acme-test-client'
    config.settings.oidc.client_secret = config.SecretStr('test-secret')  # type: ignore[assignment]

    mock_user_info = {
        'email': 'unprovisioned_person@example.com',
        'username': 'unprovisioned_person',
        'claims': {'email': 'unprovisioned_person@example.com'},
    }

    state = 'valid_test_state'
    nonce = 'valid_test_nonce'
    state_payload = {'state': state, 'nonce': nonce, 'next': '/'}
    state_cookie_val, _ = web.auth.create_session_cookie(json.dumps(state_payload), remember_me=False)

    anon_client.cookies['acme_oidc_state'] = state_cookie_val

    with patch('web.oidc.exchange_code_for_user', new=AsyncMock(return_value=mock_user_info)):
        resp = anon_client.get(f'/oidc/callback?code=mock_code&state={state}', follow_redirects=False)
        assert resp.status_code == 303
        assert '/login' in resp.headers['Location']
        assert 'not pre-provisioned' in unquote(resp.headers['Location'])

    config.settings.oidc.enabled = False


def test_oidc_callback_preprovisioned_user_success(anon_client: httpx.Client):
    """Pre-provisioned OIDC user is successfully authenticated and receives session cookie."""
    config.settings.oidc.enabled = True
    config.settings.oidc.issuer_url = 'https://auth.example.com/'  # type: ignore[assignment]
    config.settings.oidc.client_id = 'acme-test-client'
    config.settings.oidc.client_secret = config.SecretStr('test-secret')  # type: ignore[assignment]

    # Pre-provision the user in the database
    user_id = asyncio.run(web.auth.create_oidc_user('authelia_user', 'authelia_user@company.com'))

    mock_user_info = {
        'email': 'authelia_user@company.com',
        'username': 'authelia_user',
        'claims': {'email': 'authelia_user@company.com'},
    }

    state = 'valid_test_state_2'
    nonce = 'valid_test_nonce_2'
    state_payload = {'state': state, 'nonce': nonce, 'next': '/domains'}
    state_cookie_val, _ = web.auth.create_session_cookie(json.dumps(state_payload), remember_me=False)

    anon_client.cookies['acme_oidc_state'] = state_cookie_val

    with patch('web.oidc.exchange_code_for_user', new=AsyncMock(return_value=mock_user_info)):
        resp = anon_client.get(f'/oidc/callback?code=mock_code_2&state={state}', follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers['Location'] == '/domains'
        assert web.auth.COOKIE_NAME in resp.cookies

    # Clean up
    asyncio.run(web.auth.delete_user(user_id, current_username='admin'))
    config.settings.oidc.enabled = False


def test_users_web_management(testclient: TestClient):
    """Verify Users UI web endpoints (list, create, delete, reset-password)."""
    # 1. View users list
    resp_list = testclient.get('/users')
    assert resp_list.status_code == 200
    assert 'Registered Accounts' in resp_list.text
    assert 'admin' in resp_list.text

    # 2. Create local user via form
    resp_create_local = testclient.post(
        '/users/create',
        data={
            'user_type': 'local',
            'username': 'web_created_local',
            'email': 'web_local@example.com',
            'password': 'StrongPassword123!',
            'confirm_password': 'StrongPassword123!',
        },
        follow_redirects=False,
    )
    assert resp_create_local.status_code == 303
    assert 'success=' in resp_create_local.headers['Location']

    # 3. Create OIDC user via form
    resp_create_oidc = testclient.post(
        '/users/create',
        data={
            'user_type': 'oidc',
            'username': 'web_created_oidc',
            'email': 'web_oidc@example.com',
        },
        follow_redirects=False,
    )
    assert resp_create_oidc.status_code == 303
    assert 'success=' in resp_create_oidc.headers['Location']

    # Verify both exist
    created_local = asyncio.run(web.auth.get_user_by_username('web_created_local'))
    assert created_local is not None
    created_oidc = asyncio.run(web.auth.get_user_by_username('web_created_oidc'))
    assert created_oidc is not None

    # 4. Reset password for local user
    resp_reset = testclient.post(
        f'/users/{created_local["id"]}/reset-password',
        data={
            'password': 'BrandNewPassword789!',
            'confirm_password': 'BrandNewPassword789!',
        },
        follow_redirects=False,
    )
    assert resp_reset.status_code == 303
    assert 'success=' in resp_reset.headers['Location']

    # Verify new password works
    auth_check = asyncio.run(web.auth.authenticate_user('web_created_local', 'BrandNewPassword789!'))
    assert auth_check is not None

    # 5. Delete both test users
    resp_del1 = testclient.post(f'/users/{created_local["id"]}/delete', follow_redirects=False)
    assert resp_del1.status_code == 303
    resp_del2 = testclient.post(f'/users/{created_oidc["id"]}/delete', follow_redirects=False)
    assert resp_del2.status_code == 303


def test_oidc_ssl_context_configurations():
    """Verify get_oidc_ssl_context returns correct context based on settings."""
    orig_verify = config.settings.oidc.verify_ssl
    orig_x509 = config.settings.oidc.x509_required

    try:
        # Case 1: verify_ssl = False
        config.settings.oidc.verify_ssl = False
        assert web.oidc.get_oidc_ssl_context() is False

        # Case 2: verify_ssl = True, x509_required = True (strict default)
        config.settings.oidc.verify_ssl = True
        config.settings.oidc.x509_required = True
        assert web.oidc.get_oidc_ssl_context() is True

        # Case 3: verify_ssl = True, x509_required = False (relaxed for older certs)
        config.settings.oidc.x509_required = False
        ctx = web.oidc.get_oidc_ssl_context()
        assert isinstance(ctx, ssl.SSLContext)
        # VERIFY_X509_STRICT must be cleared
        assert (ctx.verify_flags & ssl.VERIFY_X509_STRICT) == 0
        if hasattr(ssl, 'OP_LEGACY_SERVER_CONNECT'):
            assert (ctx.options & ssl.OP_LEGACY_SERVER_CONNECT) != 0

    finally:
        config.settings.oidc.verify_ssl = orig_verify
        config.settings.oidc.x509_required = orig_x509


def test_navbar_ca_certificate_placement(testclient: TestClient):
    """Verify CA Certificate is in main top navbar, Change Password is first hamburger item, and user badge has no online status."""
    resp = testclient.get('/accounts')
    assert resp.status_code == 200

    # Main navbar list must include CA Certificate link
    assert '<a href="/ca" class="nav-link' in resp.text

    # Hamburger settings dropdown must NOT include CA Certificate
    assert 'class="dropdown-item' in resp.text
    assert 'Users &amp; Access' in resp.text or 'Users & Access' in resp.text
    # CA Certificate should not appear as a dropdown-item
    assert '<a href="/ca" class="dropdown-item' not in resp.text

    # Change Password is the 1st item in the settings dropdown
    dropdown_html = resp.text.split('id="settingsDropdownMenu"')[1].split('</div>')[0]
    idx_pwd = resp.text.find('Change Password')
    idx_users = resp.text.find('Users & Access') if 'Users & Access' in resp.text else resp.text.find('Users &amp; Access')
    assert idx_pwd != -1
    assert idx_users != -1
    assert idx_pwd < idx_users, 'Change Password should appear before Users & Access in the hamburger menu'

    # User badge has username and avatar, but online status text and dot are removed
    assert '<span class="user-status"' not in resp.text
    assert '<span class="status-dot"' not in resp.text
    assert 'class="user-avatar"' in resp.text
    assert 'class="user-name"' in resp.text



def test_pkce_generation_and_flow():
    """Verify PKCE RFC 7636 verifier and challenge generation."""
    verifier, challenge = web.oidc.generate_pkce_pair()
    assert 43 <= len(verifier) <= 128
    assert len(challenge) > 0
    # Verifier must be URL-safe
    assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~' for c in verifier)

    # Compute expected S256 challenge manually
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    expected_challenge = base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
    assert challenge == expected_challenge


def test_oidc_login_pkce_disabled(anon_client: httpx.Client):
    """Verify PKCE parameters are omitted when oidc.use_pkce is False."""
    config.settings.oidc.enabled = True
    config.settings.oidc.issuer_url = 'https://auth.example.com/'  # type: ignore[assignment]
    config.settings.oidc.client_id = 'acme-test-client'
    config.settings.oidc.client_secret = config.SecretStr('test-secret')  # type: ignore[assignment]
    config.settings.oidc.use_pkce = False

    mock_discovery = {
        'authorization_endpoint': 'https://auth.example.com/api/oidc/authorization',
        'token_endpoint': 'https://auth.example.com/api/oidc/token',
        'jwks_uri': 'https://auth.example.com/api/oidc/jwks',
    }

    try:
        with patch('web.oidc.get_discovery_document', new=AsyncMock(return_value=mock_discovery)):
            resp = anon_client.get('/oidc/login?next=/', follow_redirects=False)
            assert resp.status_code == 302
            assert 'code_challenge=' not in resp.headers['Location']
            assert 'code_challenge_method=' not in resp.headers['Location']
    finally:
        config.settings.oidc.use_pkce = True
        config.settings.oidc.enabled = False


def test_modal_overlay_styles_present(testclient: TestClient):
    """Verify modal overlay styles in base.html enforce fixed positioning and hidden default."""
    resp = testclient.get('/accounts')
    assert resp.status_code == 200
    assert 'position: fixed;' in resp.text
    assert 'visibility: hidden;' in resp.text
    assert '.modal-overlay.active' in resp.text


def test_build_token_request_auth_and_data():
    """Verify RFC 6749 client authentication schemes."""
    # 1. client_secret_basic: credentials ONLY in Authorization header
    auth_basic, data_basic = web.oidc._build_token_request_auth_and_data(  # pylint: disable=protected-access
        method='client_secret_basic',
        client_id='my_client',
        client_secret='my_secret',
        code='code_123',
        redirect_uri='http://localhost/callback',
        code_verifier='verifier_456',
    )
    assert isinstance(auth_basic, httpx.BasicAuth)
    assert 'client_secret' not in data_basic
    assert data_basic['code'] == 'code_123'
    assert data_basic['code_verifier'] == 'verifier_456'

    # 2. client_secret_post: credentials in request body, no auth header
    auth_post, data_post = web.oidc._build_token_request_auth_and_data(  # pylint: disable=protected-access
        method='client_secret_post',
        client_id='my_client',
        client_secret='my_secret',
        code='code_123',
        redirect_uri='http://localhost/callback',
        code_verifier='verifier_456',
    )
    assert auth_post is None
    assert data_post['client_id'] == 'my_client'
    assert data_post['client_secret'] == 'my_secret'
    assert data_post['code'] == 'code_123'
    assert data_post['code_verifier'] == 'verifier_456'


def test_exchange_code_error_description_extraction():
    """Verify detailed error messages are extracted from failed token responses."""
    mock_discovery = {
        'token_endpoint': 'https://auth.example.com/api/oidc/token',
        'jwks_uri': 'https://auth.example.com/api/oidc/jwks',
        'token_endpoint_auth_methods_supported': ['client_secret_basic'],
    }

    mock_resp = httpx.Response(
        status_code=401,
        json={'error': 'invalid_client', 'error_description': 'Client authentication failed: invalid secret'},
        request=httpx.Request('POST', 'https://auth.example.com/api/oidc/token'),
    )

    with patch('web.oidc.get_discovery_document', new=AsyncMock(return_value=mock_discovery)):
        with patch('httpx.AsyncClient.post', new=AsyncMock(return_value=mock_resp)):
            try:
                asyncio.run(web.oidc.exchange_code_for_user('code_x', 'nonce_y'))
                assert False, 'Expected ValueError'
            except ValueError as e:
                assert 'HTTP 401' in str(e)
                assert 'Client authentication failed: invalid secret' in str(e)
