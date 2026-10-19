import base64
import hashlib
import json
import secrets
import ssl
import time
from typing import Any
from urllib.parse import urlencode

import httpx
from config import settings
from jwcrypto import jwk, jwt
from logger import logger

# Cache for OIDC provider discovery document and JWKS
_DISCOVERY_CACHE: dict[str, Any] | None = None
_DISCOVERY_CACHE_TIME: float = 0.0
_JWKS_CACHE: jwk.JWKSet | None = None
_JWKS_CACHE_TIME: float = 0.0
CACHE_TTL = 3600.0  # 1 hour


def get_oidc_ssl_context() -> ssl.SSLContext | bool:
    """Return SSL context or verification boolean based on OIDC configuration.

    If verify_ssl is disabled, returns False.
    If x509_required is True, returns True for standard strict RFC 5280 verification.
    If x509_required is False, returns a relaxed SSLContext with VERIFY_X509_STRICT
    cleared, legacy server connect permitted, and SECLEVEL=1 ciphers configured for
    compatibility with older IdP certificates in Python 3.10+ / OpenSSL 3+.
    """
    if not settings.oidc.verify_ssl:
        return False
    if settings.oidc.x509_required:
        return True

    ctx = ssl.create_default_context()
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    if hasattr(ssl, 'OP_LEGACY_SERVER_CONNECT'):
        ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
    try:
        ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
    except ssl.SSLError:
        pass
    return ctx


def get_redirect_uri() -> str:
    """Get the OIDC redirect URI (callback endpoint)."""
    if settings.oidc.redirect_url:
        return str(settings.oidc.redirect_url)
    return str(settings.external_url).rstrip('/') + '/oidc/callback'


async def get_discovery_document() -> dict[str, Any]:
    """Fetch and cache OpenID Connect configuration from provider."""
    global _DISCOVERY_CACHE, _DISCOVERY_CACHE_TIME  # pylint: disable=global-statement
    now = time.time()
    if _DISCOVERY_CACHE and (now - _DISCOVERY_CACHE_TIME) < CACHE_TTL:
        return _DISCOVERY_CACHE

    if not settings.oidc.issuer_url:
        raise ValueError('OIDC issuer URL is not configured.')

    issuer = str(settings.oidc.issuer_url).rstrip('/')
    discovery_url = f'{issuer}/.well-known/openid-configuration'

    async with httpx.AsyncClient(verify=get_oidc_ssl_context(), timeout=10.0) as client:
        resp = await client.get(discovery_url)
        resp.raise_for_status()
        data = resp.json()

    _DISCOVERY_CACHE = data
    _DISCOVERY_CACHE_TIME = now
    return data


async def get_jwks(jwks_uri: str) -> jwk.JWKSet:
    """Fetch and cache provider JSON Web Key Set."""
    global _JWKS_CACHE, _JWKS_CACHE_TIME  # pylint: disable=global-statement
    now = time.time()
    if _JWKS_CACHE and (now - _JWKS_CACHE_TIME) < CACHE_TTL:
        return _JWKS_CACHE

    async with httpx.AsyncClient(verify=get_oidc_ssl_context(), timeout=10.0) as client:
        resp = await client.get(jwks_uri)
        resp.raise_for_status()
        jwks_data = resp.text

    keyset = jwk.JWKSet.from_json(jwks_data)
    _JWKS_CACHE = keyset
    _JWKS_CACHE_TIME = now
    return keyset


async def get_authorization_url(state: str, nonce: str, code_challenge: str | None = None) -> str:
    """Generate the full authorization URL to redirect the user to the OIDC provider."""
    discovery = await get_discovery_document()
    auth_endpoint = discovery.get('authorization_endpoint')
    if not auth_endpoint:
        raise ValueError('OIDC discovery document missing authorization_endpoint.')

    params = {
        'client_id': settings.oidc.client_id,
        'response_type': 'code',
        'scope': settings.oidc.scopes,
        'redirect_uri': get_redirect_uri(),
        'state': state,
        'nonce': nonce,
    }
    if code_challenge:
        params['code_challenge'] = code_challenge
        params['code_challenge_method'] = 'S256'

    return f'{auth_endpoint}?{urlencode(params)}'


def _build_token_request_auth_and_data(
    method: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    code_verifier: str | None,
) -> tuple[httpx.BasicAuth | None, dict[str, str]]:
    """Build auth header and form data conforming to RFC 6749 Section 2.3.1."""
    data: dict[str, str] = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
    }
    if code_verifier:
        data['code_verifier'] = code_verifier

    if method == 'client_secret_post':
        data['client_id'] = client_id
        if client_secret:
            data['client_secret'] = client_secret
        return None, data

    # Default to client_secret_basic: credentials ONLY in Authorization header
    auth = httpx.BasicAuth(client_id, client_secret) if (client_id and client_secret) else None
    return auth, data


async def exchange_code_for_user(
    code: str,
    expected_nonce: str,
    code_verifier: str | None = None,
) -> dict[str, Any]:
    """Exchange authorization code at token_endpoint and validate ID token claims.

    Returns dict containing validated email, username, and raw claims.
    """
    discovery = await get_discovery_document()
    token_endpoint = discovery.get('token_endpoint')
    jwks_uri = discovery.get('jwks_uri')

    if not token_endpoint or not jwks_uri:
        raise ValueError('OIDC discovery document missing token_endpoint or jwks_uri.')

    client_id = settings.oidc.client_id or ''
    client_secret = settings.oidc.client_secret.get_secret_value() if settings.oidc.client_secret else ''

    supported_methods = discovery.get('token_endpoint_auth_methods_supported', ['client_secret_basic', 'client_secret_post'])
    configured_method = settings.oidc.token_auth_method

    if configured_method == 'client_secret_post':
        primary_method = 'client_secret_post'
    elif configured_method == 'client_secret_basic':
        primary_method = 'client_secret_basic'
    else:  # 'auto'
        if 'client_secret_basic' in supported_methods or not supported_methods:
            primary_method = 'client_secret_basic'
        else:
            primary_method = 'client_secret_post'

    auth, data = _build_token_request_auth_and_data(
        method=primary_method,
        client_id=client_id,
        client_secret=client_secret,
        code=code,
        redirect_uri=get_redirect_uri(),
        code_verifier=code_verifier,
    )

    # Request token exchange
    async with httpx.AsyncClient(verify=get_oidc_ssl_context(), timeout=15.0) as client:
        resp = await client.post(
            token_endpoint,
            data=data,
            headers={'Accept': 'application/json'},
            auth=auth if auth is not None else httpx.USE_CLIENT_DEFAULT,
        )

        # Fallback: if 'auto' with client_secret_basic failed with 401, retry with client_secret_post
        if resp.status_code in (400, 401) and configured_method == 'auto' and primary_method == 'client_secret_basic':
            logger.info('OIDC token exchange failed with %s using %s, trying client_secret_post fallback', resp.status_code, primary_method)
            fallback_auth, fallback_data = _build_token_request_auth_and_data(
                method='client_secret_post',
                client_id=client_id,
                client_secret=client_secret,
                code=code,
                redirect_uri=get_redirect_uri(),
                code_verifier=code_verifier,
            )
            fallback_resp = await client.post(
                token_endpoint,
                data=fallback_data,
                headers={'Accept': 'application/json'},
                auth=fallback_auth if fallback_auth is not None else httpx.USE_CLIENT_DEFAULT,
            )
            if fallback_resp.status_code == 200:
                resp = fallback_resp

        if resp.status_code != 200:
            logger.error('OIDC token exchange failed: HTTP %s - %s', resp.status_code, resp.text)
            err_detail = ''
            try:
                err_json = resp.json()
                err_detail = err_json.get('error_description') or err_json.get('error') or ''
            except (json.JSONDecodeError, ValueError):
                if resp.text:
                    err_detail = resp.text[:120].strip()

            error_msg = f'Token exchange failed: HTTP {resp.status_code}'
            if err_detail:
                error_msg = f'{error_msg} - {err_detail}'
            raise ValueError(error_msg)

        token_response = resp.json()

    id_token_raw = token_response.get('id_token')
    if not id_token_raw:
        raise ValueError('No id_token returned in OIDC token response.')

    # Validate and decode ID token with provider JWKS
    keyset = await get_jwks(jwks_uri)
    try:
        jwt_token = jwt.JWT(key=keyset, jwt=id_token_raw)
        claims = json.loads(jwt_token.claims)
    except Exception as e:
        logger.error('Failed to verify OIDC id_token signature: %s', e)
        raise ValueError('Invalid OIDC ID token signature.') from e

    # Verify standard claims
    issuer = str(settings.oidc.issuer_url).rstrip('/')
    token_iss = str(claims.get('iss', '')).rstrip('/')
    if token_iss != issuer:
        logger.error('OIDC issuer mismatch: expected %s, got %s', issuer, token_iss)
        raise ValueError('OIDC token issuer mismatch.')

    token_aud = claims.get('aud')
    if isinstance(token_aud, list):
        if client_id not in token_aud:
            raise ValueError('OIDC token audience does not contain client_id.')
    elif token_aud != client_id:
        raise ValueError('OIDC token audience does not match client_id.')

    token_nonce = claims.get('nonce')
    if expected_nonce and token_nonce != expected_nonce:
        logger.error('OIDC nonce mismatch: expected %s, got %s', expected_nonce, token_nonce)
        raise ValueError('OIDC token nonce mismatch.')

    # Extract email claim
    user_claim_name = settings.oidc.user_claim or 'email'
    email = claims.get(user_claim_name) or claims.get('email')

    # If email claim is not directly in id_token, query userinfo_endpoint
    access_token = token_response.get('access_token')
    if not email and access_token and discovery.get('userinfo_endpoint'):
        userinfo_url = discovery['userinfo_endpoint']
        async with httpx.AsyncClient(verify=get_oidc_ssl_context(), timeout=10.0) as client:
            ui_resp = await client.get(userinfo_url, headers={'Authorization': f'Bearer {access_token}'})
            if ui_resp.status_code == 200:
                ui_data = ui_resp.json()
                email = ui_data.get(user_claim_name) or ui_data.get('email')
                claims.update(ui_data)

    if not email:
        raise ValueError('OIDC identity provider did not supply a verified email address.')

    username = claims.get('preferred_username') or claims.get('name') or email.split('@')[0]

    return {
        'email': str(email).strip().lower(),
        'username': str(username).strip(),
        'claims': claims,
    }


def generate_state_and_nonce() -> tuple[str, str]:
    """Generate cryptographically secure state and nonce tokens."""
    return secrets.token_urlsafe(24), secrets.token_urlsafe(24)


def generate_pkce_pair() -> tuple[str, str]:
    """Generate (code_verifier, code_challenge) for PKCE (RFC 7636) using S256."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    challenge = base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
    return verifier, challenge
