# pylint: disable=too-many-lines,duplicate-code
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import quote, urlencode

import ca
import db
import mail.service
from ca import distribution as ca_distribution
from ca import service as ca_service
from config import settings
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from fastapi import APIRouter, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader
from logger import logger
from pydantic import constr

from . import auth as web_auth
from . import oidc as web_oidc

template_engine = Environment(loader=FileSystemLoader(Path(__file__).parent / 'templates'), enable_async=True, autoescape=True)


def to_local(dt: datetime | str | None) -> datetime | None:
    if not dt:
        return None
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return None
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone()


def format_datetime(dt: datetime | str | None, fmt: str = '%Y-%m-%d %H:%M') -> str:
    if not dt:
        return ''
    loc = to_local(dt)
    if not loc:
        return str(dt) if dt else ''
    return loc.strftime(fmt)


def local_isoformat(dt: datetime | str | None) -> str:
    if not dt:
        return ''
    loc = to_local(dt)
    if not loc:
        return str(dt) if dt else ''
    return loc.isoformat()


def get_service_tz_label() -> str:
    now = datetime.now().astimezone()
    tz_name = now.tzname() or ''
    offset = now.strftime('%z')
    formatted_offset = f'UTC{offset[:3]}:{offset[3:]}' if offset else 'UTC'
    return f'{tz_name} ({formatted_offset})' if tz_name else formatted_offset


def make_redirect_url(base_path: str, params: dict[str, str | None]) -> str:
    query = {k: v for k, v in params.items() if v is not None and v != ''}
    qs = urlencode(query)
    return f'{base_path}?{qs}' if qs else base_path


template_engine.filters['to_local'] = to_local
template_engine.filters['format_datetime'] = format_datetime
template_engine.filters['local_isoformat'] = local_isoformat


def format_app_version(ver: str | None) -> str:
    ver_str = str(ver or '').strip()
    if not ver_str:
        return 'v0.0.0'
    if ver_str.startswith('v') or ver_str == 'edge':
        return ver_str
    return f'v{ver_str}'


def get_app_version() -> str:
    try:
        import main  # pylint: disable=import-outside-toplevel

        return format_app_version(getattr(main, '__version__', '0.0.0'))
    except (ImportError, AttributeError):
        return 'v0.0.0'


default_params = {  # pylint: disable=duplicate-code
    'app_title': settings.web.app_title,
    'app_desc': settings.web.app_description,
    'app_version': get_app_version(),
    'github_url': getattr(settings.web, 'github_url', 'https://github.com/diepeterpan/acme-ca-server'),
    'web_url': str(settings.external_url),
    'acme_url': str(settings.external_url).removesuffix('/') + '/acme/directory',
    'service_tz_label': get_service_tz_label(),
    'service_tz_name': datetime.now().astimezone().tzname() or 'Local',
    'oidc_enabled': settings.oidc.enabled,
    'oidc_button_label': settings.oidc.button_label,
}


api = APIRouter(tags=['web'])


@api.get('/', response_class=HTMLResponse)
async def index(request: Request, error: str = '', success: str = ''):
    stats = {
        'accounts_count': 0,
        'total_domains': 0,
        'active_domains': 0,
        'certs_total': 0,
        'certs_valid': 0,
        'certs_expiring': 0,
        'certs_revoked': 0,
        'certs_expired': 0,
    }

    async with db.transaction(readonly=True) as sql:
        accounts_count = await sql.value('select count(*) from accounts')
        stats['accounts_count'] = accounts_count or 0

        cert_stats = await sql.record(
            """
            select
                count(*) as total,
                count(*) filter (where not_valid_after > now() and revoked_at is null) as valid,
                count(*) filter (where not_valid_after > now() and revoked_at is null and not_valid_after - now() <= interval '20 days') as expiring,
                count(*) filter (where revoked_at is not null) as revoked,
                count(*) filter (where not_valid_after <= now() and revoked_at is null) as expired
            from certificates
            """
        )
        if cert_stats:
            stats['certs_total'] = cert_stats['total']
            stats['certs_valid'] = cert_stats['valid']
            stats['certs_expiring'] = cert_stats['expiring']
            stats['certs_revoked'] = cert_stats['revoked']
            stats['certs_expired'] = cert_stats['expired']

        domain_stats = await sql.record(
            """
            with doms as (
                select
                    authz.domain,
                    bool_or(cert.not_valid_after > now() and cert.revoked_at is null) as has_valid_cert
                from authorizations authz
                left join certificates cert on cert.order_id = authz.order_id
                group by authz.domain
            )
            select
                count(*) as total,
                count(*) filter (where has_valid_cert is true) as active
            from doms
            """
        )
        if domain_stats:
            stats['total_domains'] = domain_stats['total']
            stats['active_domains'] = domain_stats['active']

    ca_details = None
    if settings.ca.enabled and ca.is_initialized:
        ca_details = await ca_service.get_active_ca_details()

    return await template_engine.get_template('index.html').render_async(
        **default_params,
        request=request,
        stats=stats,
        ca_details=ca_details,
        error=error,
        success=success,
    )


@api.get('/setup', response_class=HTMLResponse)
async def setup_get(request: Request, error: str = ''):
    if await web_auth.has_users():
        return RedirectResponse(url='/login', status_code=status.HTTP_303_SEE_OTHER)
    return await template_engine.get_template('setup.html').render_async(
        **default_params,
        request=request,
        error=error,
    )


@api.post('/setup', response_class=HTMLResponse)
async def setup_post(
    request: Request,
    username: str = Form(''),
    password: str = Form(''),
    confirm_password: str = Form(''),
):
    if await web_auth.has_users():
        return RedirectResponse(url='/login', status_code=status.HTTP_303_SEE_OTHER)

    username_clean = username.strip()
    if not username_clean:
        return await template_engine.get_template('setup.html').render_async(
            **default_params,
            request=request,
            error='Username is required.',
            username=username,
        )

    if len(username_clean) < 3 or len(username_clean) > 64:
        return await template_engine.get_template('setup.html').render_async(
            **default_params,
            request=request,
            error='Username must be between 3 and 64 characters.',
            username=username,
        )

    if len(password) < 8:
        return await template_engine.get_template('setup.html').render_async(
            **default_params,
            request=request,
            error='Password must be at least 8 characters long.',
            username=username,
        )

    if password != confirm_password:
        return await template_engine.get_template('setup.html').render_async(
            **default_params,
            request=request,
            error='Passwords do not match.',
            username=username,
        )

    # Create admin user
    await web_auth.create_user(username_clean, password)

    # Create session cookie and redirect to /
    cookie_val, max_age = web_auth.create_session_cookie(username_clean)
    response = RedirectResponse(url='/', status_code=status.HTTP_303_SEE_OTHER)
    is_secure = str(settings.external_url).startswith('https')
    response.set_cookie(
        web_auth.COOKIE_NAME,
        cookie_val,
        max_age=max_age,
        httponly=True,
        samesite='lax',
        secure=is_secure,
    )
    return response


@api.get('/login', response_class=HTMLResponse)
async def login_get(request: Request, next: str = '/', error: str = ''):  # noqa: A002  # pylint: disable=redefined-builtin
    # If user is already authenticated, redirect to next or /
    cookie_val = request.cookies.get(web_auth.COOKIE_NAME)
    if cookie_val and web_auth.verify_session_cookie(cookie_val):
        target = next if next.startswith('/') and not next.startswith('//') and next != '/login' else '/'
        return RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)

    ca_ready = bool(settings.ca.enabled and ca.is_initialized)
    ca_pem = None
    if ca_ready:
        ca_details = await ca_service.get_active_ca_details()
        if ca_details:
            ca_pem = ca_details.get('cert_pem')

    return await template_engine.get_template('login.html').render_async(
        **default_params,
        request=request,
        next=next,
        error=error,
        ca_ready=ca_ready,
        ca_pem=ca_pem,
    )


@api.post('/login', response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(''),
    password: str = Form(''),
    remember_me: bool = Form(False),
    next: str = Form('/'),  # noqa: A002  # pylint: disable=redefined-builtin
):
    user = await web_auth.authenticate_user(username, password)
    if not user:
        ca_ready = bool(settings.ca.enabled and ca.is_initialized)
        ca_pem = None
        if ca_ready:
            ca_details = await ca_service.get_active_ca_details()
            if ca_details:
                ca_pem = ca_details.get('cert_pem')
        html_content = await template_engine.get_template('login.html').render_async(
            **default_params,
            request=request,
            next=next,
            username=username,
            error='Invalid username or password.',
            ca_ready=ca_ready,
            ca_pem=ca_pem,
        )
        return HTMLResponse(content=html_content)

    cookie_val, max_age = web_auth.create_session_cookie(user['username'], remember_me=remember_me)

    # Sanitize redirect target to prevent open redirect vulnerabilities
    target = next if next.startswith('/') and not next.startswith('//') and next not in ('/login', '/setup', '/logout') else '/'
    response = RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)
    is_secure = str(settings.external_url).startswith('https')
    response.set_cookie(
        web_auth.COOKIE_NAME,
        cookie_val,
        max_age=max_age,
        httponly=True,
        samesite='lax',
        secure=is_secure,
    )
    return response


@api.get('/logout')
@api.post('/logout')
async def logout():
    response = RedirectResponse(url='/login', status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(web_auth.COOKIE_NAME, path='/', httponly=True, samesite='lax')
    return response


@api.get('/oidc/login')
async def oidc_login(next: str = '/'):  # noqa: A002  # pylint: disable=redefined-builtin
    if not settings.oidc.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='OIDC authentication is not enabled.')

    target = next if next.startswith('/') and not next.startswith('//') and next not in ('/login', '/setup', '/logout') else '/'

    state, nonce = web_oidc.generate_state_and_nonce()
    code_verifier: str | None = None
    code_challenge: str | None = None
    if settings.oidc.use_pkce:
        code_verifier, code_challenge = web_oidc.generate_pkce_pair()

    try:
        auth_url = await web_oidc.get_authorization_url(state=state, nonce=nonce, code_challenge=code_challenge)
    except Exception as e:  # noqa: BLE001
        logger.error('Failed to generate OIDC authorization URL: %s', e)
        return RedirectResponse(url=f'/login?error=OIDC+Configuration+Error:+{quote(str(e), safe="")}', status_code=status.HTTP_303_SEE_OTHER)

    response = RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)
    state_payload = {'state': state, 'nonce': nonce, 'code_verifier': code_verifier, 'next': target}
    state_cookie_val, _ = web_auth.create_session_cookie(json.dumps(state_payload), remember_me=False)
    is_secure = str(settings.external_url).startswith('https')
    response.set_cookie(
        'acme_oidc_state',
        state_cookie_val,
        max_age=300,
        httponly=True,
        samesite='lax',
        secure=is_secure,
    )
    return response


@api.get('/oidc/callback')
async def oidc_callback(
    request: Request,
    code: str = '',
    state: str = '',
    error: str = '',
    error_description: str = '',
):
    if not settings.oidc.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='OIDC authentication is not enabled.')

    if error:
        err_msg = error_description or error or 'OIDC authentication was cancelled or failed.'
        return RedirectResponse(url=f'/login?error={quote(err_msg, safe="")}', status_code=status.HTTP_303_SEE_OTHER)

    if not code or not state:
        return RedirectResponse(url='/login?error=Missing+OIDC+callback+code+or+state.', status_code=status.HTTP_303_SEE_OTHER)

    state_cookie = request.cookies.get('acme_oidc_state')
    state_data = web_auth.verify_session_cookie(state_cookie) if state_cookie else None
    if not state_data:
        return RedirectResponse(url='/login?error=OIDC+session+expired+or+invalid.+Please+try+again.', status_code=status.HTTP_303_SEE_OTHER)

    try:
        saved_payload = json.loads(state_data.get('sub', '{}'))
        saved_state = saved_payload.get('state')
        saved_nonce = saved_payload.get('nonce')
        saved_code_verifier = saved_payload.get('code_verifier')
        target_next = saved_payload.get('next', '/')
    except (json.JSONDecodeError, TypeError):
        return RedirectResponse(url='/login?error=Invalid+OIDC+state+payload.', status_code=status.HTTP_303_SEE_OTHER)

    if not saved_state or saved_state != state:
        return RedirectResponse(url='/login?error=OIDC+state+mismatch+possible+CSRF.', status_code=status.HTTP_303_SEE_OTHER)

    try:
        user_info = await web_oidc.exchange_code_for_user(
            code=code,
            expected_nonce=saved_nonce,
            code_verifier=saved_code_verifier,
        )
    except Exception as e:  # noqa: BLE001
        logger.error('OIDC token verification failed: %s', e)
        return RedirectResponse(url=f'/login?error=OIDC+Authentication+Failed:+{quote(str(e), safe="")}', status_code=status.HTTP_303_SEE_OTHER)

    email = user_info['email']

    # Authenticate pre-provisioned user in DB
    db_user = await web_auth.authenticate_oidc_user(email)
    if not db_user:
        logger.warning('OIDC login rejected for unprovisioned email: %s', email)
        err_msg = f'Access denied: Account for {email} is not pre-provisioned. Contact an administrator.'
        return RedirectResponse(url=f'/login?error={quote(err_msg, safe="")}', status_code=status.HTTP_303_SEE_OTHER)

    cookie_val, max_age = web_auth.create_session_cookie(db_user['username'], remember_me=False)
    target = target_next if target_next.startswith('/') and not target_next.startswith('//') and target_next not in ('/login', '/setup', '/logout') else '/'
    response = RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)
    is_secure = str(settings.external_url).startswith('https')
    response.set_cookie(
        web_auth.COOKIE_NAME,
        cookie_val,
        max_age=max_age,
        httponly=True,
        samesite='lax',
        secure=is_secure,
    )
    response.delete_cookie('acme_oidc_state', path='/', httponly=True, samesite='lax')
    logger.info('User %s (%s) successfully authenticated via OIDC.', db_user['username'], email)
    return response


@api.get('/users', response_class=HTMLResponse)
async def users_list_get(request: Request, error: str = '', success: str = ''):
    all_users = await web_auth.list_users()
    return await template_engine.get_template('users.html').render_async(
        **default_params,
        request=request,
        users=all_users,
        error=error,
        success=success,
    )


@api.post('/users/create')
async def user_create_post(
    user_type: str = Form('local'),
    username: str = Form(''),
    email: str = Form(''),
    password: str = Form(''),
    confirm_password: str = Form(''),
):
    clean_username = username.strip()
    clean_email = email.strip()

    if not clean_username:
        return RedirectResponse(url='/users?error=Username+is+required.', status_code=status.HTTP_303_SEE_OTHER)

    existing_u = await web_auth.get_user_by_username(clean_username)
    if existing_u:
        return RedirectResponse(url=f"/users?error=User+'{quote(clean_username, safe='')}'+already+exists.", status_code=status.HTTP_303_SEE_OTHER)

    if user_type == 'oidc':
        if not clean_email or '@' not in clean_email:
            return RedirectResponse(url='/users?error=A+valid+email+address+is+mandatory+for+OIDC+users.', status_code=status.HTTP_303_SEE_OTHER)
        existing_e = await web_auth.get_user_by_email(clean_email)
        if existing_e:
            return RedirectResponse(url=f"/users?error=Email+'{quote(clean_email, safe='')}'+is+already+associated+with+another+user.", status_code=status.HTTP_303_SEE_OTHER)
        await web_auth.create_oidc_user(username=clean_username, email=clean_email)
        return RedirectResponse(url=f"/users?success=OIDC+user+'{quote(clean_username, safe='')}'+created+successfully.", status_code=status.HTTP_303_SEE_OTHER)

    # Local user
    if len(password) < 8:
        return RedirectResponse(url='/users?error=Password+must+be+at+least+8+characters.', status_code=status.HTTP_303_SEE_OTHER)
    if password != confirm_password:
        return RedirectResponse(url='/users?error=Passwords+do+not+match.', status_code=status.HTTP_303_SEE_OTHER)

    if clean_email:
        if '@' not in clean_email:
            return RedirectResponse(url='/users?error=Invalid+email+address+format.', status_code=status.HTTP_303_SEE_OTHER)
        existing_e = await web_auth.get_user_by_email(clean_email)
        if existing_e:
            return RedirectResponse(url=f"/users?error=Email+'{quote(clean_email, safe='')}'+is+already+associated+with+another+user.", status_code=status.HTTP_303_SEE_OTHER)

    await web_auth.create_user(username=clean_username, password=password, email=clean_email or None)
    return RedirectResponse(url=f"/users?success=Local+user+'{quote(clean_username, safe='')}'+created+successfully.", status_code=status.HTTP_303_SEE_OTHER)


@api.post('/users/{user_id}/delete')
async def user_delete_post(request: Request, user_id: str):
    current_username = getattr(request.state, 'user', {}).get('username', '')
    ok, err = await web_auth.delete_user(user_id, current_username=current_username)
    if not ok:
        return RedirectResponse(url=f'/users?error={quote(err, safe="")}', status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(url='/users?success=User+deleted+successfully.', status_code=status.HTTP_303_SEE_OTHER)


@api.post('/users/{user_id}/reset-password')
async def user_reset_password_post(
    user_id: str,
    password: str = Form(''),
    confirm_password: str = Form(''),
):
    target_user = await web_auth.get_user_by_id(user_id)
    if not target_user:
        return RedirectResponse(url='/users?error=User+not+found.', status_code=status.HTTP_303_SEE_OTHER)
    if target_user['user_type'] != 'local':
        return RedirectResponse(
            url='/users?error=Cannot+reset+password+for+OIDC+accounts.+Passwords+are+managed+at+your+identity+provider.', status_code=status.HTTP_303_SEE_OTHER
        )

    if len(password) < 8:
        return RedirectResponse(url='/users?error=New+password+must+be+at+least+8+characters.', status_code=status.HTTP_303_SEE_OTHER)
    if password != confirm_password:
        return RedirectResponse(url='/users?error=Passwords+do+not+match.', status_code=status.HTTP_303_SEE_OTHER)

    await web_auth.reset_user_password(user_id, password)
    return RedirectResponse(url=f"/users?success=Password+for+'{quote(target_user['username'], safe='')}'+reset+successfully.", status_code=status.HTTP_303_SEE_OTHER)


@api.post('/users/{user_id}/email')
async def user_email_update_post(
    user_id: str,
    email: str = Form(''),
):
    target_user = await web_auth.get_user_by_id(user_id)
    if not target_user:
        return RedirectResponse(url='/users?error=User+not+found.', status_code=status.HTTP_303_SEE_OTHER)

    clean_email = email.strip()
    if target_user['user_type'] == 'oidc' and (not clean_email or '@' not in clean_email):
        return RedirectResponse(url='/users?error=Email+address+is+mandatory+for+OIDC+users.', status_code=status.HTTP_303_SEE_OTHER)

    if clean_email:
        existing = await web_auth.get_user_by_email(clean_email)
        if existing and existing['id'] != user_id:
            return RedirectResponse(url=f"/users?error=Email+'{quote(clean_email, safe='')}'+is+already+used+by+another+account.", status_code=status.HTTP_303_SEE_OTHER)

    await web_auth.update_user_email(user_id, clean_email or None)
    return RedirectResponse(url=f"/users?success=Email+for+'{quote(target_user['username'], safe='')}'+updated+successfully.", status_code=status.HTTP_303_SEE_OTHER)


@api.post('/account/password')
async def account_change_password_post(request: Request):
    current_user_name = getattr(request.state, 'user', {}).get('username', '')
    if not current_user_name:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Not authenticated')

    content_type = request.headers.get('content-type', '').lower()
    accept_header = request.headers.get('accept', '').lower()
    is_json = 'application/json' in content_type or 'application/json' in accept_header

    if 'application/json' in content_type:
        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError):
            body = {}
        curr_pwd = str(body.get('current_password', ''))
        new_pwd = str(body.get('new_password', ''))
        confirm_pwd = str(body.get('confirm_password', ''))
    else:
        form = await request.form()
        curr_pwd = str(form.get('current_password', ''))
        new_pwd = str(form.get('new_password', ''))
        confirm_pwd = str(form.get('confirm_password', ''))

    user_type = getattr(request.state, 'user', {}).get('user_type', 'local')
    if user_type == 'oidc':
        if is_json:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={'ok': False, 'error': 'Password cannot be changed for OIDC-managed accounts.'})
        return RedirectResponse(url='/?error=Password+cannot+be+changed+for+OIDC-managed+accounts.', status_code=status.HTTP_303_SEE_OTHER)

    user = await web_auth.authenticate_user(current_user_name, curr_pwd)
    if not user:
        if is_json:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={'ok': False, 'error': 'Current password is incorrect.'})
        return RedirectResponse(url='/?error=Current+password+is+incorrect.', status_code=status.HTTP_303_SEE_OTHER)

    if len(new_pwd) < 8:
        if is_json:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={'ok': False, 'error': 'New password must be at least 8 characters.'})
        return RedirectResponse(url='/?error=New+password+must+be+at+least+8+characters.', status_code=status.HTTP_303_SEE_OTHER)

    if new_pwd != confirm_pwd:
        if is_json:
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={'ok': False, 'error': 'New passwords do not match.'})
        return RedirectResponse(url='/?error=New+passwords+do+not+match.', status_code=status.HTTP_303_SEE_OTHER)

    await web_auth.reset_user_password(user['id'], new_pwd)
    if is_json:
        return JSONResponse(status_code=status.HTTP_200_OK, content={'ok': True, 'message': 'Password changed successfully.'})
    return RedirectResponse(url='/?success=Password+changed+successfully.', status_code=status.HTTP_303_SEE_OTHER)


@api.get('/ca/setup', response_class=HTMLResponse)
async def ca_setup_get(request: Request, error: str = '', status_msg: str = ''):
    if not settings.ca.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Internal CA is disabled')
    if ca.is_initialized:
        return RedirectResponse(url='/ca', status_code=status.HTTP_303_SEE_OTHER)
    return await template_engine.get_template('ca-setup.html').render_async(
        **default_params,
        request=request,
        error=error,
        status_msg=status_msg,
        form_data={
            'common_name': 'ACME Root CA',
            'organization': '',
            'organizational_unit': '',
            'country': '',
            'state': '',
            'locality': '',
            'key_type': 'RSA',
            'key_size_or_curve': '4096',
            'digest_algorithm': 'SHA-384',
            'validity_years': 10,
        },
    )


@api.post('/ca/setup', response_class=HTMLResponse)
async def ca_setup_post(
    request: Request,
    common_name: str = Form(''),
    organization: str = Form(''),
    organizational_unit: str = Form(''),
    country: str = Form(''),
    state: str = Form(''),
    locality: str = Form(''),
    key_type: str = Form('RSA'),
    key_size_or_curve: str = Form('4096'),
    digest_algorithm: str = Form('SHA-384'),
    validity_years: int = Form(10),
):
    if not settings.ca.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Internal CA is disabled')
    if ca.is_initialized:
        return RedirectResponse(url='/ca', status_code=status.HTTP_303_SEE_OTHER)

    form_data = {
        'common_name': common_name,
        'organization': organization,
        'organizational_unit': organizational_unit,
        'country': country,
        'state': state,
        'locality': locality,
        'key_type': key_type,
        'key_size_or_curve': key_size_or_curve,
        'digest_algorithm': digest_algorithm,
        'validity_years': validity_years,
    }

    cn = common_name.strip()
    if not cn:
        return await template_engine.get_template('ca-setup.html').render_async(
            **default_params,
            request=request,
            error='Common Name (CN) is required.',
            form_data=form_data,
        )
    if len(cn) > 64:
        return await template_engine.get_template('ca-setup.html').render_async(
            **default_params,
            request=request,
            error='Common Name (CN) must not exceed 64 characters.',
            form_data=form_data,
        )

    c = country.strip().upper()
    if c and (len(c) != 2 or not c.isalpha()):
        return await template_engine.get_template('ca-setup.html').render_async(
            **default_params,
            request=request,
            error='Country code must be a 2-letter ISO 3166-1 alpha-2 code (e.g. US, DE, GB).',
            form_data=form_data,
        )

    if validity_years < 1 or validity_years > 30:
        return await template_engine.get_template('ca-setup.html').render_async(
            **default_params,
            request=request,
            error='Validity period must be between 1 and 30 years.',
            form_data=form_data,
        )

    try:
        await ca_service.create_root_ca(
            common_name=cn,
            organization=organization.strip() or None,
            organizational_unit=organizational_unit.strip() or None,
            country=c or None,
            state=state.strip() or None,
            locality=locality.strip() or None,
            key_type=key_type,
            key_size_or_curve=key_size_or_curve,
            digest_algorithm=digest_algorithm,
            validity_years=validity_years,
        )
    except Exception as exc:  # noqa: BLE001
        return await template_engine.get_template('ca-setup.html').render_async(
            **default_params,
            request=request,
            error=f'Failed to generate CA certificate: {exc}',
            form_data=form_data,
        )

    return RedirectResponse(url='/ca?status_msg=ca_created', status_code=status.HTTP_303_SEE_OTHER)


@api.get('/ca', response_class=HTMLResponse)
async def ca_view(request: Request, status_msg: str = '', error: str = ''):
    if not settings.ca.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Internal CA is disabled')
    if not ca.is_initialized:
        return RedirectResponse(url='/ca/setup', status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    ca_details = await ca_service.get_active_ca_details()
    if not ca_details:
        return RedirectResponse(url='/ca/setup', status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    all_cas = await ca_service.list_all_cas()
    renew_form = await ca_service.get_active_ca_subject_attributes()

    return await template_engine.get_template('ca-details.html').render_async(
        **default_params,
        request=request,
        ca=ca_details,
        all_cas=all_cas,
        renew_form=renew_form,
        status_msg=status_msg,
        error=error,
    )


@api.get('/ca/download', response_class=Response, responses={200: {'content': {'application/x-x509-ca-cert': {}}}})
@api.get('/ca/download/crt', response_class=Response, responses={200: {'content': {'application/x-x509-ca-cert': {}}}})
@api.get('/ca/download-crt', response_class=Response, responses={200: {'content': {'application/x-x509-ca-cert': {}}}})
async def ca_download():
    if not settings.ca.enabled or not ca.is_initialized:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='CA is not initialized')
    ca_details = await ca_service.get_active_ca_details()
    if not ca_details or not ca_details.get('cert_pem'):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='No active CA certificate found')
    filename = f'ca_{ca_details["serial_number"][:8]}.crt'
    return Response(
        content=ca_details['cert_pem'],
        media_type='application/x-x509-ca-cert',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@api.get('/ca/download/pem', response_class=Response, responses={200: {'content': {'application/x-pem-file': {}}}})
@api.get('/ca/download-pem', response_class=Response, responses={200: {'content': {'application/x-pem-file': {}}}})
async def ca_download_pem():
    if not settings.ca.enabled or not ca.is_initialized:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='CA is not initialized')
    ca_details = await ca_service.get_active_ca_details()
    if not ca_details or not ca_details.get('cert_pem'):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='No active CA certificate found')
    filename = f'ca_{ca_details["serial_number"][:8]}.pem'
    return Response(
        content=ca_details['cert_pem'],
        media_type='application/x-pem-file',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@api.get('/ca/download/crl', response_class=Response, responses={200: {'content': {'application/pkix-crl': {}}}})
@api.get('/ca/download-crl', response_class=Response, responses={200: {'content': {'application/pkix-crl': {}}}})
async def ca_download_crl():
    if not settings.ca.enabled or not ca.is_initialized:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='CA is not initialized')
    ca_details = await ca_service.get_active_ca_details()
    if not ca_details or not ca_details.get('crl_pem'):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='No CRL found for active CA')
    filename = f'ca_{ca_details["serial_number"][:8]}.crl'
    return Response(
        content=ca_details['crl_pem'],
        media_type='application/pkix-crl',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@api.get('/ca/{serial_number}/download', response_class=Response, responses={200: {'content': {'application/x-x509-ca-cert': {}}}})
@api.get('/ca/{serial_number}/download-crt', response_class=Response, responses={200: {'content': {'application/x-x509-ca-cert': {}}}})
async def ca_download_specific(serial_number: constr(pattern='^[0-9A-F]+$')):  # type: ignore[valid-type]
    if not settings.ca.enabled or not ca.is_initialized:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='CA is not initialized')
    async with db.transaction(readonly=True) as sql:
        cert_pem = await sql.value('select cert_pem from cas where serial_number = $1', serial_number)
    if not cert_pem:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='CA not found')
    filename = f'ca_{serial_number[:8]}.crt'
    return Response(
        content=cert_pem,
        media_type='application/x-x509-ca-cert',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@api.get('/ca/{serial_number}/download-pem', response_class=Response, responses={200: {'content': {'application/x-pem-file': {}}}})
async def ca_download_pem_specific(serial_number: constr(pattern='^[0-9A-F]+$')):  # type: ignore[valid-type]
    if not settings.ca.enabled or not ca.is_initialized:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='CA is not initialized')
    async with db.transaction(readonly=True) as sql:
        cert_pem = await sql.value('select cert_pem from cas where serial_number = $1', serial_number)
    if not cert_pem:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='CA not found')
    filename = f'ca_{serial_number[:8]}.pem'
    return Response(
        content=cert_pem,
        media_type='application/x-pem-file',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@api.post('/ca/renew', response_class=HTMLResponse)
async def ca_renew_post(
    common_name: str = Form(''),
    organization: str = Form(''),
    organizational_unit: str = Form(''),
    country: str = Form(''),
    state: str = Form(''),
    locality: str = Form(''),
    key_type: str = Form('RSA'),
    key_size_or_curve: str = Form('4096'),
    digest_algorithm: str = Form('SHA-384'),
    validity_years: int = Form(10),
    activate_immediately: str = Form(None),
):
    if not settings.ca.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Internal CA is disabled')

    cn = common_name.strip()
    if not cn:
        return RedirectResponse(url='/ca?error=Common+Name+(CN)+is+required', status_code=status.HTTP_303_SEE_OTHER)
    if len(cn) > 64:
        return RedirectResponse(url='/ca?error=Common+Name+must+not+exceed+64+characters', status_code=status.HTTP_303_SEE_OTHER)

    c = country.strip().upper()
    if c and (len(c) != 2 or not c.isalpha()):
        return RedirectResponse(url='/ca?error=Country+code+must+be+a+2-letter+ISO+code', status_code=status.HTTP_303_SEE_OTHER)

    if validity_years < 1 or validity_years > 30:
        return RedirectResponse(url='/ca?error=Validity+period+must+be+between+1+and+30+years', status_code=status.HTTP_303_SEE_OTHER)

    should_activate = activate_immediately in ('on', 'true', '1')

    try:
        await ca_service.renew_root_ca(
            common_name=cn,
            organization=organization.strip() or None,
            organizational_unit=organizational_unit.strip() or None,
            country=c or None,
            state=state.strip() or None,
            locality=locality.strip() or None,
            key_type=key_type,
            key_size_or_curve=key_size_or_curve,
            digest_algorithm=digest_algorithm,
            validity_years=validity_years,
            activate_immediately=should_activate,
        )
        status_code_msg = 'ca_renewed_active' if should_activate else 'ca_renewed_standby'
        return RedirectResponse(url=f'/ca?status_msg={status_code_msg}', status_code=status.HTTP_303_SEE_OTHER)
    except Exception as exc:  # noqa: BLE001
        logger.error('Failed to renew CA: %s', exc, exc_info=True)
        return RedirectResponse(url=f'/ca?error={exc}', status_code=status.HTTP_303_SEE_OTHER)


@api.post('/ca/{serial_number}/activate')
async def ca_activate_post(serial_number: constr(pattern='^[0-9A-F]+$')):  # type: ignore[valid-type]
    if not settings.ca.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Internal CA is disabled')
    try:
        await ca_service.set_active_ca(serial_number)
        return RedirectResponse(url='/ca?status_msg=ca_activated', status_code=status.HTTP_303_SEE_OTHER)
    except Exception as exc:  # noqa: BLE001
        return RedirectResponse(url=f'/ca?error={exc}', status_code=status.HTTP_303_SEE_OTHER)


@api.post('/ca/{serial_number}/retire')
async def ca_retire_post(serial_number: constr(pattern='^[0-9A-F]+$')):  # type: ignore[valid-type]
    if not settings.ca.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Internal CA is disabled')
    try:
        await ca_service.retire_ca(serial_number)
        return RedirectResponse(url='/ca?status_msg=ca_retired', status_code=status.HTTP_303_SEE_OTHER)
    except Exception as exc:  # noqa: BLE001
        return RedirectResponse(url=f'/ca?error={exc}', status_code=status.HTTP_303_SEE_OTHER)


@api.post('/ca/{serial_number}/delete')
async def ca_delete_post(serial_number: constr(pattern='^[0-9A-F]+$')):  # type: ignore[valid-type]
    if not settings.ca.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Internal CA is disabled')
    try:
        await ca_service.delete_ca(serial_number)
        return RedirectResponse(url='/ca?status_msg=ca_deleted', status_code=status.HTTP_303_SEE_OTHER)
    except Exception as exc:  # noqa: BLE001
        return RedirectResponse(url=f'/ca?error={exc}', status_code=status.HTTP_303_SEE_OTHER)


@api.get('/certificates', response_class=HTMLResponse)
async def certificate_log(
    request: Request,
    domainfilter: str = '',
    account_id: str = '',
    certstatus: Literal['all', 'valid', 'expiring', 'revoked', 'expired', 'invalid'] = 'expiring',
    status_msg: str = '',
):
    account_email = None
    async with db.transaction(readonly=True) as sql:
        if account_id:
            account_email = await sql.value('select mail from accounts where id = $1', account_id)

        certs = [
            record
            async for record in sql(
                """
                with data as (
                    select
                        cert.serial_number, cert.not_valid_before, cert.not_valid_after, cert.revoked_at,
                        (cert.not_valid_after > now() and cert.revoked_at is null) as is_valid,
                        (cert.not_valid_after <= now() and cert.revoked_at is null) as is_expired,
                        (cert.revoked_at is not null) as is_revoked,
                        ((cert.not_valid_after > now() and cert.revoked_at is null) and (cert.not_valid_after - now() <= interval '20 days')) as is_expiring,
                        (cert.not_valid_after - cert.not_valid_before) as lifetime,
                        (now() - cert.not_valid_before) as age,
                        (cert.not_valid_after - now()) as remaining,
                        array_agg(distinct authz.domain order by authz.domain) as domains
                    from certificates cert
                    join orders ord on ord.id = cert.order_id
                    join authorizations authz on authz.order_id = cert.order_id
                    where ($1::text = '' or authz.domain ilike '%' || $1::text || '%')
                      and ($3::text = '' or ord.account_id = $3::text)
                    group by cert.serial_number, cert.not_valid_before, cert.not_valid_after, cert.revoked_at
                )
                select * from data
                where (
                    $2 = 'all' or
                    ($2 = 'valid' and is_valid) or
                    ($2 = 'expiring' and is_expiring) or
                    ($2 = 'revoked' and is_revoked) or
                    ($2 = 'expired' and is_expired) or
                    ($2 = 'invalid' and not is_valid)
                )
                order by
                    case when is_valid then 0 else 1 end asc,
                    case when is_valid then not_valid_after end asc,
                    not_valid_after desc,
                    serial_number asc
                limit 1000
                """,
                domainfilter.replace('*', '%'),
                certstatus,
                account_id,
            )
        ]
    return await template_engine.get_template('cert-log.html').render_async(
        **default_params,
        request=request,
        certs=certs,
        certstatus=certstatus,
        domainfilter=domainfilter,
        account_id=account_id,
        account_email=account_email,
        status_msg=status_msg,
    )


@api.get('/certificates/{serial_number}', response_class=Response, responses={200: {'content': {'application/pem-certificate-chain': {}}}})
async def download_certificate(serial_number: constr(pattern='^[0-9A-F]+$')):  # type: ignore[valid-type]
    async with db.transaction(readonly=True) as sql:
        record = await sql.record(
            """
            select c.chain_pem, coalesce((array_agg(a.domain order by a.domain))[1], 'certificate') as primary_domain
            from certificates c
            left join authorizations a on a.order_id = c.order_id
            where c.serial_number = $1
            group by c.serial_number, c.chain_pem
            """,
            serial_number,
        )
    if not record or not record['chain_pem']:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='unknown certificate')
    filename = f'{record["primary_domain"]}_{serial_number[:8]}.crt'
    return Response(
        content=record['chain_pem'],
        media_type='application/pem-certificate-chain',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@api.get('/certificates/{serial_number}/details', response_class=JSONResponse)
async def certificate_details(serial_number: constr(pattern='^[0-9A-F]+$')):  # type: ignore[valid-type]
    async with db.transaction(readonly=True) as sql:
        record = await sql.record(
            """
            select c.serial_number, c.chain_pem, c.not_valid_before, c.not_valid_after, c.revoked_at,
                   c.order_id, ord.account_id, acc.mail as account_email,
                   array_agg(distinct a.domain order by a.domain) as domains
            from certificates c
            join orders ord on ord.id = c.order_id
            left join accounts acc on acc.id = ord.account_id
            left join authorizations a on a.order_id = c.order_id
            where c.serial_number = $1
            group by c.serial_number, c.chain_pem, c.not_valid_before, c.not_valid_after, c.revoked_at, c.order_id, ord.account_id, acc.mail
            """,
            serial_number,
        )

    if not record or not record['chain_pem']:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Certificate not found')

    try:
        cert_pem = record['chain_pem'].strip()
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
    except Exception as exc:  # pylint: disable=broad-exception-caught
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f'Failed to parse certificate: {exc}') from exc

    subject_cn = ''
    cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if cn_attrs:
        subject_cn = str(cn_attrs[0].value)

    issuer_cn = ''
    issuer_attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if issuer_attrs:
        issuer_cn = str(issuer_attrs[0].value)

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        if isinstance(san_ext.value, x509.SubjectAlternativeName):
            sans = [str(item.value) for item in san_ext.value]
    except x509.ExtensionNotFound:
        pass
    if not sans and record['domains']:
        sans = list(record['domains'])

    now_utc = datetime.now(timezone.utc)
    nvb_utc = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=timezone.utc)
    nva_utc = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)

    total_validity_sec = max(1, int((nva_utc - nvb_utc).total_seconds()))
    elapsed_sec = max(0, int((now_utc - nvb_utc).total_seconds()))
    percent_elapsed = min(100, max(0, int((elapsed_sec / total_validity_sec) * 100)))

    is_revoked = record['revoked_at'] is not None
    is_expired = nva_utc <= now_utc and not is_revoked
    days_remaining = (nva_utc - now_utc).days
    is_expiring = not is_revoked and not is_expired and days_remaining <= 20
    is_valid = not is_revoked and not is_expired and not is_expiring

    status_label = 'revoked' if is_revoked else ('expired' if is_expired else ('expiring' if is_expiring else 'valid'))

    pubkey = cert.public_key()
    key_type = 'Unknown'
    key_size = 0
    if isinstance(pubkey, rsa.RSAPublicKey):
        key_type = 'RSA'
        key_size = pubkey.key_size
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        key_type = 'ECDSA'
        key_size = pubkey.curve.key_size
    elif isinstance(pubkey, ed25519.Ed25519PublicKey):
        key_type = 'Ed25519'
        key_size = 256

    sig_algo = key_type
    if cert.signature_hash_algorithm is not None:
        sig_algo = f'{cert.signature_hash_algorithm.name.upper()} with {key_type}'

    fp_bytes = cert.fingerprint(hashes.SHA256())
    fingerprint_sha256 = ':'.join(f'{b:02X}' for b in fp_bytes)

    capabilities: list[dict[str, str]] = []
    key_usages: list[str] = []
    try:
        ku_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
        if isinstance(ku_ext.value, x509.KeyUsage):
            ku = ku_ext.value
            if ku.digital_signature:
                key_usages.append('Digital Signature')
            if ku.key_encipherment:
                key_usages.append('Key Encipherment')
            if ku.key_agreement:
                key_usages.append('Key Agreement')
    except x509.ExtensionNotFound:
        pass

    try:
        eku_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE)
        if isinstance(eku_ext.value, x509.ExtendedKeyUsage):
            for usage in eku_ext.value:
                if usage == x509.ExtendedKeyUsageOID.SERVER_AUTH:
                    capabilities.append(
                        {
                            'icon': 'globe',
                            'title': 'TLS / HTTPS Web Server',
                            'desc': 'Secures web servers, APIs, and microservices for HTTPS and encrypted TLS connections.',
                            'badge': 'Server Authentication',
                        }
                    )
                elif usage == x509.ExtendedKeyUsageOID.CLIENT_AUTH:
                    capabilities.append(
                        {
                            'icon': 'lock',
                            'title': 'TLS Client Authentication (mTLS)',
                            'desc': 'Authenticates client machines and services in zero-trust and mutual-TLS architectures.',
                            'badge': 'Client Authentication',
                        }
                    )
                elif usage == x509.ExtendedKeyUsageOID.CODE_SIGNING:
                    capabilities.append(
                        {
                            'icon': 'shield',
                            'title': 'Code Signing',
                            'desc': 'Verifies the integrity and publisher identity of software binaries and packages.',
                            'badge': 'Code Signing',
                        }
                    )
                elif usage == x509.ExtendedKeyUsageOID.EMAIL_PROTECTION:
                    capabilities.append(
                        {
                            'icon': 'mail',
                            'title': 'Secure Email (S/MIME)',
                            'desc': 'Cryptographically signs and encrypts email messages.',
                            'badge': 'Email Protection',
                        }
                    )
    except x509.ExtensionNotFound:
        pass

    if not capabilities:
        capabilities.append(
            {
                'icon': 'globe',
                'title': 'TLS / HTTPS Web Server',
                'desc': 'Secures incoming HTTPS, TLS, and gRPC traffic for validated domain names.',
                'badge': 'Server Authentication',
            }
        )

    if 'Digital Signature' in key_usages and not any(c['title'].startswith('Digital Signature') for c in capabilities):
        capabilities.append(
            {
                'icon': 'shield',
                'title': 'Digital Signatures & Integrity',
                'desc': 'Provides cryptographic proof of message authenticity and non-repudiation.',
                'badge': 'Digital Signature',
            }
        )

    problems = []
    if is_revoked:
        rev_dt_str = format_datetime(record['revoked_at'])
        problems.append(
            {
                'level': 'critical',
                'title': 'Certificate is Revoked',
                'detail': f'Revoked on {rev_dt_str}. This certificate has been published to the CRL and will be rejected by clients.',
            }
        )

    if is_expired:
        exp_dt_str = format_datetime(nva_utc)
        problems.append(
            {
                'level': 'critical',
                'title': 'Certificate has Expired',
                'detail': f'Expired on {exp_dt_str}. Browsers and ACME clients will block connections using this certificate.',
            }
        )
    elif is_expiring:
        exp_dt_str = format_datetime(nva_utc)
        problems.append(
            {
                'level': 'warning',
                'title': f'Expiring in {days_remaining} Days',
                'detail': f'Validity ends on {exp_dt_str}. Automated or manual certificate renewal should be performed now.',
            }
        )

    if key_type == 'RSA' and key_size < 2048:
        problems.append(
            {
                'level': 'warning',
                'title': 'Weak Key Length',
                'detail': f'Key length is {key_size}-bit RSA. Industry security standards require at least 2048-bit.',
            }
        )

    primary_domain = record['domains'][0] if record['domains'] else (subject_cn or '')
    if primary_domain and sans and primary_domain not in sans:
        problems.append(
            {
                'level': 'warning',
                'title': 'Common Name Missing from SANs',
                'detail': f'The primary hostname "{primary_domain}" is not listed in the Subject Alternative Names extension (RFC 5280).',
            }
        )

    return JSONResponse(
        {
            'serial_number': record['serial_number'],
            'serial_number_formatted': ':'.join(
                f'{b:02X}' for b in bytes.fromhex(record['serial_number'] if len(record['serial_number']) % 2 == 0 else '0' + record['serial_number'])
            ),
            'subject_cn': subject_cn or primary_domain,
            'primary_domain': primary_domain,
            'issuer_cn': issuer_cn,
            'domains': sans,
            'not_valid_before': format_datetime(nvb_utc),
            'not_valid_after': format_datetime(nva_utc),
            'days_remaining': days_remaining,
            'percent_elapsed': percent_elapsed,
            'status': status_label,
            'is_valid': is_valid,
            'is_expiring': is_expiring,
            'is_expired': is_expired,
            'is_revoked': is_revoked,
            'revoked_at': format_datetime(record['revoked_at']) if record['revoked_at'] else None,
            'key_type': key_type,
            'key_size': key_size,
            'signature_algorithm': sig_algo,
            'fingerprint_sha256': fingerprint_sha256,
            'account_id': record['account_id'],
            'account_email': record['account_email'],
            'order_id': record['order_id'],
            'capabilities': capabilities,
            'problems': problems,
            'healthy': len(problems) == 0,
        }
    )


@api.post('/certificates/{serial_number}/revoke')
async def revoke_certificate(
    request: Request,
    serial_number: constr(pattern='^[0-9A-F]+$'),  # type: ignore[valid-type]
    current_status: str = Form(''),
    current_filter: str = Form(''),
    current_account: str = Form(''),
):
    async with db.transaction(readonly=True) as sql:
        cert_record = await sql.record(
            """select serial_number, revoked_at from certificates where serial_number = $1""",
            serial_number,
        )
    if not cert_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='unknown certificate')
    if cert_record['revoked_at'] is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='certificate is already revoked')

    async with db.transaction(readonly=True) as sql:
        revocation_list = [(sn, rev_at) async for sn, rev_at in sql("""select serial_number, revoked_at from certificates where revoked_at is not null""")]
        revoked_at = await sql.value("""select now()""")

    if settings.ca.enabled:
        revocations = set(revocation_list)
        revocations.add((serial_number, revoked_at))
        await ca_service.revoke_cert(serial_number=serial_number, revocations=revocations)

    async with db.transaction() as sql:
        await sql.exec(
            """update certificates set revoked_at = $2 where serial_number = $1 and revoked_at is null""",
            serial_number,
            revoked_at,
        )

    if 'application/json' in request.headers.get('accept', ''):
        return JSONResponse({'status': 'revoked', 'serial_number': serial_number})

    redirect_url = make_redirect_url(
        '/certificates',
        {
            'certstatus': current_status or 'all',
            'domainfilter': current_filter,
            'account_id': current_account,
            'status_msg': 'Certificate revoked successfully',
        },
    )
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@api.post('/certificates/{serial_number}/delete')
async def delete_certificate(
    request: Request,
    serial_number: constr(pattern='^[0-9A-F]+$'),  # type: ignore[valid-type]
    current_status: str = Form(''),
    current_filter: str = Form(''),
    current_account: str = Form(''),
):
    async with db.transaction(readonly=True) as sql:
        cert_record = await sql.record(
            """select serial_number, order_id, revoked_at from certificates where serial_number = $1""",
            serial_number,
        )
    if not cert_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='unknown certificate')
    if cert_record['revoked_at'] is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='only revoked certificates can be deleted')

    order_id = cert_record['order_id']
    async with db.transaction() as sql:
        await sql.exec('delete from certificates where serial_number = $1', serial_number)
        await sql.exec(
            'delete from challenges where authz_id in (select id from authorizations where order_id = $1)',
            order_id,
        )
        await sql.exec('delete from authorizations where order_id = $1', order_id)
        await sql.exec('delete from orders where id = $1', order_id)

    if settings.ca.enabled:
        async with db.transaction(readonly=True) as sql:
            remaining_revocations = {(sn, rev_at) async for sn, rev_at in sql('select serial_number, revoked_at from certificates where revoked_at is not null')}
        await ca_service.sync_crl(remaining_revocations)

    if 'application/json' in request.headers.get('accept', ''):
        return JSONResponse({'status': 'deleted', 'serial_number': serial_number})

    redirect_url = make_redirect_url(
        '/certificates',
        {
            'certstatus': current_status or 'revoked',
            'domainfilter': current_filter,
            'account_id': current_account,
            'status_msg': 'Certificate deleted successfully',
        },
    )
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@api.post('/certificates/batch-revoke')
async def batch_revoke_certificates(
    request: Request,
    serials: str = Form(''),
    current_status: str = Form(''),
    current_filter: str = Form(''),
    current_account: str = Form(''),
):
    content_type = request.headers.get('content-type', '')
    if 'application/json' in content_type:
        try:
            body = await request.json()
            serial_list = body.get('serials', [])
        except (json.JSONDecodeError, ValueError):
            serial_list = []
    else:
        serial_list = [s.strip() for s in serials.split(',') if s.strip()]

    if not serial_list:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='No certificates selected')

    async with db.transaction() as sql:
        unrevoked = [
            sn
            async for (sn,) in sql(
                'select serial_number from certificates where serial_number = any($1::text[]) and revoked_at is null',
                serial_list,
            )
        ]
        if unrevoked:
            await sql.exec(
                'update certificates set revoked_at = now() where serial_number = any($1::text[]) and revoked_at is null',
                unrevoked,
            )

    if settings.ca.enabled and unrevoked:
        async with db.transaction(readonly=True) as sql:
            all_revoked = {(sn, rev_at) async for sn, rev_at in sql('select serial_number, revoked_at from certificates where revoked_at is not null')}
        await ca_service.sync_crl(all_revoked)

    if 'application/json' in request.headers.get('accept', ''):
        return JSONResponse({'status': 'revoked', 'count': len(unrevoked)})

    redirect_url = make_redirect_url(
        '/certificates',
        {
            'certstatus': current_status or 'all',
            'domainfilter': current_filter,
            'account_id': current_account,
            'status_msg': f'Successfully revoked {len(unrevoked)} certificates',
        },
    )
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@api.post('/certificates/batch-delete')
async def batch_delete_certificates(
    request: Request,
    serials: str = Form(''),
    current_status: str = Form(''),
    current_filter: str = Form(''),
    current_account: str = Form(''),
):
    content_type = request.headers.get('content-type', '')
    if 'application/json' in content_type:
        try:
            body = await request.json()
            serial_list = body.get('serials', [])
        except (json.JSONDecodeError, ValueError):
            serial_list = []
    else:
        serial_list = [s.strip() for s in serials.split(',') if s.strip()]

    if not serial_list:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='No certificates selected')

    async with db.transaction() as sql:
        records = [
            (sn, ord_id)
            async for sn, ord_id in sql(
                'select serial_number, order_id from certificates where serial_number = any($1::text[]) and revoked_at is not null',
                serial_list,
            )
        ]
        if not records:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='No revoked certificates found matching selection')

        del_serials = [r[0] for r in records]
        del_order_ids = [r[1] for r in records]

        await sql.exec('delete from certificates where serial_number = any($1::text[])', del_serials)
        await sql.exec(
            'delete from challenges where authz_id in (select id from authorizations where order_id = any($1::text[]))',
            del_order_ids,
        )
        await sql.exec('delete from authorizations where order_id = any($1::text[])', del_order_ids)
        await sql.exec('delete from orders where id = any($1::text[])', del_order_ids)

    if settings.ca.enabled:
        async with db.transaction(readonly=True) as sql:
            all_revoked = {(sn, rev_at) async for sn, rev_at in sql('select serial_number, revoked_at from certificates where revoked_at is not null')}
        await ca_service.sync_crl(all_revoked)

    if 'application/json' in request.headers.get('accept', ''):
        return JSONResponse({'status': 'deleted', 'count': len(del_serials)})

    redirect_url = make_redirect_url(
        '/certificates',
        {
            'certstatus': current_status or 'revoked',
            'domainfilter': current_filter,
            'account_id': current_account,
            'status_msg': f'Successfully deleted {len(del_serials)} certificates',
        },
    )
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@api.get('/domains', response_class=HTMLResponse)
async def domain_log(
    request: Request,
    domainfilter: str = '',
    domainstatus: Literal['all', 'valid', 'invalid'] = 'valid',
    status_msg: str = '',
):
    async with db.transaction(readonly=True) as sql:
        domains = [
            record
            async for record in sql(
                """
                with data as (
                    select
                        authz.domain as domain_name,
                        min(coalesce(cert.not_valid_before, ord.expires_at - interval '60 minutes')) as first_requested_at,
                        max(cert.not_valid_after) as expires_at,
                        coalesce((max(cert.not_valid_after) FILTER (WHERE cert.revoked_at is null)) > now(), false) AS is_valid,
                        count(cert.serial_number) as cert_count
                    from orders ord
                    join authorizations authz on authz.order_id = ord.id
                    left join certificates cert on cert.order_id = ord.id
                    where ($1::text = '' or authz.domain ilike '%' || $1::text || '%')
                    group by authz.domain
                )
                select * from data
                where ($2 = 'all' or ($2 = 'valid' and is_valid) or ($2 = 'invalid' and not is_valid))
                order by first_requested_at desc nulls last, domain_name asc
                """,
                domainfilter.replace('*', '%'),
                domainstatus,
            )
        ]
    return await template_engine.get_template('domain-log.html').render_async(
        **default_params,
        request=request,
        domains=domains,
        domainstatus=domainstatus,
        domainfilter=domainfilter,
        status_msg=status_msg,
    )


@api.post('/domains/delete')
@api.post('/domains/{domain_name:path}/delete')
async def delete_domain(
    request: Request,
    domain_name: str | None = None,
    domain_name_form: str | None = Form(None, alias='domain_name'),
    current_status: str = Form(''),
    current_filter: str = Form(''),
):
    target_domain = (domain_name_form or domain_name or '').strip()
    if not target_domain:
        target_domain = (request.query_params.get('domain_name') or '').strip()
    if not target_domain:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Missing domain name to delete')

    async with db.transaction(readonly=True) as sql:
        cert_count = await sql.value(
            """
            select count(cert.serial_number)
            from authorizations authz
            join certificates cert on cert.order_id = authz.order_id
            where authz.domain = $1
            """,
            target_domain,
        )
    if cert_count and cert_count > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Cannot delete domain because certificates are still associated with it. Please revoke and delete the certificates first.',
        )

    async with db.transaction() as sql:
        authz_rows = [
            (a_id, o_id)
            async for a_id, o_id in sql(
                'select id, order_id from authorizations where domain = $1',
                target_domain,
            )
        ]
        if not authz_rows:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Domain not found or has no authorizations')

        authz_ids = [r[0] for r in authz_rows]
        order_ids = list({r[1] for r in authz_rows})

        await sql.exec('delete from challenges where authz_id = any($1::text[])', authz_ids)
        await sql.exec('delete from authorizations where domain = $1', target_domain)
        await sql.exec(
            """
            delete from orders o
            where o.id = any($1::text[])
              and not exists (select 1 from authorizations a where a.order_id = o.id)
              and not exists (select 1 from certificates c where c.order_id = o.id)
            """,
            order_ids,
        )

    if 'application/json' in request.headers.get('accept', ''):
        return JSONResponse({'status': 'deleted', 'domain': target_domain})

    redirect_url = make_redirect_url(
        '/domains',
        {
            'domainstatus': current_status or 'all',
            'domainfilter': current_filter,
            'status_msg': f'Domain {target_domain} and associated records deleted successfully',
        },
    )
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@api.get('/accounts', response_class=HTMLResponse)
async def account_log(
    request: Request,
    accountfilter: str = '',
    accountstatus: Literal['all', 'valid', 'deactivated', 'revoked'] = 'valid',
    status_msg: str = '',
):
    accounts = []
    async with db.transaction(readonly=True) as sql:
        async for record in sql(
            """
            with order_summary as (
                select
                    ord.id as order_id,
                    ord.account_id,
                    ord.status as status,
                    ord.expires_at,
                    coalesce(
                        (array_agg((chal.error).type::text) filter (where chal.error is not null))[1],
                        (ord.error).type::text
                    ) as error_type,
                    coalesce(
                        (array_agg((chal.error).detail) filter (where chal.error is not null))[1],
                        (ord.error).detail
                    ) as error_detail,
                    array_agg(distinct authz.domain) filter (where authz.domain is not null) as domains,
                    coalesce(bool_or(cert.not_valid_after > now() and cert.revoked_at is null), false) as has_active_cert,
                    (array_agg(cert.serial_number) filter (where cert.serial_number is not null))[1] as cert_serial,
                    coalesce(bool_or(cert.revoked_at is not null), false) as cert_is_revoked
                from orders ord
                left join authorizations authz on authz.order_id = ord.id
                left join challenges chal on chal.authz_id = authz.id
                left join certificates cert on cert.order_id = ord.id
                group by ord.id, ord.account_id, ord.status, ord.expires_at, ord.error
            )
            select
                acc.id as account_id,
                acc.mail as email,
                acc.status as account_status,
                acc.created_at,
                acc.jwk->>'kty' as key_type,
                case
                    when acc.jwk->>'kty' = 'RSA' and acc.jwk ? 'n' then 'RSA ' || ((length(acc.jwk->>'n') * 3) / 4 * 8)::text
                    when acc.jwk ? 'crv' then (acc.jwk->>'kty') || ' ' || (acc.jwk->>'crv')
                    else coalesce(acc.jwk->>'kty', 'RSA')
                end as key_info,

                count(distinct cert.serial_number) as total_certs,
                count(distinct cert.serial_number) filter (where cert.not_valid_after > now() and cert.revoked_at is null) as certs_valid,
                count(distinct cert.serial_number) filter (where cert.revoked_at is not null) as certs_revoked,
                count(distinct cert.serial_number) filter (where cert.not_valid_after <= now() and cert.revoked_at is null) as certs_expired,

                count(distinct o.order_id) as total_orders,
                count(distinct o.order_id) filter (where o.status = 'pending') as orders_pending,
                count(distinct o.order_id) filter (where o.status in ('ready', 'processing')) as orders_processing,
                count(distinct o.order_id) filter (where o.status = 'valid') as orders_valid,
                count(distinct o.order_id) filter (where o.status = 'invalid') as orders_invalid,

                coalesce(
                    json_agg(
                        json_build_object(
                            'order_id', o.order_id,
                            'status', o.status,
                            'error_type', o.error_type,
                            'error_detail', o.error_detail,
                            'domains', coalesce(to_json(o.domains), '[]'::json),
                            'expires_at', o.expires_at,
                            'is_failed', (o.status = 'invalid' or o.error_type is not null),
                            'has_active_cert', coalesce(o.has_active_cert, false),
                            'cert_serial', o.cert_serial,
                            'cert_is_revoked', coalesce(o.cert_is_revoked, false)
                        ) order by o.expires_at desc nulls last
                    ) filter (where o.order_id is not null),
                    '[]'::json
                ) as orders_info

            from accounts acc
            left join order_summary o on o.account_id = acc.id
            left join certificates cert on cert.order_id = o.order_id
            where ($1::text = '' or acc.mail ilike '%' || $1::text || '%' or acc.id = $1::text)
              and ($2 = 'all' or acc.status::text = $2)
            group by acc.id, acc.mail, acc.status, acc.created_at, acc.jwk
            order by acc.created_at desc nulls last, acc.id desc
            """,
            accountfilter.replace('*', '%'),
            accountstatus,
        ):
            item = dict(record)
            orders_raw = item.get('orders_info')
            if isinstance(orders_raw, str):
                try:
                    item['orders_info'] = json.loads(orders_raw)
                except (json.JSONDecodeError, TypeError):
                    item['orders_info'] = []
            if isinstance(item.get('orders_info'), list):
                for ord_info in item['orders_info']:
                    if isinstance(ord_info, dict) and ord_info.get('expires_at'):
                        ord_info['expires_at_formatted'] = format_datetime(ord_info['expires_at'], '%Y-%m-%d %H:%M')
            accounts.append(item)

    return await template_engine.get_template('account-log.html').render_async(
        **default_params,
        request=request,
        accounts=accounts,
        accountfilter=accountfilter,
        accountstatus=accountstatus,
        status_msg=status_msg,
    )


@api.post('/accounts/{account_id}/status')
async def update_account_status(
    account_id: str,
    action: Literal['activate', 'deactivate'] = Form(...),
    current_status: str = Form(''),
    current_filter: str = Form(''),
):
    new_status = 'valid' if action == 'activate' else 'deactivated'
    async with db.transaction() as sql:
        await sql.exec(
            'update accounts set status = $2 where id = $1',
            account_id,
            new_status,
        )
    msg = 'Account activated successfully' if action == 'activate' else 'Account deactivated successfully'
    redirect_url = make_redirect_url(
        '/accounts',
        {
            'accountstatus': current_status or 'all',
            'accountfilter': current_filter,
            'status_msg': msg,
        },
    )
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@api.post('/accounts/{account_id}/delete')
async def delete_account(
    request: Request,
    account_id: str,
    current_status: str = Form(''),
    current_filter: str = Form(''),
):
    async with db.transaction(readonly=True) as sql:
        acc = await sql.record('select id, mail, status from accounts where id = $1', account_id)
    if not acc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='unknown account')
    if acc['status'] != 'deactivated':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Only deactivated accounts can be deleted. Please deactivate the account first.',
        )

    async with db.transaction(readonly=True) as sql:
        active_cert_count = await sql.value(
            """
            select count(cert.serial_number)
            from orders ord
            join certificates cert on cert.order_id = ord.id
            where ord.account_id = $1 and cert.not_valid_after > now() and cert.revoked_at is null
            """,
            account_id,
        )
    if active_cert_count and active_cert_count > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Cannot delete account while it still has active, valid certificates. Please revoke the certificates first.',
        )

    async with db.transaction() as sql:
        order_ids = [o_id async for (o_id,) in sql('select id from orders where account_id = $1', account_id)]
        if order_ids:
            await sql.exec('delete from certificates where order_id = any($1::text[])', order_ids)
            await sql.exec(
                'delete from challenges where authz_id in (select id from authorizations where order_id = any($1::text[]))',
                order_ids,
            )
            await sql.exec('delete from authorizations where order_id = any($1::text[])', order_ids)
            await sql.exec('delete from orders where account_id = $1', account_id)

        await sql.exec('delete from accounts where id = $1', account_id)

    if settings.ca.enabled:
        async with db.transaction(readonly=True) as sql:
            remaining_revocations = {(sn, rev_at) async for sn, rev_at in sql('select serial_number, revoked_at from certificates where revoked_at is not null')}
        await ca_service.sync_crl(remaining_revocations)

    if 'application/json' in request.headers.get('accept', ''):
        return JSONResponse({'status': 'deleted', 'account_id': account_id})

    redirect_url = make_redirect_url(
        '/accounts',
        {
            'accountstatus': current_status or 'all',
            'accountfilter': current_filter,
            'status_msg': 'Account and all associated data deleted successfully',
        },
    )
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@api.post('/accounts/orders/batch-delete')
async def batch_delete_orders(
    request: Request,
    order_ids: str = Form(''),
    current_status: str = Form(''),
    current_filter: str = Form(''),
):
    content_type = request.headers.get('content-type', '')
    if 'application/json' in content_type:
        try:
            body = await request.json()
            order_list = body.get('order_ids', [])
        except (json.JSONDecodeError, ValueError):
            order_list = []
    else:
        order_list = [o.strip() for o in order_ids.split(',') if o.strip()]

    if not order_list:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='No orders selected')

    async with db.transaction(readonly=True) as sql:
        existing_orders = [
            o_id
            async for (o_id,) in sql(
                'select id from orders where id = any($1::text[])',
                order_list,
            )
        ]
        if not existing_orders:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='No matching orders found')

        # Safeguard: Check if any of these orders have active valid certificates
        active_certs = [
            (ord_id, sn)
            async for ord_id, sn in sql(
                """
                select ord.id, cert.serial_number
                from orders ord
                join certificates cert on cert.order_id = ord.id
                where ord.id = any($1::text[])
                  and cert.not_valid_after > now()
                  and cert.revoked_at is null
                """,
                existing_orders,
            )
        ]
        if active_certs:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Cannot delete orders with active valid certificates. Please revoke the certificates first.',
            )

        certs_to_delete = [
            sn
            async for (sn,) in sql(
                'select serial_number from certificates where order_id = any($1::text[])',
                existing_orders,
            )
        ]

    async with db.transaction() as sql:
        if certs_to_delete:
            await sql.exec('delete from certificates where order_id = any($1::text[])', existing_orders)
        await sql.exec(
            'delete from challenges where authz_id in (select id from authorizations where order_id = any($1::text[]))',
            existing_orders,
        )
        await sql.exec('delete from authorizations where order_id = any($1::text[])', existing_orders)
        await sql.exec('delete from orders where id = any($1::text[])', existing_orders)

    if settings.ca.enabled and certs_to_delete:
        async with db.transaction(readonly=True) as sql:
            remaining_revocations = {(sn, rev_at) async for sn, rev_at in sql('select serial_number, revoked_at from certificates where revoked_at is not null')}
        await ca_service.sync_crl(remaining_revocations)

    if 'application/json' in request.headers.get('accept', '') or 'application/json' in content_type:
        return JSONResponse({'status': 'deleted', 'deleted_order_ids': existing_orders, 'count': len(existing_orders)})

    redirect_url = make_redirect_url(
        '/accounts',
        {
            'accountstatus': current_status or 'all',
            'accountfilter': current_filter,
            'status_msg': f'Successfully deleted {len(existing_orders)} order(s)',
        },
    )
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@api.get('/mail', response_class=HTMLResponse)
async def mail_settings_get(request: Request, status_msg: str = '', error: str = ''):
    mail_cfg = await mail.service.get_mail_settings()
    return await template_engine.get_template('mail-settings.html').render_async(
        **default_params,
        request=request,
        mail_cfg=mail_cfg,
        status_msg=status_msg,
        error=error,
    )


@api.post('/mail', response_class=HTMLResponse)
async def mail_settings_post(
    request: Request,
    enabled: str = Form(None),
    host: str = Form(''),
    port: str = Form(''),
    encryption: str = Form('tls'),
    sender: str = Form(''),
    username: str = Form(''),
    password: str = Form(''),
    warn_before_cert_expires_days: int = Form(20),
    notify_when_cert_expired: str = Form(None),
    notify_on_account_creation: str = Form(None),
    admin_notification_email: str = Form(''),
    warn_before_ca_expires_days: int = Form(90),
):
    is_enabled = enabled in ('on', 'true', '1')
    has_expired_notify = notify_when_cert_expired in ('on', 'true', '1')
    has_account_notify = notify_on_account_creation in ('on', 'true', '1')

    clean_host = host.strip() or None
    clean_sender = sender.strip() or None
    clean_user = username.strip() or None
    clean_port = int(port.strip()) if port and port.strip().isdigit() else None
    clean_admin_email = admin_notification_email.strip() or None

    # Validation
    if is_enabled:
        if not clean_host:
            mail_cfg = await mail.service.get_mail_settings()
            return await template_engine.get_template('mail-settings.html').render_async(
                **default_params,
                request=request,
                mail_cfg=mail_cfg,
                error='SMTP Host is required when outgoing mail is enabled.',
            )
        if not clean_sender:
            mail_cfg = await mail.service.get_mail_settings()
            return await template_engine.get_template('mail-settings.html').render_async(
                **default_params,
                request=request,
                mail_cfg=mail_cfg,
                error='Sender Email Address is required when outgoing mail is enabled.',
            )

    update_password = bool(password and password.strip())

    try:
        updated_cfg = await mail.service.save_mail_settings(
            enabled=is_enabled,
            host=clean_host,
            port=clean_port,
            username=clean_user,
            password=password.strip() if update_password else None,
            encryption=encryption,
            sender=clean_sender,
            notify_on_account_creation=has_account_notify,
            warn_before_cert_expires_days=max(0, warn_before_cert_expires_days),
            notify_when_cert_expired=has_expired_notify,
            admin_notification_email=clean_admin_email,
            warn_before_ca_expires_days=max(0, warn_before_ca_expires_days),
            update_password=update_password,
        )
    except Exception as e:  # noqa: BLE001
        mail_cfg = await mail.service.get_mail_settings()
        return await template_engine.get_template('mail-settings.html').render_async(
            **default_params,
            request=request,
            mail_cfg=mail_cfg,
            error=f'Failed to save mail settings: {e}',
        )

    return await template_engine.get_template('mail-settings.html').render_async(
        **default_params,
        request=request,
        mail_cfg=updated_cfg,
        status_msg='Mail settings saved successfully.',
    )


@api.post('/mail/test')
async def mail_test_post(request: Request):
    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        data = {}

    host = data.get('host')
    port = data.get('port')
    encryption = data.get('encryption') or 'tls'
    sender = data.get('sender')
    recipient = data.get('recipient')
    username = data.get('username')
    password = data.get('password')

    current_cfg = await mail.service.get_mail_settings()

    host = host or current_cfg.host
    sender = sender or current_cfg.sender
    port = port or current_cfg.port
    username = username if username is not None else current_cfg.username
    if not password and current_cfg.password:
        password = current_cfg.password

    ok, msg = await mail.service.test_smtp_connection(
        host=host,
        port=port,
        encryption=encryption,
        sender=sender,
        recipient=recipient,
        username=username,
        password=password,
    )

    return JSONResponse(
        status_code=200 if ok else 400,
        content={'ok': ok, 'message' if ok else 'error': msg},
    )


@api.get('/ca-distribution', response_class=HTMLResponse)
async def ca_distribution_get(request: Request, status_msg: str = '', error: str = '', tab: str = ''):
    endpoints = await ca_distribution.get_endpoints()
    ssh_endpoints = [e for e in endpoints if e.type == 'ssh']
    email_endpoints = [e for e in endpoints if e.type == 'email']
    logs = await ca_distribution.get_distribution_logs(limit=50)
    return await template_engine.get_template('ca-distribution.html').render_async(
        **default_params,
        request=request,
        ssh_endpoints=ssh_endpoints,
        email_endpoints=email_endpoints,
        logs=logs,
        status_msg=status_msg,
        error=error,
        active_tab=tab or 'ssh',
    )


@api.post('/ca-distribution/endpoint/save')
async def ca_distribution_endpoint_save(request: Request):
    form_data = await request.form()
    endpoint_type = str(form_data.get('endpoint_type', '')).strip()
    endpoint_id = str(form_data.get('endpoint_id', '')).strip()
    name = str(form_data.get('name', '')).strip()

    if not name:
        target_tab = '?tab=email&' if endpoint_type == 'email' else '?'
        return RedirectResponse(
            f'/ca-distribution{target_tab}error={quote("Endpoint name is required.")}',
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if endpoint_type == 'ssh':
        host = str(form_data.get('host', '')).strip()
        port_raw = str(form_data.get('port', '22')).strip()
        port = int(port_raw) if port_raw.isdigit() else 22
        username = str(form_data.get('username', '')).strip()
        auth_type_raw = str(form_data.get('auth_type', 'key')).strip()
        auth_type: ca_distribution.SshAuthType = 'password' if auth_type_raw == 'password' else 'key'
        auth_secret = str(form_data.get('auth_secret', '')).strip() or None
        target_dir = str(form_data.get('target_dir', '')).strip()

        if not host or not username:
            return RedirectResponse(
                f'/ca-distribution?error={quote("Host and username are required for SSH endpoints.")}',
                status_code=status.HTTP_303_SEE_OTHER,
            )

        if endpoint_id:
            await ca_distribution.update_endpoint(
                endpoint_id=endpoint_id,
                name=name,
                host=host,
                port=port,
                username=username,
                auth_type=auth_type,
                auth_secret=auth_secret,
                target_dir=target_dir,
            )
            msg = f'SSH endpoint "{name}" updated successfully.'
        else:
            await ca_distribution.create_endpoint(
                name=name,
                endpoint_type='ssh',
                host=host,
                port=port,
                username=username,
                auth_type=auth_type,
                auth_secret=auth_secret,
                target_dir=target_dir,
            )
            msg = f'SSH endpoint "{name}" created successfully.'

        return RedirectResponse(
            f'/ca-distribution?status_msg={quote(msg)}',
            status_code=status.HTTP_303_SEE_OTHER,
        )

    elif endpoint_type == 'email':
        raw_emails = str(form_data.get('email_addresses_raw', '')).strip()
        email_list = [e.strip() for part in raw_emails.replace('\r\n', '\n').split('\n') for e in part.split(',') if e.strip()]
        target_os_list_raw = form_data.getlist('target_os')
        target_os_list = [str(os).strip() for os in target_os_list_raw if os]  # type: ignore[arg-type]

        if not email_list:
            return RedirectResponse(
                f'/ca-distribution?tab=email&error={quote("At least one recipient email address is required.")}',
                status_code=status.HTTP_303_SEE_OTHER,
            )

        if endpoint_id:
            await ca_distribution.update_endpoint(
                endpoint_id=endpoint_id,
                name=name,
                email_addresses=email_list,
                target_os_list=target_os_list,  # type: ignore[arg-type]
            )
            msg = f'Email distribution group "{name}" updated successfully.'
        else:
            await ca_distribution.create_endpoint(
                name=name,
                endpoint_type='email',
                email_addresses=email_list,
                target_os_list=target_os_list,  # type: ignore[arg-type]
            )
            msg = f'Email distribution group "{name}" created successfully.'

        return RedirectResponse(
            f'/ca-distribution?tab=email&status_msg={quote(msg)}',
            status_code=status.HTTP_303_SEE_OTHER,
        )

    else:
        return RedirectResponse(
            f'/ca-distribution?error={quote("Invalid endpoint type.")}',
            status_code=status.HTTP_303_SEE_OTHER,
        )


@api.post('/ca-distribution/endpoint/{endpoint_id}/test')
async def ca_distribution_endpoint_test(endpoint_id: str):
    endpoint = await ca_distribution.get_endpoint(endpoint_id)
    success, msg, detected_os, os_detail = await ca_distribution.test_endpoint(endpoint_id)
    return JSONResponse(
        {
            'success': success,
            'message': msg,
            'detected_os': detected_os,
            'os_detail': os_detail,
            'endpoint_name': endpoint.name if endpoint else '',
            'endpoint_type': endpoint.type if endpoint else 'ssh',
            'host': endpoint.host if endpoint else '',
            'port': endpoint.port if endpoint else 22,
            'username': endpoint.username if endpoint else '',
            'target_dir': endpoint.target_dir if endpoint else '',
        }
    )


@api.post('/ca-distribution/endpoint/{endpoint_id}/delete')
async def ca_distribution_endpoint_delete(endpoint_id: str):
    endpoint = await ca_distribution.get_endpoint(endpoint_id)
    endpoint_type = endpoint.type if endpoint else 'ssh'
    await ca_distribution.delete_endpoint(endpoint_id)
    tab_suffix = '&tab=email' if endpoint_type == 'email' else ''
    return RedirectResponse(
        f'/ca-distribution?status_msg={quote("Endpoint deleted successfully.")}{tab_suffix}',
        status_code=status.HTTP_303_SEE_OTHER,
    )


@api.get('/ca-distribution/list-active')
async def ca_distribution_list_active():
    endpoints = await ca_distribution.get_endpoints()
    return JSONResponse(
        {
            'endpoints': [
                {
                    'id': e.id,
                    'name': e.name,
                    'type': e.type,
                    'host': e.host,
                    'port': e.port,
                    'target_dir': e.target_dir,
                    'detected_os': e.detected_os,
                    'recipients_count': len(e.email_addresses or []),
                    'target_os_list': e.target_os_list or [],
                }
                for e in endpoints
            ]
        }
    )


@api.post('/ca/{serial_number}/distribute')
async def ca_distribute_post(serial_number: str, request: Request):
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        body = {}

    endpoint_ids = body.get('endpoint_ids', [])
    if not endpoint_ids:
        return JSONResponse({'detail': 'No endpoints selected for distribution.'}, status_code=400)

    async with db.transaction(readonly=True) as sql:
        ca_row = await sql.record('SELECT cert_pem, key_pem_enc FROM cas WHERE serial_number = $1', serial_number)

    if not ca_row:
        return JSONResponse({'detail': f'CA certificate with serial {serial_number} not found.'}, status_code=404)

    ca_cert, _ = ca_service.load_ca_sync(cert_pem=ca_row['cert_pem'], key_pem_enc=ca_row['key_pem_enc'])

    results = []
    for ep_id in endpoint_ids:
        ep = await ca_distribution.get_endpoint(ep_id)
        if not ep:
            results.append(
                {
                    'endpoint_id': ep_id,
                    'endpoint_name': 'Unknown',
                    'endpoint_type': 'unknown',
                    'status': False,
                    'message': 'Endpoint not found in database.',
                    'filename': '',
                    'detected_os': 'unknown',
                }
            )
            continue

        if ep.type == 'ssh':
            res = await ca_distribution.distribute_to_ssh_endpoint(ep, ca_cert, ca_row['cert_pem'])
        else:
            res = await ca_distribution.distribute_to_email_endpoint(ep, ca_cert, ca_row['cert_pem'])

        results.append(
            {
                'endpoint_id': res.endpoint_id,
                'endpoint_name': res.endpoint_name,
                'endpoint_type': res.endpoint_type,
                'status': res.status,
                'message': res.message,
                'filename': res.filename,
                'detected_os': res.detected_os,
            }
        )

    return JSONResponse({'results': results})


@api.get('/maintenance/status', tags=['web'])
async def maintenance_status():
    """Return status of maintenance mode for UI polling."""
    return JSONResponse({'maintenance': False, 'status': 'ready'})
