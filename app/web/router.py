import json
from pathlib import Path
from typing import Literal

import ca
import db
import mail.service
from ca import service as ca_service
from config import settings
from fastapi import APIRouter, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader
from pydantic import constr

from . import auth as web_auth

template_engine = Environment(loader=FileSystemLoader(Path(__file__).parent / 'templates'), enable_async=True, autoescape=True)

default_params = {  # pylint: disable=duplicate-code
    'app_title': settings.web.app_title,
    'app_desc': settings.web.app_description,
    'web_url': str(settings.external_url),
    'acme_url': str(settings.external_url).removesuffix('/') + '/acme/directory',
}


api = APIRouter(tags=['web'])


@api.get('/', response_class=HTMLResponse)
async def index(request: Request):
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
async def ca_view(request: Request, status_msg: str = ''):
    if not settings.ca.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Internal CA is disabled')
    if not ca.is_initialized:
        return RedirectResponse(url='/ca/setup', status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    ca_details = await ca_service.get_active_ca_details()
    if not ca_details:
        return RedirectResponse(url='/ca/setup', status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    return await template_engine.get_template('ca-details.html').render_async(
        **default_params,
        request=request,
        ca=ca_details,
        status_msg=status_msg,
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


@api.post('/certificates/{serial_number}/revoke')
async def revoke_certificate(request: Request, serial_number: constr(pattern='^[0-9A-F]+$')):  # type: ignore[valid-type]
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

    return RedirectResponse(url='/certificates?status_msg=revoked_success', status_code=status.HTTP_303_SEE_OTHER)


@api.get('/domains', response_class=HTMLResponse)
async def domain_log(request: Request, domainfilter: str = '', domainstatus: Literal['all', 'valid', 'invalid'] = 'valid'):
    async with db.transaction(readonly=True) as sql:
        domains = [
            record
            async for record in sql(
                """
                with data as (
                    select
                        authz.domain as domain_name,
                        min(cert.not_valid_before) as first_requested_at,
                        max(cert.not_valid_after) as expires_at,
                        (max(cert.not_valid_after) FILTER (WHERE revoked_at is null)) > now() AS is_valid
                    from orders ord
                    join authorizations authz on authz.order_id = ord.id
                    join certificates cert on cert.order_id = ord.id
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
        **default_params, request=request, domains=domains, domainstatus=domainstatus, domainfilter=domainfilter
    )


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
                    array_agg(distinct authz.domain) filter (where authz.domain is not null) as domains
                from orders ord
                left join authorizations authz on authz.order_id = ord.id
                left join challenges chal on chal.authz_id = authz.id
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
                            'is_failed', (o.status = 'invalid' or o.error_type is not null)
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
):
    new_status = 'valid' if action == 'activate' else 'deactivated'
    async with db.transaction() as sql:
        await sql.exec(
            'update accounts set status = $2 where id = $1',
            account_id,
            new_status,
        )
    msg = 'account_activated' if action == 'activate' else 'account_deactivated'
    return RedirectResponse(url=f'/accounts?status_msg={msg}', status_code=status.HTTP_303_SEE_OTHER)


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
):
    is_enabled = enabled in ('on', 'true', '1')
    has_expired_notify = notify_when_cert_expired in ('on', 'true', '1')
    has_account_notify = notify_on_account_creation in ('on', 'true', '1')

    clean_host = host.strip() or None
    clean_sender = sender.strip() or None
    clean_user = username.strip() or None
    clean_port = int(port.strip()) if port and port.strip().isdigit() else None

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
