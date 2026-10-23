import asyncio
import time
from urllib.parse import quote

import ca
from config import settings
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from . import auth as web_auth


class MaintenanceModeMiddleware(BaseHTTPMiddleware):  # pylint: disable=too-few-public-methods
    """Enforce Maintenance Mode veil when database integrity check is running."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        is_maintenance = getattr(request.app.state, 'maintenance_mode', False)
        if not is_maintenance:
            return await call_next(request)

        path = request.url.path

        # 1. Allow static assets so maintenance veil can load styles, icons, fonts
        public_static_prefixes = (
            '/libs/',
            '/static/',
            '/favicon.png',
            '/favicon.svg',
        )
        if any(path.startswith(prefix) for prefix in public_static_prefixes):
            return await call_next(request)

        # 2. Check if maintenance status poll endpoint
        if path == '/maintenance/status':
            return JSONResponse({'maintenance': True, 'detail': 'Database integrity check in progress'}, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)

        # 3. For ACME protocol endpoints, return 503 Service Unavailable with Retry-After header
        if path.startswith(('/acme/', '/.well-known/')) or path == '/directory':
            return JSONResponse(
                {
                    'type': 'urn:ietf:params:acme:error:serverInternal',
                    'detail': 'Server is undergoing database integrity verification during startup. Please retry shortly.',
                },
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                headers={'Retry-After': '5'},
            )

        # 4. For HTML browser requests, render the maintenance veil
        from .router import template_engine  # pylint: disable=import-outside-toplevel

        template = template_engine.get_template('maintenance.html')
        content = await template.render_async(
            app_title=settings.web.app_title,
            app_description=settings.web.app_description,
        )
        return HTMLResponse(content, status_code=status.HTTP_503_SERVICE_UNAVAILABLE, headers={'Retry-After': '3'})


class SecurityHeadersMiddleware(BaseHTTPMiddleware):  # pylint: disable=too-few-public-methods
    """Add security headers to all responses."""

    def __init__(
        self,
        app: FastAPI,
        *,
        content_security_policy: dict[str, str] | None = None,
        permissions_policy: dict[str, str] | None = None,
    ) -> None:
        super().__init__(app)
        self.csp = content_security_policy
        self.pp = permissions_policy

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Dispatch of the middleware.

        :param request: Incoming request
        :param call_next: Function to process the request
        :return: Return response coming from processed request
        """
        headers = {
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000',
        }
        if self.csp:
            matches = [path for path in self.csp if request.url.path.startswith(path)]
            if matches:
                best_match = max(matches, key=len)
                headers['Content-Security-Policy'] = self.csp[best_match]
        if self.pp:
            matches = [path for path in self.pp if request.url.path.startswith(path)]
            if matches:
                best_match = max(matches, key=len)
                headers['Permissions-Policy'] = self.pp[best_match]
        response = await call_next(request)
        response.headers.update(headers)

        return response


class WebAuthMiddleware(BaseHTTPMiddleware):  # pylint: disable=too-few-public-methods
    """Enforce Web UI setup and authentication."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        # 1. Exempt public machine ACME endpoints, static assets, and CA cert/CRL downloads
        public_prefixes = (
            '/acme/',
            '/.well-known/',
            '/favicon.png',
            '/favicon.svg',
            '/libs/',
            '/static/',
            '/ca/download',
            '/ca-trust/',
        )
        if path == '/directory' or any(path.startswith(prefix) for prefix in public_prefixes):
            return await call_next(request)

        # 2. Check if any admin users exist
        has_any_user = await web_auth.has_users()

        if not has_any_user:
            # If no users exist, only /setup is accessible
            if path == '/setup':
                return await call_next(request)
            return RedirectResponse(url='/setup', status_code=status.HTTP_307_TEMPORARY_REDIRECT)

        # 3. Users exist in system. If visiting /setup, redirect away to /login
        if path == '/setup':
            return RedirectResponse(url='/login', status_code=status.HTTP_303_SEE_OTHER)

        # 4. Check for active session cookie
        cookie_val = request.cookies.get(web_auth.COOKIE_NAME)
        session_data = web_auth.verify_session_cookie(cookie_val)

        if session_data:
            # Authenticated! Attach user data to request.state
            username = session_data['sub']
            user_rec = await web_auth.get_user_by_username(username)
            user_type = user_rec['user_type'] if user_rec else 'local'
            request.state.user = {'username': username, 'user_type': user_type}
            # If already logged in and visiting /login, redirect to /
            if path == '/login':
                return RedirectResponse(url='/', status_code=status.HTTP_303_SEE_OTHER)
            return await call_next(request)

        # 5. Not authenticated
        # /login, /logout, and OIDC endpoints are accessible without session
        if path in ('/login', '/logout', '/oidc/login', '/oidc/callback'):
            return await call_next(request)

        # For /openapi.json, return 401 Unauthorized if not authenticated
        if path == '/openapi.json':
            return JSONResponse({'detail': 'Not authenticated'}, status_code=status.HTTP_401_UNAUTHORIZED)

        # For all other web management routes, redirect to /login with next param
        next_url = request.url.path
        if request.url.query:
            next_url = f'{next_url}?{request.url.query}'
        login_url = f'/login?next={quote(next_url, safe="")}' if next_url != '/' else '/login'
        return RedirectResponse(url=login_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


class CaSetupRedirectMiddleware(BaseHTTPMiddleware):  # pylint: disable=too-few-public-methods
    """Redirect to /ca/setup when internal CA is enabled but not initialized."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        if settings.ca.enabled and not ca.is_initialized:
            allowed_prefixes = (
                '/ca/setup',
                '/setup',
                '/login',
                '/logout',
                '/favicon.png',
                '/favicon.svg',
                '/libs/',
                '/static/',
                '/ca-trust/',
            )
            if any(path.startswith(prefix) for prefix in allowed_prefixes):
                return await call_next(request)

            if path.startswith('/acme/') or path in ('/directory',):
                return JSONResponse(
                    {
                        'type': 'urn:ietf:params:acme:error:serverInternal',
                        'detail': 'CA is not initialized yet. Complete CA setup in the web interface at /ca/setup.',
                    },
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                )

            return RedirectResponse(url='/ca/setup', status_code=status.HTTP_307_TEMPORARY_REDIRECT)

        if settings.ca.enabled and ca.is_initialized and path == '/ca/setup':
            return RedirectResponse(url='/ca', status_code=status.HTTP_303_SEE_OTHER)

        return await call_next(request)


class ApiTraceMiddleware(BaseHTTPMiddleware):  # pylint: disable=too-few-public-methods
    """Trace HTTP requests and responses for acme:* and ca//crl endpoints when enabled."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        import tools  # pylint: disable=import-outside-toplevel

        path = request.url.path
        # Check if URL matches acme:* or ca//crl endpoints
        is_traced_path = path.startswith('/acme/') or path in ('/directory', '/.well-known/acme-challenge') or (path.startswith('/ca/') and path.endswith('/crl'))

        if not is_traced_path or not await tools.api_trace.is_api_trace_enabled():
            return await call_next(request)

        start_time = time.time()
        client_ip = request.client.host if request.client else 'unknown'
        target_host = request.headers.get('host', request.url.netloc or 'localhost')
        http_method = request.method
        req_headers = dict(request.headers)

        # Buffer request payload safely
        req_body_bytes = await request.body()
        req_payload_str = ''
        if req_body_bytes:
            try:
                req_payload_str = req_body_bytes.decode('utf-8', errors='replace')
            except Exception:  # noqa: BLE001
                req_payload_str = f'<binary data ({len(req_body_bytes)} bytes)>'

        # Wrap receive so downstream handlers can read body without EOF
        async def receive():
            return {'type': 'http.request', 'body': req_body_bytes, 'more_body': False}

        request._receive = receive  # pylint: disable=protected-access

        resp_status = 500
        resp_headers = {}
        resp_payload_str = ''
        error_msg = None

        try:
            response = await call_next(request)
            resp_status = response.status_code
            resp_headers = dict(response.headers)

            # Consume and buffer response body
            resp_body_chunks = []
            body_iter = getattr(response, 'body_iterator', None)
            if body_iter is not None:
                async for chunk in body_iter:  # type: ignore[attr-defined]
                    resp_body_chunks.append(chunk)
            elif hasattr(response, 'body'):
                resp_body_chunks.append(response.body)  # type: ignore[attr-defined]

            full_resp_body = b''.join(resp_body_chunks)

            # Decode or format response payload
            content_type = response.headers.get('content-type', '').lower()
            if 'application/pkix-crl' in content_type or 'octet-stream' in content_type:
                resp_payload_str = f'<binary data: {content_type} ({len(full_resp_body)} bytes)>'
            else:
                try:
                    resp_payload_str = full_resp_body.decode('utf-8', errors='replace')
                except Exception:  # noqa: BLE001
                    resp_payload_str = f'<binary data ({len(full_resp_body)} bytes)>'

            # Recreate response with buffered body so client receives response intact
            response = Response(
                content=full_resp_body,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )
            return response
        except Exception as exc:  # noqa: BLE001
            error_msg = str(exc)
            raise
        finally:
            duration_ms = int((time.time() - start_time) * 1000)
            asyncio.create_task(
                tools.api_trace.record_trace(
                    client_ip=client_ip,
                    target_host=target_host,
                    http_method=http_method,
                    endpoint=path,
                    status_code=resp_status,
                    duration_ms=duration_ms,
                    request_headers=req_headers,
                    request_payload=req_payload_str,
                    response_headers=resp_headers,
                    response_payload=resp_payload_str,
                    error_message=error_msg,
                )
            )
