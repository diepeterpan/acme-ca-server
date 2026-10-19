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
