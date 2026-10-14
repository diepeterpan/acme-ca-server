from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint


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
        from urllib.parse import quote
        import web.auth
        from fastapi import status
        from fastapi.responses import JSONResponse, RedirectResponse

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
        has_any_user = await web.auth.has_users()

        if not has_any_user:
            # If no users exist, only /setup is accessible
            if path == '/setup':
                return await call_next(request)
            return RedirectResponse(url='/setup', status_code=status.HTTP_307_TEMPORARY_REDIRECT)

        # 3. Users exist in system. If visiting /setup, redirect away to /login
        if path == '/setup':
            return RedirectResponse(url='/login', status_code=status.HTTP_303_SEE_OTHER)

        # 4. Check for active session cookie
        cookie_val = request.cookies.get(web.auth.COOKIE_NAME)
        session_data = web.auth.verify_session_cookie(cookie_val)

        if session_data:
            # Authenticated! Attach user data to request.state
            request.state.user = {'username': session_data['sub']}
            # If already logged in and visiting /login, redirect to /
            if path == '/login':
                return RedirectResponse(url='/', status_code=status.HTTP_303_SEE_OTHER)
            return await call_next(request)

        # 5. Not authenticated
        # /login and /logout are accessible without session
        if path in ('/login', '/logout'):
            return await call_next(request)

        # For /openapi.json, return 401 Unauthorized if not authenticated
        if path == '/openapi.json':
            return JSONResponse({'detail': 'Not authenticated'}, status_code=status.HTTP_401_UNAUTHORIZED)

        # For all other web management routes, redirect to /login with next param
        next_url = request.url.path
        if request.url.query:
            next_url = f"{next_url}?{request.url.query}"
        login_url = f"/login?next={quote(next_url)}" if next_url != '/' else '/login'
        return RedirectResponse(url=login_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


class CaSetupRedirectMiddleware(BaseHTTPMiddleware):  # pylint: disable=too-few-public-methods
    """Redirect to /ca/setup when internal CA is enabled but not initialized."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        import ca
        from config import settings
        from fastapi import status
        from fastapi.responses import JSONResponse, RedirectResponse

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

