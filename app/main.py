__version__ = '0.0.0'  # replaced during build, do not change

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

import acme
import ca
import db
import db.integrity
import db.migrations
import tools
import web
from acme.exceptions import ACMEException
from ca import fleet_trust as ca_fleet_trust
from config import settings
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from logger import logger
from pydantic import ValidationError


async def _run_startup_integrity_audit(app_instance: FastAPI) -> None:
    try:
        await db.integrity.run_integrity_check_workflow()
    except Exception as exc:  # noqa: BLE001
        logger.error('Error during startup database integrity audit: %s', exc)
    finally:
        app_instance.state.maintenance_mode = False
        if settings.ca.enabled and not ca.is_initialized:
            await ca.init()
            if ca.is_initialized:
                await acme.start_cronjobs()
                if settings.ca.trust_probe_enabled:
                    try:
                        await ca_fleet_trust.probe_manager.start()
                    except Exception as probe_exc:  # noqa: BLE001
                        logger.warning('Failed to start CA trust probe servers: %s', probe_exc)


@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    await db.connect()
    await db.migrations.run()
    if settings.web.enabled:
        await web.auth.auto_provision_admin_if_needed()
    await ca.init()
    if ca.is_initialized:
        await acme.start_cronjobs()
        if settings.ca.trust_probe_enabled:
            try:
                await ca_fleet_trust.probe_manager.start()
            except Exception as probe_exc:  # noqa: BLE001
                logger.warning('Failed to start CA trust probe servers: %s', probe_exc)

    await tools.start_cronjobs()

    if settings.db_integrity.enabled:
        app_instance.state.maintenance_mode = True
        asyncio.create_task(_run_startup_integrity_audit(app_instance))
    else:
        app_instance.state.maintenance_mode = False

    yield

    if settings.ca.enabled and settings.ca.trust_probe_enabled:
        try:
            await ca_fleet_trust.probe_manager.stop()
        except Exception as probe_exc:  # noqa: BLE001
            logger.warning('Failed to stop CA trust probe servers: %s', probe_exc)

    await db.disconnect()


app = FastAPI(
    lifespan=lifespan,
    version=__version__,
    redoc_url=None,
    docs_url=None,
    title=settings.web.app_title,
    description=settings.web.app_description,
)
app.add_middleware(
    web.middleware.SecurityHeadersMiddleware,  # type: ignore[arg-type]
    content_security_policy={
        '/acme/': "base-uri 'self'; default-src 'none';",
        '/endpoints': "base-uri 'self'; default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-src 'none'; img-src 'self' data:;",
        '/': (
            "base-uri 'self'; default-src 'self'; connect-src 'self' https: http:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
            "frame-src 'none'; img-src 'self' data:;"
        ),
    },
)
if settings.web.enabled:
    app.add_middleware(web.middleware.CaSetupRedirectMiddleware)  # type: ignore[arg-type]
    app.add_middleware(web.middleware.WebAuthMiddleware)  # type: ignore[arg-type]

app.add_middleware(web.middleware.MaintenanceModeMiddleware)  # type: ignore[arg-type]

if settings.web.enabled:

    @app.get('/endpoints', tags=['web'])
    async def swagger_ui_html():
        return get_swagger_ui_html(
            openapi_url='/openapi.json',
            title=app.title,
            swagger_favicon_url='favicon.png',
            swagger_css_url='libs/swagger-ui.css',
            swagger_js_url='libs/swagger-ui-bundle.js',
        )


@app.exception_handler(RequestValidationError)
@app.exception_handler(HTTPException)
@app.exception_handler(ACMEException)
@app.exception_handler(Exception)
async def acme_exception_handler(request: Request, exc: Exception):
    # custom exception handler for acme specific response format
    if request.url.path.startswith('/acme/') or isinstance(exc, ACMEException):
        if isinstance(exc, ACMEException):
            return await exc.as_response()
        elif isinstance(exc, ValidationError):
            return await ACMEException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, exctype='malformed', detail=exc.json()).as_response()
        elif isinstance(exc, HTTPException):
            return await ACMEException(status_code=exc.status_code, exctype='serverInternal', detail=str(exc.detail)).as_response()
        else:
            return await ACMEException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, exctype='serverInternal', detail=str(exc)).as_response()
    else:
        if isinstance(exc, HTTPException):
            return await http_exception_handler(request, exc)
        else:
            return JSONResponse({'detail': str(exc)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


if settings.web.enabled:
    web.router_module.default_params['app_version'] = web.router_module.format_app_version(__version__)
    app.include_router(web.router)

app.include_router(acme.router)
app.include_router(acme.directory_router.api)  # serve acme directory under /acme/directory and /directory
app.include_router(ca.router)

if settings.web.enabled:
    www_dir = Path(__file__).parent / 'web' / 'www'
    if not www_dir.exists() and Path('/app/web/www').exists():
        www_dir = Path('/app/web/www')
    if www_dir.exists():
        app.mount('/', StaticFiles(directory=str(www_dir)), name='static')
