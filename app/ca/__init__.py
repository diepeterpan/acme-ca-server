import asyncio

import db
from acme.certificate.service import SerialNumberConverter
from config import settings
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, HTTPException, Response, status
from logger import logger
from pydantic import constr

router = APIRouter(prefix='/ca', tags=['ca'])

is_initialized: bool = False

if settings.ca.enabled:
    from cryptography.fernet import Fernet  # pylint: disable=ungrouped-imports

    from . import cronjob
    from .service import build_crl_sync, get_cert_dates

    @router.get('/{serial_number}/crl', response_class=Response, responses={200: {'content': {'application/pkix-crl': {}}}})
    async def download_crl(serial_number: constr(pattern='^[0-9A-F]+$')):  # type: ignore[valid-type]
        async with db.transaction(readonly=True) as sql:
            crl_pem = await sql.value("""select crl_pem from cas where serial_number = $1""", serial_number)
        if crl_pem:
            return Response(content=crl_pem, media_type='application/pkix-crl')
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='unknown CA')

    async def init():
        global is_initialized  # pylint: disable=global-statement
        if (settings.ca.import_dir / 'ca.pem').is_file() and (settings.ca.import_dir / 'ca.key').is_file():
            with open(settings.ca.import_dir / 'ca.key', 'rb') as f:  # noqa: ASYNC230
                ca_key_bytes = f.read()
            ca_key = serialization.load_pem_private_key(ca_key_bytes, None)
            f = Fernet(settings.ca.encryption_key.get_secret_value())
            ca_key_enc = f.encrypt(ca_key_bytes)

            with open(settings.ca.import_dir / 'ca.pem', 'rb') as f:  # noqa: ASYNC230
                ca_cert_bytes = f.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert_bytes, None)
            serial_number = SerialNumberConverter.int2hex(ca_cert.serial_number)
            nvb, nva = get_cert_dates(ca_cert)

            async with db.transaction(readonly=True) as sql:
                revocations = [record async for record in sql("""select serial_number, revoked_at from certificates where revoked_at is not null""")]
            _, crl_pem = await asyncio.to_thread(build_crl_sync, ca_key=ca_key, ca_cert=ca_cert, revocations=revocations)

            async with db.transaction() as sql:
                await sql.exec("""update cas set active = false""")
                await sql.exec(
                    """
                    insert into cas (serial_number, cert_pem, key_pem_enc, active, crl_pem, not_valid_before, not_valid_after)
                        values ($1, $2, $3, true, $4, $5, $6)
                    on conflict (serial_number) do update set active = true, crl_pem = $4, not_valid_before = $5, not_valid_after = $6
                    """,
                    serial_number,
                    ca_cert_bytes.decode(),
                    ca_key_enc,
                    crl_pem,
                    nvb,
                    nva,
                )
            logger.info('Successfully imported CA provided in "%s" folder', settings.ca.import_dir)
            is_initialized = True
            await cronjob.start()
        else:
            active_ca = None
            async with db.transaction(readonly=True) as sql:
                active_ca = await sql.record("""select serial_number, cert_pem, key_pem_enc from cas where active=true and not_valid_after > now()""")
            if active_ca:
                try:
                    f = Fernet(settings.ca.encryption_key.get_secret_value())
                    f.decrypt(active_ca['key_pem_enc'])
                    is_initialized = True
                    await cronjob.start()
                except Exception as dec_exc:  # noqa: BLE001
                    is_initialized = False
                    logger.error(
                        'Active CA %s private key cannot be decrypted with CA_ENCRYPTION_KEY: %s (%s). Please update CA_ENCRYPTION_KEY or rotate the Root CA.',
                        active_ca['serial_number'],
                        type(dec_exc).__name__,
                        dec_exc,
                    )
            else:
                is_initialized = False
                logger.warning('Internal CA is enabled, but no valid active CA certificate is available (expired or missing). Waiting for CA creation.')
else:
    is_initialized = True

    async def init():
        logger.info('Builtin CA is disabled, relying on custom CA implementation')
