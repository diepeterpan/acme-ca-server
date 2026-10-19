import asyncio
from datetime import datetime, timezone

import db
import mail
from cryptography import x509
from logger import logger

from .service import build_crl_sync, get_cert_dates, load_ca_sync


async def rebuild_crls():
    try:
        async with db.transaction(readonly=True) as sql:
            cas = [record async for record in sql("""select serial_number, cert_pem, key_pem_enc from cas""")]
        for sn, cert_pem, key_pem_enc in cas:
            ca_cert, ca_key = await asyncio.to_thread(load_ca_sync, cert_pem=cert_pem, key_pem_enc=key_pem_enc)
            async with db.transaction(readonly=True) as sql:
                revocations = [record async for record in sql("""select serial_number, revoked_at from certificates where revoked_at is not null""")]
            _, crl_pem = await asyncio.to_thread(build_crl_sync, ca_key=ca_key, ca_cert=ca_cert, revocations=revocations)
            async with db.transaction() as sql:
                await sql.exec("""update cas set crl_pem = $1 where serial_number = $2""", crl_pem, sn)
    except Exception:  # noqa: BLE001
        logger.error('could not rebuild crl', exc_info=True)


async def _extract_ca_cn(cert_pem: str) -> str:
    cn = 'Root CA'
    try:
        ca_cert = await asyncio.to_thread(x509.load_pem_x509_certificate, cert_pem.encode(), None)
        cn_attrs = ca_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn_attrs:
            cn = str(cn_attrs[0].value)
    except Exception as e:  # noqa: BLE001
        logger.debug('Could not extract common name for CA: %s', e)
    return cn


async def _handle_expired_ca(sn: str, cert_pem: str, last_stage: int | None, nva: datetime, admin_email: str) -> None:
    if last_stage == -1:
        return
    cn = await _extract_ca_cn(cert_pem)
    try:
        await mail.send_ca_expired_info_mail(
            receiver=admin_email,
            common_name=cn,
            serial_number=sn,
            expires_at=nva,
        )
        async with db.transaction() as sql:
            await sql.exec('update cas set last_warning_stage = -1 where serial_number = $1', sn)
        logger.warning('Sent CA expired notification for CA %s to %s', sn, admin_email)
    except Exception:  # noqa: BLE001
        logger.error('Failed to send CA expired email for %s', sn, exc_info=True)


async def _handle_expiring_ca(sn: str, cert_pem: str, last_stage: int | None, nva: datetime, now: datetime, admin_email: str, warn_days: int, stages: list[int]) -> None:
    days_left = max(0, (nva - now).days)
    applicable_stage = None
    for stage in stages:
        if days_left <= stage <= warn_days:
            applicable_stage = stage
            break

    if applicable_stage is None:
        return
    if last_stage is not None and last_stage != 0 and last_stage <= applicable_stage:
        return

    cn = await _extract_ca_cn(cert_pem)
    try:
        await mail.send_ca_will_expire_warn_mail(
            receiver=admin_email,
            common_name=cn,
            serial_number=sn,
            expires_at=nva,
            days_remaining=days_left,
        )
        async with db.transaction() as sql:
            await sql.exec('update cas set last_warning_stage = $1 where serial_number = $2', applicable_stage, sn)
        logger.info('Sent CA expiration warning (%d days left) for CA %s to %s', days_left, sn, admin_email)
    except Exception:  # noqa: BLE001
        logger.error('Failed to send CA expiration warning email for %s', sn, exc_info=True)


async def check_ca_expirations():
    try:
        mail_cfg = await mail.service.get_mail_settings()
        if not mail_cfg.enabled:
            return
        admin_email = mail_cfg.effective_admin_recipient
        if not admin_email:
            return

        warn_days = mail_cfg.warn_before_ca_expires_days or 90
        stages = [90, 60, 30, 14, 7, 1]

        async with db.transaction(readonly=True) as sql:
            cas = [
                record
                async for record in sql(
                    """
                    select serial_number, cert_pem, last_warning_stage, not_valid_after
                    from cas
                    where revoked_at is null
                    """
                )
            ]

        now = datetime.now(timezone.utc)
        for sn, cert_pem, last_stage, nva in cas:
            if nva is None:
                ca_cert = await asyncio.to_thread(x509.load_pem_x509_certificate, cert_pem.encode(), None)
                _, nva = get_cert_dates(ca_cert)

            if now >= nva:
                await _handle_expired_ca(sn, cert_pem, last_stage, nva, admin_email)
            else:
                await _handle_expiring_ca(sn, cert_pem, last_stage, nva, now, admin_email, warn_days, stages)
    except Exception:  # noqa: BLE001
        logger.error('Could not check CA expirations', exc_info=True)


async def start():
    async def run():
        while True:
            try:
                await rebuild_crls()
                await check_ca_expirations()
            except Exception:  # noqa: BLE001
                logger.error('CA cronjob execution failed', exc_info=True)
            finally:
                await asyncio.sleep(6 * 60 * 60)  # run every 6h

    asyncio.create_task(run())
