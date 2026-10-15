import asyncio
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from typing import Literal

import db
from aiosmtplib import SMTP, SMTPAuthenticationError, SMTPConnectError, SMTPException, SMTPRecipientRefused
from config import settings
from logger import logger

EncryptionType = Literal['tls', 'starttls', 'plain', 'tls-nonstrict', 'starttls-nonstrict']


@dataclass
class MailConfig:
    enabled: bool = False
    host: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = None
    encryption: EncryptionType = 'tls'
    sender: str | None = None
    notify_on_account_creation: bool = True
    warn_before_cert_expires_days: int = 20
    notify_when_cert_expired: bool = True
    updated_at: datetime | None = None

    @property
    def tls_non_strict(self) -> bool:
        return self.encryption.endswith('-nonstrict')

    @property
    def effective_port(self) -> int:
        if self.port:
            return self.port
        port_map = {'tls': 465, 'starttls': 587, 'plain': 25, 'tls-nonstrict': 465, 'starttls-nonstrict': 587}
        return port_map.get(self.encryption, 587)

    @property
    def warn_before_cert_expires_interval(self) -> timedelta | None:
        if self.warn_before_cert_expires_days and self.warn_before_cert_expires_days > 0:
            return timedelta(days=self.warn_before_cert_expires_days)
        return None


_CACHED_CONFIG: MailConfig | None = None


def invalidate_cache():
    global _CACHED_CONFIG  # pylint: disable=global-statement
    _CACHED_CONFIG = None


async def get_mail_settings() -> MailConfig:
    global _CACHED_CONFIG  # pylint: disable=global-statement
    if _CACHED_CONFIG is not None:
        return _CACHED_CONFIG

    async with db.transaction() as sql:
        row = await sql.record(
            """
            select
                enabled, host, port, username, password, encryption, sender,
                notify_on_account_creation, warn_before_cert_expires_days,
                notify_when_cert_expired, updated_at
            from mail_settings
            where dummy_id = 1
            """
        )

        if row:
            cfg = MailConfig(
                enabled=bool(row['enabled']),
                host=row['host'],
                port=row['port'],
                username=row['username'],
                password=row['password'],
                encryption=row['encryption'] or 'tls',
                sender=row['sender'],
                notify_on_account_creation=bool(row['notify_on_account_creation']),
                warn_before_cert_expires_days=int(row['warn_before_cert_expires_days'] if row['warn_before_cert_expires_days'] is not None else 20),
                notify_when_cert_expired=bool(row['notify_when_cert_expired']),
                updated_at=row['updated_at'],
            )
        else:
            # Seed from config.settings.mail defaults (from environment variables)
            env_mail = settings.mail
            warn_days = 20
            if env_mail.warn_before_cert_expires is False:
                warn_days = 0
            elif hasattr(env_mail.warn_before_cert_expires, 'days'):
                warn_days = env_mail.warn_before_cert_expires.days

            env_pwd = env_mail.password.get_secret_value() if env_mail.password else None

            cfg = MailConfig(
                enabled=bool(env_mail.enabled),
                host=env_mail.host,
                port=env_mail.port,
                username=env_mail.username,
                password=env_pwd,
                encryption=env_mail.encryption,
                sender=str(env_mail.sender) if env_mail.sender else None,
                notify_on_account_creation=bool(env_mail.notify_on_account_creation),
                warn_before_cert_expires_days=warn_days,
                notify_when_cert_expired=bool(env_mail.notify_when_cert_expired),
                updated_at=datetime.now(timezone.utc),
            )

            await sql.exec(
                """
                insert into mail_settings (
                    dummy_id, enabled, host, port, username, password, encryption, sender,
                    notify_on_account_creation, warn_before_cert_expires_days, notify_when_cert_expired, updated_at
                ) values (
                    1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now()
                )
                on conflict (dummy_id) do nothing
                """,
                cfg.enabled,
                cfg.host,
                cfg.port,
                cfg.username,
                cfg.password,
                cfg.encryption,
                cfg.sender,
                cfg.notify_on_account_creation,
                cfg.warn_before_cert_expires_days,
                cfg.notify_when_cert_expired,
            )

    _CACHED_CONFIG = cfg
    return cfg


async def save_mail_settings(
    *,
    enabled: bool,
    host: str | None,
    port: int | None,
    username: str | None,
    password: str | None,
    encryption: str,
    sender: str | None,
    notify_on_account_creation: bool,
    warn_before_cert_expires_days: int,
    notify_when_cert_expired: bool,
    update_password: bool = True,
) -> MailConfig:
    global _CACHED_CONFIG  # pylint: disable=global-statement

    async with db.transaction() as sql:
        current_pwd = None
        if not update_password or password is None:
            current_pwd = await sql.value('select password from mail_settings where dummy_id = 1')
            final_pwd = current_pwd
        else:
            final_pwd = password.strip() if password else None

        clean_host = host.strip() if host else None
        clean_sender = sender.strip() if sender else None
        clean_user = username.strip() if username else None

        await sql.exec(
            """
            insert into mail_settings (
                dummy_id, enabled, host, port, username, password, encryption, sender,
                notify_on_account_creation, warn_before_cert_expires_days, notify_when_cert_expired, updated_at
            ) values (
                1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now()
            )
            on conflict (dummy_id) do update set
                enabled = excluded.enabled,
                host = excluded.host,
                port = excluded.port,
                username = excluded.username,
                password = excluded.password,
                encryption = excluded.encryption,
                sender = excluded.sender,
                notify_on_account_creation = excluded.notify_on_account_creation,
                warn_before_cert_expires_days = excluded.warn_before_cert_expires_days,
                notify_when_cert_expired = excluded.notify_when_cert_expired,
                updated_at = now()
            """,
            enabled,
            clean_host,
            port,
            clean_user,
            final_pwd,
            encryption,
            clean_sender,
            notify_on_account_creation,
            warn_before_cert_expires_days,
            notify_when_cert_expired,
        )

    _CACHED_CONFIG = MailConfig(
        enabled=enabled,
        host=clean_host,
        port=port,
        username=clean_user,
        password=final_pwd,
        encryption=encryption,  # type: ignore[arg-type]
        sender=clean_sender,
        notify_on_account_creation=notify_on_account_creation,
        warn_before_cert_expires_days=warn_before_cert_expires_days,
        notify_when_cert_expired=notify_when_cert_expired,
        updated_at=datetime.now(timezone.utc),
    )
    return _CACHED_CONFIG


async def test_smtp_connection(
    *,
    host: str | None,
    port: int | None,
    encryption: str,
    sender: str | None,
    recipient: str | None,
    username: str | None = None,
    password: str | None = None,
) -> tuple[bool, str]:
    if not host or not host.strip():
        return False, 'SMTP Host is required.'
    if not sender or not sender.strip():
        return False, 'Sender Email address is required.'
    if not recipient or not recipient.strip():
        return False, 'Test Recipient Email address is required.'

    port_map = {'tls': 465, 'starttls': 587, 'plain': 25, 'tls-nonstrict': 465, 'starttls-nonstrict': 587}
    effective_port = port or port_map.get(encryption, 587)

    now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1e1b4b; background-color: #f8fafc; padding: 24px;">
        <div style="max-width: 580px; margin: 0 auto; background: #ffffff; border: 1px solid #ede9fe; border-radius: 12px; padding: 32px;
                    box-shadow: 0 4px 6px -1px rgba(124, 58, 237, 0.08);">
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">
                <div style="background: #ecfdf5; border: 1px solid #a7f3d0; color: #059669; padding: 8px 16px; border-radius: 9999px; font-weight: 600; font-size: 14px;">
                    ✓ SMTP Test Successful
                </div>
            </div>
            <h2 style="color: #1e1b4b; margin: 0 0 12px 0;">ACME CA Server Email Delivery Test</h2>
            <p style="color: #475569; font-size: 15px; line-height: 1.6; margin: 0 0 20px 0;">
                Congratulations! If you are reading this email, your ACME CA Server SMTP settings have been verified and are operating correctly.
            </p>
            <div style="background: #f5f3ff; border: 1px solid #ddd6fe; border-radius: 8px; padding: 16px; margin-bottom: 20px;">
                <table style="width: 100%; border-collapse: collapse; font-size: 13px; color: #334155;">
                    <tr><td style="padding: 4px 0; font-weight: 600; width: 140px;">SMTP Host:</td><td>{host}:{effective_port}</td></tr>
                    <tr><td style="padding: 4px 0; font-weight: 600;">Encryption:</td><td>{encryption.upper()}</td></tr>
                    <tr><td style="padding: 4px 0; font-weight: 600;">Sender:</td><td>{sender}</td></tr>
                    <tr><td style="padding: 4px 0; font-weight: 600;">Timestamp:</td><td>{now_str}</td></tr>
                </table>
            </div>
            <p style="color: #64748b; font-size: 13px; margin: 0;">
                Sent automatically by ACME CA Server Administration Console.
            </p>
        </div>
    </body>
    </html>
    """

    message = MIMEText(html_body, 'html', 'utf-8')
    message['From'] = sender.strip()
    message['To'] = recipient.strip()
    message['Subject'] = f'[ACME CA Server] SMTP Test Notification - {now_str}'

    auth: dict[str, str] = {}
    if username and password:
        auth = {'username': username.strip(), 'password': password}

    ctx = None
    if encryption != 'plain' and encryption.endswith('-nonstrict'):
        ctx = ssl.create_default_context()
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT

    try:
        async with SMTP(
            hostname=host.strip(),
            port=effective_port,
            **auth,  # type: ignore[arg-type]
            use_tls=encryption.startswith('tls'),
            start_tls=encryption.startswith('starttls'),
            tls_context=ctx,
            timeout=15,
        ) as client:
            await client.send_message(message)
        return True, f'Test email sent successfully to {recipient.strip()} via {host}:{effective_port}!'

    except SMTPAuthenticationError as e:
        logger.warning('SMTP authentication failed during test: %s', e)
        return False, f'Authentication failed: Invalid SMTP username or password (code {e.code}: {e.message}).'
    except SMTPRecipientRefused as e:
        logger.warning('SMTP recipient refused during test: %s', e)
        return False, f'Recipient rejected by server: {recipient} (code {e.code}: {e.message}).'
    except SMTPConnectError as e:
        logger.warning('SMTP connection failed during test: %s', e)
        return False, f'Failed to connect to SMTP server at {host}:{effective_port}: {e}.'
    except ssl.SSLError as e:
        logger.warning('SSL error during SMTP test: %s', e)
        return False, f'SSL/TLS Handshake failed: {e}. If using internal or self-signed certs, try selecting non-strict encryption.'
    except (TimeoutError, asyncio.TimeoutError):
        logger.warning('SMTP test timed out connecting to %s:%s', host, effective_port)
        return False, f'Connection timed out after 15 seconds trying to connect to {host}:{effective_port}.'
    except SMTPException as e:
        logger.warning('SMTP exception during test: %s', e)
        return False, f'SMTP Error ({type(e).__name__}): {e}'
    except Exception as e:  # noqa: BLE001
        logger.error('Unexpected error during SMTP test: %s', e, exc_info=True)
        return False, f'Connection error ({type(e).__name__}): {e}'
