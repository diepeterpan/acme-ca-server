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
    admin_notification_email: str | None = None
    warn_before_ca_expires_days: int = 90
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

    @property
    def warn_before_ca_expires_interval(self) -> timedelta | None:
        if self.warn_before_ca_expires_days and self.warn_before_ca_expires_days > 0:
            return timedelta(days=self.warn_before_ca_expires_days)
        return None

    @property
    def effective_admin_recipient(self) -> str | None:
        if self.admin_notification_email and self.admin_notification_email.strip():
            return self.admin_notification_email.strip()
        if self.sender and self.sender.strip():
            return self.sender.strip()
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
                notify_when_cert_expired, admin_notification_email, warn_before_ca_expires_days, updated_at
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
                admin_notification_email=row['admin_notification_email'],
                warn_before_ca_expires_days=int(row['warn_before_ca_expires_days'] if row['warn_before_ca_expires_days'] is not None else 90),
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
                admin_notification_email=None,
                warn_before_ca_expires_days=90,
                updated_at=datetime.now(timezone.utc),
            )

            await sql.exec(
                """
                insert into mail_settings (
                    dummy_id, enabled, host, port, username, password, encryption, sender,
                    notify_on_account_creation, warn_before_cert_expires_days, notify_when_cert_expired,
                    admin_notification_email, warn_before_ca_expires_days, updated_at
                ) values (
                    1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now()
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
                cfg.admin_notification_email,
                cfg.warn_before_ca_expires_days,
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
    admin_notification_email: str | None = None,
    warn_before_ca_expires_days: int = 90,
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
        clean_admin = admin_notification_email.strip() if admin_notification_email else None

        await sql.exec(
            """
            insert into mail_settings (
                dummy_id, enabled, host, port, username, password, encryption, sender,
                notify_on_account_creation, warn_before_cert_expires_days, notify_when_cert_expired,
                admin_notification_email, warn_before_ca_expires_days, updated_at
            ) values (
                1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now()
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
                admin_notification_email = excluded.admin_notification_email,
                warn_before_ca_expires_days = excluded.warn_before_ca_expires_days,
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
            clean_admin,
            warn_before_ca_expires_days,
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
        admin_notification_email=clean_admin,
        warn_before_ca_expires_days=warn_before_ca_expires_days,
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
    ext_url = str(settings.external_url).rstrip('/')
    html_body = f"""<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <link rel="stylesheet" href="{ext_url}/fonts/switzer.css" type="text/css" />
        <!--[if mso]>
        <style type="text/css">
            body, table, td, h1, h2, h3, h4, p, a, span {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
            }}
        </style>
        <![endif]-->
    </head>
    <body style="font-family: 'Switzer', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                 color: #1c2830; background-color: #f8fafb; margin: 0; padding: 24px 12px;">
        <table border="0" cellpadding="0" cellspacing="0" width="100%">
            <tr>
                <td align="center">
                    <table border="0" cellpadding="0" cellspacing="0" width="100%"
                           style="max-width: 600px; background: #ffffff; border: 1px solid #d0dee5;
                                  border-radius: 6px; overflow: hidden;
                                  box-shadow: 0 4px 6px -1px rgba(28, 40, 48, 0.08); text-align: left;">
                        <tr>
                            <td style="background-color: #006994;
                                       background: linear-gradient(135deg, #006994 0%, #004d6e 100%);
                                       padding: 24px 28px; color: #ffffff;">
                                <div style="font-size: 11px; font-weight: 700; letter-spacing: 0.06em;
                                            text-transform: uppercase; color: #e6f4fa; margin-bottom: 6px;">
                                    Diagnostics &amp; Verification
                                </div>
                                <h1 style="margin: 0; font-size: 20px; font-weight: 700; line-height: 28px; color: #ffffff;">
                                    SMTP Delivery Test Successful
                                </h1>
                                <div style="margin-top: 4px; font-size: 13px; color: #e6f4fa; opacity: 0.9;">
                                    ACME CA Server Mail Engine
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 24px 28px; font-size: 14px; line-height: 22px; color: #1c2830;">
                                <div style="margin-bottom: 16px;">
                                    <span style="background-color: #eaf6f2; border: 1px solid #1a7a5d; color: #1a7a5d;
                                                 padding: 3px 8px; border-radius: 2px; font-size: 11px; font-weight: 700;
                                                 text-transform: uppercase; letter-spacing: 0.04em; display: inline-block;">
                                        ✓ Connection Verified
                                    </span>
                                </div>
                                <p style="color: #1c2830; font-size: 15px; line-height: 24px; margin: 0 0 16px 0;">
                                    Congratulations! Your ACME CA Server SMTP settings have been verified and outgoing email delivery is operating correctly.
                                </p>
                                <div style="background-color: #e6f4fa; border: 1px solid #d0dee5; border-radius: 6px; padding: 16px; margin: 20px 0;">
                                    <div style="font-size: 12px; font-weight: 700; color: #004d6e; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px;">
                                        Connection Parameters
                                    </div>
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-size: 13px; color: #1c2830;">
                                        <tr>
                                            <td style="padding: 4px 0; font-weight: 600; color: #536571; width: 140px;">SMTP Host:</td>
                                            <td style="font-family: ui-monospace, SFMono-Regular, monospace; font-size: 12px; color: #004d6e;">
                                                {host}:{effective_port}
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 4px 0; font-weight: 600; color: #536571;">Encryption:</td>
                                            <td style="font-weight: 600; color: #1c2830;">{encryption.upper()}</td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 4px 0; font-weight: 600; color: #536571;">Sender Address:</td>
                                            <td style="color: #1c2830;">{sender}</td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 4px 0; font-weight: 600; color: #536571;">Test Timestamp:</td>
                                            <td style="color: #1c2830;">{now_str}</td>
                                        </tr>
                                    </table>
                                </div>
                                <div style="border-top: 1px solid #d0dee5; margin-top: 28px; padding-top: 16px; font-size: 12px; color: #536571; text-align: center;">
                                    Sent automatically by ACME CA Server Administration Console.
                                </div>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
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
