import json
import re
import sys
from datetime import timedelta
from pathlib import Path
from re import Pattern
from typing import Any, Literal

from logger import logger
from pydantic import AnyHttpUrl, EmailStr, PostgresDsn, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class WebSettings(BaseSettings):
    enabled: bool = True
    app_title: str = 'ACME CA Server'
    app_description: str = 'Self-hosted ACME CA Server'
    github_url: str = 'https://github.com/diepeterpan/acme-ca-server'
    admin_username: str | None = None
    admin_password: SecretStr | None = None
    session_secret: SecretStr | None = None
    model_config = SettingsConfigDict(env_prefix='web_', secrets_dir='/run/secrets')


class DbIntegritySettings(BaseSettings):
    enabled: bool = True
    prompt_timeout: int = 60
    auto_repair: bool = False
    model_config = SettingsConfigDict(env_prefix='db_integrity_', secrets_dir='/run/secrets')


class CaSettings(BaseSettings):
    enabled: bool = True
    cert_lifetime: timedelta = timedelta(days=60)
    crl_lifetime: timedelta = timedelta(days=7)
    cert_cdp_enabled: bool = True
    encryption_key: SecretStr | None = None  # encryption of private keys in database
    import_dir: Path = '/import'  # type: ignore[assignment]
    trust_probe_enabled: bool = True
    trust_probe_base_port: int = 9443
    trust_probe_host: str = '0.0.0.0'  # noqa: S104

    model_config = SettingsConfigDict(env_prefix='ca_', secrets_dir='/run/secrets')

    @model_validator(mode='after')
    def valid_check(self) -> 'CaSettings':
        if self.enabled:
            if not self.encryption_key:
                from cryptography.fernet import Fernet  # pylint: disable=import-outside-toplevel

                logger.fatal('Env Var ca_encryption_key is missing, use this freshly generated key: %s', Fernet.generate_key().decode())
                sys.exit(1)
            if self.cert_lifetime.days < 1:
                raise ValueError('Cert lifetime for internal CA must be at least one day, not: ' + str(self.cert_lifetime))
            if self.crl_lifetime.days < 1:
                raise ValueError('CRL lifetime for internal CA must be at least one day, not: ' + str(self.crl_lifetime))
            if self.trust_probe_enabled and (self.trust_probe_base_port < 1024 or self.trust_probe_base_port > 65530):
                raise ValueError('Trust probe base port must be between 1024 and 65530, not: ' + str(self.trust_probe_base_port))
        return self


class MailSettings(BaseSettings):
    enabled: bool = False
    host: str | None = None
    port: int | None = None
    username: str | None = None
    password: SecretStr | None = None
    encryption: Literal['tls', 'starttls', 'plain', 'tls-nonstrict', 'starttls-nonstrict'] = 'tls'
    sender: EmailStr | None = None
    notify_on_account_creation: bool = True
    warn_before_cert_expires: timedelta | Literal[False] = timedelta(days=20)
    notify_when_cert_expired: bool = True

    model_config = SettingsConfigDict(env_prefix='mail_', secrets_dir='/run/secrets')

    @model_validator(mode='before')
    @classmethod
    def sanitize_values(cls, values: Any) -> Any:
        if 'warn_before_cert_expires' in values and (values['warn_before_cert_expires'] or '').lower().strip() in ('', 'false', '0', '-1'):
            values['warn_before_cert_expires'] = False
        return values

    @model_validator(mode='after')
    def valid_check(self) -> 'MailSettings':
        if self.enabled and (not self.host or not self.sender):
            raise ValueError('Mail parameters (mail_host, mail_sender) are missing as SMTP is enabled')
        if (self.username and not self.password) or (not self.username and self.password):
            raise ValueError('Either no mail auth must be specified or username and password must be provided')
        if self.enabled and not self.port:
            self.port = {'tls': 465, 'starttls': 587, 'plain': 25, 'tls-nonstrict': 465, 'starttls-nonstrict': 587}[self.encryption]
        return self

    @property
    def tls_non_strict(self) -> bool:
        return self.encryption.endswith('-nonstrict')


class AcmeSettings(BaseSettings):
    terms_of_service_url: AnyHttpUrl | None = None
    mail_target_regex: Pattern = r'[^@]+@[^@]+\.[^@]+'  # type: ignore[assignment]
    mail_required: bool = True
    dns_challenge_enabled: bool = True
    http_challenge_enabled: bool = True
    dns_resolvers: list[str] | str = []
    dns_timeout: float = 5.0
    dns_retries: int = 3
    allow_wildcards: bool = True
    target_domain_regex: Pattern = r'(\*\.)?[^\*]+\.[^\.]+'  # type: ignore[assignment]

    model_config = SettingsConfigDict(env_prefix='acme_', secrets_dir='/run/secrets')

    @model_validator(mode='after')
    def sanitize_acme_values(self) -> 'AcmeSettings':
        if isinstance(self.dns_resolvers, str):
            val = self.dns_resolvers.strip()
            if val.startswith('[') and val.endswith(']'):
                try:
                    self.dns_resolvers = json.loads(val)
                except (json.JSONDecodeError, TypeError):
                    self.dns_resolvers = [r.strip() for r in val.strip('[]').split(',') if r.strip()]
            elif val:
                self.dns_resolvers = [r.strip() for r in val.split(',') if r.strip()]
            else:
                self.dns_resolvers = []
        if not self.allow_wildcards:
            self.target_domain_regex = re.compile(r'[^\*]+\.[^\.]+')
        return self


class OidcSettings(BaseSettings):
    enabled: bool = False
    issuer_url: AnyHttpUrl | None = None
    client_id: str | None = None
    client_secret: SecretStr | None = None
    button_label: str = 'Sign In with OIDC'
    scopes: str = 'openid profile email'
    redirect_url: AnyHttpUrl | None = None
    user_claim: str = 'email'
    verify_ssl: bool = True
    x509_required: bool = True
    use_pkce: bool = True
    token_auth_method: Literal['auto', 'client_secret_basic', 'client_secret_post'] = 'auto'

    model_config = SettingsConfigDict(env_prefix='oidc_', secrets_dir='/run/secrets')

    @model_validator(mode='after')
    def valid_check(self) -> 'OidcSettings':
        if self.enabled:
            if not self.issuer_url:
                raise ValueError('Env var oidc_issuer_url is required when OIDC is enabled')
            if not self.client_id:
                raise ValueError('Env var oidc_client_id is required when OIDC is enabled')
            if not self.client_secret or not self.client_secret.get_secret_value():
                raise ValueError('Env var oidc_client_secret is required when OIDC is enabled')
        return self


class DataManagementSettings(BaseSettings):
    enabled: bool = True
    cron_schedule_hours: int = 24
    run_at_hour_utc: int = 2
    delete_deactivated_accounts_days: int = 28
    delete_stale_orders_days: int = 14
    delete_invalid_domains_days: int = 28
    revoke_expired_certs_days: int = 7
    delete_revoked_certs_days: int = 14
    delete_distribution_logs_days: int = 14
    delete_fleet_audits_days: int = 7
    delete_run_history_days: int = 30
    email_notification_enabled: bool = True
    notify_only_on_changes: bool = True
    admin_email: str | None = None

    model_config = SettingsConfigDict(env_prefix='data_mgmt_', secrets_dir='/run/secrets')


class Settings(BaseSettings):
    external_url: AnyHttpUrl
    db_dsn: PostgresDsn
    log_level: Literal['debug', 'info', 'warning', 'error'] = 'info'
    acme: AcmeSettings = AcmeSettings()
    ca: CaSettings = CaSettings()
    mail: MailSettings = MailSettings()
    web: WebSettings = WebSettings()
    oidc: OidcSettings = OidcSettings()
    db_integrity: DbIntegritySettings = DbIntegritySettings()
    data_mgmt: DataManagementSettings = DataManagementSettings()

    model_config = SettingsConfigDict(secrets_dir='/run/secrets')

    @model_validator(mode='before')
    @classmethod
    def sanitize_values(cls, data: Any) -> Any:
        if 'external_url' in data and not data['external_url'].endswith('/'):
            data['external_url'] += '/'
        return data

    @model_validator(mode='after')
    def valid_check(self) -> 'Settings':
        if self.external_url.scheme != 'https':
            logger.warning('Env Var "external_url" is not HTTPS. This is insecure!')
        if self.mail.warn_before_cert_expires and self.ca.enabled and self.mail.enabled:
            if self.mail.warn_before_cert_expires >= self.ca.cert_lifetime:
                raise ValueError('Env var web_warn_before_cert_expires cannot be greater than ca_cert_lifetime')
            if self.mail.warn_before_cert_expires.days > self.ca.cert_lifetime.days / 2:
                logger.warning('Env var mail_warn_before_cert_expires should be more than half of the cert lifetime')
        return self


settings = Settings()  # type: ignore[call-arg]

logger.setLevel(settings.log_level.upper())

logger.debug('Settings: %s', settings.model_dump())
