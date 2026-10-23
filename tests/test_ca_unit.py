import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

# Add app to path
REPO_DIR = Path(__file__).resolve().parent.parent
APP_DIR = REPO_DIR / 'app'
sys.path.insert(0, str(APP_DIR))

import os

os.environ.setdefault('external_url', 'http://localhost:8000')
os.environ.setdefault('db_dsn', 'postgresql://localhost/dummy')
os.environ.setdefault('ca_encryption_key', 'fIj-aQgcgfMUphrXikMlZ2bQkBdWtcuSJXjycQJFC70=')

import ca.cronjob as ca_cronjob
import ca.service as ca_service
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from jinja2 import Environment, FileSystemLoader
from mail.service import MailConfig


class TestCALifecycleUnit(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mock_smtp_client = mock.AsyncMock()
        self.mock_smtp_client.send_message = mock.AsyncMock(return_value=({}, '250 OK: Mock message queued'))
        self.mock_smtp_client.login = mock.AsyncMock(return_value=(235, '2.7.0 Accepted'))
        self.mock_smtp_client.connect = mock.AsyncMock(return_value=(220, 'smtp.mock.local ready'))
        self.mock_smtp_client.quit = mock.AsyncMock(return_value=(221, 'Bye'))
        self.mock_smtp_client.__aenter__ = mock.AsyncMock(return_value=self.mock_smtp_client)
        self.mock_smtp_client.__aexit__ = mock.AsyncMock(return_value=None)
        self.mock_smtp_cls = mock.MagicMock(return_value=self.mock_smtp_client)

        self.patches = [
            mock.patch('aiosmtplib.SMTP', self.mock_smtp_cls),
            mock.patch('mail.service.SMTP', self.mock_smtp_cls),
            mock.patch('mail.SMTP', self.mock_smtp_cls),
            mock.patch('ca.distribution.SMTP', self.mock_smtp_cls),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()

    def test_mail_config_ca_properties(self):
        # Default with no admin email -> uses sender
        cfg = MailConfig(
            sender='ca-sender@example.com',
            warn_before_ca_expires_days=90,
        )
        self.assertEqual(cfg.effective_admin_recipient, 'ca-sender@example.com')
        self.assertEqual(cfg.warn_before_ca_expires_interval, timedelta(days=90))

        # Explicit admin email -> overrides sender
        cfg2 = MailConfig(
            sender='ca-sender@example.com',
            admin_notification_email='pki-team@example.com',
            warn_before_ca_expires_days=60,
        )
        self.assertEqual(cfg2.effective_admin_recipient, 'pki-team@example.com')
        self.assertEqual(cfg2.warn_before_ca_expires_interval, timedelta(days=60))

    def test_leaf_cert_validity_capped_by_ca(self):
        ca_key = rsa.generate_private_key(65537, 2048)
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Expiring CA')])
        now = datetime.now(timezone.utc)
        ca_expiry = now + timedelta(days=15)

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(ca_key.public_key())
            .serial_number(999999)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(ca_expiry)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )

        leaf_key = rsa.generate_private_key(65537, 2048)
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'test.domain.com')])).sign(leaf_key, hashes.SHA256())

        cert, chain_pem = ca_service.generate_cert_sync(
            ca_key=ca_key,
            ca_cert=ca_cert,
            csr=csr,
            subject_domain='test.domain.com',
            san_domains=['test.domain.com'],
        )
        _, leaf_nva = ca_service.get_cert_dates(cert)
        self.assertLessEqual(leaf_nva, ca_expiry)
        self.assertIn('BEGIN CERTIFICATE', chain_pem)

    async def test_cronjob_warning_alerts(self):
        with mock.patch('mail.send_ca_will_expire_warn_mail', new_callable=mock.AsyncMock) as mock_warn, mock.patch('db.transaction') as mock_tx:
            now = datetime.now(timezone.utc)
            test_nva = now + timedelta(days=45)

            mock_sql = mock.AsyncMock()
            mock_tx.return_value.__aenter__.return_value = mock_sql

            await ca_cronjob._handle_expiring_ca(
                sn='0A1B2C3D4E',
                cert_pem='dummy',
                last_stage=0,
                nva=test_nva,
                now=now,
                admin_email='alerts@example.com',
                warn_days=90,
                stages=[90, 60, 30, 14, 7, 1],
            )

            self.assertTrue(mock_warn.called)
            kwargs = mock_warn.call_args[1]
            self.assertEqual(kwargs['receiver'], 'alerts@example.com')
            self.assertEqual(kwargs['serial_number'], '0A1B2C3D4E')
            self.assertEqual(kwargs['days_remaining'], 45)

    async def test_cronjob_expired_alerts(self):
        with mock.patch('mail.send_ca_expired_info_mail', new_callable=mock.AsyncMock) as mock_expired, mock.patch('db.transaction') as mock_tx:
            now = datetime.now(timezone.utc)
            test_nva = now - timedelta(days=2)

            mock_sql = mock.AsyncMock()
            mock_tx.return_value.__aenter__.return_value = mock_sql

            await ca_cronjob._handle_expired_ca(
                sn='DEADBEEFCA',
                cert_pem='dummy',
                last_stage=0,
                nva=test_nva,
                admin_email='alerts@example.com',
            )

            self.assertTrue(mock_expired.called)
            kwargs = mock_expired.call_args[1]
            self.assertEqual(kwargs['receiver'], 'alerts@example.com')
            self.assertEqual(kwargs['serial_number'], 'DEADBEEFCA')

    def test_email_template_rendering(self):
        templates_dir = APP_DIR / 'mail' / 'templates'
        engine = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)

        # Warning email
        subj_tmpl = engine.get_template('ca-expires-warning/subject.txt')
        body_tmpl = engine.get_template('ca-expires-warning/body.html')
        now = datetime.now(timezone.utc)

        subj = subj_tmpl.render(app_title='ACME CA', days_remaining=45)
        self.assertIn('45 Days', subj)

        body = body_tmpl.render(
            app_title='ACME CA',
            common_name='ACME Root CA G2',
            serial_number='0A1B2C3D',
            expires_at=now + timedelta(days=45),
            days_remaining=45,
            web_url='https://ca.example.com/',
        )
        self.assertIn('ACME Root CA G2', body)
        self.assertIn('0A1B2C3D', body)
        self.assertIn('45 days', body)

        # Expired email
        exp_subj_tmpl = engine.get_template('ca-expired-info/subject.txt')
        exp_body_tmpl = engine.get_template('ca-expired-info/body.html')

        exp_subj = exp_subj_tmpl.render(app_title='ACME CA')
        self.assertIn('CRITICAL', exp_subj)

        exp_body = exp_body_tmpl.render(
            app_title='ACME CA',
            common_name='ACME Root CA G1',
            serial_number='FFEEDDCC',
            expires_at=now - timedelta(days=1),
            web_url='https://ca.example.com/',
        )
        self.assertIn('FFEEDDCC', exp_body)
        self.assertIn('Critical', exp_body)

    async def test_ca_init_expired_ca_marks_uninitialized(self):
        import ca
        with mock.patch('ca.settings.ca.import_dir', Path('/nonexistent')), \
             mock.patch('db.transaction') as mock_tx:
            mock_sql = mock.AsyncMock()
            mock_tx.return_value.__aenter__.return_value = mock_sql
            mock_sql.value.return_value = False

            await ca.init()
            self.assertFalse(ca.is_initialized)

    async def test_ca_init_valid_ca_marks_initialized(self):
        import ca
        with mock.patch('ca.settings.ca.import_dir', Path('/nonexistent')), \
             mock.patch('db.transaction') as mock_tx, \
             mock.patch('ca.cronjob.start', new_callable=mock.AsyncMock):
            mock_sql = mock.AsyncMock()
            mock_tx.return_value.__aenter__.return_value = mock_sql
            mock_sql.value.return_value = True

            await ca.init()
            self.assertTrue(ca.is_initialized)


if __name__ == '__main__':
    unittest.main()
