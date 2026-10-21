import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

REPO_DIR = Path(__file__).resolve().parent.parent
APP_DIR = REPO_DIR / 'app'
sys.path.insert(0, str(APP_DIR))

os.environ.setdefault('external_url', 'http://localhost:8080')
os.environ.setdefault('db_dsn', 'postgresql://localhost/dummy')
os.environ.setdefault('ca_encryption_key', 'fIj-aQgcgfMUphrXikMlZ2bQkBdWtcuSJXjycQJFC70=')

from ca import fleet_trust
from fastapi.testclient import TestClient
from main import app


class TestCaFleetTrustUnit(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_cli_probe_script_generation(self):
        script = fleet_trust.generate_cli_probe_script('https://ca.example.com')
        self.assertIn('#!/usr/bin/env sh', script)
        self.assertIn('SERVER_URL="https://ca.example.com"', script)
        self.assertIn('/ca-trust/api/cas', script)
        self.assertIn('/ca-trust/api/report', script)
        self.assertIn('check_ca_trust', script)
        self.assertIn('openssl x509', script)
        self.assertIn('-fingerprint -sha256', script)
        self.assertIn('OVERALL FLEET STATUS', script)

    def test_public_probe_script_endpoint(self):
        from config import settings

        res = self.client.get('/ca-trust/probe.sh')
        self.assertEqual(res.status_code, 200)
        self.assertIn('text/plain', res.headers.get('content-type', ''))
        self.assertIn(f'SERVER_URL="{str(settings.external_url).rstrip("/")}"', res.text)

    def test_public_probe_active_endpoint(self):
        mock_stats = fleet_trust.ComplianceStats(
            total_audited=1,
            compliant_count=1,
            partial_count=0,
            untrusted_count=0,
            compliant_pct=100.0,
            partial_pct=0.0,
            untrusted_pct=0.0,
            active_ca_name='Test Root CA',
            active_ca_serial='DEADBEEF',
        )
        with mock.patch('ca.fleet_trust.get_compliance_stats', new=mock.AsyncMock(return_value=mock_stats)):
            res = self.client.get('/ca-trust/api/probe-active')
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data.get('status'), 'ok')
            self.assertEqual(data.get('active_ca'), 'Test Root CA')
            self.assertEqual(data.get('serial'), 'DEADBEEF')

    def test_public_probe_endpoints_route(self):
        mock_endpoints = [
            {
                'ca_serial': 'DEADBEEF11',
                'cn': 'Active Root CA',
                'active': True,
                'port': 9443,
                'is_running': True,
                'probe_url': 'https://localhost:9443/probe',
            },
            {
                'ca_serial': 'STANDBY22',
                'cn': 'Standby Root CA',
                'active': False,
                'port': 9444,
                'is_running': True,
                'probe_url': 'https://localhost:9444/probe',
            },
        ]
        with mock.patch.object(fleet_trust.probe_manager, 'get_probe_endpoints', new=mock.AsyncMock(return_value=mock_endpoints)):
            res = self.client.get('/ca-trust/api/probe-endpoints')
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data.get('status'), 'ok')
            self.assertTrue(data.get('enabled'))
            self.assertEqual(len(data.get('endpoints', [])), 2)
            self.assertEqual(data['endpoints'][0]['port'], 9443)
            self.assertEqual(data['endpoints'][1]['port'], 9444)

    def test_probe_leaf_cert_generation(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa

        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Test Probe Root')]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Test Probe Root')]))
            .public_key(ca_key.public_key())
            .serial_number(123456789)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + fleet_trust.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )

        leaf_cert, leaf_key = fleet_trust.generate_probe_leaf_cert_sync(
            ca_cert=ca_cert,
            ca_key=ca_key,
            hostnames=['ca.corp.internal', '10.0.0.1'],
        )

        self.assertIsNotNone(leaf_cert)
        self.assertIsNotNone(leaf_key)
        self.assertEqual(leaf_cert.issuer, ca_cert.subject)

        # Verify Server Auth EKU
        eku = leaf_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE).value
        self.assertIn(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, eku)

        # Verify SANs include provided hostnames and loopback
        san = leaf_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        dns_names = [name.value for name in san if isinstance(name, x509.DNSName)]
        ip_addresses = [str(name.value) for name in san if isinstance(name, x509.IPAddress)]

        self.assertIn('ca.corp.internal', dns_names)
        self.assertIn('localhost', dns_names)
        self.assertIn('10.0.0.1', ip_addresses)
        self.assertIn('127.0.0.1', ip_addresses)

    async def test_probe_manager_get_probe_endpoints(self):
        mock_cas = [
            {'serial_number': '1111', 'cn': 'CA One', 'active': True},
            {'serial_number': '2222', 'cn': 'CA Two', 'active': False},
        ]
        with mock.patch('ca.fleet_trust.get_expected_cas', new=mock.AsyncMock(return_value=mock_cas)):
            endpoints = await fleet_trust.probe_manager.get_probe_endpoints(external_hostname='ca.example.com')
            self.assertEqual(len(endpoints), 2)
            self.assertEqual(endpoints[0]['port'], 9443)
            self.assertEqual(endpoints[0]['probe_url'], 'https://ca.example.com:9443/probe')
            self.assertEqual(endpoints[1]['port'], 9444)
            self.assertEqual(endpoints[1]['probe_url'], 'https://ca.example.com:9444/probe')

    def test_public_verify_portal_rendering(self):
        mock_cas = [
            {
                'serial_number': '1A2B3C4D',
                'cn': 'Corp Root CA 2026',
                'org': 'Acme Corp',
                'fingerprint_sha256': 'AA:BB:CC:DD',
                'active': True,
                'not_valid_before': datetime.now(timezone.utc).isoformat(),
                'not_valid_after': datetime.now(timezone.utc).isoformat(),
            }
        ]
        with mock.patch('ca.fleet_trust.get_expected_cas', new=mock.AsyncMock(return_value=mock_cas)):
            res = self.client.get('/ca-trust/verify')
            self.assertEqual(res.status_code, 200)
            self.assertIn('Root CA Trust Verification', res.text)
            self.assertIn('Corp Root CA 2026', res.text)
            self.assertIn('1A2B3C4D', res.text)

    def test_telemetry_reporting_endpoint(self):
        payload = {
            'device_name': 'test-server-01',
            'device_type': 'server',
            'os': 'linux',
            'os_detail': 'Ubuntu 24.04 LTS',
            'ip_address': '192.168.1.100',
            'verification_method': 'cli_probe',
            'results': [{'ca_serial': '1A2B3C4D', 'is_trusted': True, 'details': 'Found in trust store'}],
        }
        with mock.patch('ca.fleet_trust.record_audit', new=mock.AsyncMock(return_value='aud_test1234567890123456')):
            res = self.client.post('/ca-trust/api/report', json=payload)
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json(), {'status': 'ok', 'audit_id': 'aud_test1234567890123456'})

    def test_admin_dashboard_authenticated(self):
        mock_stats = fleet_trust.ComplianceStats(
            total_audited=5,
            compliant_count=4,
            partial_count=1,
            untrusted_count=0,
            compliant_pct=80.0,
            partial_pct=20.0,
            untrusted_pct=0.0,
            active_ca_name='Test Root CA',
            active_ca_serial='DEADBEEF',
        )
        mock_audit = fleet_trust.CaTrustAudit(
            id='aud_12345678901234567890',
            device_name='srv-db-01',
            device_type='server',
            os='linux',
            os_detail='Debian 12',
            ip_address='10.0.0.5',
            user_agent=None,
            endpoint_id=None,
            verification_method='cli_probe',
            overall_status='compliant',
            total_cas=1,
            trusted_cas=1,
            audited_at=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
            results=[
                fleet_trust.CaTrustResult(
                    id='res_123',
                    audit_id='aud_12345678901234567890',
                    ca_serial='DEADBEEF',
                    is_trusted=True,
                    details='OK',
                    checked_at=datetime.now(timezone.utc),
                    ca_cn='Test Root CA',
                    ca_org='Acme',
                    ca_active=True,
                )
            ],
        )

        import ca
        import web.auth as web_auth

        cookie_val, _ = web_auth.create_session_cookie('admin')
        self.client.cookies.set(web_auth.COOKIE_NAME, cookie_val)

        with (
            mock.patch.object(ca, 'is_initialized', True),
            mock.patch('web.auth.has_users', new=mock.AsyncMock(return_value=True)),
            mock.patch('web.auth.get_user_by_username', new=mock.AsyncMock(return_value={'username': 'admin', 'user_type': 'local'})),
            mock.patch('ca.fleet_trust.get_compliance_stats', new=mock.AsyncMock(return_value=mock_stats)),
            mock.patch('ca.fleet_trust.get_expected_cas', new=mock.AsyncMock(return_value=[])),
            mock.patch('ca.fleet_trust.list_audited_devices', new=mock.AsyncMock(return_value=([mock_audit], 1))),
        ):
            # Test /ca-fleet-trust
            res = self.client.get('/ca-fleet-trust')
            self.assertEqual(res.status_code, 200)
            self.assertIn('CA Fleet Trust', res.text)
            self.assertIn('srv-db-01', res.text)
            self.assertIn('Debian 12', res.text)

            # Test alias /ca-compliance
            res_comp = self.client.get('/ca-compliance')
            self.assertEqual(res_comp.status_code, 200)

            # Test alias /ca-availability
            res_avail = self.client.get('/ca-availability')
            self.assertEqual(res_avail.status_code, 200)
