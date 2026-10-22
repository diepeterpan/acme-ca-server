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

import asyncssh
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

    def test_powershell_probe_script_generation(self):
        script = fleet_trust.generate_powershell_probe_script('https://ca.example.com', endpoint_name='WinServer01', endpoint_id='ep-win-1')
        self.assertIn('$ServerUrl = "https://ca.example.com"', script)
        self.assertIn('$EndpointName = "WinServer01"', script)
        self.assertIn('$EndpointId = "ep-win-1"', script)
        self.assertIn('SecurityProtocol', script)
        self.assertIn('ServerCertificateValidationCallback', script)
        self.assertIn('/ca-trust/api/cas', script)
        self.assertIn('/ca-trust/api/report', script)
        self.assertIn('Cert:\\LocalMachine\\Root', script)
        self.assertIn('Cert:\\CurrentUser\\Root', script)
        self.assertIn('Invoke-RestMethod', script)
        self.assertIn('[OK] OVERALL FLEET STATUS', script)
        self.assertNotIn('[✓]', script)

    def test_public_probe_script_endpoint(self):
        from config import settings

        with mock.patch('ca.distribution.find_endpoint_by_host_or_name', new=mock.AsyncMock(return_value=None)):
            res = self.client.get('/ca-trust/probe.sh')
            self.assertEqual(res.status_code, 200)
            self.assertIn('text/plain', res.headers.get('content-type', ''))
            self.assertIn(f'SERVER_URL="{str(settings.external_url).rstrip("/")}"', res.text)

    def test_public_probe_powershell_endpoint(self):
        from config import settings

        with mock.patch('ca.distribution.find_endpoint_by_host_or_name', new=mock.AsyncMock(return_value=None)):
            res = self.client.get('/ca-trust/probe.ps1')
            self.assertEqual(res.status_code, 200)
            self.assertIn('text/plain', res.headers.get('content-type', ''))
            self.assertIn(f'$ServerUrl = "{str(settings.external_url).rstrip("/")}"', res.text)
            self.assertIn('Cert:\\LocalMachine\\Root', res.text)

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
        with (
            mock.patch('ca.distribution.find_endpoint_by_host_or_name', new=mock.AsyncMock(return_value=None)),
            mock.patch('ca.fleet_trust.record_audit', new=mock.AsyncMock(return_value='aud_test1234567890123456')),
        ):
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
            mock.patch('ca.distribution.get_endpoints', new=mock.AsyncMock(return_value=[])),
            mock.patch('ca.fleet_trust.list_audited_devices', new=mock.AsyncMock(return_value=([mock_audit], 1))),
        ):
            # Test /ca-fleet-trust
            res = self.client.get('/ca-fleet-trust')
            self.assertEqual(res.status_code, 200)
            self.assertIn('CA Fleet Trust', res.text)
            self.assertIn('srv-db-01', res.text)
            self.assertIn('Debian 12', res.text)
            # Verify renamed column headers and resizable data-table-id
            self.assertIn('data-table-id="ca-fleet-table"', res.text)
            self.assertIn('<th>Endpoint / Device name</th>', res.text)
            self.assertIn('<th>Hostname/IP Address</th>', res.text)
            self.assertIn('<th>CA Trust</th>', res.text)
            # Verify delete confirmation dialog on veil backdrop
            self.assertIn('id="delete-audit-dialog"', res.text)
            self.assertIn('openDeleteAuditModal', res.text)
            self.assertIn('closeDeleteAuditModal', res.text)

            # Test alias /ca-compliance
            res_comp = self.client.get('/ca-compliance')
            self.assertEqual(res_comp.status_code, 200)

            # Test alias /ca-availability
            res_avail = self.client.get('/ca-availability')
            self.assertEqual(res_avail.status_code, 200)

    def test_cli_probe_script_fqdn_and_endpoint_name(self):
        script = fleet_trust.generate_cli_probe_script(
            'https://ca.example.com',
            endpoint_name='Core Engineering',
            endpoint_id='ep_12345',
        )
        self.assertIn('ENDPOINT_NAME="Core Engineering"', script)
        self.assertIn('ENDPOINT_ID="ep_12345"', script)
        self.assertIn('RAW_FQDN', script)
        self.assertIn('DEVICE_NAME="${RAW_FQDN%%.*}"', script)
        self.assertIn('HOST_IDENTIFIER="$RAW_FQDN"', script)
        self.assertIn('DEVICE_NAME="$ENDPOINT_NAME"', script)
        self.assertIn('HOST_IDENTIFIER="$IP_ADDR"', script)
        self.assertIn('"endpoint_id": $EP_JSON_VAL,', script)

    def test_telemetry_reporting_fqdn_first(self):
        # When an FQDN is reported (contains a dot and not an IP)
        payload = {
            'device_name': '',
            'device_type': 'server',
            'os': 'linux',
            'os_detail': 'Ubuntu 24.04',
            'ip_address': 'web-01.corp.example.com',
            'verification_method': 'cli_probe',
            'results': [],
        }
        with (
            mock.patch('ca.distribution.find_endpoint_by_host_or_name', new=mock.AsyncMock(return_value=None)),
            mock.patch('ca.fleet_trust.record_audit', new=mock.AsyncMock(return_value='aud_fqdn_123')) as mock_record,
        ):
            res = self.client.post('/ca-trust/api/report', json=payload)
            self.assertEqual(res.status_code, 200)
            mock_record.assert_called_once()
            _, kwargs = mock_record.call_args
            # Hostname/IP Address gets FQDN
            self.assertEqual(kwargs['ip_address'], 'web-01.corp.example.com')
            # Device name gets part up to first dot
            self.assertEqual(kwargs['device_name'], 'web-01')

    def test_telemetry_reporting_ip_fallback_to_endpoint_name(self):
        # When an IP is reported and FQDN reverse lookup fails, fallback to endpoint name
        payload = {
            'device_name': '',
            'device_type': 'server',
            'os': 'linux',
            'os_detail': 'Debian 12',
            'ip_address': '192.168.10.50',
            'endpoint_id': 'ep_email_group',
            'verification_method': 'browser',
            'results': [],
        }
        mock_ep = mock.MagicMock()
        mock_ep.name = 'Finance Department'

        with (
            mock.patch('ca.distribution.get_endpoint', new=mock.AsyncMock(return_value=mock_ep)),
            mock.patch('web.router._resolve_fqdn', new=mock.AsyncMock(return_value=None)),
            mock.patch('ca.fleet_trust.record_audit', new=mock.AsyncMock(return_value='aud_fallback_456')) as mock_record,
        ):
            res = self.client.post('/ca-trust/api/report', json=payload)
            self.assertEqual(res.status_code, 200)
            mock_record.assert_called_once()
            _, kwargs = mock_record.call_args
            # Fallback to IP
            self.assertEqual(kwargs['ip_address'], '192.168.10.50')
            # Fallback to email Group name
            self.assertEqual(kwargs['device_name'], 'Finance Department')

    def test_telemetry_reporting_invalid_json_rejected(self):
        # Invalid JSON payloads must be rejected with 400 Bad Request
        res = self.client.post(
            '/ca-trust/api/report',
            content='{"invalid_json": true,',
            headers={'Content-Type': 'application/json'},
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json().get('status'), 'error')

    async def test_sweep_single_ssh_endpoint_prefers_endpoint_name(self):
        mock_ep = mock.MagicMock()
        mock_ep.id = 'ep_web_123'
        mock_ep.name = 'Production Cluster Node 1'
        mock_ep.host = 'node01.prod.example.com'
        mock_ep.port = 22
        mock_ep.username = 'root'
        mock_ep.auth_type = 'password'
        mock_ep.auth_secret_enc = b'dummy'

        mock_conn = mock.MagicMock()
        mock_conn.run = mock.AsyncMock(return_value=mock.MagicMock(stdout='Found'))
        mock_ctx = mock.MagicMock()
        mock_ctx.__aenter__ = mock.AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = mock.AsyncMock(return_value=None)

        with (
            mock.patch('ca.fleet_trust.get_expected_cas', new=mock.AsyncMock(return_value=[{'serial_number': '1234', 'cn': 'Root', 'active': True}])),
            mock.patch('ca.distribution.decrypt_secret', return_value='secret'),
            mock.patch('ca.fleet_trust.asyncssh.connect', return_value=mock_ctx),
            mock.patch('ca.distribution.probe_ssh_os', new=mock.AsyncMock(return_value=('linux', 'Ubuntu 24.04'))),
            mock.patch('ca.fleet_trust.record_audit', new=mock.AsyncMock(return_value='aud_test_node')) as mock_record,
        ):
            cas = [{'serial_number': '1234', 'cn': 'Root', 'active': True}]
            res = await fleet_trust.probe_endpoint_trust_via_ssh(mock_ep, expected_cas=cas)
            self.assertEqual(res['status'], 'success')
            mock_record.assert_called_once()
            _, kwargs = mock_record.call_args
            # Endpoint name must be preferred
            self.assertEqual(kwargs['device_name'], 'Production Cluster Node 1')
            self.assertEqual(kwargs['ip_address'], 'node01.prod.example.com')
            self.assertEqual(kwargs['verification_method'], 'ssh_sweep')

    async def test_sweep_single_ssh_endpoint_fallback_to_hostname_prefix_when_no_name(self):
        mock_ep = mock.MagicMock()
        mock_ep.id = 'ep_web_456'
        mock_ep.name = ''  # empty endpoint name
        mock_ep.host = 'node02.prod.example.com'
        mock_ep.port = 22
        mock_ep.username = 'root'
        mock_ep.auth_type = 'password'
        mock_ep.auth_secret_enc = b'dummy'

        mock_conn = mock.MagicMock()
        mock_conn.run = mock.AsyncMock(return_value=mock.MagicMock(stdout='Found'))
        mock_ctx = mock.MagicMock()
        mock_ctx.__aenter__ = mock.AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = mock.AsyncMock(return_value=None)

        with (
            mock.patch('ca.fleet_trust.get_expected_cas', new=mock.AsyncMock(return_value=[{'serial_number': '1234', 'cn': 'Root', 'active': True}])),
            mock.patch('ca.distribution.decrypt_secret', return_value='secret'),
            mock.patch('ca.fleet_trust.asyncssh.connect', return_value=mock_ctx),
            mock.patch('ca.distribution.probe_ssh_os', new=mock.AsyncMock(return_value=('linux', 'Debian 12'))),
            mock.patch('ca.fleet_trust.record_audit', new=mock.AsyncMock(return_value='aud_test_node2')) as mock_record,
        ):
            cas = [{'serial_number': '1234', 'cn': 'Root', 'active': True}]
            res = await fleet_trust.probe_endpoint_trust_via_ssh(mock_ep, expected_cas=cas)
            self.assertEqual(res['status'], 'success')
            mock_record.assert_called_once()
            _, kwargs = mock_record.call_args
            # Host prefix must be used when endpoint.name is empty
            self.assertEqual(kwargs['device_name'], 'node02')
            self.assertEqual(kwargs['ip_address'], 'node02.prod.example.com')
            self.assertEqual(kwargs['verification_method'], 'ssh_sweep')

    def test_format_probe_error(self):
        import asyncio
        # TimeoutError with default 20s
        err1 = fleet_trust.format_probe_error(TimeoutError(), 'debianlounge.galleon.co.za', 22)
        self.assertEqual(err1, 'Connection timed out after 20s connecting to debianlounge.galleon.co.za:22')

        # TimeoutError with custom timeout_sec=10
        err1_custom = fleet_trust.format_probe_error(TimeoutError(), 'debianlounge.galleon.co.za', 22, timeout_sec=10)
        self.assertEqual(err1_custom, 'Connection timed out after 10s connecting to debianlounge.galleon.co.za:22')

        # asyncio.TimeoutError
        err2 = fleet_trust.format_probe_error(asyncio.TimeoutError(), 'debianlounge.galleon.co.za', 22)
        self.assertEqual(err2, 'Connection timed out after 20s connecting to debianlounge.galleon.co.za:22')

        # Command timeout (asyncssh.ProcessError)
        class DummyProcessTimeout(asyncssh.ProcessError, TimeoutError):
            pass
        err_cmd = fleet_trust.format_probe_error(DummyProcessTimeout(None, 'check_cmd', None, None, None, None, '', ''), 'debianlounge.galleon.co.za', 22)
        self.assertEqual(err_cmd, 'Command execution timed out on debianlounge.galleon.co.za:22')

        # OSError
        err3 = fleet_trust.format_probe_error(ConnectionRefusedError(111, 'Connection refused'), 'host.example.com', 22)
        self.assertIn('Connection refused', err3)

        # DisconnectError or custom reason
        class DummyDisconnect(Exception):
            reason = 'Host key mismatch'
        err4 = fleet_trust.format_probe_error(DummyDisconnect(), 'host.example.com', 22)
        self.assertEqual(err4, 'DummyDisconnect: Host key mismatch')

    async def test_probe_endpoint_via_ssh_records_audit_on_timeout(self):
        import asyncio
        mock_ep = mock.MagicMock()
        mock_ep.id = 'ep_fail_1'
        mock_ep.name = ''
        mock_ep.host = 'debianlounge.galleon.co.za'
        mock_ep.port = 22
        mock_ep.username = 'root'
        mock_ep.auth_type = 'password'
        mock_ep.auth_secret_enc = b'dummy'

        with (
            mock.patch('ca.fleet_trust.get_expected_cas', new=mock.AsyncMock(return_value=[{'serial_number': '1234', 'cn': 'Root', 'active': True}])),
            mock.patch('ca.distribution.decrypt_secret', return_value='password123'),
            mock.patch('ca.fleet_trust.asyncssh.connect', side_effect=asyncio.TimeoutError()),
            mock.patch('ca.fleet_trust.record_audit', new=mock.AsyncMock(return_value='aud_failed_123')) as mock_record,
        ):
            cas = [{'serial_number': '1234', 'cn': 'Root', 'active': True}]
            res = await fleet_trust.probe_endpoint_trust_via_ssh(mock_ep, expected_cas=cas)

            self.assertEqual(res['status'], 'error')
            self.assertIn('Connection timed out', res['message'])
            self.assertEqual(res['audit_id'], 'aud_failed_123')

            mock_record.assert_called_once()
            _, kwargs = mock_record.call_args
            self.assertEqual(kwargs['device_name'], 'debianlounge')
            self.assertEqual(kwargs['ip_address'], 'debianlounge.galleon.co.za')
            self.assertEqual(kwargs['verification_method'], 'ssh_sweep')
            self.assertEqual(kwargs['overall_status'], 'error')
            self.assertEqual(kwargs['results'], [])
            self.assertIn('Connection timed out after 20s', kwargs['error_message'])

    async def test_probe_endpoint_via_ssh_records_audit_on_missing_key(self):
        mock_ep = mock.MagicMock()
        mock_ep.id = 'ep_fail_key'
        mock_ep.name = 'Keyed Server'
        mock_ep.host = 'keyserver.example.com'
        mock_ep.port = 22
        mock_ep.username = 'root'
        mock_ep.auth_type = 'key'
        mock_ep.auth_secret_enc = b''

        with (
            mock.patch('ca.distribution.decrypt_secret', return_value=''),
            mock.patch('ca.fleet_trust.record_audit', new=mock.AsyncMock(return_value='aud_key_fail')) as mock_record,
        ):
            res = await fleet_trust.probe_endpoint_trust_via_ssh(mock_ep, expected_cas=[])
            self.assertEqual(res['status'], 'error')
            self.assertEqual(res['message'], 'Missing SSH key')
            self.assertEqual(res['audit_id'], 'aud_key_fail')

            mock_record.assert_called_once()
            _, kwargs = mock_record.call_args
            self.assertEqual(kwargs['device_name'], 'Keyed Server')
            self.assertEqual(kwargs['overall_status'], 'error')
            self.assertEqual(kwargs['results'], [])
            self.assertEqual(kwargs['error_message'], 'Missing SSH key')

    async def test_probe_endpoint_via_ssh_linux_fast_path(self):
        mock_ep = mock.MagicMock()
        mock_ep.id = 'ep_linux_fast'
        mock_ep.name = 'Debian Server'
        mock_ep.host = 'debianlounge.galleon.co.za'
        mock_ep.port = 22
        mock_ep.username = 'root'
        mock_ep.auth_type = 'password'
        mock_ep.auth_secret_enc = b'dummy'

        mock_conn = mock.MagicMock()
        mock_conn.run = mock.AsyncMock(return_value=mock.MagicMock(stdout='Found in trust bundle /etc/ssl/certs/ca-certificates.crt'))
        mock_ctx = mock.MagicMock()
        mock_ctx.__aenter__ = mock.AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = mock.AsyncMock(return_value=None)

        cas = [{
            'serial_number': '1234ABCD',
            'cn': 'My Root CA',
            'pem_signature': 'MIIBxxxx',
            'fingerprint_sha256_raw': 'AABBCCDDEEFF',
            'active': True,
        }]

        with (
            mock.patch('ca.distribution.decrypt_secret', return_value='secret'),
            mock.patch('ca.fleet_trust.asyncssh.connect', return_value=mock_ctx),
            mock.patch('ca.distribution.probe_ssh_os', new=mock.AsyncMock(return_value=('linux', 'Debian 13'))),
            mock.patch('ca.fleet_trust.record_audit', new=mock.AsyncMock(return_value='aud_linux_fast')) as mock_record,
        ):
            res = await fleet_trust.probe_endpoint_trust_via_ssh(mock_ep, expected_cas=cas)
            self.assertEqual(res['status'], 'success')
            self.assertEqual(len(res['results']), 1)
            self.assertTrue(res['results'][0]['is_trusted'])
            self.assertIn('Found in trust bundle', res['results'][0]['details'])

            # Verify check_cmd contained SIG and fast-path bundle checks
            mock_conn.run.assert_called_once()
            called_cmd = mock_conn.run.call_args[0][0]
            self.assertIn('SIG="MIIBxxxx"', called_cmd)
            self.assertIn('grep -Fq "$SIG"', called_cmd)

    async def test_probe_endpoint_via_ssh_command_timeout_isolated(self):
        """Verify command timeout on individual cert check does not fail the whole probe with connection timeout."""
        mock_ep = mock.MagicMock()
        mock_ep.id = 'ep_cmd_timeout'
        mock_ep.name = 'Slow Server'
        mock_ep.host = 'slow.example.com'
        mock_ep.port = 22
        mock_ep.username = 'root'
        mock_ep.auth_type = 'password'
        mock_ep.auth_secret_enc = b'dummy'

        mock_conn = mock.MagicMock()
        mock_conn.run = mock.AsyncMock(side_effect=TimeoutError())
        mock_ctx = mock.MagicMock()
        mock_ctx.__aenter__ = mock.AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__ = mock.AsyncMock(return_value=None)

        cas = [{
            'serial_number': '1234ABCD',
            'cn': 'My Root CA',
            'pem_signature': 'MIIBxxxx',
            'fingerprint_sha256_raw': 'AABBCCDDEEFF',
            'active': True,
        }]

        with (
            mock.patch('ca.distribution.decrypt_secret', return_value='secret'),
            mock.patch('ca.fleet_trust.asyncssh.connect', return_value=mock_ctx),
            mock.patch('ca.distribution.probe_ssh_os', new=mock.AsyncMock(return_value=('linux', 'Debian 13'))),
            mock.patch('ca.fleet_trust.record_audit', new=mock.AsyncMock(return_value='aud_cmd_timeout')) as mock_record,
        ):
            res = await fleet_trust.probe_endpoint_trust_via_ssh(mock_ep, expected_cas=cas)
            # The probe completes cleanly instead of failing the connection
            self.assertEqual(res['status'], 'success')
            self.assertEqual(len(res['results']), 1)
            self.assertFalse(res['results'][0]['is_trusted'])
            self.assertIn('Check timed out', res['results'][0]['details'])


