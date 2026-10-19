import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

REPO_DIR = Path(__file__).resolve().parent.parent
APP_DIR = REPO_DIR / 'app'
sys.path.insert(0, str(APP_DIR))

os.environ.setdefault('external_url', 'http://localhost:8000')
os.environ.setdefault('db_dsn', 'postgresql://localhost/dummy')
os.environ.setdefault('ca_encryption_key', 'fIj-aQgcgfMUphrXikMlZ2bQkBdWtcuSJXjycQJFC70=')

import ca.distribution as dist
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa


class TestCaDistributionUnit(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.key = rsa.generate_private_key(65537, 2048)

    def _build_cert(self, org_name: str | None, cn: str, nvb: datetime) -> x509.Certificate:
        attrs = [x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]
        if org_name:
            attrs.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, org_name))
        name = x509.Name(attrs)
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(123456789)
            .not_valid_before(nvb)
            .not_valid_after(datetime(2035, 1, 1, 0, 0, tzinfo=timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.key, hashes.SHA256())
        )

    def test_filename_formulation_with_org(self):
        nvb = datetime(2026, 10, 19, 17, 18, 23, tzinfo=timezone.utc)
        cert = self._build_cert('Acme Corporation', 'Acme Root CA 2026', nvb)
        filename_base = dist.format_ca_filename(cert)
        self.assertEqual(filename_base, 'Acme_202610191718')
        self.assertEqual(dist.format_ca_filename(cert, 'crt'), 'Acme_202610191718.crt')
        self.assertEqual(dist.format_ca_filename(cert, '.pem'), 'Acme_202610191718.pem')
        self.assertEqual(dist.format_ca_filename(cert, 'cer'), 'Acme_202610191718.cer')

    def test_filename_formulation_fallback_to_cn(self):
        nvb = datetime(2025, 5, 1, 9, 30, 0, tzinfo=timezone.utc)
        cert = self._build_cert(None, 'Internal-Security Authority', nvb)
        filename_base = dist.format_ca_filename(cert)
        self.assertEqual(filename_base, 'InternalSecurity_202505010930')

    def test_secret_encryption_roundtrip(self):
        secret = 'my_super_secret_ssh_key_or_password_123!'
        enc = dist.encrypt_secret(secret)
        self.assertNotEqual(enc, secret.encode())
        dec = dist.decrypt_secret(enc)
        self.assertEqual(dec, secret)

    def test_readme_generation(self):
        # Linux
        linux_readme = dist.generate_readme('TestCA_2026', 'linux', 'Test Root CA', 'DEADBEEF')
        self.assertIn('update-ca-certificates', linux_readme)
        self.assertIn('update-ca-trust', linux_readme)
        self.assertIn('TestCA_2026.crt', linux_readme)

        # OpenWrt
        openwrt_readme = dist.generate_readme('TestCA_2026', 'openwrt', 'Test Root CA', 'DEADBEEF')
        self.assertIn('/etc/ssl/certs/', openwrt_readme)
        self.assertIn('opkg install ca-certificates', openwrt_readme)

        # Windows
        win_readme = dist.generate_readme('TestCA_2026', 'windows', 'Test Root CA', 'DEADBEEF')
        self.assertIn('certutil -addstore', win_readme)
        self.assertIn('Import-Certificate', win_readme)

        # macOS
        mac_readme = dist.generate_readme('TestCA_2026', 'macos', 'Test Root CA', 'DEADBEEF')
        self.assertIn('security add-trusted-cert', mac_readme)
        self.assertIn('System.keychain', mac_readme)

    async def test_email_endpoint_validation(self):
        ok, msg = await dist.test_email_endpoint([])
        self.assertFalse(ok)
        self.assertIn('required', msg)

        ok, msg = await dist.test_email_endpoint(['invalid-email-address'])
        self.assertFalse(ok)
        self.assertIn('Invalid email address', msg)

        mock_cfg = mock.MagicMock(enabled=True, host='mail.example.org', sender='ca@example.org')
        with mock.patch('mail.service.get_mail_settings', new=mock.AsyncMock(return_value=mock_cfg)):
            ok, msg = await dist.test_email_endpoint(['alice@example.com', 'bob@domain.org'])
            self.assertTrue(ok)
            self.assertIn('2 valid recipient(s)', msg)

    async def test_probe_ssh_os_openwrt(self):
        conn = mock.AsyncMock()

        # uname returns Linux
        uname_res = mock.MagicMock(stdout='Linux OpenWrt 5.15.137\n')
        # ow check returns OpenWrt release
        ow_res = mock.MagicMock(stdout="DISTRIB_ID='OpenWrt'\nDISTRIB_DESCRIPTION='OpenWrt 23.05.2'\n")

        conn.run.side_effect = [uname_res, ow_res]

        os_type, os_detail = await dist.probe_ssh_os(conn)
        self.assertEqual(os_type, 'openwrt')
        self.assertEqual(os_detail, 'OpenWrt 23.05.2')

    async def test_probe_ssh_os_linux(self):
        conn = mock.AsyncMock()
        uname_res = mock.MagicMock(stdout='Linux\n')
        ow_res = mock.MagicMock(stdout='')
        os_rel = mock.MagicMock(stdout='PRETTY_NAME="Ubuntu 24.04 LTS"\n')

        conn.run.side_effect = [uname_res, ow_res, os_rel]

        os_type, os_detail = await dist.probe_ssh_os(conn)
        self.assertEqual(os_type, 'linux')
        self.assertEqual(os_detail, 'Ubuntu 24.04 LTS')

    async def test_probe_ssh_os_macos(self):
        conn = mock.AsyncMock()
        uname_res = mock.MagicMock(stdout='Darwin\n')
        sw_res = mock.MagicMock(stdout='14.5\n')

        conn.run.side_effect = [uname_res, sw_res]

        os_type, os_detail = await dist.probe_ssh_os(conn)
        self.assertEqual(os_type, 'macos')
        self.assertEqual(os_detail, 'macOS 14.5')

    async def test_probe_ssh_os_windows(self):
        conn = mock.AsyncMock()
        uname_res = mock.MagicMock(stdout='Microsoft Windows [Version 10.0.19045.3803]\n')
        win_res = mock.MagicMock(stdout='Microsoft Windows [Version 10.0.19045.3803]\n')

        conn.run.side_effect = [uname_res, win_res]

        os_type, os_detail = await dist.probe_ssh_os(conn)
        self.assertEqual(os_type, 'windows')
        self.assertIn('Windows', os_detail)

    async def test_probe_ssh_os_unsupported(self):
        conn = mock.AsyncMock()
        uname_res = mock.MagicMock(stdout='FreeBSD 13.2-RELEASE\n')
        conn.run.return_value = uname_res

        os_type, os_detail = await dist.probe_ssh_os(conn)
        self.assertEqual(os_type, 'unsupported')
        self.assertIn('FreeBSD', os_detail)

    async def test_get_endpoints_and_logs(self):
        sample_endpoint_row = {
            'id': 'ep-123',
            'name': 'Test SSH',
            'type': 'ssh',
            'host': '192.168.1.10',
            'port': 22,
            'username': 'root',
            'auth_type': 'key',
            'target_dir': '/etc/ssl/certs',
            'email_addresses': [],
            'target_os_list': [],
            'detected_os': 'linux',
            'os_detail': 'Ubuntu 24.04',
            'last_test_at': datetime.now(timezone.utc),
            'last_test_status': 'ok',
            'last_test_message': 'Connected',
            'has_secret': True,
            'created_at': datetime.now(timezone.utc),
            'updated_at': datetime.now(timezone.utc),
        }
        sample_log_row = {
            'id': 'log-456',
            'ca_serial': '123456789',
            'endpoint_id': 'ep-123',
            'endpoint_name': 'Test SSH',
            'endpoint_type': 'ssh',
            'filename': 'Acme_2026.crt',
            'status': 'ok',
            'status_message': 'Uploaded',
            'distributed_at': datetime.now(timezone.utc),
        }

        class MockSql:
            def __init__(self, rows):
                self._rows = rows

            async def __call__(self, *args, **kwargs):
                for r in self._rows:
                    yield r

        class MockTransaction:
            def __init__(self, rows):
                self._sql = MockSql(rows)

            async def __aenter__(self):
                return self._sql

            async def __aexit__(self, *args):
                pass

        with mock.patch('ca.distribution.db.transaction', side_effect=lambda **kw: MockTransaction([sample_endpoint_row])):
            endpoints = await dist.get_endpoints()
            self.assertEqual(len(endpoints), 1)
            self.assertEqual(endpoints[0].id, 'ep-123')
            self.assertEqual(endpoints[0].name, 'Test SSH')

        with mock.patch('ca.distribution.db.transaction', side_effect=lambda **kw: MockTransaction([sample_log_row])):
            logs = await dist.get_distribution_logs()
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0]['id'], 'log-456')
            self.assertEqual(logs[0]['endpoint_name'], 'Test SSH')

    def test_windows_version_formatting(self):
        # GalleonPrintSrv exact banner: Option B mapping with build
        formatted = dist._format_windows_version('Microsoft Windows  [Version 10.0.14393]')
        self.assertIn('Windows Server 2016 / Windows 10 1607', formatted)
        self.assertIn('10.0.14393', formatted)

        # Other known build (Windows Server 2022)
        formatted_2022 = dist._format_windows_version('Microsoft Windows [Version 10.0.20348.1]')
        self.assertIn('Windows Server 2022', formatted_2022)

        # Fallback to Option A for unknown build
        fallback = dist._format_windows_version('Microsoft Windows [Version 10.0.99999]')
        self.assertEqual(fallback, 'Microsoft Windows [Version 10.0.99999]')

    async def test_probe_ssh_os_windows_galleon(self):
        class MockResult:
            def __init__(self, stdout='', stderr='', exit_status=0):
                self.stdout = stdout
                self.stderr = stderr
                self.exit_status = exit_status

        mock_conn = mock.AsyncMock()

        async def fake_run(cmd, *args, **kwargs):
            if cmd == 'uname -s':
                # Windows cmd returns error for uname
                return MockResult(stdout='', stderr="'uname' is not recognized as an internal or external command", exit_status=1)
            if 'cmd.exe /c ver' in cmd:
                return MockResult(stdout='Microsoft Windows [Version 10.0.14393]\r\n', stderr='')
            return MockResult(stdout='', stderr='')

        mock_conn.run = fake_run

        os_type, os_detail = await dist.probe_ssh_os(mock_conn)
        self.assertEqual(os_type, 'windows')
        self.assertIn('Windows Server 2016', os_detail)
        self.assertIn('10.0.14393', os_detail)


if __name__ == '__main__':
    unittest.main()
