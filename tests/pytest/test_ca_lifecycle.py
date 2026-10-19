import asyncio
from datetime import datetime, timedelta, timezone
from unittest import mock

import ca.cronjob as ca_cronjob
import ca.service as ca_service
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient


def test_ca_page_renders_hero_and_repository(testclient: TestClient):
    response = testclient.get('/ca')
    assert response.status_code == 200, response.text
    assert 'Active Issuing Root CA' in response.text
    assert 'Root CA Repository' in response.text
    assert 'Renew / Rollover Root CA' in response.text
    assert 'renewModal' in response.text


def test_ca_downloads_active(testclient: TestClient):
    resp_crt = testclient.get('/ca/download')
    assert resp_crt.status_code == 200
    assert 'BEGIN CERTIFICATE' in resp_crt.text

    resp_pem = testclient.get('/ca/download-pem')
    assert resp_pem.status_code == 200
    assert 'BEGIN CERTIFICATE' in resp_pem.text

    resp_crl = testclient.get('/ca/download-crl')
    assert resp_crl.status_code == 200
    assert 'BEGIN X509 CRL' in resp_crl.text


def test_ca_renew_in_standby_and_switch_active(testclient: TestClient):
    async def _test():
        # 1. Check current active CA
        initial_active = await ca_service.get_active_ca_details()
        assert initial_active is not None
        initial_sn = initial_active['serial_number']

        # 2. Renew CA in Standby mode (activate_immediately not checked)
        resp = testclient.post(
            '/ca/renew',
            data={
                'common_name': 'Renewed Standby Root CA',
                'organization': 'ACME Enterprise',
                'organizational_unit': 'Security PKI',
                'country': 'US',
                'state': 'California',
                'locality': 'San Francisco',
                'key_type': 'RSA',
                'key_size_or_curve': '2048',
                'digest_algorithm': 'SHA-256',
                'validity_years': 5,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert 'status_msg=ca_renewed_standby' in resp.headers['location']

        # 3. Verify repository lists both CAs
        all_cas = await ca_service.list_all_cas()
        assert len(all_cas) >= 2
        standby_cas = [c for c in all_cas if c['common_name'] == 'Renewed Standby Root CA']
        assert len(standby_cas) == 1
        new_ca = standby_cas[0]
        assert new_ca['active'] is False
        assert new_ca['status_label'] == 'standby'

        # Verify original CA is still active
        current_active = await ca_service.get_active_ca_details()
        assert current_active is not None
        assert current_active['serial_number'] == initial_sn

        # 4. Test download endpoints for the specific standby CA
        resp_specific_crt = testclient.get(f'/ca/{new_ca["serial_number"]}/download')
        assert resp_specific_crt.status_code == 200
        assert 'BEGIN CERTIFICATE' in resp_specific_crt.text

        resp_specific_pem = testclient.get(f'/ca/{new_ca["serial_number"]}/download-pem')
        assert resp_specific_pem.status_code == 200
        assert 'BEGIN CERTIFICATE' in resp_specific_pem.text

        # 5. Switch active CA to the renewed CA
        resp_act = testclient.post(f'/ca/{new_ca["serial_number"]}/activate', follow_redirects=False)
        assert resp_act.status_code == 303
        assert 'status_msg=ca_activated' in resp_act.headers['location']

        # Verify new CA is now active
        active_now = await ca_service.get_active_ca_details()
        assert active_now is not None
        assert active_now['serial_number'] == new_ca['serial_number']
        assert active_now['common_name'] == 'Renewed Standby Root CA'

        # Switch back to original CA
        resp_revert = testclient.post(f'/ca/{initial_sn}/activate', follow_redirects=False)
        assert resp_revert.status_code == 303

        # Clean up test CA
        await ca_service.delete_ca(new_ca['serial_number'])

    asyncio.run(_test())


def test_ca_protection_rules(testclient: TestClient):
    async def _test():
        active_ca = await ca_service.get_active_ca_details()
        assert active_ca is not None
        sn = active_ca['serial_number']

        # 1. Cannot delete active CA
        with pytest.raises(ValueError, match='Cannot delete the currently active CA'):
            await ca_service.delete_ca(sn)

        # 2. Cannot retire active CA
        with pytest.raises(ValueError, match='Cannot retire the currently active issuing CA'):
            await ca_service.retire_ca(sn)

    asyncio.run(_test())


def test_leaf_certificate_validity_capped_by_ca():
    # Generate a CA that expires in 10 days
    ca_key = rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Short-lived Test CA')])
    now = datetime.now(timezone.utc)
    ca_expiry = now + timedelta(days=10)

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(123456789)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(ca_expiry)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    ca_cert = cert_builder.sign(ca_key, hashes.SHA256())

    # Create dummy CSR
    leaf_key = rsa.generate_private_key(65537, 2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'example.com')])).sign(leaf_key, hashes.SHA256())

    # generate_cert_sync should cap leaf cert validity to ca_expiry
    cert, _ = ca_service.generate_cert_sync(
        ca_key=ca_key,
        ca_cert=ca_cert,
        csr=csr,
        subject_domain='example.com',
        san_domains=['example.com'],
    )
    _, leaf_nva = ca_service.get_cert_dates(cert)
    assert leaf_nva <= ca_expiry


def test_ca_cronjob_expiration_alerting():
    async def _test():
        # Test expiration notification handling
        with (
            mock.patch('mail.service.get_mail_settings') as mock_settings,
            mock.patch('mail.send_ca_will_expire_warn_mail', new_callable=mock.AsyncMock) as mock_warn,
            mock.patch('mail.send_ca_expired_info_mail', new_callable=mock.AsyncMock) as mock_expired,
        ):
            mock_cfg = mock.MagicMock()
            mock_cfg.enabled = True
            mock_cfg.effective_admin_recipient = 'admin@example.com'
            mock_cfg.warn_before_ca_expires_days = 90
            mock_settings.return_value = mock_cfg

            # 1. Test warning email trigger for a 30-day expiring CA
            now = datetime.now(timezone.utc)
            test_nva = now + timedelta(days=25)
            await ca_cronjob._handle_expiring_ca(
                sn='TEST_SN_1',
                cert_pem='dummy_pem',
                last_stage=0,
                nva=test_nva,
                now=now,
                admin_email='admin@example.com',
                warn_days=90,
                stages=[90, 60, 30, 14, 7, 1],
            )
            assert mock_warn.called
            assert mock_warn.call_args[1]['receiver'] == 'admin@example.com'
            assert mock_warn.call_args[1]['days_remaining'] == 25

            # 2. Test expired email trigger
            expired_nva = now - timedelta(days=1)
            await ca_cronjob._handle_expired_ca(
                sn='TEST_SN_2',
                cert_pem='dummy_pem',
                last_stage=0,
                nva=expired_nva,
                admin_email='admin@example.com',
            )
            assert mock_expired.called
            assert mock_expired.call_args[1]['receiver'] == 'admin@example.com'

    asyncio.run(_test())
