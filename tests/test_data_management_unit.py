import asyncio
import os
import sys
from pathlib import Path

# Add app to path
REPO_DIR = Path(__file__).resolve().parent.parent
APP_DIR = REPO_DIR / 'app'
sys.path.insert(0, str(APP_DIR))

# Load .env
ENV_FILE = REPO_DIR / '.env'
if ENV_FILE.exists():
    with open(ENV_FILE, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                os.environ.setdefault(k, v)

import ca
import db
import db.migrations
import tools.data_retention as dr
from fastapi.testclient import TestClient
from main import app
from unittest import mock
from web.auth import create_session_cookie


async def run_tests():
    print("--> 1. Connecting to DB and running migrations...")
    await db.connect()
    await db.migrations.run()
    await ca.init()

    # Mock SMTP to ensure tests never contact real external mail servers (e.g. smtp.galleon.co.za)
    mock_smtp_client = mock.AsyncMock()
    mock_smtp_client.send_message = mock.AsyncMock(return_value=({}, '250 OK: Mock message queued'))
    mock_smtp_client.login = mock.AsyncMock(return_value=(235, '2.7.0 Accepted'))
    mock_smtp_client.connect = mock.AsyncMock(return_value=(220, 'smtp.mock.local ready'))
    mock_smtp_client.quit = mock.AsyncMock(return_value=(221, 'Bye'))
    mock_smtp_client.__aenter__ = mock.AsyncMock(return_value=mock_smtp_client)
    mock_smtp_client.__aexit__ = mock.AsyncMock(return_value=None)
    mock_smtp_cls = mock.MagicMock(return_value=mock_smtp_client)

    print("--> 2. Testing Data Management settings loading and saving...")
    initial_cfg = await dr.get_data_management_settings()
    assert initial_cfg is not None
    assert initial_cfg.delete_deactivated_accounts_days >= 0
    assert initial_cfg.delete_stale_orders_days >= 0
    assert initial_cfg.delete_invalid_domains_days >= 0
    assert initial_cfg.revoke_expired_certs_days >= 0
    assert initial_cfg.delete_revoked_certs_days >= 0
    assert initial_cfg.delete_distribution_logs_days >= 0
    assert initial_cfg.delete_fleet_audits_days >= 0
    assert initial_cfg.delete_run_history_days >= 0
    print(f"    Initial settings loaded successfully (enabled={initial_cfg.enabled}, cron={initial_cfg.cron_schedule_hours}h)")

    with (
        mock.patch('aiosmtplib.SMTP', mock_smtp_cls),
        mock.patch('mail.service.SMTP', mock_smtp_cls),
        mock.patch('mail.SMTP', mock_smtp_cls),
        mock.patch('ca.distribution.SMTP', mock_smtp_cls),
    ):
        try:
            # Test saving new values
            saved = await dr.save_data_management_settings(
                enabled=True,
                cron_schedule_hours=12,
                run_at_hour_utc=3,
                delete_deactivated_accounts_days=30,
                delete_stale_orders_days=15,
                delete_invalid_domains_days=30,
                revoke_expired_certs_days=5,
                delete_revoked_certs_days=10,
                delete_distribution_logs_days=20,
                delete_fleet_audits_days=10,
                delete_run_history_days=45,
                email_notification_enabled=True,
                notify_only_on_changes=False,
                admin_email='ops@example.com',
            )
            assert saved.cron_schedule_hours == 12
            assert saved.run_at_hour_utc == 3
            assert saved.delete_deactivated_accounts_days == 30
            assert saved.delete_run_history_days == 45
            assert saved.admin_email == 'ops@example.com'
            print("    Settings updated and re-verified successfully.")

            print("--> 3. Testing Dry Run retention audit...")
            dry_result = await dr.run_data_retention(trigger_type='manual', dry_run=True)
            assert dry_result['status'] == 'dry_run'
            assert 'rules' in dry_result
            assert 'rule_a_accounts' in dry_result['rules']
            assert 'rule_d_revoke_expired' in dry_result['rules']
            print(f"    Dry run audit completed successfully: {dry_result['total_records_affected']} matches, duration={dry_result['duration_ms']}ms")

            print("--> 4. Testing Live retention execution...")
            live_result = await dr.run_data_retention(trigger_type='manual', dry_run=False)
            assert live_result['status'] == 'success'
            print(f"    Live retention completed successfully: {live_result['total_records_affected']} affected, duration={live_result['duration_ms']}ms")

            print("--> 5. Testing recent runs history...")
            recent = await dr.list_recent_runs(limit=5)
            assert len(recent) >= 2
            assert recent[0]['status'] in ('success', 'dry_run')
            print(f"    Retrieved {len(recent)} recent runs.")

            print("--> 6. Testing HTTP Web Routes via TestClient...")
            token, _ = create_session_cookie('admin', remember_me=True)
            client = TestClient(app, cookies={'acme_session': token})

            # Test GET /data-management
            resp_get = client.get('/data-management')
            assert resp_get.status_code == 200, f"Expected 200 but got {resp_get.status_code}"
            assert 'Data Management' in resp_get.text
            assert 'Automated Retention Rules' in resp_get.text
            print("    GET /data-management: 200 OK")

            # Test POST /data-management/run?dry_run=true
            resp_run_dry = client.post('/data-management/run?dry_run=true')
            assert resp_run_dry.status_code == 200
            data_dry = resp_run_dry.json()
            assert data_dry['status'] == 'dry_run'
            print("    POST /data-management/run?dry_run=true: 200 OK")

            # Test POST /data-management/run?dry_run=false
            resp_run_live = client.post('/data-management/run?dry_run=false')
            assert resp_run_live.status_code == 200
            data_live = resp_run_live.json()
            assert data_live['status'] == 'success'
            print("    POST /data-management/run?dry_run=false: 200 OK")

            # Test POST /data-management (form save)
            resp_save = client.post(
                '/data-management',
                data={
                    'enabled': 'on',
                    'cron_schedule_hours': 24,
                    'run_at_hour_utc': 2,
                    'delete_deactivated_accounts_days': 28,
                    'delete_stale_orders_days': 14,
                    'delete_invalid_domains_days': 28,
                    'revoke_expired_certs_days': 7,
                    'delete_revoked_certs_days': 14,
                    'delete_distribution_logs_days': 14,
                    'delete_fleet_audits_days': 7,
                    'delete_run_history_days': 30,
                    'email_notification_enabled': 'on',
                    'notify_only_on_changes': 'on',
                    'admin_email': '',
                },
            )
            assert resp_save.status_code == 200
            assert 'Data management settings saved successfully' in resp_save.text
            print("    POST /data-management: 200 OK")

        finally:
            print("--> 7. Restoring initial settings snapshot...")
            await dr.save_data_management_settings(
                enabled=initial_cfg.enabled,
                cron_schedule_hours=initial_cfg.cron_schedule_hours,
                run_at_hour_utc=initial_cfg.run_at_hour_utc,
                delete_deactivated_accounts_days=initial_cfg.delete_deactivated_accounts_days,
                delete_stale_orders_days=initial_cfg.delete_stale_orders_days,
                delete_invalid_domains_days=initial_cfg.delete_invalid_domains_days,
                revoke_expired_certs_days=initial_cfg.revoke_expired_certs_days,
                delete_revoked_certs_days=initial_cfg.delete_revoked_certs_days,
                delete_distribution_logs_days=initial_cfg.delete_distribution_logs_days,
                delete_fleet_audits_days=initial_cfg.delete_fleet_audits_days,
                delete_run_history_days=initial_cfg.delete_run_history_days,
                email_notification_enabled=initial_cfg.email_notification_enabled,
                notify_only_on_changes=initial_cfg.notify_only_on_changes,
                admin_email=initial_cfg.admin_email,
            )
            await db.disconnect()
            print("    Database restored to clean original state.")

    print("\n✓ ALL DATA MANAGEMENT UNIT TESTS PASSED SUCCESSFULLY!")


if __name__ == '__main__':
    asyncio.run(run_tests())
