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
    with open(ENV_FILE) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                os.environ.setdefault(k, v)

import db
import db.migrations
import mail
import mail.service
from fastapi.testclient import TestClient
from main import app
from web.auth import create_session_cookie


async def run_tests():
    print("--> 1. Connecting to DB and running migrations...")
    await db.connect()
    await db.migrations.run()

    print("--> 2. Snapshotting initial settings and testing mail settings service...")
    initial_cfg = await mail.service.get_mail_settings()
    assert initial_cfg is not None
    print(f"    Initial config snapshot: host={initial_cfg.host}, enabled={initial_cfg.enabled}")

    try:
        # Test saving new values
        saved = await mail.service.save_mail_settings(
            enabled=True,
            host='smtp.testdomain.org',
            port=587,
            username='mytestuser',
            password='secret_password_123',
            encryption='starttls',
            sender='no-reply@testdomain.org',
            notify_on_account_creation=True,
            warn_before_cert_expires_days=25,
            notify_when_cert_expired=True,
            update_password=True,
        )
        assert saved.host == 'smtp.testdomain.org'
        assert saved.port == 587
        assert saved.password == 'secret_password_123'
        assert saved.warn_before_cert_expires_days == 25

        # Verify reloading from DB matches
        mail.service.invalidate_cache()
        reloaded = await mail.service.get_mail_settings()
        assert reloaded.host == 'smtp.testdomain.org'
        assert reloaded.password == 'secret_password_123'
        assert reloaded.warn_before_cert_expires_days == 25

        # Test updating settings without changing password (keep existing)
        saved2 = await mail.service.save_mail_settings(
            enabled=True,
            host='smtp.updated.org',
            port=465,
            username='mytestuser',
            password='',
            encryption='tls',
            sender='no-reply@updated.org',
            notify_on_account_creation=False,
            warn_before_cert_expires_days=10,
            notify_when_cert_expired=False,
            update_password=False,
        )
        assert saved2.host == 'smtp.updated.org'
        assert saved2.password == 'secret_password_123', "Password should be preserved when update_password=False"
        assert saved2.warn_before_cert_expires_days == 10
        assert saved2.notify_on_account_creation is False

        print("    Mail service unit assertions passed!")

        print("--> 3. Testing Web UI endpoints (/mail, /mail/test)...")
        token, _ = create_session_cookie('admin', remember_me=True)
        client = TestClient(app, cookies={'acme_session': token})

        # GET /mail
        resp = client.get('/mail')
        assert resp.status_code == 200, f"GET /mail failed: {resp.text}"
        assert 'Mail Settings' in resp.text
        assert 'SMTP Server Configuration' in resp.text
        assert 'smtp.updated.org' in resp.text
        assert 'Test Email Delivery' in resp.text
        print("    GET /mail returned 200 with populated settings.")

        # POST /mail (update settings via form)
        post_data = {
            'enabled': 'on',
            'host': 'smtp.webform.org',
            'port': '587',
            'encryption': 'starttls',
            'sender': 'mailer@webform.org',
            'username': 'webuser',
            'password': 'new_web_password',
            'warn_before_cert_expires_days': '14',
            'notify_when_cert_expired': 'on',
            'notify_on_account_creation': 'on',
        }
        resp_post = client.post('/mail', data=post_data)
        assert resp_post.status_code == 200, f"POST /mail failed: {resp_post.text}"
        assert 'Mail settings saved successfully' in resp_post.text
        assert 'smtp.webform.org' in resp_post.text
        print("    POST /mail saved settings successfully.")

        # Verify DB has new values
        mail.service.invalidate_cache()
        db_cfg = await mail.service.get_mail_settings()
        assert db_cfg.host == 'smtp.webform.org'
        assert db_cfg.password == 'new_web_password'
        assert db_cfg.warn_before_cert_expires_days == 14

        # POST /mail/test
        test_payload = {
            'host': '127.0.0.1',
            'port': 9999,
            'encryption': 'plain',
            'sender': 'admin@test.org',
            'recipient': 'user@test.org',
        }
        test_resp = client.post('/mail/test', json=test_payload)
        assert test_resp.status_code == 400
        test_json = test_resp.json()
        assert test_json['ok'] is False
        assert 'Failed to connect to SMTP server' in test_json['error']
        print("    POST /mail/test diagnostic error handling verified.")

    finally:
        print("--> 4. Restoring original settings snapshot to database...")
        await mail.service.save_mail_settings(
            enabled=initial_cfg.enabled,
            host=initial_cfg.host,
            port=initial_cfg.port,
            username=initial_cfg.username,
            password=initial_cfg.password,
            encryption=initial_cfg.encryption,
            sender=initial_cfg.sender,
            notify_on_account_creation=initial_cfg.notify_on_account_creation,
            warn_before_cert_expires_days=initial_cfg.warn_before_cert_expires_days,
            notify_when_cert_expired=initial_cfg.notify_when_cert_expired,
            update_password=True,
        )
        mail.service.invalidate_cache()
        await db.disconnect()
        print("    Database restored to clean original state.")

    print("==> ALL MAIL SETTINGS TESTS PASSED SUCCESSFULLY! <==")


if __name__ == '__main__':
    asyncio.run(run_tests())
