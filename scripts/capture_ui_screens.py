#!/usr/bin/env python3
"""
ACME CA Server - Automated UI Screen Capture Utility
Captures high-resolution screenshots of all web UI screens:
  1. Login Screen
  2. Initial Admin Setup / Onboarding
  3. Root CA Certificate Setup / Onboarding
  4. Home Dashboard
  5. Root CA Certificate Details (40% / 60% layout)
  6. Certificates Audit Log
  6b. Certificate Details & Capability Inspection Modal
  7. Domains Registry
  8. Accounts Management
  9. Account Orders & Error Details Modal
  10. Mail Settings & Delivery Diagnostics
  11. User Management & Access Control
  12. CA Certificate Distribution Hub
  12b. Root CA Certificate Distribution & Deployment Modal
  13. CA Fleet Trust & Compliance Audit
  13b. CA Fleet Trust - CLI Probe & Manual Diagnostics Modal
  14. Client Root CA Trust Verification Portal

Usage:
  python3 scripts/capture_ui_screens.py
  python3 scripts/capture_ui_screens.py --base-url http://localhost:8080 --output-dir Documentation/screenshots
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

# Resolve repository paths
REPO_DIR = Path(__file__).resolve().parent.parent
APP_DIR = REPO_DIR / 'app'
TEMPLATES_DIR = APP_DIR / 'web' / 'templates'
DEFAULT_OUTPUT_DIR = REPO_DIR / 'Documentation' / 'screenshots'

# Load environment configuration (.env)
ENV_FILE = REPO_DIR / '.env'
if ENV_FILE.exists():
    with open(ENV_FILE) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                os.environ.setdefault(k, v)

# Import app modules for session authentication
sys.path.insert(0, str(APP_DIR))
try:
    from web.auth import create_session_cookie
except ImportError as e:
    print(f"Error: Could not import app modules: {e}")
    print("Ensure the script is run in the project virtualenv (.venv/bin/python3).")
    sys.exit(1)

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("Error: 'playwright' is not installed.")
    print("Run: pip install playwright && playwright install chromium")
    sys.exit(1)

import jinja2


class MockURL:
    def __init__(self, path: str):
        self.path = path


class MockUser:
    def __init__(self, username: str = 'admin'):
        self.username = username


class MockState:
    def __init__(self, username: str = 'admin'):
        self.user = MockUser(username)


class MockRequest:
    def __init__(self, path: str, username: str = 'admin'):
        self.url = MockURL(path)
        self.state = MockState(username)


async def obfuscate_page(page):
    """Obfuscate any real domain names, email addresses, and DN fields in the DOM."""
    js_code = r"""() => {
        const emailRegex = /[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g;
        
        function sanitizeText(str) {
            if (!str) return str;
            let res = str;
            
            // 1. Obfuscate domain names
            res = res.replace(/andregaming\.galleon\.co\.za/gi, 'workstation01.example.com');
            res = res.replace(/Macmini\.galleon\.co\.za/gi, 'macmini01.example.com');
            res = res.replace(/debianserver\.galleon\.co\.za/gi, 'srv-deb01.example.com');
            res = res.replace(/galleonprintsrv\.galleon\.co\.za/gi, 'printer01.example.com');
            res = res.replace(/galleonwds\.galleon\.co\.za/gi, 'wds01.example.com');
            res = res.replace(/AndreiPhone16e\.galleon\.co\.za/gi, 'iphone01.example.com');
            res = res.replace(/[a-z0-9_.-]+\.galleon\.co\.za/gi, 'service.example.com');
            res = res.replace(/galleon\.co\.za/gi, 'example.com');
            res = res.replace(/galleon\s*beach/gi, 'Internal ACME Root CA');
            res = res.replace(/galleon/gi, 'Example Security Corp');
            res = res.replace(/\bandregaming\b/gi, 'workstation-dev-01');
            res = res.replace(/\bagreylin\b/gi, 'mac-mini-office');
            res = res.replace(/\bdebianserver\b/gi, 'srv-debian-prod');
            res = res.replace(/\bgalleonprintsrv\b/gi, 'corp-print-server');
            res = res.replace(/\bgalleonwds\b/gi, 'win-wds-deploy');
            res = res.replace(/\bAndreiPhone16e\b/gi, 'executive-iphone-16');

            // 2. Obfuscate Location & Subject Distinguished Name (DN) fields
            res = res.replace(/Cape Town/gi, 'San Francisco');
            res = res.replace(/Western Cape/gi, 'California');
            res = res.replace(/\bZA\b/g, 'US');

            // If Subject DN string contains sanitized terms, format cleanly
            if (res.includes('San Francisco') && res.includes('California') && (res.includes('CN=') || res.includes('L='))) {
                res = 'CN=Internal ACME Root CA, O=Example Security Corp, OU=Security Operations, L=San Francisco, ST=California, C=US';
            }

            // 3. Obfuscate any email addresses
            res = res.replace(emailRegex, (match) => {
                if (match.includes('example.com') || match.includes('example.org')) return match;
                return 'admin@example.com';
            });
            
            return res;
        }

        // Walk DOM nodes
        function walk(node) {
            if (node.nodeType === Node.TEXT_NODE) {
                const updated = sanitizeText(node.nodeValue);
                if (updated !== node.nodeValue) {
                    node.nodeValue = updated;
                }
            } else if (node.nodeType === Node.ELEMENT_NODE) {
                if (node.tagName === 'INPUT' || node.tagName === 'TEXTAREA') {
                    if (node.value) node.value = sanitizeText(node.value);
                }
                if (node.hasAttribute('title')) {
                    node.setAttribute('title', sanitizeText(node.getAttribute('title')));
                }
                for (let child of node.childNodes) {
                    walk(child);
                }
            }
        }
        
        walk(document.body);

        // Sanitize PEM viewer block if present on CA details screen
        const pemElem = document.getElementById('pemCode');
        if (pemElem) {
            pemElem.textContent = 
`-----BEGIN CERTIFICATE-----
MIIEczCCA1ugAwIBAgIUQ4hO7qB0h1P9Y7h8m0xX+R1a5qYwDQYJKoZIhvcNAQEL
BQAwYjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT
DVNhbiBGcmFuY2lzY28xHzAdBgNVBAoTFkV4YW1wbGUgU2VjdXJpdHkgQ29ycDEe
... [SAMPLE BASE64 ENCODED ROOT CA CERTIFICATE] ...
a1Z9L2N4m9O0P1qR2sT3uV4wX5yZ6a7b8c9d0e1f2g3h4i5j6k7l8m9n0o1p2q==
-----END CERTIFICATE-----`;
        }
    }"""
    try:
        await page.evaluate(js_code)
    except Exception as e:
        print(f"    Notice: DOM obfuscation error: {e}")


async def capture_all_screens(base_url: str, output_dir: Path, admin_user: str = 'admin', obfuscate: bool = True):
    output_dir.mkdir(parents=True, exist_ok=True)
    token, _ = create_session_cookie(admin_user, remember_me=True)

    loader = jinja2.FileSystemLoader(str(TEMPLATES_DIR))
    env = jinja2.Environment(loader=loader, enable_async=True)
    env.filters['format_datetime'] = lambda dt, fmt='%Y-%m-%d %H:%M': dt.strftime(fmt) if hasattr(dt, 'strftime') else str(dt or '')
    env.filters['to_local'] = lambda dt: dt
    env.filters['local_isoformat'] = lambda dt: dt.isoformat() if hasattr(dt, 'isoformat') else str(dt or '')

    default_params = {
        'app_title': 'ACME CA Server',
        'app_version': 'v1.0.6',
        'is_authenticated': False,
        'current_user': None,
        'active_tab': '',
        'service_tz_label': 'Local',
        'service_tz_name': 'Local',
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)

        # -------------------------------------------------------------
        # 1. Unauthenticated Context (Login & First-Boot Onboarding)
        # -------------------------------------------------------------
        context_guest = await browser.new_context(
            viewport={'width': 1440, 'height': 900},
            device_scale_factor=1.5
        )
        page_guest = await context_guest.new_page()

        # 01: Login Screen
        print("--> Capturing 01_login_screen.png...")
        try:
            await page_guest.goto(f"{base_url}/login", wait_until='networkidle', timeout=3000)
            if obfuscate:
                await obfuscate_page(page_guest)
            await page_guest.screenshot(path=str(output_dir / "01_login_screen.png"), full_page=False)
        except Exception as e:
            print(f"    Warning: Could not fetch {base_url}/login: {e}")
            await page_guest.close()
            page_guest = await context_guest.new_page()

        # 02: Admin Setup / Onboarding
        print("--> Capturing 02_admin_setup_onboarding.png...")
        try:
            setup_template = env.get_template('setup.html')
            setup_html = await setup_template.render_async(
                **default_params,
                request=MockRequest('/setup'),
                error='',
                status_msg=''
            )
            await page_guest.set_content(setup_html, wait_until='networkidle')
            if obfuscate:
                await obfuscate_page(page_guest)
            await page_guest.screenshot(path=str(output_dir / "02_admin_setup_onboarding.png"), full_page=False)
        except Exception as e:
            print(f"    Warning: Could not render setup.html: {e}")

        # 03: Root CA Certificate Setup / Onboarding
        print("--> Capturing 03_ca_certificate_onboarding.png...")
        try:
            ca_setup_template = env.get_template('ca-setup.html')
            ca_params = dict(default_params)
            ca_params.update({
                'is_authenticated': True,
                'current_user': admin_user,
                'active_tab': 'ca',
                'request': MockRequest('/ca/setup'),
                'error': '',
                'status_msg': '',
                'form_data': {
                    'common_name': 'ACME Root CA',
                    'organization': 'Example Security Corp',
                    'organizational_unit': 'Security Operations',
                    'country': 'US',
                    'state': 'California',
                    'locality': 'San Francisco',
                    'key_type': 'RSA',
                    'key_size_or_curve': '4096',
                    'digest_algorithm': 'SHA-384',
                    'validity_years': 10,
                }
            })
            ca_setup_html = await ca_setup_template.render_async(**ca_params)
            await page_guest.set_content(ca_setup_html, wait_until='networkidle')
            if obfuscate:
                await obfuscate_page(page_guest)
            await page_guest.screenshot(path=str(output_dir / "03_ca_certificate_onboarding.png"), full_page=False)
        except Exception as e:
            print(f"    Warning: Could not render ca-setup.html: {e}")

        await context_guest.close()

        # -------------------------------------------------------------
        # 2. Authenticated Context (Dashboard, CA, Certs, Domains, Accounts)
        # -------------------------------------------------------------
        context_auth = await browser.new_context(
            viewport={'width': 1440, 'height': 920},
            device_scale_factor=1.5
        )
        # Set session cookie for authenticated views across target hostname, localhost, and 127.0.0.1
        cookie_host = urlparse(base_url).hostname or 'localhost'
        target_domains = {cookie_host, 'localhost', '127.0.0.1'}
        for domain_name in target_domains:
            await context_auth.add_cookies([{
                'name': 'acme_session',
                'value': token,
                'domain': domain_name,
                'path': '/',
                'httpOnly': True,
                'sameSite': 'Lax'
            }])
        page_auth = await context_auth.new_page()

        # 04: Home Dashboard
        print("--> Capturing 04_home_dashboard.png...")
        try:
            await page_auth.goto(f"{base_url}/", wait_until='networkidle')
            if obfuscate:
                await obfuscate_page(page_auth)
            await page_auth.screenshot(path=str(output_dir / "04_home_dashboard.png"), full_page=False)
        except Exception as e:
            print(f"    Warning: Could not capture dashboard: {e}")

        # 05: Root CA Certificate Details (40% / 60% layout)
        print("--> Capturing 05_ca_certificate.png...")
        try:
            await page_auth.goto(f"{base_url}/ca", wait_until='networkidle')
            if obfuscate:
                await obfuscate_page(page_auth)
            await page_auth.screenshot(path=str(output_dir / "05_ca_certificate.png"), full_page=False)
        except Exception as e:
            print(f"    Warning: Could not capture CA details: {e}")

        # 06: Certificates Log
        print("--> Capturing 06_certificates_log.png...")
        try:
            await page_auth.goto(f"{base_url}/certificates?certstatus=all", wait_until='networkidle')
            chk_boxes = page_auth.locator('.cert-select-chk')
            if await chk_boxes.count() >= 2:
                await chk_boxes.nth(0).check()
                await chk_boxes.nth(1).check()
                await asyncio.sleep(0.4)
            if obfuscate:
                await obfuscate_page(page_auth)
            await page_auth.screenshot(path=str(output_dir / "06_certificates_log.png"), full_page=False)
        except Exception as e:
            print(f"    Warning: Could not capture certificates: {e}")

        # 06b: Certificate Details & Capability Inspection Modal
        print("--> Capturing 06b_certificate_details_modal.png...")
        try:
            details_btn = page_auth.locator(".open-details-modal").first
            if await details_btn.count() > 0:
                await details_btn.click()
                await page_auth.wait_for_selector("#modalCertContent", state='visible', timeout=5000)
                await asyncio.sleep(0.5)
                if obfuscate:
                    await obfuscate_page(page_auth)
                await page_auth.screenshot(path=str(output_dir / "06b_certificate_details_modal.png"), full_page=False)
                print("    Certificate details modal captured successfully!")
                # Dismiss modal
                close_btn = page_auth.locator("#cert-details-close-btn")
                if await close_btn.count() > 0:
                    await close_btn.click()
                    await asyncio.sleep(0.3)
            else:
                print("    Notice: No details button found on certificates page.")
        except Exception as e:
            print(f"    Warning: Could not capture certificate details modal: {e}")

        # 07: Domains Log
        print("--> Capturing 07_domains_log.png...")
        try:
            await page_auth.goto(f"{base_url}/domains", wait_until='networkidle')
            if obfuscate:
                await obfuscate_page(page_auth)
            await page_auth.screenshot(path=str(output_dir / "07_domains_log.png"), full_page=False)
        except Exception as e:
            print(f"    Warning: Could not capture domains: {e}")

        # 08: Accounts Log
        print("--> Capturing 08_accounts_log.png...")
        try:
            await page_auth.goto(f"{base_url}/accounts", wait_until='networkidle')
            if obfuscate:
                await obfuscate_page(page_auth)
            await page_auth.screenshot(path=str(output_dir / "08_accounts_log.png"), full_page=False)
        except Exception as e:
            print(f"    Warning: Could not capture accounts: {e}")

        # 09: Account Orders & Error Details Modal
        print("--> Capturing 09_account_orders_modal.png...")
        try:
            orders_btn = page_auth.locator("button.btn-action-outline:has-text('Orders'), .pill-order-error").first
            if await orders_btn.count() > 0:
                await orders_btn.click()
                await page_auth.wait_for_selector("#orderModal.open", timeout=3000)
                await asyncio.sleep(0.5)  # Allow smooth fade-in
                chk_boxes = page_auth.locator('.order-select-chk:not(:disabled)')
                if await chk_boxes.count() > 0:
                    await chk_boxes.first.check()
                    await asyncio.sleep(0.3)
                if obfuscate:
                    await obfuscate_page(page_auth)
                await page_auth.screenshot(path=str(output_dir / "09_account_orders_modal.png"), full_page=False)
                print("    Modal captured successfully!")
            else:
                print("    Notice: No orders button found on accounts page.")
        except Exception as e:
            print(f"    Warning: Could not capture orders modal: {e}")

        # 10: Mail Settings (in-memory mock preview to prevent database pollution)
        print("--> Capturing 10_mail_settings.png...")
        try:
            mail_template = env.get_template('mail-settings.html')
            sample_cfg = {
                'enabled': True,
                'host': 'smtp.example.org',
                'port': 587,
                'username': 'smtp-operator',
                'password': '••••••••••••',
                'encryption': 'starttls',
                'sender': 'acme-notifications@example.org',
                'notify_on_account_creation': True,
                'warn_before_cert_expires_days': 20,
                'notify_when_cert_expired': True,
            }
            mail_params = dict(default_params)
            mail_params.update({
                'is_authenticated': True,
                'current_user': admin_user,
                'request': MockRequest('/mail', admin_user),
                'mail_cfg': sample_cfg,
                'error': '',
                'status_msg': '',
            })
            mail_html = await mail_template.render_async(**mail_params)
            await page_auth.set_content(mail_html, wait_until='networkidle')
            if obfuscate:
                await obfuscate_page(page_auth)
            await page_auth.screenshot(path=str(output_dir / "10_mail_settings.png"), full_page=False)
        except Exception as e:
            print(f"    Warning: Could not capture mail settings: {e}")

        # 11: Users & Access
        print("--> Capturing 11_users_and_access.png...")
        try:
            captured = False
            try:
                resp = await page_auth.goto(f"{base_url}/users", wait_until='networkidle', timeout=3000)
                if resp and resp.status == 200:
                    captured = True
            except Exception:
                captured = False

            if not captured:
                users_template = env.get_template('users.html')
                sample_users = [
                    {
                        'id': 'u-1',
                        'username': 'admin',
                        'email': 'admin@example.com',
                        'user_type': 'local',
                        'created_at': datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc),
                        'last_login_at': datetime(2026, 10, 19, 22, 15, tzinfo=timezone.utc),
                    },
                    {
                        'id': 'u-2',
                        'username': 'secops-operator',
                        'email': 'secops@example.com',
                        'user_type': 'local',
                        'created_at': datetime(2026, 10, 5, 14, 30, tzinfo=timezone.utc),
                        'last_login_at': datetime(2026, 10, 18, 9, 20, tzinfo=timezone.utc),
                    },
                    {
                        'id': 'u-3',
                        'username': 'johndoe',
                        'email': 'johndoe@example.com',
                        'user_type': 'oidc',
                        'created_at': datetime(2026, 10, 12, 11, 45, tzinfo=timezone.utc),
                        'last_login_at': datetime(2026, 10, 19, 16, 50, tzinfo=timezone.utc),
                    },
                ]
                users_params = dict(default_params)
                users_params.update({
                    'is_authenticated': True,
                    'current_user': admin_user,
                    'request': MockRequest('/users', admin_user),
                    'users': sample_users,
                    'error': '',
                    'success': '',
                })
                users_html = await users_template.render_async(**users_params)
                await page_auth.set_content(users_html, wait_until='networkidle')

            if obfuscate:
                await obfuscate_page(page_auth)
            await page_auth.screenshot(path=str(output_dir / "11_users_and_access.png"), full_page=False)
            print("    Users & Access captured successfully!")
        except Exception as e:
            print(f"    Warning: Could not capture users and access: {e}")

        # 12: CA Certificate Distribution Hub
        print("--> Capturing 12_ca_distribution.png...")
        try:
            captured = False
            try:
                resp = await page_auth.goto(f"{base_url}/ca-distribution", wait_until='networkidle', timeout=3000)
                if resp and resp.status == 200:
                    captured = True
            except Exception:
                captured = False

            if not captured:
                import ca.distribution as ca_dist
                sample_ssh = [
                    ca_dist.Endpoint(
                        id='ep-01', name='Ubuntu Web Cluster', type='ssh', host='web01.example.org', port=22,
                        username='deploy', auth_type='key', target_dir='/usr/local/share/ca-certificates',
                        target_os_list=['linux'], detected_os='linux', os_detail='Ubuntu 24.04 LTS (Noble Numbat)',
                        last_test_at=datetime(2026, 10, 19, 20, 15, tzinfo=timezone.utc), last_test_status=True,
                        last_test_message='SSH connection successful. SFTP directory writable.', has_secret=True,
                    ),
                    ca_dist.Endpoint(
                        id='ep-02', name='Core OpenWrt Router', type='ssh', host='192.168.1.1', port=22,
                        username='root', auth_type='key', target_dir='/etc/ssl/certs',
                        target_os_list=['openwrt'], detected_os='openwrt', os_detail='OpenWrt 23.05.2 (r23630-9429070123)',
                        last_test_at=datetime(2026, 10, 19, 21, 30, tzinfo=timezone.utc), last_test_status=True,
                        last_test_message='SSH connection successful. Ready for automated CA installation.', has_secret=True,
                    ),
                    ca_dist.Endpoint(
                        id='ep-03', name='Active Directory WinServer', type='ssh', host='dc01.example.org', port=22,
                        username='Administrator', auth_type='password', target_dir='C:\\ProgramData\\Certificates',
                        target_os_list=['windows'], detected_os='windows', os_detail='Windows Server 2022 Datacenter (10.0.20348)',
                        last_test_at=datetime(2026, 10, 19, 22, 10, tzinfo=timezone.utc), last_test_status=True,
                        last_test_message='SSH connection and PowerShell execution verified.', has_secret=True,
                    ),
                ]
                sample_email = [
                    ca_dist.Endpoint(
                        id='ep-04', name='SecOps & IT Administrators', type='email',
                        email_addresses=['secops@example.com', 'it-alerts@example.com'],
                        target_os_list=['linux', 'windows', 'macos', 'ios', 'android'],
                        last_test_at=datetime(2026, 10, 19, 19, 45, tzinfo=timezone.utc), last_test_status=True,
                        last_test_message='2 valid recipient(s). Outbound SMTP ready.',
                    ),
                ]
                sample_logs = [
                    {
                        'id': 'log-1', 'ca_serial': '7A1EC5392C74', 'endpoint_id': 'ep-01', 'endpoint_name': 'Ubuntu Web Cluster',
                        'endpoint_type': 'ssh', 'filename': 'AcmeCorp_20261019.crt', 'status': 'ok',
                        'status_message': 'Uploaded AcmeCorp_20261019.crt, .pem, .cer and README.txt. update-ca-certificates verified.',
                        'distributed_at': datetime(2026, 10, 19, 23, 10, tzinfo=timezone.utc),
                    },
                    {
                        'id': 'log-2', 'ca_serial': '7A1EC5392C74', 'endpoint_id': 'ep-02', 'endpoint_name': 'Core OpenWrt Router',
                        'endpoint_type': 'ssh', 'filename': 'AcmeCorp_20261019.crt', 'status': 'ok',
                        'status_message': 'Uploaded certificates to /etc/ssl/certs/ with OpenWrt deployment script.',
                        'distributed_at': datetime(2026, 10, 19, 23, 12, tzinfo=timezone.utc),
                    },
                    {
                        'id': 'log-3', 'ca_serial': '7A1EC5392C74', 'endpoint_id': 'ep-04', 'endpoint_name': 'SecOps & IT Administrators',
                        'endpoint_type': 'email', 'filename': 'AcmeCorp_20261019', 'status': 'ok',
                        'status_message': 'Email successfully sent to 2 recipient(s) with .crt, .pem, and .cer attachments.',
                        'distributed_at': datetime(2026, 10, 19, 23, 15, tzinfo=timezone.utc),
                    },
                ]
                dist_template = env.get_template('ca-distribution.html')
                dist_params = dict(default_params)
                dist_params.update({
                    'is_authenticated': True,
                    'current_user': admin_user,
                    'request': MockRequest('/ca-distribution', admin_user),
                    'active_tab': 'ssh',
                    'ssh_endpoints': sample_ssh,
                    'email_endpoints': sample_email,
                    'logs': sample_logs,
                    'error': '',
                    'status_msg': '',
                })
                dist_html = await dist_template.render_async(**dist_params)
                await page_auth.set_content(dist_html, wait_until='networkidle')

            if obfuscate:
                await obfuscate_page(page_auth)
            await page_auth.screenshot(path=str(output_dir / "12_ca_distribution.png"), full_page=False)
            print("    CA Certificate Distribution Hub captured successfully!")
        except Exception as e:
            print(f"    Warning: Could not capture CA distribution hub: {e}")

        # 12b: Root CA Certificate Distribution & Deployment Modal
        print("--> Capturing 12b_ca_distribution_modal.png...")
        try:
            captured = False
            try:
                resp = await page_auth.goto(f"{base_url}/ca", wait_until='networkidle', timeout=3000)
                if resp and resp.status == 200:
                    dist_btn = page_auth.locator(".btn-action-distribute, button:has-text('Distribute')").first
                    if await dist_btn.count() > 0:
                        await dist_btn.click()
                        await page_auth.wait_for_selector("#distributeModal", state='visible', timeout=3000)
                        await asyncio.sleep(0.4)
                        chks = page_auth.locator(".dist-endpoint-chk")
                        if await chks.count() > 0:
                            await chks.first.check()
                        captured = True
            except Exception:
                captured = False

            if not captured:
                ca_template = env.get_template('ca-details.html')
                ca_mock = {
                    'serial_number': '7A1EC5392C74',
                    'common_name': 'ACME Root CA',
                    'subject': 'CN=ACME Root CA, O=Example Security Corp, C=US',
                    'not_valid_before': '2026-10-01 00:00:00',
                    'not_valid_after': '2036-10-01 00:00:00',
                    'days_remaining': 3632,
                    'validity_pct': 99,
                    'key_type': 'RSA',
                    'key_size_or_curve': '4096-bit',
                    'digest_algorithm': 'SHA-256',
                    'fingerprint_sha256': 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855',
                    'cert_pem': '-----BEGIN CERTIFICATE-----\nMIIEczCCA1ugAwIBAgIUQ4hO7qB0h1P9Y7h8m0xX+R1a5qYwDQYJKoZIhvcNAQEL\n... [SAMPLE ROOT CA CERTIFICATE] ...\n-----END CERTIFICATE-----',
                    'is_active': True,
                    'active_certs_count': 42,
                    'x509_strict': {
                        'is_compliant': True,
                        'badge_class': 'strict-compliant',
                        'badge_text': 'X.509 Strict Compliant',
                        'home_badge_text': 'Strict',
                        'summary': 'All RFC 5280 and OpenSSL strict profile requirements are satisfied.',
                        'issues': [],
                        'checks': [],
                    },
                }
                ca_params = dict(default_params)
                ca_params.update({
                    'is_authenticated': True,
                    'current_user': admin_user,
                    'request': MockRequest('/ca', admin_user),
                    'ca': ca_mock,
                    'all_cas': [ca_mock],
                    'renew_form': {
                        'common_name': 'ACME Root CA',
                        'organization': 'Example Security Corp',
                        'organizational_unit': 'Security Operations',
                        'country': 'US',
                        'key_type': 'RSA',
                        'key_size_or_curve': '4096',
                        'digest_algorithm': 'SHA-256',
                    },
                    'error': '',
                    'status_msg': '',
                })
                ca_html = await ca_template.render_async(**ca_params)
                await page_auth.set_content(ca_html, wait_until='networkidle')
                # Inject sample endpoints into modal table and open modal
                js_populate_modal = """() => {
                    const modal = document.getElementById('distributeModal');
                    if (modal) {
                        modal.style.display = 'flex';
                        const body = document.getElementById('distributeEndpointsBody');
                        if (body) {
                            body.innerHTML = `
                                <tr>
                                    <td style="width: 36px; text-align: center;"><input type="checkbox" class="dist-endpoint-chk" checked></td>
                                    <td><strong>Ubuntu Web Cluster</strong></td>
                                    <td><span class="badge-type badge-type-local">SSH</span></td>
                                    <td><code>web01.example.org:22</code></td>
                                    <td><span style="font-family: monospace; font-size: 0.8rem;">/usr/local/share/ca-certificates</span></td>
                                    <td><span class="badge badge-valid">Ready</span></td>
                                </tr>
                                <tr>
                                    <td style="width: 36px; text-align: center;"><input type="checkbox" class="dist-endpoint-chk" checked></td>
                                    <td><strong>Core OpenWrt Router</strong></td>
                                    <td><span class="badge-type badge-type-local">SSH</span></td>
                                    <td><code>192.168.1.1:22</code></td>
                                    <td><span style="font-family: monospace; font-size: 0.8rem;">/etc/ssl/certs</span></td>
                                    <td><span class="badge badge-valid">Ready</span></td>
                                </tr>
                                <tr>
                                    <td style="width: 36px; text-align: center;"><input type="checkbox" class="dist-endpoint-chk"></td>
                                    <td><strong>SecOps & IT Administrators</strong></td>
                                    <td><span class="badge-type badge-type-oidc">Email</span></td>
                                    <td><code>2 Recipients</code></td>
                                    <td><span style="color: var(--text-muted); font-size: 0.8rem;">Inbox (.crt/.pem/.cer)</span></td>
                                    <td><span class="badge badge-valid">Ready</span></td>
                                </tr>
                            `;
                        }
                        const countSpan = document.getElementById('distributeSelectedCount');
                        if (countSpan) countSpan.textContent = '2';
                    }
                }"""
                await page_auth.evaluate(js_populate_modal)
                await asyncio.sleep(0.3)

            if obfuscate:
                await obfuscate_page(page_auth)
            await page_auth.screenshot(path=str(output_dir / "12b_ca_distribution_modal.png"), full_page=False)
            print("    Root CA Certificate Distribution Modal captured successfully!")
        except Exception as e:
            print(f"    Warning: Could not capture CA distribution modal: {e}")

        # 13: CA Fleet Trust & Compliance Audit
        print("--> Capturing 13_ca_fleet_trust.png...")
        try:
            captured = False
            try:
                resp = await page_auth.goto(f"{base_url}/ca-fleet-trust", wait_until='networkidle', timeout=4000)
                if resp and resp.status == 200:
                    captured = True
            except Exception:
                captured = False

            if not captured:
                fleet_template = env.get_template('ca-fleet-trust.html')
                fleet_params = dict(default_params)
                fleet_params.update({
                    'is_authenticated': True,
                    'current_user': admin_user,
                    'request': MockRequest('/ca-fleet-trust', admin_user),
                    'active_tab': 'fleet',
                    'stats': {
                        'total_audits': 12,
                        'compliant': 10,
                        'partial': 2,
                        'untrusted': 0,
                        'compliance_rate': 83.3,
                    },
                    'cas': [
                        {'serial_number': '7A1EC5392C74', 'cn': 'Internal ACME Root CA', 'active': True},
                        {'serial_number': '8B2FD64A3D85', 'cn': 'Standby ACME Root CA', 'active': False},
                    ],
                    'endpoints': [],
                    'audits': [
                        {
                            'id': 'aud-01',
                            'device_name': 'workstation-dev-01',
                            'ip_address': '192.168.1.101',
                            'user_agent': 'Mozilla/5.0 (X11; Linux x86_64)',
                            'os': 'linux',
                            'os_detail': 'Ubuntu 24.04 LTS',
                            'verification_method': 'tls_probe',
                            'overall_status': 'compliant',
                            'total_cas': 2,
                            'trusted_cas': 2,
                            'audited_at': datetime(2026, 10, 21, 14, 20, tzinfo=timezone.utc),
                            'results': [
                                {'ca_serial': '7A1EC5392C74', 'ca_cn': 'Internal ACME Root CA', 'is_trusted': True, 'details': 'TLS probe handshake successful (Port 9443)'},
                                {'ca_serial': '8B2FD64A3D85', 'ca_cn': 'Standby ACME Root CA', 'is_trusted': True, 'details': 'TLS probe handshake successful (Port 9444)'},
                            ],
                        },
                        {
                            'id': 'aud-02',
                            'device_name': 'core-openwrt-router',
                            'ip_address': '192.168.1.1',
                            'user_agent': 'uclient-fetch/OpenWrt',
                            'os': 'openwrt',
                            'os_detail': 'OpenWrt 23.05.2',
                            'verification_method': 'ssh_sweep',
                            'overall_status': 'compliant',
                            'total_cas': 2,
                            'trusted_cas': 2,
                            'audited_at': datetime(2026, 10, 21, 14, 15, tzinfo=timezone.utc),
                            'results': [
                                {'ca_serial': '7A1EC5392C74', 'ca_cn': 'Internal ACME Root CA', 'is_trusted': True, 'details': 'Certificate verified in /etc/ssl/certs/'},
                                {'ca_serial': '8B2FD64A3D85', 'ca_cn': 'Standby ACME Root CA', 'is_trusted': True, 'details': 'Certificate verified in /etc/ssl/certs/'},
                            ],
                        },
                        {
                            'id': 'aud-03',
                            'device_name': 'win-wds-deploy',
                            'ip_address': '192.168.1.25',
                            'user_agent': 'PowerShell/7.4.1',
                            'os': 'windows',
                            'os_detail': 'Windows Server 2022',
                            'verification_method': 'ssh_sweep',
                            'overall_status': 'partial',
                            'total_cas': 2,
                            'trusted_cas': 1,
                            'audited_at': datetime(2026, 10, 21, 13, 50, tzinfo=timezone.utc),
                            'results': [
                                {'ca_serial': '7A1EC5392C74', 'ca_cn': 'Internal ACME Root CA', 'is_trusted': True, 'details': 'Installed in Root store'},
                                {'ca_serial': '8B2FD64A3D85', 'ca_cn': 'Standby ACME Root CA', 'is_trusted': False, 'details': 'Not found in Root store'},
                            ],
                        },
                        {
                            'id': 'aud-04',
                            'device_name': 'mac-mini-office',
                            'ip_address': '192.168.1.42',
                            'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
                            'os': 'macos',
                            'os_detail': 'Apple macOS 14.5 (Sonoma)',
                            'verification_method': 'browser',
                            'overall_status': 'compliant',
                            'total_cas': 2,
                            'trusted_cas': 2,
                            'audited_at': datetime(2026, 10, 21, 13, 30, tzinfo=timezone.utc),
                            'results': [
                                {'ca_serial': '7A1EC5392C74', 'ca_cn': 'Internal ACME Root CA', 'is_trusted': True, 'details': 'Browser probe verified'},
                                {'ca_serial': '8B2FD64A3D85', 'ca_cn': 'Standby ACME Root CA', 'is_trusted': True, 'details': 'Browser probe verified'},
                            ],
                        },
                    ],
                    'audits_json': '[]',
                    'search': '',
                    'selected_ca': '',
                    'selected_status': 'all',
                    'selected_os': 'all',
                    'status_msg': '',
                    'error': '',
                    'external_url': 'http://localhost:8080',
                })
                fleet_html = await fleet_template.render_async(**fleet_params)
                await page_auth.set_content(fleet_html, wait_until='networkidle')

            if obfuscate:
                await obfuscate_page(page_auth)
            await page_auth.screenshot(path=str(output_dir / "13_ca_fleet_trust.png"), full_page=False)
            print("    CA Fleet Trust & Compliance Audit captured successfully!")
        except Exception as e:
            print(f"    Warning: Could not capture CA fleet trust: {e}")

        # 13b: CA Fleet Trust - CLI Probe & Manual Diagnostics Modal
        print("--> Capturing 13b_ca_fleet_trust_cli_modal.png...")
        try:
            cli_btn = page_auth.locator("#openCliProbeModal")
            if await cli_btn.count() > 0:
                await cli_btn.click()
                await page_auth.wait_for_selector("#cliProbeModal", state='visible', timeout=3000)
                await asyncio.sleep(0.4)
                if obfuscate:
                    await obfuscate_page(page_auth)
                await page_auth.screenshot(path=str(output_dir / "13b_ca_fleet_trust_cli_modal.png"), full_page=False)
                print("    CA Fleet Trust CLI Probe Modal captured successfully!")
                close_btn = page_auth.locator("#cliProbeModal .modal-close-btn, #cliProbeModal button:has-text('Close')").first
                if await close_btn.count() > 0:
                    await close_btn.click()
                    await asyncio.sleep(0.3)
            else:
                print("    Notice: #openCliProbeModal button not found on fleet trust page.")
        except Exception as e:
            print(f"    Warning: Could not capture CLI probe modal: {e}")

        # 14: Client Root CA Trust Verification Portal
        print("--> Capturing 14_ca_trust_verify.png...")
        try:
            context_verify = await browser.new_context(
                viewport={'width': 1440, 'height': 920},
                device_scale_factor=1.5
            )
            page_verify = await context_verify.new_page()
            captured = False
            try:
                resp = await page_verify.goto(f"{base_url}/ca-trust/verify", wait_until='networkidle', timeout=4000)
                if resp and resp.status == 200:
                    captured = True
                    await asyncio.sleep(0.6)
            except Exception:
                captured = False

            if not captured:
                verify_template = env.get_template('ca-trust-verify.html')
                verify_params = dict(default_params)
                verify_params.update({
                    'request': MockRequest('/ca-trust/verify'),
                    'cas': [
                        {
                            'serial_number': '7A1EC5392C74',
                            'cn': 'Internal ACME Root CA',
                            'active': True,
                            'fingerprint_sha256': 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855',
                        },
                        {
                            'serial_number': '8B2FD64A3D85',
                            'cn': 'Standby ACME Root CA',
                            'active': False,
                            'fingerprint_sha256': 'F4C1D553A9FD2D250BCCF5D9AA7FC03538BF52F575AC045DB506AA2C8963C966',
                        },
                    ],
                    'cas_json': json.dumps([
                        {
                            'serial_number': '7A1EC5392C74',
                            'cn': 'Internal ACME Root CA',
                            'active': True,
                            'fingerprint_sha256': 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855',
                        },
                    ]),
                    'probe_endpoints': [
                        {'ca_serial': '7A1EC5392C74', 'port': 9443, 'host': 'localhost'},
                    ],
                    'probe_endpoints_json': json.dumps([
                        {'ca_serial': '7A1EC5392C74', 'port': 9443, 'host': 'localhost'},
                    ]),
                    'probe_base_port': 9443,
                    'endpoint_id': '',
                    'client_ip': '192.168.1.101',
                    'prefill_device_name': 'workstation-dev-01',
                })
                verify_html = await verify_template.render_async(**verify_params)
                await page_verify.set_content(verify_html, wait_until='networkidle')

            if obfuscate:
                await obfuscate_page(page_verify)
            await page_verify.screenshot(path=str(output_dir / "14_ca_trust_verify.png"), full_page=False)
            print("    Client Root CA Trust Verification Portal captured successfully!")
            await context_verify.close()
        except Exception as e:
            print(f"    Warning: Could not capture CA trust verification portal: {e}")

        await context_auth.close()
        await browser.close()
        print(f"Done! All screenshots saved to: {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="Automated UI screen capture utility for ACME CA Server")
    parser.add_argument(
        '--base-url',
        default=os.environ.get('EXTERNAL_URL', 'http://localhost:8080'),
        help="Base URL of running server (default: %(default)s)"
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Target folder for saved images (default: %(default)s)"
    )
    parser.add_argument(
        '--admin-user',
        default='admin',
        help="Admin username for session authentication (default: %(default)s)"
    )
    parser.add_argument(
        '--no-obfuscate',
        action='store_true',
        help="Disable automatic obfuscation of domain names, emails, and DN fields"
    )
    args = parser.parse_args()

    asyncio.run(capture_all_screens(args.base_url, args.output_dir, args.admin_user, obfuscate=not args.no_obfuscate))


if __name__ == '__main__':
    main()
