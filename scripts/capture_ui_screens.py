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
  7. Domains Registry
  8. Accounts Management
  9. Account Orders & Error Details Modal

Usage:
  python3 scripts/capture_ui_screens.py
  python3 scripts/capture_ui_screens.py --base-url http://localhost:8080 --output-dir Documentation/screenshots
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path

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


async def capture_all_screens(base_url: str, output_dir: Path, admin_user: str = 'admin'):
    output_dir.mkdir(parents=True, exist_ok=True)
    token, _ = create_session_cookie(admin_user, remember_me=True)

    loader = jinja2.FileSystemLoader(str(TEMPLATES_DIR))
    env = jinja2.Environment(loader=loader, enable_async=True)

    default_params = {
        'app_title': 'ACME CA Server',
        'is_authenticated': False,
        'current_user': None,
        'active_tab': '',
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
            await page_guest.goto(f"{base_url}/login", wait_until='networkidle')
            await page_guest.screenshot(path=str(output_dir / "01_login_screen.png"), full_page=False)
        except Exception as e:
            print(f"    Warning: Could not fetch {base_url}/login: {e}")

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
                    'organization': 'Acme Security Corp',
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
        # Set session cookie for authenticated views
        await context_auth.add_cookies([{
            'name': 'acme_session',
            'value': token,
            'domain': 'localhost',
            'path': '/',
            'httpOnly': True,
            'sameSite': 'Lax'
        }])
        page_auth = await context_auth.new_page()

        # 04: Home Dashboard
        print("--> Capturing 04_home_dashboard.png...")
        try:
            await page_auth.goto(f"{base_url}/", wait_until='networkidle')
            await page_auth.screenshot(path=str(output_dir / "04_home_dashboard.png"), full_page=False)
        except Exception as e:
            print(f"    Warning: Could not capture dashboard: {e}")

        # 05: Root CA Certificate Details (40% / 60% layout)
        print("--> Capturing 05_ca_certificate.png...")
        try:
            await page_auth.goto(f"{base_url}/ca", wait_until='networkidle')
            await page_auth.screenshot(path=str(output_dir / "05_ca_certificate.png"), full_page=False)
        except Exception as e:
            print(f"    Warning: Could not capture CA details: {e}")

        # 06: Certificates Log
        print("--> Capturing 06_certificates_log.png...")
        try:
            await page_auth.goto(f"{base_url}/certificates", wait_until='networkidle')
            await page_auth.screenshot(path=str(output_dir / "06_certificates_log.png"), full_page=False)
        except Exception as e:
            print(f"    Warning: Could not capture certificates: {e}")

        # 07: Domains Log
        print("--> Capturing 07_domains_log.png...")
        try:
            await page_auth.goto(f"{base_url}/domains", wait_until='networkidle')
            await page_auth.screenshot(path=str(output_dir / "07_domains_log.png"), full_page=False)
        except Exception as e:
            print(f"    Warning: Could not capture domains: {e}")

        # 08: Accounts Log
        print("--> Capturing 08_accounts_log.png...")
        try:
            await page_auth.goto(f"{base_url}/accounts", wait_until='networkidle')
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
                await page_auth.screenshot(path=str(output_dir / "09_account_orders_modal.png"), full_page=False)
                print("    Modal captured successfully!")
            else:
                print("    Notice: No orders button found on accounts page.")
        except Exception as e:
            print(f"    Warning: Could not capture orders modal: {e}")

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
    args = parser.parse_args()

    asyncio.run(capture_all_screens(args.base_url, args.output_dir, args.admin_user))


if __name__ == '__main__':
    main()
