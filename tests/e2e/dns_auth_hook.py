#!/usr/bin/env python3
import json
import os
import sys
import urllib.request

domain = os.environ.get('CERTBOT_DOMAIN', '').removeprefix('*.')
validation = os.environ.get('CERTBOT_VALIDATION', '')

if not domain or not validation:
    sys.exit(0)

payload = json.dumps({'domain': f'_acme-challenge.{domain}', 'value': validation}).encode('utf-8')
req = urllib.request.Request(
    'http://test_dns:8053/records',
    data=payload,
    headers={'Content-Type': 'application/json'},
    method='POST',
)
try:
    with urllib.request.urlopen(req, timeout=5):
        pass
except (urllib.error.URLError, OSError) as e:
    print(f'Error setting DNS record: {e}', file=sys.stderr)
    sys.exit(1)
