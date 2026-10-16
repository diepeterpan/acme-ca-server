#!/usr/bin/env python3
import json
import os
import sys
import urllib.request

domain = os.environ.get('CERTBOT_DOMAIN', '').removeprefix('*.')
validation = os.environ.get('CERTBOT_VALIDATION', '')
if not domain:
    sys.exit(0)

payload_dict = {'domain': f'_acme-challenge.{domain}'}
if validation:
    payload_dict['value'] = validation
payload = json.dumps(payload_dict).encode('utf-8')
req = urllib.request.Request(
    'http://test_dns:8053/records',
    data=payload,
    headers={'Content-Type': 'application/json'},
    method='DELETE',
)
try:
    with urllib.request.urlopen(req, timeout=5):
        pass
except (urllib.error.URLError, OSError) as e:
    print(f'Error cleaning DNS record: {e}', file=sys.stderr)
    sys.exit(1)
