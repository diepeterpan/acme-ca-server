import secrets

import db
import pytest
from config import settings
from db.integrity import (
    Discrepancy,
    IntegrityAuditReport,
    _extract_domains_from_cert,
    _generate_dummy_jwk,
    _generate_random_id,
    apply_repairs,
    inspect_database,
    prompt_for_repair,
    render_report_to_terminal,
)


def test_helpers():
    """Verify ID generation, JWK generation, and domain extraction."""
    rand_id = _generate_random_id('test_prefix')
    assert len(rand_id) > 20
    assert rand_id.startswith('test_prefix_')

    jwk = _generate_dummy_jwk('test_account_123')
    assert jwk['kty'] == 'RSA'
    assert 'test_account_123' in jwk['n']
    assert jwk.get('dummy_corrected') is True

    # Test domain extraction fallback
    domains = _extract_domains_from_cert('invalid-cert-content')
    assert domains == ['unknown.domain.local']


def test_render_report(capsys):
    """Verify terminal report rendering with and without discrepancies."""
    # Clean report
    clean_report = IntegrityAuditReport()
    clean_report.add_passed('All orders valid.')
    render_report_to_terminal(clean_report)
    captured = capsys.readouterr()
    assert 'DATABASE INTEGRITY AUDIT' in captured.out
    assert '0 integrity issues detected' in captured.out

    # Report with discrepancies
    dirty_report = IntegrityAuditReport()
    dirty_report.add_discrepancy(
        Discrepancy(
            category='Referential Integrity',
            issue_type='Orphan Certificate',
            record_id='Serial: 12345678',
            details={'Missing Order ID': 'ord_missing_123456789012345'},
            action_needed='Create dummy Order',
            repair_type='orphan_certificate',
        )
    )
    render_report_to_terminal(dirty_report)
    captured = capsys.readouterr()
    assert 'DISCREPANCIES DETECTED' in captured.out
    assert 'Orphan Certificate' in captured.out
    assert 'Create dummy Order' in captured.out


@pytest.mark.asyncio
async def test_prompt_for_repair_non_tty():
    """Verify non-interactive terminal skips prompt automatically."""
    settings.db_integrity.auto_repair = False
    # In pytest, sys.stdin is not a TTY or is mocked
    res = await prompt_for_repair(timeout_seconds=1)
    assert res is False


@pytest.mark.asyncio
async def test_prompt_for_repair_auto_setting():
    """Verify auto-repair setting returns True immediately."""
    settings.db_integrity.auto_repair = True
    res = await prompt_for_repair(timeout_seconds=1)
    assert res is True
    settings.db_integrity.auto_repair = False


def test_maintenance_mode_middleware():
    """Test MaintenanceModeMiddleware behavior when active vs inactive."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from web.middleware import MaintenanceModeMiddleware

    test_app = FastAPI()
    test_app.state.maintenance_mode = False

    @test_app.get('/')
    async def index():
        return {'page': 'index'}

    @test_app.get('/acme/directory')
    async def directory():
        return {'dir': 'acme'}

    @test_app.get('/maintenance/status')
    async def status():
        return {'maintenance': False, 'status': 'ready'}

    test_app.add_middleware(MaintenanceModeMiddleware)

    with TestClient(test_app) as client:
        # 1. Normal state
        r1 = client.get('/')
        assert r1.status_code == 200

        # 2. Enable maintenance mode
        test_app.state.maintenance_mode = True

        # Browser visiting web UI gets 503 Maintenance Veil
        resp_web = client.get('/')
        assert resp_web.status_code == 503
        assert 'System Maintenance in Progress' in resp_web.text
        assert 'Maintenance Mode' in resp_web.text
        assert resp_web.headers.get('Retry-After') == '3'

        # ACME endpoint gets 503 JSON problem document
        resp_acme = client.get('/acme/directory')
        assert resp_acme.status_code == 503
        data_acme = resp_acme.json()
        assert data_acme['type'] == 'urn:ietf:params:acme:error:serverInternal'
        assert resp_acme.headers.get('Retry-After') == '5'

        # Maintenance status polling endpoint returns 503 with maintenance=True
        resp_poll = client.get('/maintenance/status')
        assert resp_poll.status_code == 503
        assert resp_poll.json()['maintenance'] is True

        # 3. Lift maintenance mode
        test_app.state.maintenance_mode = False

        # Status polling endpoint now returns 200 with maintenance=False
        resp_poll_off = client.get('/maintenance/status')
        assert resp_poll_off.status_code == 200
        assert resp_poll_off.json()['maintenance'] is False


@pytest.mark.asyncio
async def test_db_integrity_inspection_and_repair():
    """Test full database inspection and auto-repair logic against PostgreSQL."""
    # Ensure database connection is active
    await db.connect()

    async with db.transaction() as sql:
        # Create a test account
        test_acc_id = _generate_random_id('test_acc')
        test_mail = f'test-{secrets.token_hex(4)}@example.com'
        jwk = _generate_dummy_jwk(test_acc_id)
        await sql.exec(
            'INSERT INTO accounts (id, mail, jwk, status, created_at) VALUES ($1, $2, $3, $4, NOW())',
            test_acc_id,
            test_mail,
            jwk,
            'valid',
        )

        # 1. Insert a Valid Order missing Certificate
        ord_missing_cert = _generate_random_id('ord_nocert')
        await sql.exec(
            "INSERT INTO orders (id, account_id, status, expires_at) VALUES ($1, $2, 'valid', NOW() + interval '1 day')",
            ord_missing_cert,
            test_acc_id,
        )

        # 2. Insert an Expired Pending Order
        ord_expired = _generate_random_id('ord_exp')
        await sql.exec(
            "INSERT INTO orders (id, account_id, status, expires_at) VALUES ($1, $2, 'pending', NOW() - interval '2 hours')",
            ord_expired,
            test_acc_id,
        )

    # Run inspection
    report = await inspect_database()
    assert report.has_issues is True

    # Verify both issues are caught
    types = [d.issue_type for d in report.discrepancies]
    assert 'Valid Order Missing Certificate' in types
    assert 'Expired Pending Order' in types

    # Apply repairs
    repaired_count = await apply_repairs(report)
    assert repaired_count >= 2

    # Verify orders are repaired
    async with db.transaction(readonly=True) as sql:
        row1 = await sql.record('SELECT status, error FROM orders WHERE id = $1', ord_missing_cert)
        assert row1['status'] == 'invalid'

        row2 = await sql.record('SELECT status, error FROM orders WHERE id = $1', ord_expired)
        assert row2['status'] == 'invalid'

    # Clean up test records
    async with db.transaction() as sql:
        await sql.exec('DELETE FROM orders WHERE id IN ($1, $2)', ord_missing_cert, ord_expired)
        await sql.exec('DELETE FROM accounts WHERE id = $1', test_acc_id)
