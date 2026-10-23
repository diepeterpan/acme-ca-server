# pylint: disable=duplicate-code
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import db
from ca import service as ca_service
from config import settings
from logger import logger


@dataclass
class DataManagementConfig:
    enabled: bool = True
    cron_schedule_hours: int = 24
    run_at_hour_utc: int = 2
    delete_deactivated_accounts_days: int = 28
    delete_stale_orders_days: int = 14
    delete_invalid_domains_days: int = 28
    revoke_expired_certs_days: int = 7
    delete_revoked_certs_days: int = 14
    delete_distribution_logs_days: int = 14
    delete_fleet_audits_days: int = 7
    delete_run_history_days: int = 30
    email_notification_enabled: bool = True
    notify_only_on_changes: bool = True
    admin_email: str | None = None
    last_run_at: datetime | None = None
    updated_at: datetime | None = None


_CACHED_CONFIG: DataManagementConfig | None = None


def invalidate_cache() -> None:
    global _CACHED_CONFIG  # pylint: disable=global-statement
    _CACHED_CONFIG = None


async def get_data_management_settings() -> DataManagementConfig:
    global _CACHED_CONFIG  # pylint: disable=global-statement
    if _CACHED_CONFIG is not None:
        return _CACHED_CONFIG

    async with db.transaction() as sql:
        row = await sql.record(
            """
            select
                enabled, cron_schedule_hours, run_at_hour_utc,
                delete_deactivated_accounts_days, delete_stale_orders_days,
                delete_invalid_domains_days, revoke_expired_certs_days,
                delete_revoked_certs_days, delete_distribution_logs_days,
                delete_fleet_audits_days, delete_run_history_days,
                email_notification_enabled, notify_only_on_changes,
                admin_email, last_run_at, updated_at
            from data_management_settings
            where dummy_id = 1
            """
        )

        if row:
            cfg = DataManagementConfig(
                enabled=bool(row['enabled']),
                cron_schedule_hours=int(row['cron_schedule_hours'] or 24),
                run_at_hour_utc=int(row['run_at_hour_utc'] if row['run_at_hour_utc'] is not None else 2),
                delete_deactivated_accounts_days=int(row['delete_deactivated_accounts_days'] or 0),
                delete_stale_orders_days=int(row['delete_stale_orders_days'] or 0),
                delete_invalid_domains_days=int(row['delete_invalid_domains_days'] or 0),
                revoke_expired_certs_days=int(row['revoke_expired_certs_days'] or 0),
                delete_revoked_certs_days=int(row['delete_revoked_certs_days'] or 0),
                delete_distribution_logs_days=int(row['delete_distribution_logs_days'] or 0),
                delete_fleet_audits_days=int(row['delete_fleet_audits_days'] or 0),
                delete_run_history_days=int(row['delete_run_history_days'] if row['delete_run_history_days'] is not None else 30),
                email_notification_enabled=bool(row['email_notification_enabled']),
                notify_only_on_changes=bool(row['notify_only_on_changes']),
                admin_email=row['admin_email'],
                last_run_at=row['last_run_at'],
                updated_at=row['updated_at'],
            )
        else:
            # Seed defaults from config.settings.data_mgmt (environment variables)
            env_cfg = settings.data_mgmt
            cfg = DataManagementConfig(
                enabled=bool(env_cfg.enabled),
                cron_schedule_hours=int(env_cfg.cron_schedule_hours),
                run_at_hour_utc=int(env_cfg.run_at_hour_utc),
                delete_deactivated_accounts_days=int(env_cfg.delete_deactivated_accounts_days),
                delete_stale_orders_days=int(env_cfg.delete_stale_orders_days),
                delete_invalid_domains_days=int(env_cfg.delete_invalid_domains_days),
                revoke_expired_certs_days=int(env_cfg.revoke_expired_certs_days),
                delete_revoked_certs_days=int(env_cfg.delete_revoked_certs_days),
                delete_distribution_logs_days=int(env_cfg.delete_distribution_logs_days),
                delete_fleet_audits_days=int(env_cfg.delete_fleet_audits_days),
                delete_run_history_days=int(env_cfg.delete_run_history_days),
                email_notification_enabled=bool(env_cfg.email_notification_enabled),
                notify_only_on_changes=bool(env_cfg.notify_only_on_changes),
                admin_email=env_cfg.admin_email,
                last_run_at=None,
                updated_at=datetime.now(timezone.utc),
            )
            await sql.exec(
                """
                insert into data_management_settings (
                    dummy_id, enabled, cron_schedule_hours, run_at_hour_utc,
                    delete_deactivated_accounts_days, delete_stale_orders_days,
                    delete_invalid_domains_days, revoke_expired_certs_days,
                    delete_revoked_certs_days, delete_distribution_logs_days,
                    delete_fleet_audits_days, delete_run_history_days,
                    email_notification_enabled, notify_only_on_changes,
                    admin_email, updated_at
                ) values (
                    1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, now()
                )
                on conflict (dummy_id) do nothing
                """,
                cfg.enabled,
                cfg.cron_schedule_hours,
                cfg.run_at_hour_utc,
                cfg.delete_deactivated_accounts_days,
                cfg.delete_stale_orders_days,
                cfg.delete_invalid_domains_days,
                cfg.revoke_expired_certs_days,
                cfg.delete_revoked_certs_days,
                cfg.delete_distribution_logs_days,
                cfg.delete_fleet_audits_days,
                cfg.delete_run_history_days,
                cfg.email_notification_enabled,
                cfg.notify_only_on_changes,
                cfg.admin_email,
            )

    _CACHED_CONFIG = cfg
    return cfg


async def save_data_management_settings(
    *,
    enabled: bool,
    cron_schedule_hours: int,
    run_at_hour_utc: int,
    delete_deactivated_accounts_days: int,
    delete_stale_orders_days: int,
    delete_invalid_domains_days: int,
    revoke_expired_certs_days: int,
    delete_revoked_certs_days: int,
    delete_distribution_logs_days: int,
    delete_fleet_audits_days: int,
    delete_run_history_days: int,
    email_notification_enabled: bool,
    notify_only_on_changes: bool,
    admin_email: str | None,
) -> DataManagementConfig:
    global _CACHED_CONFIG  # pylint: disable=global-statement
    clean_admin = admin_email.strip() if admin_email else None

    async with db.transaction() as sql:
        await sql.exec(
            """
            insert into data_management_settings (
                dummy_id, enabled, cron_schedule_hours, run_at_hour_utc,
                delete_deactivated_accounts_days, delete_stale_orders_days,
                delete_invalid_domains_days, revoke_expired_certs_days,
                delete_revoked_certs_days, delete_distribution_logs_days,
                delete_fleet_audits_days, delete_run_history_days,
                email_notification_enabled, notify_only_on_changes,
                admin_email, updated_at
            ) values (
                1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, now()
            )
            on conflict (dummy_id) do update set
                enabled = excluded.enabled,
                cron_schedule_hours = excluded.cron_schedule_hours,
                run_at_hour_utc = excluded.run_at_hour_utc,
                delete_deactivated_accounts_days = excluded.delete_deactivated_accounts_days,
                delete_stale_orders_days = excluded.delete_stale_orders_days,
                delete_invalid_domains_days = excluded.delete_invalid_domains_days,
                revoke_expired_certs_days = excluded.revoke_expired_certs_days,
                delete_revoked_certs_days = excluded.delete_revoked_certs_days,
                delete_distribution_logs_days = excluded.delete_distribution_logs_days,
                delete_fleet_audits_days = excluded.delete_fleet_audits_days,
                delete_run_history_days = excluded.delete_run_history_days,
                email_notification_enabled = excluded.email_notification_enabled,
                notify_only_on_changes = excluded.notify_only_on_changes,
                admin_email = excluded.admin_email,
                updated_at = now()
            """,
            enabled,
            cron_schedule_hours,
            run_at_hour_utc,
            delete_deactivated_accounts_days,
            delete_stale_orders_days,
            delete_invalid_domains_days,
            revoke_expired_certs_days,
            delete_revoked_certs_days,
            delete_distribution_logs_days,
            delete_fleet_audits_days,
            delete_run_history_days,
            email_notification_enabled,
            notify_only_on_changes,
            clean_admin,
        )

    _CACHED_CONFIG = None
    return await get_data_management_settings()


async def list_recent_runs(limit: int = 15) -> list[dict[str, Any]]:
    async with db.transaction(readonly=True) as sql:
        rows = [
            dict(r)
            async for r in sql(
                """
                select
                    id, trigger_type, started_at, completed_at,
                    status, duration_ms, total_records_affected,
                    summary_data, error_message
                from data_management_runs
                order by started_at desc
                limit $1
                """,
                limit,
            )
        ]
    return rows


async def run_data_retention(*, trigger_type: str = 'cron', dry_run: bool = False) -> dict[str, Any]:
    """Execute the configured automated clean-up rules safely and transactionally."""
    cfg = await get_data_management_settings()
    if not cfg.enabled and trigger_type == 'cron':
        logger.info('Data Management is disabled; skipping scheduled retention run.')
        return {'status': 'skipped', 'reason': 'Data Management is disabled'}

    run_id = f'dm_{secrets.token_urlsafe(20)}'
    start_time = datetime.now(timezone.utc)
    status_str = 'dry_run' if dry_run else 'running'

    # Record run start in database
    async with db.transaction() as sql:
        await sql.exec(
            """
            insert into data_management_runs (
                id, trigger_type, started_at, status
            ) values ($1, $2, $3, $4)
            """,
            run_id,
            trigger_type if not dry_run else 'dry_run',
            start_time,
            status_str,
        )

    rule_results: dict[str, dict[str, Any]] = {}
    total_affected = 0
    error_msg: str | None = None
    needs_crl_sync = False

    try:
        # Rule a: Delete Deactivated accounts after X days
        # Safeguard: Skip accounts with active valid certificates
        rule_a_days = cfg.delete_deactivated_accounts_days
        if rule_a_days > 0:
            async with db.transaction(readonly=True) as sql:
                accounts_to_purge = [
                    acc_id
                    async for (acc_id,) in sql(
                        """
                        select id from accounts
                        where status in ('deactivated', 'revoked')
                          and coalesce(deactivated_at, created_at) < now() - ($1 || ' days')::interval
                          and not exists (
                              select 1 from orders ord
                              join certificates cert on cert.order_id = ord.id
                              where ord.account_id = accounts.id
                                and cert.not_valid_after > now()
                                and cert.revoked_at is null
                          )
                        """,
                        str(rule_a_days),
                    )
                ]
            count_a = len(accounts_to_purge)
            if not dry_run and count_a > 0:
                for acc_id in accounts_to_purge:
                    async with db.transaction() as sql:
                        ord_ids = [o async for (o,) in sql('select id from orders where account_id = $1', acc_id)]
                        if ord_ids:
                            await sql.exec('delete from certificates where order_id = any($1::text[])', ord_ids)
                            await sql.exec(
                                'delete from challenges where authz_id in (select id from authorizations where order_id = any($1::text[]))',
                                ord_ids,
                            )
                            await sql.exec('delete from authorizations where order_id = any($1::text[])', ord_ids)
                            await sql.exec('delete from orders where account_id = $1', acc_id)
                        await sql.exec('delete from accounts where id = $1', acc_id)
                needs_crl_sync = True

            rule_results['rule_a_accounts'] = {
                'name': 'Deactivated Accounts',
                'threshold_days': rule_a_days,
                'count': count_a,
                'status': 'completed',
            }
            total_affected += count_a
        else:
            rule_results['rule_a_accounts'] = {'name': 'Deactivated Accounts', 'threshold_days': 0, 'count': 0, 'status': 'disabled'}

        # Rule d: Revoke Expired certificates after X days (Two-step flow: expired -> revoked)
        rule_d_days = cfg.revoke_expired_certs_days
        if rule_d_days > 0:
            async with db.transaction(readonly=True) as sql:
                expired_to_revoke = [
                    sn
                    async for (sn,) in sql(
                        """
                        select serial_number from certificates
                        where revoked_at is null
                          and not_valid_after < now() - ($1 || ' days')::interval
                        """,
                        str(rule_d_days),
                    )
                ]
            count_d = len(expired_to_revoke)
            if not dry_run and count_d > 0:
                async with db.transaction() as sql:
                    await sql.exec(
                        """
                        update certificates
                        set revoked_at = now()
                        where serial_number = any($1::text[]) and revoked_at is null
                        """,
                        expired_to_revoke,
                    )
                needs_crl_sync = True

            rule_results['rule_d_revoke_expired'] = {
                'name': 'Revoke Expired Certificates',
                'threshold_days': rule_d_days,
                'count': count_d,
                'status': 'completed',
            }
            total_affected += count_d
        else:
            rule_results['rule_d_revoke_expired'] = {'name': 'Revoke Expired Certificates', 'threshold_days': 0, 'count': 0, 'status': 'disabled'}

        # Rule e: Delete Revoked certificates after X days
        rule_e_days = cfg.delete_revoked_certs_days
        if rule_e_days > 0:
            async with db.transaction(readonly=True) as sql:
                revoked_to_delete = [
                    (sn, ord_id)
                    async for sn, ord_id in sql(
                        """
                        select serial_number, order_id from certificates
                        where revoked_at is not null
                          and revoked_at < now() - ($1 || ' days')::interval
                        """,
                        str(rule_e_days),
                    )
                ]
            count_e = len(revoked_to_delete)
            if not dry_run and count_e > 0:
                order_ids_e = list({r[1] for r in revoked_to_delete})
                serials_e = [r[0] for r in revoked_to_delete]
                async with db.transaction() as sql:
                    await sql.exec('delete from certificates where serial_number = any($1::text[])', serials_e)
                    await sql.exec(
                        'delete from challenges where authz_id in (select id from authorizations where order_id = any($1::text[]))',
                        order_ids_e,
                    )
                    await sql.exec('delete from authorizations where order_id = any($1::text[])', order_ids_e)
                    await sql.exec('delete from orders where id = any($1::text[])', order_ids_e)
                needs_crl_sync = True

            rule_results['rule_e_delete_revoked'] = {
                'name': 'Delete Revoked Certificates',
                'threshold_days': rule_e_days,
                'count': count_e,
                'status': 'completed',
            }
            total_affected += count_e
        else:
            rule_results['rule_e_delete_revoked'] = {'name': 'Delete Revoked Certificates', 'threshold_days': 0, 'count': 0, 'status': 'disabled'}

        # Rule b: Delete Orders deletable via UI after X days
        rule_b_days = cfg.delete_stale_orders_days
        if rule_b_days > 0:
            async with db.transaction(readonly=True) as sql:
                orders_to_delete = [
                    ord_id
                    async for (ord_id,) in sql(
                        """
                        select ord.id from orders ord
                        where not exists (
                            select 1 from certificates cert
                            where cert.order_id = ord.id
                              and cert.not_valid_after > now()
                              and cert.revoked_at is null
                        )
                        and (
                            exists (
                                select 1 from certificates cert
                                where cert.order_id = ord.id
                                  and (
                                      (cert.revoked_at is not null and cert.revoked_at < now() - ($1 || ' days')::interval)
                                      or (cert.revoked_at is null and cert.not_valid_after < now() - ($1 || ' days')::interval)
                                  )
                            )
                            or (
                                not exists (select 1 from certificates cert where cert.order_id = ord.id)
                                and ord.expires_at < now() - ($1 || ' days')::interval
                            )
                        )
                        """,
                        str(rule_b_days),
                    )
                ]
            count_b = len(orders_to_delete)
            if not dry_run and count_b > 0:
                async with db.transaction() as sql:
                    await sql.exec('delete from certificates where order_id = any($1::text[])', orders_to_delete)
                    await sql.exec(
                        'delete from challenges where authz_id in (select id from authorizations where order_id = any($1::text[]))',
                        orders_to_delete,
                    )
                    await sql.exec('delete from authorizations where order_id = any($1::text[])', orders_to_delete)
                    await sql.exec('delete from orders where id = any($1::text[])', orders_to_delete)
                needs_crl_sync = True

            rule_results['rule_b_orders'] = {
                'name': 'Inactive Orders',
                'threshold_days': rule_b_days,
                'count': count_b,
                'status': 'completed',
            }
            total_affected += count_b
        else:
            rule_results['rule_b_orders'] = {'name': 'Inactive Orders', 'threshold_days': 0, 'count': 0, 'status': 'disabled'}

        # Rule c: Delete Invalid domains after X days
        rule_c_days = cfg.delete_invalid_domains_days
        if rule_c_days > 0:
            async with db.transaction(readonly=True) as sql:
                domains_to_clean = [
                    dom
                    async for (dom,) in sql(
                        """
                        with domain_summary as (
                            select
                                authz.domain,
                                max(cert.not_valid_after) filter (where cert.revoked_at is null) as max_valid_nva,
                                max(coalesce(cert.revoked_at, cert.not_valid_after, ord.expires_at)) as last_activity
                            from authorizations authz
                            join orders ord on ord.id = authz.order_id
                            left join certificates cert on cert.order_id = ord.id
                            group by authz.domain
                        )
                        select domain from domain_summary
                        where (max_valid_nva is null or max_valid_nva <= now())
                          and last_activity < now() - ($1 || ' days')::interval
                        """,
                        str(rule_c_days),
                    )
                ]
            count_c = len(domains_to_clean)
            if not dry_run and count_c > 0:
                for target_domain in domains_to_clean:
                    async with db.transaction() as sql:
                        authz_rows = [
                            (a_id, o_id)
                            async for a_id, o_id in sql(
                                'select id, order_id from authorizations where domain = $1',
                                target_domain,
                            )
                        ]
                        if authz_rows:
                            auth_ids = [r[0] for r in authz_rows]
                            ord_ids = list({r[1] for r in authz_rows})
                            await sql.exec('delete from certificates where order_id = any($1::text[])', ord_ids)
                            await sql.exec('delete from challenges where authz_id = any($1::text[])', auth_ids)
                            await sql.exec('delete from authorizations where domain = $1', target_domain)
                            await sql.exec(
                                """
                                delete from orders o
                                where o.id = any($1::text[])
                                  and not exists (select 1 from authorizations a where a.order_id = o.id)
                                  and not exists (select 1 from certificates c where c.order_id = o.id)
                                """,
                                ord_ids,
                            )
                needs_crl_sync = True

            rule_results['rule_c_domains'] = {
                'name': 'Invalid Domains',
                'threshold_days': rule_c_days,
                'count': count_c,
                'status': 'completed',
            }
            total_affected += count_c
        else:
            rule_results['rule_c_domains'] = {'name': 'Invalid Domains', 'threshold_days': 0, 'count': 0, 'status': 'disabled'}

        # Rule f: Delete Distribution Log entries after X days (keep latest 1 per endpoint)
        rule_f_days = cfg.delete_distribution_logs_days
        if rule_f_days > 0:
            async with db.transaction(readonly=True) as sql:
                dist_logs_to_delete = [
                    log_id
                    async for (log_id,) in sql(
                        """
                        with ranked as (
                            select id,
                                   row_number() over (partition by coalesce(endpoint_id, endpoint_name) order by distributed_at desc) as rn
                            from ca_distribution_logs
                        )
                        select l.id
                        from ca_distribution_logs l
                        join ranked r on r.id = l.id
                        where r.rn > 1
                          and l.distributed_at < now() - ($1 || ' days')::interval
                        """,
                        str(rule_f_days),
                    )
                ]
            count_f = len(dist_logs_to_delete)
            if not dry_run and count_f > 0:
                async with db.transaction() as sql:
                    await sql.exec('delete from ca_distribution_logs where id = any($1::text[])', dist_logs_to_delete)

            rule_results['rule_f_dist_logs'] = {
                'name': 'CA Distribution Logs',
                'threshold_days': rule_f_days,
                'count': count_f,
                'status': 'completed',
            }
            total_affected += count_f
        else:
            rule_results['rule_f_dist_logs'] = {'name': 'CA Distribution Logs', 'threshold_days': 0, 'count': 0, 'status': 'disabled'}

        # Rule g: Delete Fleet Trust audit history after X days (keep latest 1 per device/host/method)
        rule_g_days = cfg.delete_fleet_audits_days
        if rule_g_days > 0:
            async with db.transaction(readonly=True) as sql:
                fleet_audits_to_delete = [
                    aud_id
                    async for (aud_id,) in sql(
                        """
                        with ranked as (
                            select id,
                                   row_number() over (partition by device_name, ip_address, verification_method order by audited_at desc) as rn
                            from ca_trust_audits
                        )
                        select a.id
                        from ca_trust_audits a
                        join ranked r on r.id = a.id
                        where r.rn > 1
                          and a.audited_at < now() - ($1 || ' days')::interval
                        """,
                        str(rule_g_days),
                    )
                ]
            count_g = len(fleet_audits_to_delete)
            if not dry_run and count_g > 0:
                async with db.transaction() as sql:
                    await sql.exec('delete from ca_trust_audits where id = any($1::text[])', fleet_audits_to_delete)

            rule_results['rule_g_fleet_audits'] = {
                'name': 'CA Fleet Trust Audits',
                'threshold_days': rule_g_days,
                'count': count_g,
                'status': 'completed',
            }
            total_affected += count_g
        else:
            rule_results['rule_g_fleet_audits'] = {'name': 'CA Fleet Trust Audits', 'threshold_days': 0, 'count': 0, 'status': 'disabled'}

        # Rule h: Delete Maintenance Run History after X days (keep latest 15 runs)
        rule_h_days = cfg.delete_run_history_days
        if rule_h_days > 0:
            async with db.transaction(readonly=True) as sql:
                runs_to_delete = [
                    r_id
                    async for (r_id,) in sql(
                        """
                        with ranked as (
                            select id,
                                   row_number() over (order by started_at desc) as rn
                            from data_management_runs
                        )
                        select r.id
                        from data_management_runs r
                        join ranked k on k.id = r.id
                        where k.rn > 15
                          and r.started_at < now() - ($1 || ' days')::interval
                        """,
                        str(rule_h_days),
                    )
                ]
            count_h = len(runs_to_delete)
            if not dry_run and count_h > 0:
                async with db.transaction() as sql:
                    await sql.exec('delete from data_management_runs where id = any($1::text[])', runs_to_delete)

            rule_results['rule_h_run_history'] = {
                'name': 'Maintenance Run History',
                'threshold_days': rule_h_days,
                'count': count_h,
                'status': 'completed',
            }
            total_affected += count_h
        else:
            rule_results['rule_h_run_history'] = {'name': 'Maintenance Run History', 'threshold_days': 0, 'count': 0, 'status': 'disabled'}

        # Re-sync CRL if certificates were modified/revoked/deleted
        if needs_crl_sync and settings.ca.enabled:
            try:
                async with db.transaction(readonly=True) as sql:
                    remaining_revocations = {(sn, rev_at) async for sn, rev_at in sql('select serial_number, revoked_at from certificates where revoked_at is not null')}
                await ca_service.sync_crl(remaining_revocations)
            except Exception as crl_err:  # noqa: BLE001
                logger.error('Failed to sync CRL after retention cleanup: %s', crl_err, exc_info=True)

        final_status = 'dry_run' if dry_run else 'success'

    except Exception as exc:  # noqa: BLE001
        logger.error('Error during data retention routine: %s', exc, exc_info=True)
        final_status = 'failed'
        error_msg = str(exc)

    end_time = datetime.now(timezone.utc)
    duration_ms = int((end_time - start_time).total_seconds() * 1000)

    # Update run record in database
    async with db.transaction() as sql:
        await sql.exec(
            """
            update data_management_runs set
                completed_at = $2,
                status = $3,
                duration_ms = $4,
                total_records_affected = $5,
                summary_data = $6,
                error_message = $7
            where id = $1
            """,
            run_id,
            end_time,
            final_status,
            duration_ms,
            total_affected,
            rule_results,
            error_msg,
        )
        if not dry_run and final_status == 'success':
            await sql.exec('update data_management_settings set last_run_at = now() where dummy_id = 1')

    # Invalidate cache so last_run_at updates
    invalidate_cache()

    run_summary = {
        'run_id': run_id,
        'trigger_type': trigger_type if not dry_run else 'dry_run',
        'status': final_status,
        'started_at': start_time.isoformat(),
        'completed_at': end_time.isoformat(),
        'duration_ms': duration_ms,
        'total_records_affected': total_affected,
        'rules': rule_results,
        'error_message': error_msg,
    }

    # Dispatch administrative summary email if configured
    if not dry_run and cfg.email_notification_enabled:
        should_send = total_affected > 0 or not cfg.notify_only_on_changes or final_status == 'failed'
        if should_send:
            try:
                import mail  # pylint: disable=import-outside-toplevel

                mail_cfg = await mail.service.get_mail_settings()
                recipient = cfg.admin_email or mail_cfg.effective_admin_recipient
                if recipient:
                    await mail.send_data_maintenance_report(
                        receiver=recipient,
                        run_summary=run_summary,
                    )
                else:
                    logger.debug('No admin email recipient configured for data maintenance report.')
            except Exception as mail_err:  # noqa: BLE001
                logger.error('Could not send data maintenance report email: %s', mail_err, exc_info=True)

    return run_summary
