import asyncio
from datetime import datetime, timezone

from logger import logger

from .data_retention import get_data_management_settings, run_data_retention


async def check_and_run_retention() -> None:
    try:
        cfg = await get_data_management_settings()
        if not cfg.enabled:
            return

        now = datetime.now(timezone.utc)
        schedule_hours = max(1, cfg.cron_schedule_hours)

        should_run = False
        if cfg.last_run_at is None:
            should_run = True
        else:
            elapsed_seconds = (now - cfg.last_run_at).total_seconds()
            elapsed_hours = elapsed_seconds / 3600.0

            # If enough hours have passed and we're at or past the configured target hour
            if elapsed_hours >= schedule_hours:
                if schedule_hours >= 24:
                    # For daily runs, prefer matching the configured UTC hour
                    if now.hour == cfg.run_at_hour_utc or elapsed_hours >= 28:
                        should_run = True
                else:
                    should_run = True

        if should_run:
            logger.info('Starting scheduled automated data retention maintenance run...')
            summary = await run_data_retention(trigger_type='cron', dry_run=False)
            logger.info('Scheduled data retention completed: %s records affected (status=%s)', summary.get('total_records_affected', 0), summary.get('status'))

    except Exception:  # noqa: BLE001
        logger.error('Error in scheduled data retention job', exc_info=True)


async def start() -> None:
    async def run() -> None:
        # Initial brief wait on startup to let DB migrations & other services finish initialization
        await asyncio.sleep(30)
        while True:
            try:
                await check_and_run_retention()
            except Exception:  # noqa: BLE001
                logger.error('Data retention cron worker iteration failed', exc_info=True)
            finally:
                # Poll every 30 minutes
                await asyncio.sleep(30 * 60)

    asyncio.create_task(run())
