-- Migration 012: Data Management Settings, Audit Log, and Account Deactivation Timestamp

-- 1. Add deactivated_at column to accounts
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS deactivated_at TIMESTAMPTZ DEFAULT NULL;
CREATE INDEX IF NOT EXISTS idx_accounts_deactivated_at ON accounts(deactivated_at) WHERE status = 'deactivated';

-- 2. Data management configuration table (singleton row dummy_id = 1)
CREATE TABLE IF NOT EXISTS data_management_settings (
    dummy_id INTEGER PRIMARY KEY DEFAULT 1 CHECK (dummy_id = 1),
    enabled BOOLEAN NOT NULL DEFAULT true,
    cron_schedule_hours INTEGER NOT NULL DEFAULT 24,
    run_at_hour_utc INTEGER NOT NULL DEFAULT 2,
    
    -- Retention threshold rules in days (0 = rule disabled)
    delete_deactivated_accounts_days INTEGER NOT NULL DEFAULT 28,
    delete_stale_orders_days INTEGER NOT NULL DEFAULT 14,
    delete_invalid_domains_days INTEGER NOT NULL DEFAULT 28,
    revoke_expired_certs_days INTEGER NOT NULL DEFAULT 7,
    delete_revoked_certs_days INTEGER NOT NULL DEFAULT 14,
    delete_distribution_logs_days INTEGER NOT NULL DEFAULT 14,
    delete_fleet_audits_days INTEGER NOT NULL DEFAULT 7,
    delete_run_history_days INTEGER NOT NULL DEFAULT 30,
    
    -- Notifications
    email_notification_enabled BOOLEAN NOT NULL DEFAULT true,
    notify_only_on_changes BOOLEAN NOT NULL DEFAULT true,
    admin_email TEXT DEFAULT NULL,
    
    last_run_at TIMESTAMPTZ DEFAULT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE data_management_settings ADD COLUMN IF NOT EXISTS delete_run_history_days INTEGER NOT NULL DEFAULT 30;

-- 3. Execution history table for administrative auditing
CREATE TABLE IF NOT EXISTS data_management_runs (
    id random_id PRIMARY KEY,
    trigger_type TEXT NOT NULL DEFAULT 'cron', -- 'cron', 'manual', 'dry_run'
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ DEFAULT NULL,
    status TEXT NOT NULL DEFAULT 'running',    -- 'success', 'failed', 'running', 'dry_run'
    duration_ms INTEGER DEFAULT NULL,
    total_records_affected INTEGER NOT NULL DEFAULT 0,
    summary_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_dm_runs_started ON data_management_runs(started_at DESC);
