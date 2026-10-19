-- Migration 007: Support CA Expiration Monitoring, Rollover and Multi-CA Management
ALTER TABLE cas ADD COLUMN IF NOT EXISTS not_valid_before timestamptz;
ALTER TABLE cas ADD COLUMN IF NOT EXISTS not_valid_after timestamptz;
ALTER TABLE cas ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE cas ADD COLUMN IF NOT EXISTS revoked_at timestamptz DEFAULT NULL;
ALTER TABLE cas ADD COLUMN IF NOT EXISTS last_warning_stage integer DEFAULT 0;

ALTER TABLE mail_settings ADD COLUMN IF NOT EXISTS admin_notification_email text DEFAULT NULL;
ALTER TABLE mail_settings ADD COLUMN IF NOT EXISTS warn_before_ca_expires_days integer DEFAULT 90;
