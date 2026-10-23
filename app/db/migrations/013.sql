-- Migration 013: Add delete_run_history_days to data_management_settings
ALTER TABLE data_management_settings ADD COLUMN IF NOT EXISTS delete_run_history_days INTEGER NOT NULL DEFAULT 30;
