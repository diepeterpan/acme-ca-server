-- Migration 011: Add error_message to ca_trust_audits
ALTER TABLE ca_trust_audits ADD COLUMN IF NOT EXISTS error_message TEXT;
