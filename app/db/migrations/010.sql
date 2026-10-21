-- Migration 010: Composite index for Fleet Trust Deduplication
CREATE INDEX IF NOT EXISTS idx_ca_trust_audits_composite
ON ca_trust_audits(device_name, ip_address, verification_method, audited_at DESC);
