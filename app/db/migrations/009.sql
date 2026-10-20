-- Migration 009: CA Trust Fleet Audit & Compliance Tracking
CREATE TYPE ca_compliance_status AS ENUM ('compliant', 'partial', 'untrusted', 'error');
CREATE TYPE audit_device_type AS ENUM ('server', 'workstation', 'mobile', 'router', 'unknown');

CREATE TABLE ca_trust_audits (
    id random_id NOT NULL PRIMARY KEY,
    device_name TEXT NOT NULL,
    device_type audit_device_type NOT NULL DEFAULT 'unknown',
    os target_os_type NOT NULL DEFAULT 'unknown',
    os_detail TEXT,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    endpoint_id random_id REFERENCES distribution_endpoints(id) ON DELETE SET NULL,
    verification_method TEXT NOT NULL DEFAULT 'browser',
    overall_status ca_compliance_status NOT NULL DEFAULT 'untrusted',
    total_cas INTEGER NOT NULL DEFAULT 0,
    trusted_cas INTEGER NOT NULL DEFAULT 0,
    audited_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ca_trust_audit_results (
    id random_id NOT NULL PRIMARY KEY,
    audit_id random_id NOT NULL REFERENCES ca_trust_audits(id) ON DELETE CASCADE,
    ca_serial serial_number NOT NULL REFERENCES cas(serial_number) ON DELETE CASCADE,
    is_trusted BOOLEAN NOT NULL DEFAULT false,
    details TEXT,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_ca_trust_audits_device ON ca_trust_audits(device_name);
CREATE INDEX idx_ca_trust_audits_status ON ca_trust_audits(overall_status);
CREATE INDEX idx_ca_trust_audits_os ON ca_trust_audits(os);
CREATE INDEX idx_ca_trust_audits_date ON ca_trust_audits(audited_at DESC);
CREATE INDEX idx_ca_trust_results_audit ON ca_trust_audit_results(audit_id);
CREATE INDEX idx_ca_trust_results_ca ON ca_trust_audit_results(ca_serial);
