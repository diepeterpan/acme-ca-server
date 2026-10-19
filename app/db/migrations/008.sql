-- Migration 008: CA Distribution Endpoints and Audit Log
CREATE TYPE distribution_endpoint_type AS ENUM ('ssh', 'email');
CREATE TYPE target_os_type AS ENUM ('linux', 'windows', 'macos', 'openwrt', 'ios', 'android', 'unsupported', 'unknown');
CREATE TYPE ssh_auth_type AS ENUM ('key', 'password');

CREATE TABLE distribution_endpoints (
    id random_id NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    type distribution_endpoint_type NOT NULL,
    host TEXT,
    port INTEGER DEFAULT 22,
    username TEXT,
    auth_type ssh_auth_type DEFAULT 'key',
    auth_secret_enc BYTEA,
    target_dir TEXT,
    email_addresses TEXT[],
    target_os_list target_os_type[],
    detected_os target_os_type NOT NULL DEFAULT 'unknown',
    os_detail TEXT,
    last_test_at TIMESTAMPTZ,
    last_test_status BOOLEAN,
    last_test_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ca_distribution_logs (
    id random_id NOT NULL PRIMARY KEY,
    ca_serial serial_number NOT NULL REFERENCES cas(serial_number) ON DELETE CASCADE,
    endpoint_id random_id REFERENCES distribution_endpoints(id) ON DELETE SET NULL,
    endpoint_name TEXT NOT NULL,
    endpoint_type distribution_endpoint_type NOT NULL,
    filename TEXT NOT NULL,
    status BOOLEAN NOT NULL,
    status_message TEXT,
    distributed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_dist_endpoints_type ON distribution_endpoints(type);
CREATE INDEX idx_dist_logs_ca_serial ON ca_distribution_logs(ca_serial);
CREATE INDEX idx_dist_logs_distributed_at ON ca_distribution_logs(distributed_at DESC);
