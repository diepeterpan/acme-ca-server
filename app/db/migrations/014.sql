-- Migration 014: API Trace configuration and logs

-- 1. Configuration table (singleton row dummy_id = 1)
CREATE TABLE IF NOT EXISTS api_trace_settings (
    dummy_id INTEGER PRIMARY KEY DEFAULT 1 CHECK (dummy_id = 1),
    enabled BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. Trace log table
CREATE TABLE IF NOT EXISTS api_traces (
    id random_id PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    client_ip TEXT NOT NULL,
    target_host TEXT NOT NULL DEFAULT '',
    http_method TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    request_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    request_payload TEXT NOT NULL DEFAULT '',
    response_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    response_payload TEXT NOT NULL DEFAULT '',
    error_message TEXT DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_traces_timestamp ON api_traces(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_api_traces_endpoint ON api_traces(endpoint);
CREATE INDEX IF NOT EXISTS idx_api_traces_client_ip ON api_traces(client_ip);
