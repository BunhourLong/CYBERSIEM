CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    ip INET NOT NULL,
    method VARCHAR(16) NOT NULL,
    endpoint TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    user_agent TEXT NOT NULL,
    request_target TEXT NOT NULL,
    query_string TEXT NOT NULL DEFAULT '',
    referer TEXT NOT NULL DEFAULT '-',
    raw_line TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_occurred_at ON events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_ip_occurred_at ON events (ip, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_endpoint_occurred_at ON events (endpoint, occurred_at DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,
    event_id BIGINT REFERENCES events(id) ON DELETE SET NULL,
    ip INET NOT NULL,
    endpoint TEXT NOT NULL,
    type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'open',
    message TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts (type);
