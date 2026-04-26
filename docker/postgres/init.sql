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
    status VARCHAR(32) NOT NULL DEFAULT 'unresolved',
    message TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    confidence INTEGER NOT NULL DEFAULT 50
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts (type);
CREATE INDEX IF NOT EXISTS idx_alerts_ip_created_at ON alerts (ip, created_at DESC);

CREATE TABLE IF NOT EXISTS ip_reputations (
    ip INET PRIMARY KEY,
    reputation_status VARCHAR(32) NOT NULL DEFAULT 'trusted',
    current_state VARCHAR(32) NOT NULL DEFAULT 'trusted',
    current_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    lifetime_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    alert_count INTEGER NOT NULL DEFAULT 0,
    malicious_count INTEGER NOT NULL DEFAULT 0,
    block_count INTEGER NOT NULL DEFAULT 0,
    offense_streak INTEGER NOT NULL DEFAULT 0,
    blocked_reason TEXT,
    manual_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    total_alert_count INTEGER NOT NULL DEFAULT 0,
    safe_alert_count INTEGER NOT NULL DEFAULT 0,
    unresolved_alert_count INTEGER NOT NULL DEFAULT 0,
    malicious_alert_count INTEGER NOT NULL DEFAULT 0,
    alert_hold_active BOOLEAN NOT NULL DEFAULT FALSE,
    threshold_reached BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen TIMESTAMPTZ,
    last_alert_at TIMESTAMPTZ,
    blocked_until TIMESTAMPTZ,
    cooldown_until TIMESTAMPTZ,
    whitelist BOOLEAN NOT NULL DEFAULT FALSE,
    analyst_override VARCHAR(32),
    reputation_reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_reputations_state ON ip_reputations (current_state, current_score DESC);
CREATE INDEX IF NOT EXISTS idx_ip_reputations_blocked_until ON ip_reputations (blocked_until);

CREATE TABLE IF NOT EXISTS ip_reputation_transitions (
    id BIGSERIAL PRIMARY KEY,
    ip INET NOT NULL,
    old_state VARCHAR(32) NOT NULL,
    new_state VARCHAR(32) NOT NULL,
    score_before DOUBLE PRECISION NOT NULL DEFAULT 0,
    score_after DOUBLE PRECISION NOT NULL DEFAULT 0,
    trigger_reason TEXT NOT NULL,
    source_alert_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    manual_or_auto VARCHAR(16) NOT NULL DEFAULT 'auto',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_reputation_transitions_created_at
    ON ip_reputation_transitions (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ip_reputation_transitions_ip_created_at
    ON ip_reputation_transitions (ip, created_at DESC);

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(16) NOT NULL DEFAULT 'readonly',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor VARCHAR(64),
    action VARCHAR(64) NOT NULL,
    target TEXT,
    source_ip TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs (actor);
