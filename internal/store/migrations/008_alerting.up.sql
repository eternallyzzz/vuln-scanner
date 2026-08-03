CREATE TABLE IF NOT EXISTS alert_rules (
    id               BIGSERIAL PRIMARY KEY,
    name             TEXT NOT NULL,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    severity_filter  TEXT NOT NULL DEFAULT 'HIGH',
    source_filter    TEXT NOT NULL DEFAULT '',
    agent_id_filter  TEXT NOT NULL DEFAULT '',
    asset_filter     TEXT NOT NULL DEFAULT '',
    min_cvss         REAL NOT NULL DEFAULT 0,
    cooldown_minutes INT NOT NULL DEFAULT 1440,
    channels         JSONB NOT NULL DEFAULT '["webhook"]',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id                BIGSERIAL PRIMARY KEY,
    rule_id           BIGINT NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    agent_id          TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    cve_id            TEXT NOT NULL,
    asset_name        TEXT NOT NULL,
    severity          TEXT NOT NULL DEFAULT 'MEDIUM',
    cvss_score        REAL NOT NULL DEFAULT 0,
    status            TEXT NOT NULL DEFAULT 'open',
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    occurrence_count  INT NOT NULL DEFAULT 1,
    resolved_at       TIMESTAMPTZ,
    source            TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_open
    ON alerts(rule_id, agent_id, cve_id, asset_name)
    WHERE status = 'open';

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, agent_id);
CREATE INDEX IF NOT EXISTS idx_alerts_agent ON alerts(agent_id, severity);

CREATE TABLE IF NOT EXISTS alert_deliveries (
    id            BIGSERIAL PRIMARY KEY,
    alert_id      BIGINT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    channel       TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    attempt_count INT NOT NULL DEFAULT 0,
    last_error    TEXT NOT NULL DEFAULT '',
    sent_at       TIMESTAMPTZ,
    UNIQUE (alert_id, channel)
);

CREATE INDEX IF NOT EXISTS idx_alert_deliveries_pending
    ON alert_deliveries(status, attempt_count);
