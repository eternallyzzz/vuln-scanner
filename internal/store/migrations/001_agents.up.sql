CREATE TABLE IF NOT EXISTS agents (
    id          TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL,
    os_type     TEXT NOT NULL,
    os_version  TEXT NOT NULL DEFAULT '',
    arch        TEXT NOT NULL DEFAULT '',
    agent_ver   TEXT NOT NULL DEFAULT '1.0.0',
    ip          TEXT NOT NULL DEFAULT '',
    token_hash  TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending',
    fingerprint_hash TEXT NOT NULL DEFAULT '',
    last_seen   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen);
CREATE INDEX IF NOT EXISTS idx_agents_fingerprint ON agents(fingerprint_hash);
