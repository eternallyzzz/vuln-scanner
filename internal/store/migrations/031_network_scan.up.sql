CREATE TABLE IF NOT EXISTS network_scan_tasks (
    id                BIGSERIAL PRIMARY KEY,
    target            TEXT NOT NULL,
    ports             TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'pending',
    assigned_agent_id TEXT NOT NULL DEFAULT '',
    created_by        TEXT NOT NULL DEFAULT 'api',
    error             TEXT NOT NULL DEFAULT '',
    result_summary    JSONB,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at        TIMESTAMPTZ,
    finished_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_network_scan_tasks_status ON network_scan_tasks(status);

CREATE TABLE IF NOT EXISTS network_hosts (
    id                BIGSERIAL PRIMARY KEY,
    ip                TEXT NOT NULL UNIQUE,
    hostname          TEXT NOT NULL DEFAULT '',
    os_type           TEXT NOT NULL DEFAULT 'unknown',
    services          JSONB NOT NULL DEFAULT '[]',
    scanner_agent_id  TEXT NOT NULL DEFAULT '',
    agent_id          TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'active',
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_network_hosts_last_seen ON network_hosts(last_seen);
