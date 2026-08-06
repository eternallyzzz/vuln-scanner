CREATE TABLE IF NOT EXISTS webdb_credentials (
    id                    BIGSERIAL PRIMARY KEY,
    name                  TEXT NOT NULL,
    username              TEXT NOT NULL DEFAULT '',
    password_ciphertext   TEXT NOT NULL DEFAULT '',
    created_by            TEXT NOT NULL DEFAULT 'api',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at            TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS webdb_scan_tasks (
    id             BIGSERIAL PRIMARY KEY,
    kind           TEXT NOT NULL,
    target         TEXT NOT NULL,
    db_type        TEXT NOT NULL DEFAULT '',
    credential_id  BIGINT REFERENCES webdb_credentials(id),
    status         TEXT NOT NULL DEFAULT 'pending',
    created_by     TEXT NOT NULL DEFAULT 'api',
    error          TEXT NOT NULL DEFAULT '',
    result_summary JSONB,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at     TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_webdb_scan_tasks_status ON webdb_scan_tasks(status);

CREATE TABLE IF NOT EXISTS webdb_targets (
    id             BIGSERIAL PRIMARY KEY,
    kind           TEXT NOT NULL,
    target         TEXT NOT NULL,
    db_type        TEXT NOT NULL DEFAULT '',
    credential_id  BIGINT NOT NULL DEFAULT 0,
    agent_id       TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'active',
    title          TEXT NOT NULL DEFAULT '',
    detail         JSONB NOT NULL DEFAULT '{}',
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (kind, target)
);

CREATE INDEX IF NOT EXISTS idx_webdb_targets_last_seen ON webdb_targets(last_seen);
