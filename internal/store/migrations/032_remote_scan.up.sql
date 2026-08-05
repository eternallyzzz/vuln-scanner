CREATE TABLE IF NOT EXISTS remote_credentials (
    id                       BIGSERIAL PRIMARY KEY,
    name                     TEXT NOT NULL,
    username                 TEXT NOT NULL,
    auth_type                TEXT NOT NULL DEFAULT 'password',
    password_ciphertext      TEXT NOT NULL DEFAULT '',
    private_key_ciphertext   TEXT NOT NULL DEFAULT '',
    passphrase_ciphertext    TEXT NOT NULL DEFAULT '',
    created_by               TEXT NOT NULL DEFAULT 'api',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at               TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS remote_hosts (
    id            BIGSERIAL PRIMARY KEY,
    address       TEXT NOT NULL,
    credential_id BIGINT NOT NULL REFERENCES remote_credentials(id) ON DELETE CASCADE,
    host_key      TEXT NOT NULL DEFAULT '',
    agent_id      TEXT NOT NULL DEFAULT '',
    hostname      TEXT NOT NULL DEFAULT '',
    os_type       TEXT NOT NULL DEFAULT 'unknown',
    os_version    TEXT NOT NULL DEFAULT '',
    arch          TEXT NOT NULL DEFAULT '',
    package_count INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'active',
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (address, credential_id)
);

CREATE INDEX IF NOT EXISTS idx_remote_hosts_last_seen ON remote_hosts(last_seen);

CREATE TABLE IF NOT EXISTS remote_scan_tasks (
    id             BIGSERIAL PRIMARY KEY,
    credential_id  BIGINT NOT NULL REFERENCES remote_credentials(id) ON DELETE CASCADE,
    address        TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    created_by     TEXT NOT NULL DEFAULT 'api',
    error          TEXT NOT NULL DEFAULT '',
    result_summary JSONB,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at     TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_remote_scan_tasks_status ON remote_scan_tasks(status);
