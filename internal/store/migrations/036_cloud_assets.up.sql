CREATE TABLE IF NOT EXISTS cloud_accounts (
    id                       BIGSERIAL PRIMARY KEY,
    provider                 TEXT NOT NULL CHECK (provider IN ('aws','azure','gcp')),
    name                     TEXT NOT NULL,
    account_id               TEXT NOT NULL,
    regions                  TEXT[] NOT NULL DEFAULT '{}',
    credential_ciphertext    TEXT NOT NULL,
    enabled                  BOOLEAN NOT NULL DEFAULT TRUE,
    refresh_interval_minutes INT NOT NULL DEFAULT 60,
    last_refresh_at          TIMESTAMPTZ,
    last_error               TEXT NOT NULL DEFAULT '',
    created_by               TEXT NOT NULL DEFAULT 'api',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, account_id)
);

CREATE TABLE IF NOT EXISTS cloud_resources (
    id            BIGSERIAL PRIMARY KEY,
    account_id    BIGINT NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    provider      TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    name          TEXT NOT NULL,
    region        TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'active',
    tags          JSONB NOT NULL DEFAULT '{}',
    metadata      JSONB NOT NULL DEFAULT '{}',
    asset_key     TEXT NOT NULL DEFAULT '',
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, resource_type, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_cloud_resources_provider ON cloud_resources(provider);
CREATE INDEX IF NOT EXISTS idx_cloud_resources_type ON cloud_resources(resource_type);
CREATE INDEX IF NOT EXISTS idx_cloud_resources_region ON cloud_resources(region);
CREATE INDEX IF NOT EXISTS idx_cloud_resources_last_seen ON cloud_resources(last_seen);
