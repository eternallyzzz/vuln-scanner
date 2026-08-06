-- 多租户 v2：租户级配置、报表、合成 agent 归属与 API key

-- Alert rules and SLA policies become per-tenant rows. Existing rows keep
-- tenant 1 (Default), preserving single-tenant deployments unchanged.
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
ALTER TABLE sla_policies ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);

CREATE INDEX IF NOT EXISTS idx_alert_rules_tenant ON alert_rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sla_policies_tenant ON sla_policies(tenant_id);

-- The old global severity uniqueness is replaced by per-tenant uniqueness.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'sla_policies_severity_key'
          AND conrelid = 'sla_policies'::regclass
    ) THEN
        ALTER TABLE sla_policies DROP CONSTRAINT sla_policies_severity_key;
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_sla_policies_tenant_severity
    ON sla_policies(tenant_id, severity);

-- Per-tenant report settings. Tenant rows override only schedule/timezone/
-- recipients; the global reporting.enabled switch and alerting.smtp remain
-- the master delivery configuration.
CREATE TABLE IF NOT EXISTS tenant_reports (
    tenant_id BIGINT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    enabled   BOOLEAN NOT NULL DEFAULT TRUE,
    schedule  TEXT NOT NULL DEFAULT '0 8 * * *',
    timezone  TEXT NOT NULL DEFAULT 'Local',
    recipients JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO tenant_reports (tenant_id, enabled, schedule, timezone, recipients)
VALUES (1, TRUE, '0 8 * * *', 'Local', '[]'::jsonb)
ON CONFLICT (tenant_id) DO NOTHING;

-- Tenant-scoped API keys. key_hash stores SHA-256 only; the plaintext key is
-- shown once at creation. NULL tenant_id means a global (legacy-style) key.
CREATE TABLE IF NOT EXISTS api_keys (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,
    tenant_id    BIGINT REFERENCES tenants(id) ON DELETE CASCADE,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_by   TEXT NOT NULL DEFAULT 'api',
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);

-- Synthetic scan sources carry an explicit tenant. Scan tasks inherit the
-- tenant of their credential/source where applicable, and synthetic agents
-- keep the tenant of the first scan that created them.
ALTER TABLE remote_credentials ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
ALTER TABLE webdb_credentials ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
ALTER TABLE webdb_scan_tasks ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
ALTER TABLE network_scan_tasks ADD COLUMN IF NOT EXISTS tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);

CREATE INDEX IF NOT EXISTS idx_remote_credentials_tenant ON remote_credentials(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_tenant ON cloud_accounts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_webdb_credentials_tenant ON webdb_credentials(tenant_id);
CREATE INDEX IF NOT EXISTS idx_webdb_scan_tasks_tenant ON webdb_scan_tasks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_network_scan_tasks_tenant ON network_scan_tasks(tenant_id);
