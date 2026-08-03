CREATE TABLE IF NOT EXISTS patch_campaigns (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL DEFAULT '',
    filters    JSONB NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL DEFAULT 'api',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE patch_tasks ADD COLUMN IF NOT EXISTS campaign_id BIGINT REFERENCES patch_campaigns(id);

CREATE INDEX IF NOT EXISTS idx_patch_tasks_campaign ON patch_tasks(campaign_id, status);

CREATE TABLE IF NOT EXISTS campaign_audit_log (
    id             BIGSERIAL PRIMARY KEY,
    campaign_id    BIGINT NOT NULL REFERENCES patch_campaigns(id) ON DELETE CASCADE,
    action         TEXT NOT NULL,
    actor          TEXT NOT NULL DEFAULT 'api',
    affected_count BIGINT NOT NULL DEFAULT 0,
    detail         JSONB NOT NULL DEFAULT '{}',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_campaign_audit_campaign
    ON campaign_audit_log(campaign_id, created_at);
