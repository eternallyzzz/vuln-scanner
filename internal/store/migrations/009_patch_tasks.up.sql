CREATE TABLE IF NOT EXISTS patch_tasks (
    id                 BIGSERIAL PRIMARY KEY,
    agent_id           TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    asset_name         TEXT NOT NULL,
    fix_type           TEXT NOT NULL,
    fix_value          TEXT NOT NULL DEFAULT '',
    action             TEXT NOT NULL DEFAULT 'monitor',
    cve_ids            TEXT[] NOT NULL DEFAULT '{}',
    command            TEXT NOT NULL DEFAULT '',
    commands           JSONB NOT NULL DEFAULT '[]',
    status             TEXT NOT NULL DEFAULT 'pending',
    approval_required  BOOLEAN NOT NULL DEFAULT TRUE,
    window_start       TIMESTAMPTZ,
    window_end         TIMESTAMPTZ,
    result             JSONB NOT NULL DEFAULT '{}',
    created_by         TEXT NOT NULL DEFAULT 'system',
    approved_by        TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_patch_tasks_status ON patch_tasks(status, agent_id);
CREATE INDEX IF NOT EXISTS idx_patch_tasks_agent ON patch_tasks(agent_id, created_at);
