CREATE TABLE IF NOT EXISTS asset_changes (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    change_type TEXT NOT NULL,
    asset_name  TEXT NOT NULL,
    old_version TEXT DEFAULT '',
    new_version TEXT DEFAULT '',
    format      TEXT DEFAULT '',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asset_changes_agent ON asset_changes(agent_id, detected_at);
