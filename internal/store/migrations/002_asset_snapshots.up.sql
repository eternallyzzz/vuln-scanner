CREATE TABLE IF NOT EXISTS asset_snapshots (
    agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    mode        TEXT NOT NULL,
    assets      JSONB NOT NULL,
    checksum    TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (agent_id)
);
