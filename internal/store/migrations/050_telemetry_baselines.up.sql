-- Periodic telemetry baselines for file integrity and behavior drift.
-- The agent sends bounded file facts and SystemInfo subsets on its own
-- cadence; the server diffs each snapshot against these tables and turns
-- drifts into edr_findings rows (source file_integrity / behavior).
CREATE TABLE IF NOT EXISTS file_baselines (
    agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    path        TEXT NOT NULL,
    sha256      TEXT NOT NULL DEFAULT '',
    size_bytes  BIGINT NOT NULL DEFAULT 0,
    mode        TEXT NOT NULL DEFAULT '',
    modified_at TEXT NOT NULL DEFAULT '',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (agent_id, path)
);

CREATE INDEX IF NOT EXISTS idx_file_baselines_agent
    ON file_baselines(agent_id, last_seen DESC);

CREATE TABLE IF NOT EXISTS behavior_baselines (
    agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    category    TEXT NOT NULL,
    payload     JSONB NOT NULL DEFAULT '[]'::jsonb,
    checksum    TEXT NOT NULL DEFAULT '',
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (agent_id, category)
);

CREATE INDEX IF NOT EXISTS idx_behavior_baselines_agent
    ON behavior_baselines(agent_id, captured_at DESC);
