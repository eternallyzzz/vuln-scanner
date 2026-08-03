CREATE TABLE IF NOT EXISTS analysis_logs (
    id          TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    cve_ids     JSONB NOT NULL DEFAULT '[]',
    prompt      TEXT NOT NULL DEFAULT '',
    response    TEXT NOT NULL DEFAULT '',
    summary     TEXT NOT NULL DEFAULT '',
    provider    TEXT NOT NULL DEFAULT '',
    model       TEXT NOT NULL DEFAULT '',
    tokens_used INT NOT NULL DEFAULT 0,
    duration_ms INT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analysis_agent ON analysis_logs(agent_id, created_at DESC);
