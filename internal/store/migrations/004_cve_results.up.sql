CREATE TABLE IF NOT EXISTS cve_results (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    cve_id      TEXT NOT NULL,
    asset_name  TEXT NOT NULL,
    asset_version TEXT NOT NULL DEFAULT '',
    fixed_version TEXT DEFAULT '',
    kb_article  TEXT DEFAULT '',
    kb_url      TEXT DEFAULT '',
    severity    TEXT NOT NULL DEFAULT 'MEDIUM',
    cvss_score  REAL NOT NULL DEFAULT 0,
    summary     TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'active',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (agent_id, cve_id, asset_name, asset_version)
);

CREATE INDEX IF NOT EXISTS idx_cve_agent ON cve_results(agent_id, severity);
CREATE INDEX IF NOT EXISTS idx_cve_lookup ON cve_results(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_status ON cve_results(status);
