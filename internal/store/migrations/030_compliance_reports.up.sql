CREATE TABLE IF NOT EXISTS compliance_reports (
    agent_id    TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    benchmark   TEXT NOT NULL DEFAULT 'cis-v1',
    score       DOUBLE PRECISION NOT NULL DEFAULT 0,
    total       INT NOT NULL DEFAULT 0,
    passed      INT NOT NULL DEFAULT 0,
    failed      INT NOT NULL DEFAULT 0,
    na          INT NOT NULL DEFAULT 0,
    checks      JSONB NOT NULL DEFAULT '[]'::jsonb,
    checked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_compliance_reports_score ON compliance_reports(score DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_checked ON compliance_reports(checked_at DESC);
