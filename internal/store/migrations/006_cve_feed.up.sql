CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS cve_feed (
    id           BIGSERIAL PRIMARY KEY,
    source       TEXT NOT NULL,
    source_key   TEXT NOT NULL,
    cve_id       TEXT NOT NULL,
    cve_url      TEXT NOT NULL DEFAULT '',
    affected     JSONB NOT NULL DEFAULT '[]',
    fixed_kb     TEXT NOT NULL DEFAULT '',
    fixed_ver    TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT 'MEDIUM',
    cvss_score   REAL NOT NULL DEFAULT 0,
    summary      TEXT NOT NULL DEFAULT '',
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    fetched_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    ttl_seconds  INT NOT NULL DEFAULT 86400,
    UNIQUE(source, source_key, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_cve_feed_source_key ON cve_feed(source, source_key);
CREATE INDEX IF NOT EXISTS idx_cve_feed_cve_id ON cve_feed(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_feed_severity ON cve_feed(severity);
CREATE INDEX IF NOT EXISTS idx_cve_feed_fetched_at ON cve_feed(fetched_at);
CREATE INDEX IF NOT EXISTS idx_cve_feed_affected_gin ON cve_feed USING gin(affected);
CREATE INDEX IF NOT EXISTS idx_cve_feed_summary_trgm ON cve_feed USING gin(summary gin_trgm_ops);
