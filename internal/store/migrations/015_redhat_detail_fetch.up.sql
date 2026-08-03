CREATE TABLE IF NOT EXISTS redhat_detail_fetch (
    cve_id TEXT PRIMARY KEY,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
