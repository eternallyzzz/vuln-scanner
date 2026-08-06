CREATE TABLE IF NOT EXISTS cve_intel (
    cve_id           TEXT PRIMARY KEY,
    epss_score       DOUBLE PRECISION NOT NULL DEFAULT 0,
    epss_percentile  DOUBLE PRECISION NOT NULL DEFAULT 0,
    kev              BOOLEAN NOT NULL DEFAULT FALSE,
    kev_added        DATE,
    known_ransomware BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cve_alias (
    alias_id          TEXT PRIMARY KEY,
    canonical_cve_id  TEXT NOT NULL,
    source            TEXT NOT NULL DEFAULT '',
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cve_alias_canonical ON cve_alias(canonical_cve_id);

CREATE TABLE IF NOT EXISTS vulnerability_exceptions (
    id         BIGSERIAL PRIMARY KEY,
    cve_id     TEXT NOT NULL,
    asset_key  TEXT NOT NULL DEFAULT '',
    reason     TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL DEFAULT 'api',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_vuln_exceptions_active
    ON vulnerability_exceptions(cve_id, asset_key) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS sla_policies (
    id                   BIGSERIAL PRIMARY KEY,
    name                 TEXT NOT NULL,
    severity             TEXT NOT NULL UNIQUE,
    max_remediation_hours INT NOT NULL,
    enabled              BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO sla_policies (name, severity, max_remediation_hours) VALUES
    ('Critical SLA', 'CRITICAL', 24),
    ('High SLA', 'HIGH', 72),
    ('Medium SLA', 'MEDIUM', 168),
    ('Low SLA', 'LOW', 720)
ON CONFLICT DO NOTHING;

ALTER TABLE cve_results ADD COLUMN IF NOT EXISTS canonical_cve_id TEXT NOT NULL DEFAULT '';
ALTER TABLE cve_results ADD COLUMN IF NOT EXISTS epss_score DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE cve_results ADD COLUMN IF NOT EXISTS epss_percentile DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE cve_results ADD COLUMN IF NOT EXISTS kev BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE cve_results ADD COLUMN IF NOT EXISTS exposure_score DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE cve_results ADD COLUMN IF NOT EXISTS asset_criticality DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE cve_results ADD COLUMN IF NOT EXISTS risk_score DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE cve_results ADD COLUMN IF NOT EXISTS risk_level TEXT NOT NULL DEFAULT '';
ALTER TABLE cve_results ADD COLUMN IF NOT EXISTS fixed_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_cve_results_risk ON cve_results(agent_id, status, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_cve_results_canonical ON cve_results(canonical_cve_id);

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS epss_score DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS kev BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS risk_score DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS risk_level TEXT NOT NULL DEFAULT '';

UPDATE cve_results SET fixed_at = detected_at
WHERE status = 'fixed' AND fixed_at IS NULL;

UPDATE cve_results SET canonical_cve_id = CASE
    WHEN cve_id ~ '^(DEBIAN|UBUNTU|ALPINE)-CVE-([0-9]{4}-[0-9]+)$'
        THEN substring(cve_id from 'CVE-[0-9]{4}-[0-9]+')
    ELSE cve_id
END
WHERE canonical_cve_id = '';

INSERT INTO cve_alias (alias_id, canonical_cve_id, source)
SELECT cve_id, canonical_cve_id, 'backfill' FROM cve_results
WHERE cve_id <> canonical_cve_id
ON CONFLICT (alias_id) DO NOTHING;
