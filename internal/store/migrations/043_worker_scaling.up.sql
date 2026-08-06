-- 043_worker_scaling.up.sql
-- Horizontal scaling: PostgreSQL-backed job queue, single-runner loop
-- leases, cross-instance state, and claim columns for parallel loops.

CREATE TABLE IF NOT EXISTS worker_leases (
    loop         TEXT PRIMARY KEY,
    worker_id    TEXT NOT NULL,
    hostname     TEXT NOT NULL DEFAULT '',
    pid          INTEGER NOT NULL DEFAULT 0,
    acquired_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_worker_leases_worker
    ON worker_leases(worker_id);

CREATE TABLE IF NOT EXISTS worker_state (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS job_queue (
    id            BIGSERIAL PRIMARY KEY,
    kind          TEXT NOT NULL,
    key           TEXT NOT NULL DEFAULT '',
    payload       JSONB NOT NULL DEFAULT '{}',
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','claimed','done','failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT NOT NULL DEFAULT '',
    available_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_by    TEXT NOT NULL DEFAULT '',
    claimed_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One live job per (kind,key): trigger coalescing for wakeup jobs and
-- exactly-one-in-flight semantics for sync jobs (report/eol/intel/match).
CREATE UNIQUE INDEX IF NOT EXISTS uq_job_queue_live
    ON job_queue(kind, key) WHERE status IN ('pending','claimed');

CREATE INDEX IF NOT EXISTS idx_job_queue_claim
    ON job_queue(status, kind, available_at, id);

-- Parallel loop claim columns with a shared 2-minute stale-claim lease.
ALTER TABLE siem_events ADD COLUMN IF NOT EXISTS claimed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE siem_events ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_siem_events_claim ON siem_events(status, claimed_at);

ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS claimed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE alert_deliveries ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_alert_deliveries_claim ON alert_deliveries(status, claimed_at);

ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS claimed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_claim ON cloud_accounts(claimed_at);

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ticket_claimed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ticket_claimed_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_alerts_ticket_claim ON alerts(ticket_claimed_at);
