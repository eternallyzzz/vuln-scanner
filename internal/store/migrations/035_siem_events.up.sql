CREATE TABLE IF NOT EXISTS siem_events (
    id            BIGSERIAL PRIMARY KEY,
    dedupe_key    TEXT NOT NULL UNIQUE,
    event_type    TEXT NOT NULL,
    payload       JSONB NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    attempt_count INT NOT NULL DEFAULT 0,
    last_error    TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_siem_events_pending
    ON siem_events(status, attempt_count, id)
    WHERE status = 'pending';
