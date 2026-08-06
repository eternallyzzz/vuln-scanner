ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS ticket_enabled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ticket_provider TEXT NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ticket_key TEXT NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ticket_url TEXT NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ticket_status TEXT NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ticket_error TEXT NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ticket_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ticket_sync_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ticket_synced_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_alerts_ticket_create_pending
    ON alerts(status, ticket_key, ticket_attempts)
    WHERE ticket_key = '';

CREATE INDEX IF NOT EXISTS idx_alerts_ticket_sync_pending
    ON alerts(status, ticket_key, ticket_status)
    WHERE ticket_key <> '';
