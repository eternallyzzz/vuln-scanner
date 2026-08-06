ALTER TABLE patch_tasks ADD COLUMN IF NOT EXISTS cancel_requested BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS patch_task_events (
    id         BIGSERIAL PRIMARY KEY,
    task_id    BIGINT NOT NULL REFERENCES patch_tasks(id) ON DELETE CASCADE,
    stream     TEXT NOT NULL DEFAULT 'stdout',
    data       TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_patch_task_events_task_id ON patch_task_events(task_id, id);
