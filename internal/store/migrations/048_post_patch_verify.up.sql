-- Post-patch re-scan verification: a successful patch task enters pending
-- and the next CVE match for the same agent decides whether its target CVEs
-- are still active. runtime_verify stays independent.
ALTER TABLE patch_tasks
    ADD COLUMN IF NOT EXISTS post_patch_status TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS post_patch_detail TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS post_patch_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_patch_tasks_post_patch
    ON patch_tasks(agent_id, status, post_patch_status);
