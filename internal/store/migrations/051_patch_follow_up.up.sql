-- Post-patch follow-up closure: a failed post-patch verification with
-- missing fixes can produce a follow-up campaign instead of accumulating
-- failed tasks. follow_up_status is '' (not applicable/not processed),
-- 'pending' (awaiting the follow-up loop), 'created' or 'skipped'.
ALTER TABLE patch_tasks
    ADD COLUMN IF NOT EXISTS post_patch_follow_up_status TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS post_patch_follow_up_campaign_id BIGINT REFERENCES patch_campaigns(id),
    ADD COLUMN IF NOT EXISTS post_patch_follow_up_attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS post_patch_follow_up_depth INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS post_patch_follow_up_detail TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS post_patch_source_task_id BIGINT REFERENCES patch_tasks(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_patch_tasks_post_patch_follow_up
    ON patch_tasks(post_patch_follow_up_status, post_patch_follow_up_attempts)
    WHERE post_patch_follow_up_status = 'pending';
