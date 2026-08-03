ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS auto_remediate BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS remediation_campaign_id BIGINT REFERENCES patch_campaigns(id);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS remediation_error TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_alerts_remediation
    ON alerts(remediation_campaign_id)
    WHERE remediation_campaign_id IS NOT NULL;
