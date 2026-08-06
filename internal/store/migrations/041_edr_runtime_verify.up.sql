-- EDR 恶意软件发现与补丁运行时验证（P3 v1）
-- edr_findings：REST 上报（edr_api）与 Agent ClamAV（clamav）发现的统一数据面；
-- 去重键 = agent + source + 非空 hash，否则 name；仅 open/acknowledged 部分唯一，
-- ignored/resolved 后再次上报会生成新 open 记录。
CREATE TABLE IF NOT EXISTS edr_findings (
    id               BIGSERIAL PRIMARY KEY,
    agent_id         TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    source           TEXT NOT NULL DEFAULT 'edr_api',
    finding_type     TEXT NOT NULL DEFAULT 'malware',
    name             TEXT NOT NULL,
    severity         TEXT NOT NULL DEFAULT 'MEDIUM',
    path             TEXT NOT NULL DEFAULT '',
    hash             TEXT NOT NULL DEFAULT '',
    detail           TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'open',
    occurrence_count INT NOT NULL DEFAULT 1,
    alert_id         BIGINT REFERENCES alerts(id) ON DELETE SET NULL,
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_edr_findings_open
    ON edr_findings(agent_id, source, COALESCE(NULLIF(hash, ''), name))
    WHERE status IN ('open', 'acknowledged');

CREATE INDEX IF NOT EXISTS idx_edr_findings_status ON edr_findings(status, agent_id);
CREATE INDEX IF NOT EXISTS idx_edr_findings_agent ON edr_findings(agent_id, last_seen DESC);

-- 补丁运行时验证：领任务时抓基线（services+processes），任务成功后置 pending，
-- Agent 上报当前 SystemInfo 或 operator 手动触发后写入评估结果。
ALTER TABLE patch_tasks
    ADD COLUMN IF NOT EXISTS runtime_verify_baseline JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS runtime_verify_status TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS runtime_verify_detail TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS runtime_verify_at TIMESTAMPTZ;

-- 告警与 EDR 发现关联：cve_id 置空时仍可按发现去重/联动处置。
ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS edr_finding_id BIGINT REFERENCES edr_findings(id) ON DELETE SET NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_edr_finding_open
    ON alerts(rule_id, agent_id, edr_finding_id)
    WHERE status = 'open' AND edr_finding_id IS NOT NULL;

-- EDR 告警使用空 cve_id，若不替换旧唯一索引，同一主机多个 open 发现会在
-- (rule_id, agent_id, '', asset_name) 上冲突；改用含 edr_finding_id 的表达式
-- 索引（NULL 归一为 0）同时保持普通 CVE 告警去重不变。
DROP INDEX IF EXISTS uq_alerts_open;
CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_open
    ON alerts(rule_id, agent_id, cve_id, asset_name, COALESCE(edr_finding_id, 0))
    WHERE status = 'open';
