CREATE TABLE IF NOT EXISTS agent_update_facts (
    agent_id        TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    kb              TEXT NOT NULL,
    title           TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL DEFAULT 'pending',
    severity        TEXT NOT NULL DEFAULT '',
    reboot_required BOOLEAN NOT NULL DEFAULT FALSE,
    source          TEXT NOT NULL DEFAULT 'wua',
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (agent_id, kb, state)
);

CREATE INDEX IF NOT EXISTS idx_agent_update_facts_agent
    ON agent_update_facts(agent_id, collected_at DESC);

CREATE TABLE IF NOT EXISTS agent_update_status (
    agent_id         TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    source_reachable BOOLEAN NOT NULL DEFAULT FALSE,
    last_checked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    error            TEXT NOT NULL DEFAULT ''
);

ALTER TABLE cve_results ADD COLUMN IF NOT EXISTS verification_source TEXT NOT NULL DEFAULT '';
