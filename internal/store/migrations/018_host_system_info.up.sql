CREATE TABLE IF NOT EXISTS host_system_info (
    agent_id           TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    hostname           TEXT NOT NULL DEFAULT '',
    os                 TEXT NOT NULL DEFAULT '',
    os_version         TEXT NOT NULL DEFAULT '',
    arch               TEXT NOT NULL DEFAULT '',
    machine_id         TEXT NOT NULL DEFAULT '',
    system_manufacturer TEXT NOT NULL DEFAULT '',
    system_model       TEXT NOT NULL DEFAULT '',
    system_serial      TEXT NOT NULL DEFAULT '',
    memory_mb          BIGINT NOT NULL DEFAULT 0,
    cpu                JSONB NOT NULL DEFAULT '[]'::jsonb,
    gpu                JSONB NOT NULL DEFAULT '[]'::jsonb,
    motherboard        JSONB NOT NULL DEFAULT '{}'::jsonb,
    net_interfaces     JSONB NOT NULL DEFAULT '[]'::jsonb,
    open_ports         JSONB NOT NULL DEFAULT '[]'::jsonb,
    processes          JSONB NOT NULL DEFAULT '[]'::jsonb,
    storage            JSONB NOT NULL DEFAULT '[]'::jsonb,
    collected_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_host_system_info_collected ON host_system_info(collected_at);
