ALTER TABLE asset_changes ADD COLUMN IF NOT EXISTS asset_key TEXT NOT NULL DEFAULT '';
ALTER TABLE asset_changes ADD COLUMN IF NOT EXISTS change_source TEXT NOT NULL DEFAULT 'agent';
ALTER TABLE asset_changes ADD COLUMN IF NOT EXISTS actor TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS assets (
    id            BIGSERIAL PRIMARY KEY,
    asset_key     TEXT NOT NULL UNIQUE,
    asset_type    TEXT NOT NULL DEFAULT 'software',
    name          TEXT NOT NULL,
    version       TEXT NOT NULL DEFAULT '',
    os_type       TEXT NOT NULL DEFAULT '',
    os_version    TEXT NOT NULL DEFAULT '',
    format        TEXT NOT NULL DEFAULT '',
    vendor        TEXT NOT NULL DEFAULT '',
    arch          TEXT NOT NULL DEFAULT '',
    location      TEXT NOT NULL DEFAULT '',
    agent_id      TEXT NOT NULL DEFAULT '' REFERENCES agents(id) ON DELETE CASCADE,
    lifecycle     TEXT NOT NULL DEFAULT 'active',
    environment   TEXT NOT NULL DEFAULT '',
    business_unit TEXT NOT NULL DEFAULT '',
    owner         TEXT NOT NULL DEFAULT '',
    tags          TEXT[] NOT NULL DEFAULT '{}',
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assets_agent ON assets(agent_id, asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_env ON assets(environment);
CREATE INDEX IF NOT EXISTS idx_assets_lifecycle ON assets(lifecycle);
CREATE INDEX IF NOT EXISTS idx_assets_tags ON assets USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_assets_name ON assets(name);

CREATE TABLE IF NOT EXISTS asset_relations (
    id            BIGSERIAL PRIMARY KEY,
    parent_key    TEXT NOT NULL REFERENCES assets(asset_key) ON DELETE CASCADE,
    child_key     TEXT NOT NULL REFERENCES assets(asset_key) ON DELETE CASCADE,
    relation_type TEXT NOT NULL DEFAULT 'installs',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (parent_key, child_key, relation_type)
);

ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS asset_tag_filter TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS environment_filter TEXT NOT NULL DEFAULT '';
