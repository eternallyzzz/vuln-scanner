-- Patch fix-set closure: a task may now carry a set of co-required fixes
-- (e.g. upgrading A also requires upgrading B), not just one asset/fix pair.
-- fix_set_hash is the canonical dedupe key for campaigns.
ALTER TABLE patch_tasks
    ADD COLUMN IF NOT EXISTS fix_set JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS fix_set_hash TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_patch_tasks_fix_set_hash
    ON patch_tasks(agent_id, fix_set_hash)
    WHERE fix_set_hash <> '';

-- Static dependency rules: when a main fix (asset_name/fix_type/fix_value)
-- is generated, the listed dependency fixes are added to the task when the
-- dependency asset is installed on the same agent. fix_value '' means "any".
CREATE TABLE IF NOT EXISTS patch_dependency_rules (
    id                   BIGSERIAL PRIMARY KEY,
    asset_name           TEXT NOT NULL,
    fix_type             TEXT NOT NULL DEFAULT 'version',
    fix_value            TEXT NOT NULL DEFAULT '',
    dependency_asset     TEXT NOT NULL,
    dependency_fix_type  TEXT NOT NULL DEFAULT 'version',
    dependency_fix_value TEXT NOT NULL DEFAULT '',
    required             BOOLEAN NOT NULL DEFAULT TRUE,
    reason               TEXT NOT NULL DEFAULT '',
    source_ref           TEXT NOT NULL DEFAULT '',
    enabled              BOOLEAN NOT NULL DEFAULT TRUE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_patch_dependency_rules_lookup
    ON patch_dependency_rules(asset_name, fix_type, enabled);

-- Conservative seeds: ensure the companion library package is upgraded
-- together with the main binary. Expansion only applies when the dependency
-- asset is actually installed on the agent, so these never add a package
-- that is absent.
INSERT INTO patch_dependency_rules
    (asset_name, fix_type, fix_value, dependency_asset, dependency_fix_type,
     dependency_fix_value, required, reason, source_ref)
VALUES
    ('curl', 'version', '', 'libcurl4', 'version', '', TRUE,
     'curl vulnerabilities are often fixed in the shared libcurl4 library; upgrade both together',
     'debian-tracker/ubuntu-usn'),
    ('samba', 'version', '', 'libldb2', 'version', '', TRUE,
     'samba security updates commonly require the matching libldb2 update',
     'debian-dsa/ubuntu-usn'),
    ('openssl', 'version', '', 'libssl3', 'version', '', TRUE,
     'openssl vulnerabilities are fixed in libssl3; upgrade the runtime library together',
     'ubuntu-usn')
ON CONFLICT DO NOTHING;
