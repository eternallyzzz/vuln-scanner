CREATE TABLE IF NOT EXISTS kb_metadata (
    kb             TEXT PRIMARY KEY,
    title          TEXT NOT NULL DEFAULT '',
    product_family TEXT NOT NULL DEFAULT '',
    support_url    TEXT NOT NULL DEFAULT '',
    catalog_url    TEXT NOT NULL DEFAULT '',
    download_url   TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'unknown',
    verified_at    TIMESTAMPTZ,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS feed_meta (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
