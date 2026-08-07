-- Per-KB/per-OS/per-arch direct downloads. The old single download_url on
-- kb_metadata cannot represent Windows 10 vs 11 vs Server or x64 vs ARM64
-- variants, so it is retired; existing rows are cleared once (guarded by a
-- feed_meta flag because migrations re-run on every startup).
CREATE TABLE IF NOT EXISTS kb_downloads (
    kb          TEXT NOT NULL,
    os_family   TEXT NOT NULL DEFAULT '',
    arch        TEXT NOT NULL DEFAULT 'x64',
    title       TEXT NOT NULL DEFAULT '',
    url         TEXT NOT NULL DEFAULT '',
    sha256      TEXT NOT NULL DEFAULT '',
    verified_at TIMESTAMPTZ,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (kb, os_family, arch)
);

INSERT INTO feed_meta (key, value, updated_at)
VALUES ('kb_downloads_v2', 'pending', now())
ON CONFLICT (key) DO NOTHING;

UPDATE kb_metadata
SET download_url='', download_sha256='', download_resolved_at=NULL
WHERE (SELECT value FROM feed_meta WHERE key = 'kb_downloads_v2') = 'pending';

UPDATE feed_meta
SET value='cleared', updated_at=now()
WHERE key = 'kb_downloads_v2';
