-- Patch matching accuracy seeds: library/package alias translations that let
-- generic CVE products resolve to installed binary packages. The stricter
-- token matching (feed product must be contained in the asset name, extra
-- tokens must be generic qualifiers) moves these relationships to explicit
-- translation rules instead of implicit token overlap.
INSERT INTO package_translations (pattern, cpe_name, platform, priority) VALUES
('^libcurl[0-9].*', 'curl', 'any', 10),
('^openssl-libs$',  'openssl', 'any', 10),
('^openssh-portable$', 'openssh', 'any', 10),
('^libcrypto.*',    'openssl', 'any', 10),
('^libxml2-.*',     'libxml2', 'any', 10)
ON CONFLICT DO NOTHING;
