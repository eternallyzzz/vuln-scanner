-- Common display-name -> NVD CPE product aliases, implemented as translation
-- rules without a vendor condition so both Linux and Windows assets benefit.
-- Patterns intentionally do not overlap with the Windows-specific rules.
INSERT INTO package_translations (pattern, cpe_name, platform, priority)
VALUES
('^PostgreSQL .*', 'postgresql', 'any',     10),
('^Postgres .*',   'postgresql', 'any',     10),
('^MySQL .*',      'mysql',      'any',     10),
('^Redis .*',      'redis',      'any',     10),
('^nginx.*',       'nginx',      'any',     10),
('^python[0-9].*', 'python',     'any',     10),
('^nodejs.*',      'node.js',    'any',     10),
('^Git for Windows.*', 'git',    'windows', 10)
ON CONFLICT DO NOTHING;
