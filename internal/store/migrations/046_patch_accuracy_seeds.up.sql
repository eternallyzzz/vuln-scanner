-- Patch matching accuracy seeds (round 2): Windows multi-word product
-- translations. Higher-priority rules run first, so Visual Studio Code must
-- never fall through to the generic Visual Studio rule. All rows are pure
-- seeds and are safe to re-run anywhere (ON CONFLICT DO NOTHING).
INSERT INTO package_translations (pattern, cpe_name, platform, priority) VALUES
('^Microsoft Visual Studio Code.*', 'visual_studio_code', 'windows', 20),
('^Microsoft Visual Studio .*',    'visual_studio',      'windows', 10),
('^Microsoft Office.*',            'office',             'windows', 10),
('^Microsoft Edge.*',              'edge',               'windows', 10),
('^Google Chrome.*',               'chrome',             'windows', 10)
ON CONFLICT DO NOTHING;
