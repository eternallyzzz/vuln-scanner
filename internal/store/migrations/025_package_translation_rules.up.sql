ALTER TABLE package_translations ADD COLUMN IF NOT EXISTS vendor_pattern  TEXT NOT NULL DEFAULT '';
ALTER TABLE package_translations ADD COLUMN IF NOT EXISTS version_pattern TEXT NOT NULL DEFAULT '';
ALTER TABLE package_translations ADD COLUMN IF NOT EXISTS hotfix_kb      TEXT NOT NULL DEFAULT '';

-- Windows seed rules mirroring the Wazuh translation ideas: a product name
-- that embeds its version (LibreOffice 4.2.0.1) and a package that needs a
-- hotfix KB (Skype for Business Basic 2016 -> KB3114960).
INSERT INTO package_translations (pattern, cpe_name, platform, vendor_pattern, version_pattern, hotfix_kb, priority)
VALUES
('LibreOffice .*',              'libreoffice',        'windows', '(?i)the document foundation', ' (\d+(?:\.\d+)+)\s*$', '',            10),
('Skype for Business Basic .*', 'skype_for_business', 'windows', '(?i)microsoft corporation',   ' (\d+)\s*$',           'KB3114960', 10)
ON CONFLICT DO NOTHING;
