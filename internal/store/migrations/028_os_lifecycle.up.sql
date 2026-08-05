CREATE TABLE IF NOT EXISTS os_lifecycle (
    product      TEXT NOT NULL,
    cycle        TEXT NOT NULL,
    eol_date     DATE,
    support_date DATE,
    lts          BOOLEAN NOT NULL DEFAULT FALSE,
    notes        TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (product, cycle)
);

-- Static lifecycle seeds (approximate, based on vendor public lifecycle pages
-- as of 2026-08; verify against the vendor before relying on a specific date).
INSERT INTO os_lifecycle (product, cycle, eol_date, support_date, lts, notes) VALUES
('windows', '7',        '2020-01-14', NULL, FALSE, 'extended support ended'),
('windows', '8.1',      '2023-01-10', NULL, FALSE, 'extended support ended'),
('windows', '10',       '2025-10-14', NULL, FALSE, 'family-level date'),
('windows', '11',       '2034-10-08', NULL, FALSE, 'family-level approximation; per-release dates vary'),
('windows-server', '2012 r2', '2023-10-10', NULL, FALSE, 'extended support ended'),
('windows-server', '2016', '2027-01-12', NULL, FALSE, ''),
('windows-server', '2019', '2029-01-09', NULL, FALSE, ''),
('windows-server', '2022', '2031-10-14', NULL, FALSE, ''),
('windows-server', '2025', '2034-10-10', NULL, FALSE, ''),
('ubuntu', '18.04', '2023-05-31', NULL, TRUE, 'standard support ended; ESM available'),
('ubuntu', '20.04', '2025-05-29', NULL, TRUE, 'standard support ended; ESM available'),
('ubuntu', '22.04', '2027-06-01', NULL, TRUE, ''),
('ubuntu', '24.04', '2029-06-01', NULL, TRUE, ''),
('ubuntu', '23.10', '2024-07-11', NULL, FALSE, 'interim release'),
('ubuntu', '24.10', '2025-07-17', NULL, FALSE, 'interim release'),
('ubuntu', '25.04', '2026-01-31', NULL, FALSE, 'interim release'),
('debian', '10', '2024-06-30', NULL, FALSE, 'LTS ended'),
('debian', '11', '2026-08-31', NULL, FALSE, 'LTS window'),
('debian', '12', '2028-06-30', NULL, FALSE, ''),
('debian', '13', '2030-06-30', NULL, FALSE, ''),
('centos', '7', '2024-06-30', NULL, FALSE, ''),
('centos', '8', '2021-12-31', NULL, FALSE, ''),
('centos-stream', '8', '2024-05-31', NULL, FALSE, ''),
('centos-stream', '9', '2027-05-31', NULL, FALSE, ''),
('almalinux', '8', '2029-03-01', NULL, FALSE, ''),
('almalinux', '9', '2032-05-31', NULL, FALSE, ''),
('rocky', '8', '2029-05-31', NULL, FALSE, ''),
('rocky', '9', '2032-05-31', NULL, FALSE, ''),
('sles', '12', '2027-10-31', NULL, FALSE, ''),
('sles', '15', '2031-07-31', NULL, FALSE, ''),
('amazon-linux', '1', '2023-12-31', NULL, FALSE, ''),
('amazon-linux', '2', '2025-06-30', NULL, FALSE, ''),
('amazon-linux', '2023', '2028-03-15', NULL, FALSE, ''),
('fedora', '40', '2025-05-13', NULL, FALSE, 'short-lived release'),
('fedora', '41', '2025-11-12', NULL, FALSE, 'short-lived release'),
('fedora', '42', '2026-05-12', NULL, FALSE, 'short-lived release'),
('rhel', '7', '2024-06-30', NULL, FALSE, 'ELS available'),
('rhel', '8', '2029-05-31', NULL, FALSE, ''),
('rhel', '9', '2032-05-31', NULL, FALSE, ''),
('arch', 'rolling', NULL, NULL, FALSE, 'rolling release, no fixed EOL')
ON CONFLICT (product, cycle) DO NOTHING;

ALTER TABLE agents ADD COLUMN IF NOT EXISTS eol_status  TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS eol_date    DATE;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS eol_product TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS eol_cycle   TEXT NOT NULL DEFAULT '';
