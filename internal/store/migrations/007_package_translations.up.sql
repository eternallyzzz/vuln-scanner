CREATE TABLE IF NOT EXISTS package_translations (
    id       BIGSERIAL PRIMARY KEY,
    pattern  TEXT NOT NULL,
    cpe_name TEXT NOT NULL,
    platform TEXT NOT NULL DEFAULT 'any',
    priority INT  NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_pt_platform ON package_translations(platform);

INSERT INTO package_translations (pattern, cpe_name, platform) VALUES
('Microsoft \.NET .*',               '.net',                 'windows'),
('Microsoft Visual C\+\+.*',         'visual_c++',           'windows'),
('Notepad\+\+.*',                    'notepad-plus-plus',    'windows'),
('Mozilla Firefox.*',                'firefox',              'windows'),
('Mozilla Maintenance.*',            'firefox',              'windows'),
('Git$',                             'git',                  'windows'),
('Python [0-9].*',                   'python',               'any'),
('Docker.*',                         'docker',               'any'),
('VMware.*',                         'workstation',          'windows'),
('OpenSSL.*',                        'openssl',              'any'),
('Node\.js.*',                       'node.js',              'any'),
('Typora.*',                         'typora',               'any'),
('PremiumSoft Navicat.*',            'navicat',              'windows'),
('AMD Software.*',                   'radeon_software',      'windows'),
('AMD_Chipset_Drivers.*',            'amd',                  'windows'),
('Wireshark.*',                      'wireshark',            'any'),
('Steam.*',                          'steam',                'windows'),
('OBS Studio.*',                     'obs',                  'any'),
('7-Zip.*',                          '7-zip',                'any'),
('libssl[0-9].*',                    'openssl',              'debian'),
('linux-image-.*',                   'linux_kernel',         'debian'),
('systemd.*',                        'systemd',              'debian'),
('libc[0-9]?$',                      'glibc',                'debian'),
('libc-bin',                         'glibc',                'debian'),
('libpam.*',                         'pam',                  'debian'),
('openssh-.*',                       'openssh',              'debian'),
('TortoiseGit.*',                    'tortoisegit',          'windows')
ON CONFLICT DO NOTHING;
