package cve

import "testing"

// TestWazuhParityCorpus re-expresses the version-boundary scenarios from
// Wazuh's vulnerability scanner QA corpus (qa/test_data 001-005/007/009) as
// vuln-scanner fixtures. The assertions mirror the upstream "does affect /
// does not affect" verdicts for the same installed version vs the same
// affected/fixed boundary.
func TestWazuhParityCorpus(t *testing.T) {
	cases := []struct {
		name         string
		installed    string
		cve          string
		ap           AffectedProduct
		wantAffected bool
	}{
		{
			name:      "001-debian-libldb2-affected",
			installed: "2:2.6.2+samba4.17.9+dfsg-0+deb12u1",
			cve:       "CVE-2023-34966",
			ap: AffectedProduct{
				Name:      "libldb2",
				MaxVer:    "2:2.6.2+samba4.17.10+dfsg-0+deb12u1",
				Ecosystem: "debian",
			},
			wantAffected: true,
		},
		{
			name:      "001-debian-libldb2-fixed",
			installed: "2:2.6.2+samba4.17.12+dfsg-0+deb12u1",
			cve:       "CVE-2023-34966",
			ap: AffectedProduct{
				Name:      "libldb2",
				MaxVer:    "2:2.6.2+samba4.17.10+dfsg-0+deb12u1",
				Ecosystem: "debian",
			},
			wantAffected: false,
		},
		{
			name:      "002-rhel-nss-affected",
			installed: "3.53.1-3.el7_9",
			cve:       "CVE-2020-25648",
			ap: AffectedProduct{
				Name:      "nss",
				MaxVer:    "0:3.53.1-7.el7_9",
				Ecosystem: "Red Hat",
			},
			wantAffected: true,
		},
		{
			name:      "003-ubuntu-networkd-dispatcher-affected",
			installed: "2.1-1~ubuntu20.04.3",
			cve:       "CVE-2022-29800",
			ap: AffectedProduct{
				Name:      "networkd-dispatcher",
				MaxVer:    "0:2.1-2~ubuntu20.04.2",
				Ecosystem: "ubuntu",
			},
			wantAffected: true,
		},
		{
			name:      "004-arch-openssh-affected",
			installed: "9.7p1-2",
			cve:       "CVE-2024-6387",
			ap: AffectedProduct{
				Name:   "openssh",
				MaxVer: "9.8p1-1",
			},
			wantAffected: true,
		},
		{
			name:      "004-arch-openssh-fixed",
			installed: "9.8p1-1",
			cve:       "CVE-2024-6387",
			ap: AffectedProduct{
				Name:   "openssh",
				MaxVer: "9.8p1-1",
			},
			wantAffected: false,
		},
		{
			name:      "005-sles-libopenssl1_1-affected",
			installed: "1.1.0i-150100.14.42.1.x86_64",
			cve:       "CVE-2002-20001",
			ap: AffectedProduct{
				Name:      "libopenssl1_1",
				MaxVer:    "0:1.1.1l-150500.15.4",
				Ecosystem: "SUSE",
			},
			wantAffected: true,
		},
		{
			name:      "007-amazon-openssh-affected",
			installed: "8.7p1-8.amzn2023.0.9",
			cve:       "CVE-2023-51385",
			ap: AffectedProduct{
				Name:      "openssh",
				MaxVer:    "8.7p1-8.amzn2023.0.10",
				Ecosystem: "rpm",
			},
			wantAffected: true,
		},
		{
			name:      "009-macos-os-affected",
			installed: "14.0",
			cve:       "CVE-2024-23224",
			ap: AffectedProduct{
				Name:   "MacOS",
				MaxVer: "14.3",
			},
			wantAffected: true,
		},
		{
			name:      "009-macos-os-fixed",
			installed: "14.3",
			cve:       "CVE-2024-23224",
			ap: AffectedProduct{
				Name:   "MacOS",
				MaxVer: "14.3",
			},
			wantAffected: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isVersionAffected(c.installed, c.ap); got != c.wantAffected {
				t.Fatalf("%s: isVersionAffected(%q) = %v, want %v",
					c.cve, c.installed, got, c.wantAffected)
			}
		})
	}
}
