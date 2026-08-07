package cve

import "testing"

func TestNameCompatible(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"exact", "openssl", "openssl", true},
		{"exact case", "OpenSSL", "openssl", true},
		{"multi-token feed vs single asset", "python-openssl", "openssl", false},
		{"single feed vs multi-token asset", "openssl", "python-openssl", false},
		{"rpm libs without translation", "openssl", "openssl-libs", false},
		{"qualifier suffix allowed", "openssh", "openssh-server", true},
		{"qualifier suffix reverse", "openssh-server", "openssh", true},
		{"node alias needs translation", "node.js", "nodejs", false},
		{"office edition needs translation", "microsoft office", "microsoft office 365", false},
		{"7-zip normalizes", "7-zip", "7-Zip", true},
		{"empty side", "openssl", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nameCompatible(tc.a, tc.b); got != tc.want {
				t.Fatalf("nameCompatible(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestSelectBestMatchesPriority(t *testing.T) {
	nvd := MatchedCVE{
		CVEID:        "CVE-2099-0003",
		AssetName:    "openssl",
		FixedVersion: "",
		CVSSScore:    9.8,
		Severity:     "CRITICAL",
		Source:       "nvd",
		MatchStatus:  "active",
	}
	debian := MatchedCVE{
		CVEID:        "CVE-2099-0003",
		AssetName:    "openssl",
		FixedVersion: "1.1.1n-0+deb11u6",
		CVSSScore:    8.0,
		Severity:     "HIGH",
		Source:       "debian",
		MatchStatus:  "active",
	}

	got := selectBestMatches([]MatchedCVE{nvd, debian})
	if len(got) != 1 {
		t.Fatalf("selectBestMatches returned %d results, want 1", len(got))
	}
	if got[0].Source != "debian" {
		t.Fatalf("source = %q, want debian", got[0].Source)
	}
	if got[0].FixedVersion != "1.1.1n-0+deb11u6" {
		t.Fatalf("fixed version = %q, want debian advisory version", got[0].FixedVersion)
	}
	if got[0].CVSSScore != 9.8 {
		t.Fatalf("cvss = %v, want max 9.8", got[0].CVSSScore)
	}
}

func TestSelectBestMatchesTieBreak(t *testing.T) {
	a := MatchedCVE{CVEID: "CVE-1", AssetName: "b", Source: "osv", MatchStatus: "active"}
	b := MatchedCVE{CVEID: "CVE-1", AssetName: "a", Source: "osv", MatchStatus: "active"}
	got := selectBestMatches([]MatchedCVE{a, b})
	if len(got) != 2 {
		t.Fatalf("got %d results, want 2", len(got))
	}
	if got[0].AssetName != "a" || got[1].AssetName != "b" {
		t.Fatalf("results not sorted: %#v", got)
	}
}
