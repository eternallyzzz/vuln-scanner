package cve

import (
	"testing"

	"vuln-scanner/internal/collector"
)

func TestParseWindowsFullBuild(t *testing.T) {
	cases := []struct {
		version     string
		build       int
		revision    int
		hasRevision bool
		ok          bool
	}{
		{"10.0.22621.3007", 22621, 3007, true, true},
		{"6.3.22621.3007", 22621, 3007, true, true},
		{"10.0.22621", 22621, 0, false, true},
		{"22621.674", 22621, 674, true, true},
		{"10.0.19045", 19045, 0, false, true},
		{"not-a-version", 0, 0, false, false},
	}
	for _, tc := range cases {
		build, rev, hasRev, ok := parseWindowsFullBuild(tc.version)
		if build != tc.build || rev != tc.revision || hasRev != tc.hasRevision || ok != tc.ok {
			t.Fatalf("parseWindowsFullBuild(%q) = (%d,%d,%v,%v), want (%d,%d,%v,%v)",
				tc.version, build, rev, hasRev, ok,
				tc.build, tc.revision, tc.hasRevision, tc.ok)
		}
	}
}

func TestMsrcOSFixedByBuild(t *testing.T) {
	cases := []struct {
		agent string
		fixed string
		want  bool
	}{
		{"10.0.22621.3007", "10.0.22621.674", true},
		{"10.0.22621.300", "10.0.22621.674", false},
		{"10.0.22622.1", "10.0.22621.674", true},
		{"10.0.22621.674", "10.0.22621.674", true},
		{"10.0.22621", "10.0.22621.674", false},
		{"10.0.22621.3007", "10.0.22621", false},
		{"10.0.22621.3007", "10.0.22622.0", false},
		{"10.0.22621.3007", "garbage", false},
	}
	for _, tc := range cases {
		if got := msrcOSFixedByBuild(tc.agent, tc.fixed); got != tc.want {
			t.Fatalf("msrcOSFixedByBuild(%q, %q) = %v, want %v", tc.agent, tc.fixed, got, tc.want)
		}
	}
}

func TestApplyWUAVerificationPendingWins(t *testing.T) {
	results := []MatchedCVE{{
		CVEID: "CVE-2021-34527", Source: "msrc", KBArticle: "KB5004945",
		MatchStatus: "fixed",
	}}
	facts := []collector.UpdateFact{{
		KB: "KB5004945", State: "pending", Source: "wua",
	}}
	status := &collector.UpdateSourceStatus{SourceReachable: true}
	got := applyWUAVerification(results, facts, status)
	if got[0].MatchStatus != "active" {
		t.Fatalf("pending WUA fact must override local fixed, got %q", got[0].MatchStatus)
	}
	if got[0].VerificationSource != "wua" {
		t.Fatalf("verification source wrong: %q", got[0].VerificationSource)
	}
	if got[0].FixedVersion != "KB5004945" {
		t.Fatalf("active result should keep recommended KB, got %q", got[0].FixedVersion)
	}
}

func TestApplyWUAVerificationInstalledWins(t *testing.T) {
	results := []MatchedCVE{{
		CVEID: "CVE-2021-34527", Source: "msrc", KBArticle: "KB5004945",
		MatchStatus: "active",
	}}
	facts := []collector.UpdateFact{{
		KB: "KB5004945", State: "installed", Source: "wsus",
	}}
	status := &collector.UpdateSourceStatus{SourceReachable: true}
	got := applyWUAVerification(results, facts, status)
	if got[0].MatchStatus != "fixed" {
		t.Fatalf("installed WUA fact must override local active, got %q", got[0].MatchStatus)
	}
	if got[0].VerificationSource != "wsus" {
		t.Fatalf("verification source wrong: %q", got[0].VerificationSource)
	}
}

func TestApplyWUAVerificationUnreachableFallsBack(t *testing.T) {
	results := []MatchedCVE{{
		CVEID: "CVE-2021-34527", Source: "msrc", KBArticle: "KB5004945",
		MatchStatus: "active",
	}}
	facts := []collector.UpdateFact{{
		KB: "KB5004945", State: "installed", Source: "wua",
	}}
	status := &collector.UpdateSourceStatus{SourceReachable: false}
	got := applyWUAVerification(results, facts, status)
	if got[0].MatchStatus != "active" {
		t.Fatalf("unreachable WUA must not override local inference, got %q", got[0].MatchStatus)
	}
	if got[0].VerificationSource != "local" {
		t.Fatalf("fallback must be labelled local, got %q", got[0].VerificationSource)
	}
}

func TestApplyWUAVerificationNoFactForKB(t *testing.T) {
	results := []MatchedCVE{{
		CVEID: "CVE-2021-34527", Source: "msrc", KBArticle: "KB5004945",
		MatchStatus: "active",
	}}
	facts := []collector.UpdateFact{{
		KB: "KB9999999", State: "pending", Source: "wua",
	}}
	status := &collector.UpdateSourceStatus{SourceReachable: true}
	got := applyWUAVerification(results, facts, status)
	if got[0].MatchStatus != "active" || got[0].VerificationSource != "local" {
		t.Fatalf("missing KB fact must keep local result, got %+v", got[0])
	}
}
