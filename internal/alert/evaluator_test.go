package alert

import (
	"testing"

	"vuln-scanner/internal/store"
)

func testRule() store.AlertRule {
	return store.AlertRule{
		Name:           "high-nvd",
		Enabled:        true,
		SeverityFilter: "HIGH",
		SourceFilter:   "nvd",
		AgentIDFilter:  "agent-1",
		AssetFilter:    "openssl",
		MinCVSS:        7.0,
	}
}

func TestRuleMatchesFilters(t *testing.T) {
	rule := testRule()
	ok := Result{CVEID: "CVE-1", AssetName: "openssl", Severity: "CRITICAL", Source: "nvd", CVSSScore: 9.8, Status: "active"}
	if !ruleMatches(rule, "agent-1", ok, store.AssetMeta{}) {
		t.Fatal("expected match")
	}

	if ruleMatches(rule, "agent-2", ok, store.AssetMeta{}) {
		t.Fatal("agent filter must reject")
	}
	if ruleMatches(rule, "agent-1", Result{CVEID: "CVE-1", AssetName: "openssl", Severity: "MEDIUM", Source: "nvd", CVSSScore: 9.8}, store.AssetMeta{}) {
		t.Fatal("severity filter must reject MEDIUM")
	}
	if ruleMatches(rule, "agent-1", Result{CVEID: "CVE-1", AssetName: "openssl", Severity: "HIGH", Source: "osv", CVSSScore: 9.8}, store.AssetMeta{}) {
		t.Fatal("source filter must reject osv")
	}
	if ruleMatches(rule, "agent-1", Result{CVEID: "CVE-1", AssetName: "libssl", Severity: "HIGH", Source: "nvd", CVSSScore: 9.8}, store.AssetMeta{}) {
		t.Fatal("asset filter must reject libssl")
	}
	if ruleMatches(rule, "agent-1", Result{CVEID: "CVE-1", AssetName: "openssl", Severity: "HIGH", Source: "nvd", CVSSScore: 6.0}, store.AssetMeta{}) {
		t.Fatal("min_cvss must reject 6.0")
	}
	if ruleMatches(rule, "agent-1", Result{CVEID: "CVE-1", AssetName: "openssl", Severity: "HIGH", Source: "nvd", CVSSScore: 8.0, Status: "fixed"}, store.AssetMeta{}) {
		t.Fatal("fixed status must not alert")
	}

	disabled := testRule()
	disabled.Enabled = false
	if ruleMatches(disabled, "agent-1", ok, store.AssetMeta{}) {
		t.Fatal("disabled rule must not match")
	}
}

func TestRuleMatchesEmptyFilters(t *testing.T) {
	rule := store.AlertRule{Enabled: true, Name: "all"}
	if !ruleMatches(rule, "any-agent", Result{CVEID: "CVE-9", AssetName: "anything", Severity: "LOW", Source: "debian", CVSSScore: 0}, store.AssetMeta{}) {
		t.Fatal("empty filters should match any active result")
	}
	if ruleMatches(rule, "any-agent", Result{AssetName: "no-cve"}, store.AssetMeta{}) {
		t.Fatal("empty cve must not match")
	}
}

func TestRuleMatchesTagAndEnvironment(t *testing.T) {
	rule := store.AlertRule{
		Enabled:           true,
		SeverityFilter:    "HIGH",
		AssetTagFilter:    []string{"critical-host", "dmz"},
		EnvironmentFilter: "production",
	}
	res := Result{CVEID: "CVE-1", AssetName: "openssl", Severity: "HIGH", Source: "nvd", CVSSScore: 9.0}
	if !ruleMatches(rule, "a", res, store.AssetMeta{Tags: []string{"dmz"}, Environment: "production"}) {
		t.Fatal("tag+env match expected")
	}
	if ruleMatches(rule, "a", res, store.AssetMeta{Tags: []string{"internal"}, Environment: "production"}) {
		t.Fatal("tag mismatch must reject")
	}
	if ruleMatches(rule, "a", res, store.AssetMeta{Tags: []string{"dmz"}, Environment: "staging"}) {
		t.Fatal("env mismatch must reject")
	}
	if ruleMatches(rule, "a", res, store.AssetMeta{}) {
		t.Fatal("missing meta must reject")
	}
}

func TestSeverityRanking(t *testing.T) {
	if severityRank["HIGH"] <= severityRank["MEDIUM"] {
		t.Fatal("HIGH must rank above MEDIUM")
	}
	if severityRank["CRITICAL"] <= severityRank["HIGH"] {
		t.Fatal("CRITICAL must rank above HIGH")
	}
}
