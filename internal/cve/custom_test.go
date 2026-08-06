package cve

import (
	"encoding/json"
	"testing"

	"vuln-scanner/internal/store"
)

func TestCustomIntelFeedEntries(t *testing.T) {
	rows := []store.CustomIntel{
		{
			ID: 1, IntelID: "CUSTOM-2026-001", Title: "Nginx", Summary: "s",
			Severity: "HIGH", CVSSScore: 7.5, AdvisoryURL: "https://nginx.org",
			Affected: json.RawMessage(`[{"name":"nginx","max_ver":"1.22.0","fixed_in":"1.22.0"}]`),
			Enabled:  true,
		},
		{
			ID: 2, IntelID: "CUSTOM-BAD", Title: "bad",
			Affected: json.RawMessage(`[]`), Enabled: true,
		},
	}
	entries := customIntelFeedEntries(rows)
	if len(entries) != 1 {
		t.Fatalf("customIntelFeedEntries = %d entries, want 1 (invalid row skipped)", len(entries))
	}
	e := entries[0]
	if e.Source != "custom" || e.SourceKey != "intel-1" || e.CVEID != "CUSTOM-2026-001" ||
		e.CVEURL != "https://nginx.org" || e.Severity != "HIGH" || e.CVSSScore != 7.5 ||
		e.Summary != "s" {
		t.Fatalf("unexpected feed entry: %+v", e)
	}
	if len(customIntelFeedEntries(nil)) != 0 {
		t.Fatal("empty rules must produce no entries")
	}
}

func TestNormalizeCustomAffected(t *testing.T) {
	if _, err := normalizeCustomAffected(json.RawMessage(`[{"name":"nginx","max_ver":"1.22.0"}]`)); err != nil {
		t.Fatalf("valid affected rejected: %v", err)
	}
	for _, raw := range []string{``, `[]`, `{}`, `[{"max_ver":"1.0"}]`, `not json`} {
		if _, err := normalizeCustomAffected(json.RawMessage(raw)); err == nil {
			t.Fatalf("invalid affected %q accepted", raw)
		}
	}
}

func TestMatchFeedEntryCustomSource(t *testing.T) {
	affected := func(products ...AffectedProduct) json.RawMessage {
		raw, err := json.Marshal(products)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	names := []string{"nginx"}
	lower := map[string]bool{"nginx": true}
	base := FeedEntry{
		Source: "custom", CVEID: "CUSTOM-2026-001", CVEURL: "https://nginx.org",
		Severity: "HIGH", CVSSScore: 7.5, Summary: "s",
	}

	run := func(e FeedEntry, version string) []MatchedCVE {
		return matchFeedEntry(e, names, map[string]string{"nginx": version}, lower,
			nil, nil, "unknown", "", "", "")
	}

	e := base
	e.Affected = affected(AffectedProduct{Name: "nginx", MaxVer: "1.22.0", FixedIn: "1.22.0"})
	res := run(e, "1.21.5")
	if len(res) != 1 {
		t.Fatalf("nginx 1.21.5 must match custom rule, got %d results", len(res))
	}
	if res[0].Source != "custom" || res[0].CVEID != "CUSTOM-2026-001" ||
		res[0].AssetVersion != "1.21.5" || res[0].FixedVersion != "1.22.0" ||
		res[0].MatchStatus != "active" || res[0].Severity != "HIGH" || res[0].CVSSScore != 7.5 {
		t.Fatalf("unexpected custom match: %+v", res[0])
	}
	if got := run(e, "1.22.0"); len(got) != 0 {
		t.Fatalf("nginx 1.22.0 must not match (max exclusive), got %d", len(got))
	}

	e2 := base
	e2.CVEID = "CUSTOM-X"
	e2.Affected = affected(AffectedProduct{Name: "nginx", MinVer: "1.0.0", MaxVer: "1.22.0", FixedIn: "1.20.0"})
	res = run(e2, "1.21.5")
	if len(res) != 1 || res[0].MatchStatus != "fixed" || res[0].FixedVersion != "1.20.0" {
		t.Fatalf("fixed_in reached must mark fixed: %+v", res)
	}

	e3 := base
	e3.CVEID = "CUSTOM-Y"
	e3.Affected = affected(AffectedProduct{Name: "nginx"})
	if got := run(e3, "1.21.5"); len(got) != 0 {
		t.Fatalf("rule without version range must not match, got %d", len(got))
	}
}

func TestMatchFeedEntryCustomMultiRangeAndSuffix(t *testing.T) {
	affected := func(products ...AffectedProduct) json.RawMessage {
		raw, err := json.Marshal(products)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	redis := FeedEntry{
		Source: "custom", CVEID: "CUSTOM-2026-003", Severity: "HIGH", CVSSScore: 8.8,
		Affected: affected(
			AffectedProduct{Name: "redis", MaxVer: "6.2.13", FixedIn: "6.2.13"},
			AffectedProduct{Name: "redis", MinVer: "7.0.0", MaxVer: "7.0.15", FixedIn: "7.0.15"},
		),
	}
	run := func(version string) []MatchedCVE {
		return matchFeedEntry(redis, []string{"redis"}, map[string]string{"redis": version},
			map[string]bool{"redis": true}, nil, nil, "unknown", "", "", "")
	}
	if got := run("6.2.12"); len(got) != 1 || got[0].MatchStatus != "active" {
		t.Fatalf("redis 6.2.12 must match first range: %+v", got)
	}
	if got := run("7.0.10"); len(got) != 1 || got[0].MatchStatus != "active" {
		t.Fatalf("redis 7.0.10 must match second range: %+v", got)
	}
	if got := run("7.0.15"); len(got) != 0 {
		t.Fatalf("redis 7.0.15 must not match, got %d", len(got))
	}

	ssh := FeedEntry{
		Source: "custom", CVEID: "CUSTOM-2026-002", Severity: "MEDIUM",
		Affected: affected(AffectedProduct{Name: "openssh", MaxVer: "9.6p1", FixedIn: "9.6p1"}),
	}
	sshRun := func(version string) []MatchedCVE {
		return matchFeedEntry(ssh, []string{"openssh"}, map[string]string{"openssh": version},
			map[string]bool{"openssh": true}, nil, nil, "unknown", "", "", "")
	}
	if got := sshRun("9.3p1"); len(got) != 1 || got[0].MatchStatus != "active" {
		t.Fatalf("openssh 9.3p1 must match, got %+v", got)
	}
	if got := sshRun("9.6p1"); len(got) != 0 {
		t.Fatalf("openssh 9.6p1 must not match, got %d", len(got))
	}
}
