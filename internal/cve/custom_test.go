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

func TestMatchFeedEntryCustomCPE(t *testing.T) {
	affected := func(products ...AffectedProduct) json.RawMessage {
		raw, err := json.Marshal(products)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	base := FeedEntry{
		Source: "custom", CVEID: "CUSTOM-2026-005", CVEURL: "https://www.openssl.org",
		Severity: "HIGH", CVSSScore: 7.5, Summary: "s",
		Affected: affected(AffectedProduct{
			Name: "openssl", CPE: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
			MaxVer: "3.0.7", FixedIn: "3.0.7",
		}),
	}
	run := func(version string, index map[string]string) []MatchedCVE {
		names := []string{"openssl"}
		lower := map[string]bool{"openssl": true}
		return matchFeedEntry(base, names, map[string]string{"openssl": version}, lower,
			index, nil, "unknown", "", "", "")
	}

	res := run("3.0.6", map[string]string{"openssl": "3.0.6"})
	if len(res) != 1 || res[0].MatchStatus != "active" || res[0].AssetName != "openssl" ||
		res[0].AssetVersion != "3.0.6" || res[0].FixedVersion != "3.0.7" {
		t.Fatalf("custom CPE rule must match openssl 3.0.6: %+v", res)
	}
	if got := run("3.0.7", map[string]string{"openssl": "3.0.7"}); len(got) != 0 {
		t.Fatalf("openssl 3.0.7 must not match (fixed_in reached), got %d", len(got))
	}
	if got := run("3.0.6", map[string]string{"other": "1.0"}); len(got) != 0 {
		t.Fatalf("custom CPE rule must not match when CPE product is absent, got %d", len(got))
	}

	withVer := base
	withVer.Affected = affected(AffectedProduct{
		Name: "openssl", CPE: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
		CpeVer: "3.0.6", MaxVer: "3.0.7", FixedIn: "3.0.7",
	})
	verRun := func(version string) []MatchedCVE {
		names := []string{"openssl"}
		return matchFeedEntry(withVer, names, map[string]string{"openssl": version},
			map[string]bool{"openssl": true}, map[string]string{"openssl": version},
			nil, "unknown", "", "", "")
	}
	if got := verRun("3.0.5"); len(got) != 0 {
		t.Fatalf("custom CPE rule with cpe_ver must reject 3.0.5, got %d", len(got))
	}
	if got := verRun("3.0.6"); len(got) != 1 {
		t.Fatalf("custom CPE rule with cpe_ver must accept 3.0.6, got %d", len(got))
	}
}

func TestCPEMatchesCustom(t *testing.T) {
	ap := AffectedProduct{
		Name: "openssl", CPE: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
		MaxVer: "3.0.7", FixedIn: "3.0.7",
	}
	index := map[string]string{"openssl": "3.0.6"}
	if got := extractCPEProduct(ap.CPE); got != "openssl" {
		t.Fatalf("extractCPEProduct(%q) = %q, want openssl", ap.CPE, got)
	}
	if got := findMatchingKey("openssl", index); got != "openssl" {
		t.Fatalf("findMatchingKey = %q, want openssl", got)
	}
	if !cpeVersionCompatible("", "3.0.6", "openssl", index) {
		t.Fatal("cpeVersionCompatible with empty feed version must accept")
	}
	if !cpeMatches(ap, "custom", index, map[string]bool{"openssl": true}) {
		t.Fatal("custom CPE gate must accept openssl with matching index")
	}
	if cpeMatches(ap, "custom", map[string]string{"other": "1.0"}, map[string]bool{"openssl": true}) {
		t.Fatal("custom CPE gate must reject when CPE product is absent")
	}
	noCPE := AffectedProduct{Name: "nginx", MaxVer: "1.22.0", FixedIn: "1.22.0"}
	if !cpeMatches(noCPE, "custom", nil, map[string]bool{"nginx": true}) {
		t.Fatal("custom rule without CPE must keep name matching")
	}
}
