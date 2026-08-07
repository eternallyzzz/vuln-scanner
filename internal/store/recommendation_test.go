package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestActiveVersionFixGroups verifies that version-style recommendations are
// grouped per (asset, fixed_version) instead of collapsing every CVE under
// one MAX version, and that KB fixes are excluded from the groups.
func TestActiveVersionFixGroups(t *testing.T) {
	s := testWorkerScaleDB(t)
	ctx := context.Background()
	agentID := fmt.Sprintf("agent-fixgroups-%d", time.Now().UnixNano())
	now := time.Now().UTC()
	if err := s.CreateAgent(ctx, &Agent{
		ID:        agentID,
		Hostname:  agentID + ".local",
		OSType:    "linux",
		OSVersion: "Debian 12",
		Arch:      "amd64",
		Status:    "online",
		TokenHash: "fixgroups-token",
		LastSeen:  now,
		CreatedAt: now,
		UpdatedAt: now,
	}, 1); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteAgent(ctx, agentID) })

	seed := func(cveID, asset, fixed, source string, cvss float64, severity string) {
		t.Helper()
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO cve_results (agent_id, cve_id, asset_name, asset_version,
				fixed_version, severity, cvss_score, source, status)
			VALUES ($1,$2,$3,'1.0.0',$4,$6,$5,$7,'active')
			ON CONFLICT (agent_id, cve_id, asset_name, asset_version)
			DO UPDATE SET fixed_version=$4, severity=$6, source=$7, status='active'
		`, agentID, cveID, asset, fixed, cvss, severity, source); err != nil {
			t.Fatalf("seed %s: %v", cveID, err)
		}
	}
	seed("CVE-FG-0001", "curl", "8.4.0", "debian", 7.0, "HIGH")
	seed("CVE-FG-0002", "curl", "8.4.0", "osv", 8.0, "HIGH")
	seed("CVE-FG-0003", "curl", "9.0.0", "nvd", 9.0, "CRITICAL")
	seed("CVE-FG-0004", "openssl", "KB5000000", "msrc", 9.5, "CRITICAL")

	groups, err := s.ActiveVersionFixGroups(ctx, agentID, "", 0, nil)
	if err != nil {
		t.Fatalf("groups: %v", err)
	}
	curl := groups["curl"]
	if len(curl) != 2 {
		t.Fatalf("curl groups = %d, want 2 (8.4.0 and 9.0.0)", len(curl))
	}
	first := curl[0]
	if first.FixedVersion != "8.4.0" || len(first.CVEIDs) != 2 {
		t.Fatalf("first group = %+v, want 8.4.0 with 2 CVEs", first)
	}
	if first.MaxCVSS != 8.0 {
		t.Fatalf("first group max cvss = %v, want 8.0", first.MaxCVSS)
	}
	second := curl[1]
	if second.FixedVersion != "9.0.0" || len(second.CVEIDs) != 1 || second.CVEIDs[0] != "CVE-FG-0003" {
		t.Fatalf("second group = %+v", second)
	}
	if _, ok := groups["openssl"]; ok {
		t.Fatalf("KB fix must not appear in version groups: %+v", groups["openssl"])
	}

	filtered, err := s.ActiveVersionFixGroups(ctx, agentID, "CRITICAL", 0, nil)
	if err != nil {
		t.Fatalf("filtered groups: %v", err)
	}
	if len(filtered["curl"]) != 1 || filtered["curl"][0].FixedVersion != "9.0.0" {
		t.Fatalf("critical filter groups = %+v, want only 9.0.0", filtered["curl"])
	}

	recs, err := s.GetAgentRecommendations(ctx, agentID)
	if err != nil {
		t.Fatalf("recommendations: %v", err)
	}
	var curlRec *FixRecommendation
	for i := range recs {
		if recs[i].AssetName == "curl" {
			curlRec = &recs[i]
			break
		}
	}
	if curlRec == nil {
		t.Fatal("curl recommendation missing")
	}
	if len(curlRec.FixGroups) != 2 {
		t.Fatalf("curl recommendation fix_groups = %d, want 2", len(curlRec.FixGroups))
	}
	if curlRec.FixedVersion != "9.0.0" {
		t.Fatalf("legacy fixed_version should stay the MAX for compatibility, got %q", curlRec.FixedVersion)
	}
}
