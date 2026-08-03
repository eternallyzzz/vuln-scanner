package server

import (
	"reflect"
	"testing"

	"vuln-scanner/internal/store"
)

func TestSeverityRank(t *testing.T) {
	cases := map[string]int{
		"": 0, "low": 1, "MEDIUM": 2, "high": 3, "Critical": 4, "bogus": 0,
	}
	for in, want := range cases {
		if got := severityRank(in); got != want {
			t.Errorf("severityRank(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestMatchesAssetFilters(t *testing.T) {
	meta := store.AssetMeta{
		Environment: "prod",
		Tags:        []string{"web", "critical"},
	}
	cases := []struct {
		name       string
		assetName  string
		tags, envs []string
		assetNames []string
		want       bool
	}{
		{"no filters", "nginx", nil, nil, nil, true},
		{"asset name match", "nginx", nil, nil, []string{"nginx"}, true},
		{"asset name miss", "nginx", nil, nil, []string{"openssl"}, false},
		{"env match", "nginx", nil, []string{"Prod"}, nil, true},
		{"env miss", "nginx", nil, []string{"dev"}, nil, false},
		{"tag match", "nginx", []string{"WEB"}, nil, nil, true},
		{"tag miss", "nginx", []string{"db"}, nil, nil, false},
		{"any tag wins", "nginx", []string{"db", "web"}, nil, nil, true},
		{"combined and", "nginx", []string{"web"}, []string{"prod"}, []string{"nginx"}, true},
		{"combined miss", "nginx", []string{"web"}, []string{"dev"}, []string{"nginx"}, false},
	}
	for _, c := range cases {
		if got := matchesAssetFilters(c.assetName, meta, c.tags, c.envs, c.assetNames); got != c.want {
			t.Errorf("matchesAssetFilters(%q, %+v, %v, %v, %v) = %v, want %v",
				c.assetName, meta, c.tags, c.envs, c.assetNames, got, c.want)
		}
	}
}

func TestValidateCampaignInput(t *testing.T) {
	base := func() campaignGenerateInput {
		return campaignGenerateInput{AgentIDs: []string{"agent-1"}}
	}

	valid := base()
	if err := validateCampaignInput(&valid); err != nil {
		t.Errorf("valid input rejected: %v", err)
	}

	in := base()
	in.AgentIDs = nil
	if err := validateCampaignInput(&in); err == nil {
		t.Error("expected error for empty selection")
	}

	in = base()
	in.MinSeverity = "urgent"
	if err := validateCampaignInput(&in); err == nil {
		t.Error("expected error for invalid severity")
	}
	in.MinSeverity = "high"
	if err := validateCampaignInput(&in); err != nil {
		t.Errorf("high severity rejected: %v", err)
	}
	if in.MinSeverity != "HIGH" {
		t.Errorf("severity not normalized: %q", in.MinSeverity)
	}

	in = base()
	in.MinCVSS = 11
	if err := validateCampaignInput(&in); err == nil {
		t.Error("expected error for cvss > 10")
	}

	in = base()
	in.WindowStart = "2026-08-03T10:00:00Z"
	in.WindowEnd = "2026-08-03T09:00:00Z"
	if err := validateCampaignInput(&in); err == nil {
		t.Error("expected error for end before start")
	}

	in = base()
	in.CVEIDs = []string{" cve-2024-0001 ", "CVE-2024-0002", ""}
	if err := validateCampaignInput(&in); err != nil {
		t.Fatalf("cve normalization failed: %v", err)
	}
	want := []string{"CVE-2024-0001", "CVE-2024-0002"}
	if !reflect.DeepEqual(in.CVEIDs, want) {
		t.Errorf("cve ids = %v, want %v", in.CVEIDs, want)
	}
}

func TestParseCampaignWindow(t *testing.T) {
	start, end, err := parseCampaignWindow("2026-08-03T10:00:00Z", "2026-08-03T12:00:00Z")
	if err != nil {
		t.Fatalf("valid window rejected: %v", err)
	}
	if start == nil || end == nil || !end.After(*start) {
		t.Error("window bounds not preserved")
	}
	if _, _, err := parseCampaignWindow("not-a-time", ""); err == nil {
		t.Error("expected error for invalid start")
	}
	if _, _, err := parseCampaignWindow("2026-08-03T12:00:00Z", "2026-08-03T10:00:00Z"); err == nil {
		t.Error("expected error for end before start")
	}
}

func TestCampaignStatusTransition(t *testing.T) {
	cases := []struct {
		action   string
		from, to string
		ok       bool
	}{
		{"approve", "pending", "approved", true},
		{"reject", "pending", "rejected", true},
		{"cancel", "pending,approved", "cancelled", true},
		{"retry", "failed,cancelled", "pending", true},
		{"explode", "", "", false},
	}
	for _, c := range cases {
		from, to, ok := campaignStatusTransition(c.action)
		if ok != c.ok {
			t.Errorf("campaignStatusTransition(%q) ok = %v, want %v", c.action, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		gotFrom := ""
		for i, s := range from {
			if i > 0 {
				gotFrom += ","
			}
			gotFrom += s
		}
		if gotFrom != c.from || to != c.to {
			t.Errorf("campaignStatusTransition(%q) = (%q,%q), want (%q,%q)",
				c.action, gotFrom, to, c.from, c.to)
		}
	}
}
