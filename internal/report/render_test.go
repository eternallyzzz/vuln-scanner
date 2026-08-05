package report

import (
	"strings"
	"testing"
	"time"

	"vuln-scanner/internal/store"
)

func TestRenderHTML(t *testing.T) {
	now := time.Date(2026, 8, 5, 8, 0, 0, 0, time.UTC)
	due := now.Add(24 * time.Hour)
	eolDate := now.AddDate(0, 0, -10)
	d := Data{
		GeneratedAt: now,
		Period:      "2026-08-05",
		Summary: Summary{
			AgentsTotal: 2, AgentsOnline: 1, AssetsTotal: 5,
			ActiveCVEs: 3, FixedCVEs: 1, OpenAlerts: 2, EOLAgents: 1,
			ComplianceReported: 1, ComplianceAvgScore: 50,
		},
		Compliance: store.ComplianceSummary{
			ReportedAgents: 1, AvgScore: 50, MinScore: 50, MaxScore: 50,
			PassedChecks: 5, FailedChecks: 3, NAChecks: 2,
			TopFailedChecks: []store.FailedCheckCount{{ID: "linux.firewall_active", Title: "防火墙已激活", Count: 1}},
		},
		Risk: store.RiskSummary{
			TotalActive: 3, TotalFixed: 1, KEVCount: 1, Overdue: 1,
			AverageEPSS: 0.25, FixRate: 25,
			ByRiskLevel: map[string]int{"CRITICAL": 1, "HIGH": 2},
		},
		TopRisks: []store.RiskRow{{
			CVEID: "CVE-2024-0001", Hostname: "web-01", AssetName: "nginx",
			Severity: "HIGH", RiskLevel: "HIGH", CVSSScore: 8.5, EPSSScore: 0.2,
			KEV: true, EOL: true, DueAt: &due, Overdue: true, DetectedAt: now,
		}},
		Trend: []store.RiskTrendPoint{{Date: "2026-08-05", Active: 3, New: 1, Fixed: 0}},
		EOLAgents: []store.EOLAgentRow{{
			AgentID: "agent-1", Hostname: "legacy-01", OSType: "windows",
			OSVersion: "10", EOLStatus: "eol", EOLDate: &eolDate,
			EOLProduct: "windows", EOLCycle: "10", LastSeen: now,
		}},
		Alerts: []store.AlertDetail{{
			Alert: store.Alert{
				ID: 7, CVEID: "CVE-2024-0001", AssetName: "nginx",
				AgentID: "agent-1", Severity: "HIGH", FirstSeen: now, LastSeen: now,
			},
			RuleName: "high-severity",
		}},
		Patch:        store.PatchSummary{TasksByStatus: map[string]int{"pending": 1}, Campaigns: 2},
		AuditLast24h: 5,
	}

	html, err := RenderHTML(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"每日安全报告", "CVE-2024-0001", "web-01", "agent-1", ">1<", "合规概览", "linux.firewall_active"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}

func TestBuildCSV(t *testing.T) {
	now := time.Date(2026, 8, 5, 8, 0, 0, 0, time.UTC)
	d := Data{
		Risks: []store.RiskRow{{
			CVEID: "CVE-2024-0001", CanonicalCVEID: "CVE-2024-0001",
			AgentID: "agent-1", Hostname: "web-01", AssetName: "nginx",
			Severity: "HIGH", RiskLevel: "HIGH", CVSSScore: 8.5, EPSSScore: 0.2,
			KEV: true, ExposureScore: 7, AssetCriticality: 8, RiskScore: 8.4,
			EOL: true, EOLProduct: "windows", DetectedAt: now,
			Overdue: true, FixedVersion: "1.2.3",
		}},
	}
	csv, err := BuildCSV(d)
	if err != nil {
		t.Fatal(err)
	}
	text := string(csv)
	if !strings.HasPrefix(text, "cve_id,canonical_cve_id,agent_id,hostname,asset_name") {
		t.Fatalf("unexpected header: %q", text)
	}
	if !strings.Contains(text, "CVE-2024-0001") || !strings.Contains(text, "true") {
		t.Fatalf("unexpected CSV body: %q", text)
	}
}
