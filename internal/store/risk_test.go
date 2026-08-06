package store

import (
	"testing"

	"vuln-scanner/internal/collector"
)

func TestCanonicalCVEID(t *testing.T) {
	cases := map[string]string{
		"DEBIAN-CVE-2026-42770": "CVE-2026-42770",
		"UBUNTU-CVE-2025-69418": "CVE-2025-69418",
		"ALPINE-CVE-2026-40200": "CVE-2026-40200",
		"CVE-2021-43893":        "CVE-2021-43893",
		"DSA-6113-1":            "DSA-6113-1",
		"USN-1234-1":            "USN-1234-1",
		"ADV180012":             "ADV180012",
	}
	for in, want := range cases {
		if got := CanonicalCVEID(in); got != want {
			t.Errorf("CanonicalCVEID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRiskScoreAndLevel(t *testing.T) {
	if got := RiskScore(9.8, 0.97, 9, 9, false, false); got != 9.5 {
		t.Fatalf("high risk score = %v, want 9.5", got)
	}
	if got := RiskScore(9.8, 0.01, 9, 9, true, false); got != 9.0 {
		t.Fatalf("kev must raise the score to 9: %v", got)
	}
	if got := RiskScore(5, 0, 2, 2, false, false); got != 2.7 {
		t.Fatalf("low risk score = %v, want 2.7", got)
	}
	if got := RiskScore(9.8, 0, 4, 2, false, false); got != 5.0 {
		t.Fatalf("medium risk score = %v, want 5.0", got)
	}
	if got := RiskScore(5, 0, 2, 2, false, true); got != 3.2 {
		t.Fatalf("eol bonus = %v, want 3.2", got)
	}
	if got := RiskScore(9.8, 0.97, 9, 9, false, true); got != 10.0 {
		t.Fatalf("eol bonus must cap at 10: %v", got)
	}
	if got := RiskScore(9.8, 0.01, 9, 9, true, true); got != 9.5 {
		t.Fatalf("kev + eol = %v, want 9.5", got)
	}
	if RiskLevel(8.5) != "CRITICAL" || RiskLevel(7.0) != "HIGH" ||
		RiskLevel(4.0) != "MEDIUM" || RiskLevel(3.9) != "LOW" {
		t.Fatal("risk level bucketing wrong")
	}
}

func TestApplyIntelRiskFloor(t *testing.T) {
	cases := []struct {
		name        string
		score       float64
		threatLevel string
		exploited   bool
		want        float64
	}{
		{"unannotated unchanged", 2.7, "", false, 2.7},
		{"exploited raises to 9", 3.0, "LOW", true, 9.0},
		{"exploited keeps higher score", 9.5, "LOW", true, 9.5},
		{"critical floor", 5.0, "CRITICAL", false, 9.0},
		{"high floor", 5.0, "HIGH", false, 7.0},
		{"medium floor", 3.2, "MEDIUM", false, 5.0},
		{"low is no floor", 3.2, "LOW", false, 3.2},
		{"case insensitive", 5.0, "critical", false, 9.0},
		{"unknown level unchanged", 5.0, "SEVERE", false, 5.0},
		{"cap at 10", 10.4, "CRITICAL", true, 10.0},
		{"score above floor unchanged", 9.2, "CRITICAL", false, 9.2},
	}
	for _, tc := range cases {
		if got := applyIntelRiskFloor(tc.score, tc.threatLevel, tc.exploited); got != tc.want {
			t.Errorf("%s: applyIntelRiskFloor(%v, %q, %v) = %v, want %v",
				tc.name, tc.score, tc.threatLevel, tc.exploited, got, tc.want)
		}
	}
}

func TestAnnotationLookupKeys(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"CVE-2021-44228", []string{"CVE-2021-44228"}},
		{"DEBIAN-CVE-2021-44228", []string{"DEBIAN-CVE-2021-44228", "CVE-2021-44228"}},
		{"UBUNTU-CVE-2023-34362", []string{"UBUNTU-CVE-2023-34362", "CVE-2023-34362"}},
		{"ALPINE-CVE-2024-3400", []string{"ALPINE-CVE-2024-3400", "CVE-2024-3400"}},
		{"DSA-6113-1", []string{"DSA-6113-1"}},
	}
	for _, tc := range cases {
		got := annotationLookupKeys(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("annotationLookupKeys(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("annotationLookupKeys(%q) = %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}
}

func TestAssetCriticality(t *testing.T) {
	if got := AssetCriticality("production", []string{"core"}, "host"); got != 10 {
		t.Fatalf("prod core host = %v, want 10", got)
	}
	if got := AssetCriticality("test", nil, "software"); got != 5 {
		t.Fatalf("test software = %v, want 5", got)
	}
	if got := AssetCriticality("", nil, ""); got != 4 {
		t.Fatalf("unknown asset = %v, want 4", got)
	}
	if got := AssetCriticality("", []string{"db"}, ""); got != 9 {
		t.Fatalf("db tag = %v, want 9", got)
	}
}

func TestExposureScore(t *testing.T) {
	ports := []collector.PortInfo{{Protocol: "tcp", Address: "0.0.0.0", Port: 8080, Process: "nginx(123)"}}
	procs := []collector.ProcessInfo{{PID: 1, Name: "nginx"}}
	if got := ExposureScore(ports, nil, "nginx", "software", true); got != 9 {
		t.Fatalf("port match = %v, want 9", got)
	}
	if got := ExposureScore(nil, procs, "nginx", "software", true); got != 6 {
		t.Fatalf("process match = %v, want 6", got)
	}
	if got := ExposureScore(nil, nil, "web", "container", true); got != 7 {
		t.Fatalf("container = %v, want 7", got)
	}
	if got := ExposureScore(nil, nil, "web", "software", false); got != 3 {
		t.Fatalf("no telemetry = %v, want 3", got)
	}
	if got := ExposureScore(nil, nil, "web", "software", true); got != 2 {
		t.Fatalf("default = %v, want 2", got)
	}
}
