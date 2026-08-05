package eol

import (
	"testing"
	"time"

	"vuln-scanner/internal/store"
)

func TestNormalizeOS(t *testing.T) {
	cases := []struct {
		osType, osVersion, wantProduct, wantCycle string
	}{
		{"Ubuntu 22.04 LTS", "22.04.4", "ubuntu", "22.04"},
		{"Ubuntu 20.04.6 LTS", "20.04", "ubuntu", "20.04"},
		{"Debian GNU/Linux 12 (bookworm)", "12.5", "debian", "12"},
		{"CentOS Stream 9", "9", "centos-stream", "9"},
		{"CentOS Linux 7 (Core)", "7.9.2009", "centos", "7"},
		{"AlmaLinux 9.4", "9.4", "almalinux", "9"},
		{"Rocky Linux 8.10", "8.10", "rocky", "8"},
		{"SUSE Linux Enterprise Server 15 SP5", "15.5", "sles", "15"},
		{"Amazon Linux 2023", "2023.4.20240416", "amazon-linux", "2023"},
		{"Amazon Linux 2", "2.0.20240416", "amazon-linux", "2"},
		{"Fedora Linux 42", "42", "fedora", "42"},
		{"Red Hat Enterprise Linux 9.4", "9.4", "rhel", "9"},
		{"Arch Linux", "rolling", "arch", "rolling"},
		{"Windows 10 Pro 22H2", "10.0.19045.4043", "windows", "10"},
		{"Windows 11 Pro", "10.0.22631.3007", "windows", "11"},
		{"Windows Server 2019 Standard", "10.0.17763.1", "windows-server", "2019"},
		{"Windows Server 2025", "10.0.26100.1", "windows-server", "2025"},
		{"macOS 14.0", "14.0", "", ""},
		{"", "", "", ""},
	}
	for _, c := range cases {
		p, cy := NormalizeOS(c.osType, c.osVersion)
		if p != c.wantProduct || cy != c.wantCycle {
			t.Errorf("NormalizeOS(%q, %q) = (%q, %q), want (%q, %q)",
				c.osType, c.osVersion, p, cy, c.wantProduct, c.wantCycle)
		}
	}
}

func lifecycleRows() []store.OSLifecycle {
	ubuntu2204 := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	win10 := time.Date(2025, 10, 14, 0, 0, 0, 0, time.UTC)
	arch := store.OSLifecycle{Product: "arch", Cycle: "rolling"}
	return []store.OSLifecycle{
		{Product: "ubuntu", Cycle: "22.04", EOLDate: &ubuntu2204, LTS: true},
		{Product: "windows", Cycle: "10", EOLDate: &win10},
		arch,
	}
}

func TestEvaluateBoundaries(t *testing.T) {
	rows := lifecycleRows()
	before := time.Date(2027, 5, 31, 23, 59, 59, 0, time.UTC)
	on := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	after := time.Date(2027, 6, 2, 0, 0, 0, 0, time.UTC)

	if st := Evaluate("ubuntu", "22.04", rows, before); st.State != "supported" {
		t.Fatalf("day before eol = %q, want supported", st.State)
	}
	if st := Evaluate("ubuntu", "22.04", rows, on); st.State != "eol" {
		t.Fatalf("eol day = %q, want eol", st.State)
	}
	if st := Evaluate("ubuntu", "22.04", rows, after); st.State != "eol" {
		t.Fatalf("day after eol = %q, want eol", st.State)
	}
	if st := Evaluate("windows", "10", rows, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)); st.State != "supported" {
		t.Fatalf("windows 10 before eol = %q, want supported", st.State)
	}
}

func TestEvaluateRollingAndUnknown(t *testing.T) {
	rows := lifecycleRows()
	now := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)
	if st := Evaluate("arch", "rolling", rows, now); st.State != "supported" {
		t.Fatalf("arch rolling = %q, want supported", st.State)
	}
	if st := Evaluate("ubuntu", "24.04", rows, now); st.State != "unknown" {
		t.Fatalf("missing row = %q, want unknown", st.State)
	}
	if st := Evaluate("", "", rows, now); st.State != "unknown" {
		t.Fatalf("empty key = %q, want unknown", st.State)
	}
}

func TestEvaluateSupportDate(t *testing.T) {
	supportEnd := time.Date(2025, 6, 30, 0, 0, 0, 0, time.UTC)
	rows := []store.OSLifecycle{
		{Product: "rhel", Cycle: "8", SupportDate: &supportEnd},
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if st := Evaluate("rhel", "8", rows, now); st.State != "unsupported" {
		t.Fatalf("past support date without eol = %q, want unsupported", st.State)
	}
	before := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	if st := Evaluate("rhel", "8", rows, before); st.State != "supported" {
		t.Fatalf("before support date = %q, want supported", st.State)
	}
}
