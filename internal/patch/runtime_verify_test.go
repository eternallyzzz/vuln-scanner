package patch

import (
	"encoding/json"
	"testing"

	"vuln-scanner/internal/collector"
)

func TestEvaluateRuntimeVerification(t *testing.T) {
	cases := []struct {
		name     string
		baseline RuntimeBaseline
		current  RuntimeSnapshot
		asset    string
		want     string
	}{
		{
			name: "running service stays running",
			baseline: RuntimeBaseline{
				Services: []collector.ServiceInfo{{Name: "nginx", State: "running"}},
			},
			current: RuntimeSnapshot{
				Services: []collector.ServiceInfo{{Name: "nginx", State: "running"}},
			},
			want: "passed",
		},
		{
			name: "running service failed",
			baseline: RuntimeBaseline{
				Services: []collector.ServiceInfo{{Name: "nginx", State: "running"}},
			},
			current: RuntimeSnapshot{
				Services: []collector.ServiceInfo{{Name: "nginx", State: "failed"}},
			},
			want: "failed",
		},
		{
			name: "running service disappeared",
			baseline: RuntimeBaseline{
				Services: []collector.ServiceInfo{{Name: "nginx", State: "running"}},
			},
			current: RuntimeSnapshot{},
			want:    "failed",
		},
		{
			name: "matching process still exists",
			baseline: RuntimeBaseline{
				Processes: []collector.ProcessInfo{{PID: 100, Name: "nginx"}},
			},
			current: RuntimeSnapshot{
				Processes: []collector.ProcessInfo{{PID: 100, Name: "nginx"}},
			},
			asset: "nginx",
			want:  "passed",
		},
		{
			name: "matching process disappeared",
			baseline: RuntimeBaseline{
				Processes: []collector.ProcessInfo{{PID: 100, Name: "nginx"}},
			},
			current: RuntimeSnapshot{
				Processes: []collector.ProcessInfo{{PID: 200, Name: "apache2"}},
			},
			asset: "nginx",
			want:  "failed",
		},
		{
			name: "process pid changed still passes",
			baseline: RuntimeBaseline{
				Processes: []collector.ProcessInfo{{PID: 100, Name: "nginx"}},
			},
			current: RuntimeSnapshot{
				Processes: []collector.ProcessInfo{{PID: 999, Name: "nginx"}},
			},
			asset: "nginx",
			want:  "passed",
		},
		{
			name:     "empty baseline is na",
			baseline: RuntimeBaseline{},
			current:  RuntimeSnapshot{},
			asset:    "nginx",
			want:     "na",
		},
		{
			name: "baseline without applicable checks is na",
			baseline: RuntimeBaseline{
				Services:  []collector.ServiceInfo{{Name: "nginx", State: "stopped"}},
				Processes: []collector.ProcessInfo{{PID: 1, Name: "systemd"}},
			},
			current: RuntimeSnapshot{},
			asset:   "nginx",
			want:    "na",
		},
		{
			name: "multiple failures are all reported",
			baseline: RuntimeBaseline{
				Services:  []collector.ServiceInfo{{Name: "nginx", State: "running"}},
				Processes: []collector.ProcessInfo{{PID: 1, Name: "nginx"}},
			},
			current: RuntimeSnapshot{},
			asset:   "nginx",
			want:    "failed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateRuntimeVerification(tc.baseline, tc.current, tc.asset)
			if got.Status != tc.want {
				t.Fatalf("status = %q (detail %q), want %q", got.Status, got.Detail, tc.want)
			}
		})
	}
}

func TestParseRuntimeBaseline(t *testing.T) {
	raw, err := json.Marshal(RuntimeBaseline{
		Services:  []collector.ServiceInfo{{Name: "nginx", State: "running"}},
		Processes: []collector.ProcessInfo{{PID: 42, Name: "nginx"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseRuntimeBaseline(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Services) != 1 || b.Services[0].Name != "nginx" || b.Services[0].State != "running" {
		t.Fatalf("services parsed wrong: %+v", b.Services)
	}
	if len(b.Processes) != 1 || b.Processes[0].PID != 42 || b.Processes[0].Name != "nginx" {
		t.Fatalf("processes parsed wrong: %+v", b.Processes)
	}
	if _, err := ParseRuntimeBaseline([]byte("{bad")); err == nil {
		t.Fatal("invalid baseline must error")
	}
}
