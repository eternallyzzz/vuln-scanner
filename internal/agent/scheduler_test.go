package agent

import (
	"testing"

	"vuln-scanner/internal/collector"
)

func TestSystemInfoToPbIncludesWUA(t *testing.T) {
	sys := collector.SystemInfo{
		Hostname: "host",
		OS:       "Windows",
		Arch:     "amd64",
		UpdateFacts: []collector.UpdateFact{{
			KB: "KB5001", State: "pending", Source: "wua",
		}},
		UpdateSourceStatus: &collector.UpdateSourceStatus{
			SourceReachable: false,
			Error:           "exit status 1",
		},
	}
	pb := systemInfoToPb(sys)
	if pb == nil {
		t.Fatal("systemInfoToPb returned nil")
	}
	if len(pb.GetUpdateFacts()) != 1 || pb.GetUpdateFacts()[0].GetKb() != "KB5001" {
		t.Fatalf("update facts missing: %+v", pb.GetUpdateFacts())
	}
	if pb.GetUpdateSourceStatus() == nil || pb.GetUpdateSourceStatus().GetSourceReachable() {
		t.Fatalf("update source status missing or wrong: %+v", pb.GetUpdateSourceStatus())
	}
}
