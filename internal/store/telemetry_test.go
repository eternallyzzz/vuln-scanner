package store

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"vuln-scanner/internal/monitor"
)

func TestTelemetryBaselinesAndRebaseline(t *testing.T) {
	s := testWorkerScaleDB(t)
	ctx := context.Background()
	agentID := fmt.Sprintf("agent-telemetry-%d", time.Now().UnixNano())
	now := time.Now().UTC()
	if err := s.CreateAgent(ctx, &Agent{
		ID:        agentID,
		Hostname:  agentID + ".local",
		OSType:    "linux",
		OSVersion: "Ubuntu 22.04",
		Arch:      "amd64",
		Status:    "online",
		TokenHash: "telemetry-token",
		LastSeen:  now,
		CreatedAt: now,
		UpdatedAt: now,
	}, 1); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteAgent(ctx, agentID) })

	facts := []monitor.FileFact{
		{Path: "/etc/ssh/sshd_config", SHA256: "a", SizeBytes: 10, Mode: "0644", ModifiedAt: "t1"},
	}
	if drifts, err := s.ReplaceFileBaselines(ctx, agentID, facts); err != nil {
		t.Fatalf("warm file baseline: %v", err)
	} else if len(drifts) != 0 {
		t.Fatalf("warm-up drifts = %+v, want none", drifts)
	}

	facts[0].SHA256 = "b"
	drifts, err := s.ReplaceFileBaselines(ctx, agentID, facts)
	if err != nil {
		t.Fatalf("update file baseline: %v", err)
	}
	if len(drifts) != 1 || drifts[0].Kind != "modified" || drifts[0].Severity != "HIGH" {
		t.Fatalf("modified drift = %+v", drifts)
	}

	behavior := map[string][]monitor.BehaviorItem{
		"accounts": {{Key: "domain\\alice", Data: json.RawMessage(`{"name":"alice"}`)}},
	}
	if drifts, err := s.ReplaceBehaviorBaselines(ctx, agentID, behavior); err != nil {
		t.Fatalf("warm behavior baseline: %v", err)
	} else if len(drifts) != 0 {
		t.Fatalf("warm-up behavior drifts = %+v, want none", drifts)
	}
	behavior["accounts"] = append(behavior["accounts"],
		monitor.BehaviorItem{Key: "domain\\mallory", Data: json.RawMessage(`{"name":"mallory"}`)})
	drifts, err = s.ReplaceBehaviorBaselines(ctx, agentID, behavior)
	if err != nil {
		t.Fatalf("update behavior baseline: %v", err)
	}
	if len(drifts) != 1 || drifts[0].Kind != "added" || drifts[0].Key != "domain\\mallory" {
		t.Fatalf("behavior drift = %+v", drifts)
	}

	statusInfo, err := s.GetTelemetryStatus(ctx, agentID)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !statusInfo.Warm || statusInfo.FileCount != 1 || len(statusInfo.Categories) != 1 {
		t.Fatalf("status = %+v", statusInfo)
	}

	finding, created, err := s.UpsertEDRFinding(ctx, EDRFindingInput{
		AgentID: agentID, Source: "file_integrity", FindingType: "file_change",
		Name: "/etc/ssh/sshd_config", Severity: "HIGH",
		Path: "/etc/ssh/sshd_config", Hash: "b", Detail: `{"kind":"modified"}`,
	})
	if err != nil || !created {
		t.Fatalf("finding upsert: %v created=%v", err, created)
	}
	if err := s.RebaselineTelemetry(ctx, agentID); err != nil {
		t.Fatalf("rebaseline: %v", err)
	}
	statusInfo, err = s.GetTelemetryStatus(ctx, agentID)
	if err != nil {
		t.Fatalf("status after rebaseline: %v", err)
	}
	if statusInfo.Warm {
		t.Fatalf("baselines should be empty after rebaseline: %+v", statusInfo)
	}
	finding, err = s.GetEDRFinding(ctx, finding.ID)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if finding.Status != "resolved" {
		t.Fatalf("finding status = %q, want resolved", finding.Status)
	}
}
