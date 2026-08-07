package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"vuln-scanner/internal/patch"
)

func TestPatchFixSetMigration(t *testing.T) {
	s := testWorkerScaleDB(t)
	ctx := context.Background()
	for _, col := range []string{"fix_set", "fix_set_hash"} {
		var exists bool
		if err := s.pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_name='patch_tasks' AND column_name=$1
			)
		`, col).Scan(&exists); err != nil {
			t.Fatalf("check column %s: %v", col, err)
		}
		if !exists {
			t.Fatalf("column %s missing from patch_tasks", col)
		}
	}
	var tableExists bool
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_name='patch_dependency_rules'
		)
	`).Scan(&tableExists); err != nil {
		t.Fatalf("check patch_dependency_rules: %v", err)
	}
	if !tableExists {
		t.Fatal("patch_dependency_rules table missing")
	}
	rules, err := s.ListDependencyRules(ctx)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) < 3 {
		t.Fatalf("seeded rules = %d, want >= 3", len(rules))
	}
}

func TestHasOpenPatchTaskForFixSet(t *testing.T) {
	s := testWorkerScaleDB(t)
	ctx := context.Background()
	agentID := fmt.Sprintf("agent-fixset-%d", time.Now().UnixNano())
	now := time.Now().UTC()
	if err := s.CreateAgent(ctx, &Agent{
		ID:        agentID,
		Hostname:  agentID + ".local",
		OSType:    "linux",
		OSVersion: "Debian 12",
		Arch:      "amd64",
		Status:    "online",
		TokenHash: "fixset-token",
		LastSeen:  now,
		CreatedAt: now,
		UpdatedAt: now,
	}, 1); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteAgent(ctx, agentID) })

	hashA := patch.HashFixSet([]patch.FixSetItem{
		{AssetName: "curl", FixType: "version", FixValue: "8.4.0"},
		{AssetName: "libcurl4", FixType: "version", FixValue: ""},
	})
	hashB := patch.HashFixSet([]patch.FixSetItem{
		{AssetName: "curl", FixType: "version", FixValue: "9.0.0"},
	})
	open, err := s.HasOpenPatchTaskForFixSet(ctx, agentID, hashA)
	if err != nil {
		t.Fatalf("dedupe before task: %v", err)
	}
	if open {
		t.Fatal("no open task should exist yet")
	}
	if _, err := s.CreatePatchTask(ctx, PatchTaskInput{
		AgentID: agentID, AssetName: "curl", FixType: "version",
		FixValue: ">= 8.4.0", Action: "upgrade_package",
		CVEIDs: []string{"CVE-FS-0001"}, Command: "true",
		Commands: [][]string{{"true"}}, ApprovalRequired: false,
		CreatedBy: "test", FixSetHash: hashA,
		FixSet: []patch.FixSetItem{
			{AssetName: "curl", FixType: "version", FixValue: "8.4.0"},
			{AssetName: "libcurl4", FixType: "version", FixValue: ""},
		},
	}); err != nil {
		t.Fatalf("create task A: %v", err)
	}
	open, err = s.HasOpenPatchTaskForFixSet(ctx, agentID, hashA)
	if err != nil {
		t.Fatalf("dedupe after task A: %v", err)
	}
	if !open {
		t.Fatal("task A should dedupe by its fix set hash")
	}
	open, err = s.HasOpenPatchTaskForFixSet(ctx, agentID, hashB)
	if err != nil {
		t.Fatalf("dedupe hash B: %v", err)
	}
	if open {
		t.Fatal("different fix set must not dedupe")
	}
}

func TestMissingFixesDetailParsing(t *testing.T) {
	detail := "remaining active CVEs: CVE-1, CVE-2 | missing fixes: libldb2, curl >= 9.0.0"
	remaining := remainingCVEsFromDetail(detail)
	if len(remaining) != 2 || remaining[0] != "CVE-1" || remaining[1] != "CVE-2" {
		t.Fatalf("remaining = %#v", remaining)
	}
	missing := missingFixesFromDetail(detail)
	if len(missing) != 2 || missing[0] != "libldb2" || missing[1] != "curl >= 9.0.0" {
		t.Fatalf("missing = %#v", missing)
	}
	if got := missingFixesFromDetail("remaining active CVEs: CVE-1"); len(got) != 0 {
		t.Fatalf("missing without suffix = %#v", got)
	}
}
