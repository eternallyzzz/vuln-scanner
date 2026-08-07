package store

import (
	"context"
	"testing"
	"time"
)

func TestDeleteAuditLogsOlderThan(t *testing.T) {
	s := testWorkerScaleDB(t)
	ctx := context.Background()

	for _, actor := range []string{"old-audit", "new-audit"} {
		if err := s.AppendAuditLog(ctx, AuditLog{
			Actor:    actor,
			Method:   "POST",
			Path:     "/api/v1/test",
			Status:   200,
			TenantID: 1,
		}); err != nil {
			t.Fatalf("append audit log %s: %v", actor, err)
		}
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE audit_logs SET created_at=NOW() - interval '60 days' WHERE actor='old-audit'`); err != nil {
		t.Fatal(err)
	}

	deleted, err := s.DeleteAuditLogsOlderThan(ctx, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}

	var oldCount, newCount int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_logs WHERE actor='old-audit'`).Scan(&oldCount); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_logs WHERE actor='new-audit'`).Scan(&newCount); err != nil {
		t.Fatal(err)
	}
	if oldCount != 0 || newCount != 1 {
		t.Fatalf("old/new audit rows = %d/%d, want 0/1", oldCount, newCount)
	}
}

func TestReapStalePatchTasks(t *testing.T) {
	s := testWorkerScaleDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := s.CreateAgent(ctx, &Agent{
		ID:        "agent-reap",
		Hostname:  "reap-host",
		OSType:    "linux",
		Arch:      "amd64",
		Status:    "online",
		TokenHash: "reap-token",
		LastSeen:  now,
		CreatedAt: now,
		UpdatedAt: now,
	}, 1); err != nil {
		t.Fatalf("create agent: %v", err)
	}

	newTask, err := s.CreatePatchTask(ctx, PatchTaskInput{
		AgentID:          "agent-reap",
		AssetName:        "nginx",
		FixType:          "version",
		FixValue:         ">= 1.24.1",
		Action:           "upgrade_package",
		CVEIDs:           []string{"CVE-2099-0001"},
		Command:          "apt-get install -y nginx",
		Commands:         [][]string{{"apt-get", "install", "-y", "nginx"}},
		ApprovalRequired: false,
		CreatedBy:        "test",
	})
	if err != nil {
		t.Fatalf("create new task: %v", err)
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE patch_tasks SET status='running' WHERE id=$1`, newTask.ID); err != nil {
		t.Fatal(err)
	}

	staleTask, err := s.CreatePatchTask(ctx, PatchTaskInput{
		AgentID:          "agent-reap",
		AssetName:        "openssl",
		FixType:          "version",
		FixValue:         ">= 3.0.7",
		Action:           "upgrade_package",
		CVEIDs:           []string{"CVE-2099-0002"},
		Command:          "apt-get install -y openssl",
		Commands:         [][]string{{"apt-get", "install", "-y", "openssl"}},
		ApprovalRequired: false,
		CreatedBy:        "test",
	})
	if err != nil {
		t.Fatalf("create stale task: %v", err)
	}
	if _, err := s.pool.Exec(ctx, `
		UPDATE patch_tasks SET status='running', updated_at=NOW() - interval '2 minutes'
		WHERE id=$1`, staleTask.ID); err != nil {
		t.Fatal(err)
	}

	reaped, err := s.ReapStalePatchTasks(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 1 {
		t.Fatalf("reaped = %d, want 1", reaped)
	}

	stale, err := s.GetPatchTask(ctx, staleTask.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stale.Status != "approved" {
		t.Fatalf("stale task status = %q, want approved", stale.Status)
	}
	recent, err := s.GetPatchTask(ctx, newTask.ID)
	if err != nil {
		t.Fatal(err)
	}
	if recent.Status != "running" {
		t.Fatalf("recent task status = %q, want running", recent.Status)
	}
}
