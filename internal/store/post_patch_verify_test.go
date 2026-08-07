package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPostPatchVerdict(t *testing.T) {
	cases := []struct {
		name            string
		taskCVEIDs      []string
		remainingActive []string
		wantStatus      string
		wantDetail      string
	}{
		{
			name:       "no task CVEs",
			wantStatus: "na",
			wantDetail: "no CVEs bound to patch task",
		},
		{
			name:       "no remaining active",
			taskCVEIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
			wantStatus: "passed",
		},
		{
			name:            "remaining active",
			taskCVEIDs:      []string{"CVE-2026-0001", "CVE-2026-0002"},
			remainingActive: []string{"CVE-2026-0002", "CVE-2026-0001"},
			wantStatus:      "failed",
			wantDetail:      "remaining active CVEs: CVE-2026-0002, CVE-2026-0001",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, detail := postPatchVerdict(tc.taskCVEIDs, tc.remainingActive)
			if status != tc.wantStatus {
				t.Fatalf("postPatchVerdict status = %q, want %q", status, tc.wantStatus)
			}
			if detail != tc.wantDetail {
				t.Fatalf("postPatchVerdict detail = %q, want %q", detail, tc.wantDetail)
			}
		})
	}

	got := remainingCVEsFromDetail("remaining active CVEs: CVE-2026-0002, CVE-2026-0001")
	if len(got) != 2 || got[0] != "CVE-2026-0002" || got[1] != "CVE-2026-0001" {
		t.Fatalf("remainingCVEsFromDetail = %#v", got)
	}
	if got := remainingCVEsFromDetail("passed"); len(got) != 0 {
		t.Fatalf("remainingCVEsFromDetail(passed) = %#v, want empty", got)
	}
}

func TestPostPatchVerifyMigration(t *testing.T) {
	s := testWorkerScaleDB(t)
	ctx := context.Background()

	for _, col := range []string{"post_patch_status", "post_patch_detail", "post_patch_at"} {
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

	var defaultValue string
	if err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(column_default, '') FROM information_schema.columns
		WHERE table_name='patch_tasks' AND column_name='post_patch_status'
	`).Scan(&defaultValue); err != nil {
		t.Fatalf("check post_patch_status default: %v", err)
	}
	if defaultValue == "" {
		t.Fatal("post_patch_status has no default")
	}

	var indexExists bool
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_indexes
			WHERE tablename='patch_tasks' AND indexname='idx_patch_tasks_post_patch'
		)
	`).Scan(&indexExists); err != nil {
		t.Fatalf("check post-patch index: %v", err)
	}
	if !indexExists {
		t.Fatal("idx_patch_tasks_post_patch missing")
	}
}

func TestPostPatchVerifyLifecycle(t *testing.T) {
	s := testWorkerScaleDB(t)
	s.SetSiemEnabled(true)
	ctx := context.Background()
	agentID := fmt.Sprintf("agent-post-patch-%d", time.Now().UnixNano())
	now := time.Now().UTC()

	if err := s.CreateAgent(ctx, &Agent{
		ID:        agentID,
		Hostname:  agentID + ".local",
		OSType:    "linux",
		OSVersion: "Ubuntu 22.04",
		Arch:      "amd64",
		Status:    "online",
		TokenHash: "post-patch-token",
		LastSeen:  now,
		CreatedAt: now,
		UpdatedAt: now,
	}, 1); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	t.Cleanup(func() {
		_ = s.DeleteAgent(ctx, agentID)
	})

	createTask := func(asset string, cveIDs []string) int64 {
		t.Helper()
		task, err := s.CreatePatchTask(ctx, PatchTaskInput{
			AgentID:          agentID,
			AssetName:        asset,
			FixType:          "version",
			FixValue:         ">= 1.0",
			Action:           "upgrade_package",
			CVEIDs:           cveIDs,
			Command:          "true",
			Commands:         [][]string{{"true"}},
			ApprovalRequired: false,
			CreatedBy:        "test",
		})
		if err != nil {
			t.Fatalf("create patch task: %v", err)
		}
		return task.ID
	}
	complete := func(id int64, status string) {
		t.Helper()
		if err := s.CompletePatchTask(ctx, id, status, map[string]interface{}{
			"exit_code": 0,
			"output":    "test",
		}); err != nil {
			t.Fatalf("complete patch task %d: %v", id, err)
		}
	}
	seedActive := func(cveID, asset string) {
		t.Helper()
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO cve_results (agent_id, cve_id, asset_name, asset_version, status, source)
			VALUES ($1,$2,$3,'1.0.0','active','test')
			ON CONFLICT (agent_id, cve_id, asset_name, asset_version)
			DO UPDATE SET status='active'
		`, agentID, cveID, asset); err != nil {
			t.Fatalf("seed active CVE %s: %v", cveID, err)
		}
	}

	// Success enters pending; failed completion does not.
	failedTask := createTask("nginx", []string{"CVE-PP-0001"})
	seedActive("CVE-PP-0001", "nginx")
	complete(failedTask, "success")
	task, err := s.GetPatchTask(ctx, failedTask)
	if err != nil {
		t.Fatal(err)
	}
	if task.PostPatchStatus != "pending" {
		t.Fatalf("post-patch status after success = %q, want pending", task.PostPatchStatus)
	}
	if task.PostPatchAt != nil {
		t.Fatalf("post_patch_at should be nil while pending, got %v", task.PostPatchAt)
	}

	failedCompleteTask := createTask("tomcat", []string{"CVE-PP-0002"})
	complete(failedCompleteTask, "failed")
	task, err = s.GetPatchTask(ctx, failedCompleteTask)
	if err != nil {
		t.Fatal(err)
	}
	if task.Status != "failed" || task.PostPatchStatus != "" {
		t.Fatalf("failed completion = status %q post_patch %q, want failed/''", task.Status, task.PostPatchStatus)
	}

	pending, err := s.ListPendingPostPatchTasks(ctx, agentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].ID != failedTask {
		t.Fatalf("pending post-patch tasks = %#v, want only task %d", pending, failedTask)
	}

	// Latest match still has the target CVE active -> failed with details.
	if err := s.VerifyPendingPostPatchTasks(ctx, agentID); err != nil {
		t.Fatalf("verify pending post-patch tasks: %v", err)
	}
	task, err = s.GetPatchTask(ctx, failedTask)
	if err != nil {
		t.Fatal(err)
	}
	if task.PostPatchStatus != "failed" || !strings.Contains(task.PostPatchDetail, "CVE-PP-0001") {
		t.Fatalf("post-patch verification = %q/%q, want failed with CVE-PP-0001",
			task.PostPatchStatus, task.PostPatchDetail)
	}
	if task.PostPatchAt == nil {
		t.Fatal("post_patch_at should be set after verification")
	}

	var eventStatus string
	var remainingRaw []byte
	if err := s.pool.QueryRow(ctx, `
		SELECT payload->>'post_patch_status', payload->'remaining_cves'
		FROM siem_events
		WHERE event_type='patch_task.post_patch' AND payload->>'task_id'=$1
		ORDER BY id DESC LIMIT 1
	`, fmt.Sprint(failedTask)).Scan(&eventStatus, &remainingRaw); err != nil {
		t.Fatalf("query post-patch siem event: %v", err)
	}
	if eventStatus != "failed" || string(remainingRaw) != `["CVE-PP-0001"]` {
		t.Fatalf("post-patch siem event = status %q remaining %s", eventStatus, remainingRaw)
	}

	// No active rows for the task's asset -> passed.
	passedTask := createTask("apache", []string{"CVE-PP-0003"})
	complete(passedTask, "success")
	if err := s.VerifyPendingPostPatchTasks(ctx, agentID); err != nil {
		t.Fatalf("verify passed task: %v", err)
	}
	task, err = s.GetPatchTask(ctx, passedTask)
	if err != nil {
		t.Fatal(err)
	}
	if task.PostPatchStatus != "passed" {
		t.Fatalf("passed task post-patch status = %q, want passed", task.PostPatchStatus)
	}

	// A task with no bound CVEs is not applicable.
	naTask := createTask("redis", nil)
	complete(naTask, "success")
	if err := s.VerifyPendingPostPatchTasks(ctx, agentID); err != nil {
		t.Fatalf("verify na task: %v", err)
	}
	task, err = s.GetPatchTask(ctx, naTask)
	if err != nil {
		t.Fatal(err)
	}
	if task.PostPatchStatus != "na" {
		t.Fatalf("na task post-patch status = %q, want na", task.PostPatchStatus)
	}

	// A pending task that never sees a re-scan is failed by the reaper.
	staleTask := createTask("mysql", []string{"CVE-PP-0004"})
	complete(staleTask, "success")
	if _, err := s.pool.Exec(ctx, `
		UPDATE patch_tasks SET updated_at=NOW() - interval '2 days'
		WHERE id=$1
	`, staleTask); err != nil {
		t.Fatal(err)
	}
	reaped, err := s.ReapStalePostPatchVerifications(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if reaped < 1 {
		t.Fatalf("reaped stale post-patch verifications = %d, want at least 1", reaped)
	}
	task, err = s.GetPatchTask(ctx, staleTask)
	if err != nil {
		t.Fatal(err)
	}
	if task.PostPatchStatus != "failed" || task.PostPatchDetail != "no post-patch re-scan observed" {
		t.Fatalf("stale task = %q/%q, want failed/no post-patch re-scan observed",
			task.PostPatchStatus, task.PostPatchDetail)
	}
}
