package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"vuln-scanner/internal/patch"
)

func TestPostPatchFollowUpMigration(t *testing.T) {
	s := testWorkerScaleDB(t)
	ctx := context.Background()

	for _, col := range []string{
		"post_patch_follow_up_status", "post_patch_follow_up_campaign_id",
		"post_patch_follow_up_attempts", "post_patch_follow_up_depth",
		"post_patch_follow_up_detail", "post_patch_source_task_id",
	} {
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

	var indexExists bool
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_indexes
			WHERE tablename='patch_tasks' AND indexname='idx_patch_tasks_post_patch_follow_up'
		)
	`).Scan(&indexExists); err != nil {
		t.Fatalf("check follow-up index: %v", err)
	}
	if !indexExists {
		t.Fatal("idx_patch_tasks_post_patch_follow_up missing")
	}
}

func TestMissingFixesForTaskSkipsExistingFixSet(t *testing.T) {
	s := testWorkerScaleDB(t)
	ctx := context.Background()
	agentID := fmt.Sprintf("agent-followup-skip-%d", time.Now().UnixNano())
	now := time.Now().UTC()
	if err := s.CreateAgent(ctx, &Agent{
		ID: agentID, Hostname: agentID + ".local", OSType: "linux",
		OSVersion: "Debian 12", Arch: "amd64", Status: "online",
		TokenHash: "followup-skip-token", LastSeen: now, CreatedAt: now, UpdatedAt: now,
	}, 1); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteAgent(ctx, agentID) })
	seedInstalledAssets(t, ctx, s, agentID, "samba", "libldb2")

	fixSet := []patch.FixSetItem{
		{AssetName: "samba", FixType: "version", FixValue: "1.0", Action: "upgrade_package"},
		{AssetName: "libldb2", FixType: "version", FixValue: "", Action: "upgrade_package"},
	}
	task, err := s.CreatePatchTask(ctx, PatchTaskInput{
		AgentID: agentID, AssetName: "samba", FixType: "version", FixValue: ">= 1.0",
		Action: "upgrade_package", CVEIDs: []string{"CVE-FU-0001"},
		Command: "true", Commands: [][]string{{"true"}},
		ApprovalRequired: false, CreatedBy: "test",
		FixSet: fixSet, FixSetHash: patch.HashFixSet(fixSet),
	})
	if err != nil {
		t.Fatalf("create patch task: %v", err)
	}
	seedActiveCVEResult(t, ctx, s, agentID, "CVE-FU-0001", "samba", "1.0")

	missing, err := s.MissingFixesForTask(ctx, task)
	if err != nil {
		t.Fatalf("missing fixes: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("missing fixes = %+v, want none (dependency already in fix set)", missing)
	}
}

func TestPostPatchFollowUpLifecycle(t *testing.T) {
	s := testWorkerScaleDB(t)
	ctx := context.Background()
	agentID := fmt.Sprintf("agent-followup-%d", time.Now().UnixNano())
	now := time.Now().UTC()
	if err := s.CreateAgent(ctx, &Agent{
		ID: agentID, Hostname: agentID + ".local", OSType: "linux",
		OSVersion: "Debian 12", Arch: "amd64", Status: "online",
		TokenHash: "followup-token", LastSeen: now, CreatedAt: now, UpdatedAt: now,
	}, 1); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteAgent(ctx, agentID) })
	seedInstalledAssets(t, ctx, s, agentID, "samba", "libldb2")

	sourceFixSet := []patch.FixSetItem{
		{AssetName: "samba", FixType: "version", FixValue: "1.0", Action: "upgrade_package"},
	}
	source, err := s.CreatePatchTask(ctx, PatchTaskInput{
		AgentID: agentID, AssetName: "samba", FixType: "version", FixValue: ">= 1.0",
		Action: "upgrade_package", CVEIDs: []string{"CVE-FU-0002"},
		Command: "true", Commands: [][]string{{"true"}},
		ApprovalRequired: false, CreatedBy: "test",
		FixSet: sourceFixSet, FixSetHash: patch.HashFixSet(sourceFixSet),
	})
	if err != nil {
		t.Fatalf("create source task: %v", err)
	}
	if err := s.CompletePatchTask(ctx, source.ID, "success", map[string]interface{}{
		"exit_code": 0, "output": "test",
	}); err != nil {
		t.Fatalf("complete source task: %v", err)
	}
	seedActiveCVEResult(t, ctx, s, agentID, "CVE-FU-0002", "samba", "1.0")

	if err := s.VerifyPendingPostPatchTasks(ctx, agentID); err != nil {
		t.Fatalf("verify pending post-patch tasks: %v", err)
	}
	source, err = s.GetPatchTask(ctx, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if source.PostPatchStatus != "failed" || source.PostPatchFollowUpStatus != "pending" {
		t.Fatalf("source post-patch = %q/%q, want failed/pending",
			source.PostPatchStatus, source.PostPatchFollowUpStatus)
	}
	if !strings.Contains(source.PostPatchDetail, "libldb2") {
		t.Fatalf("source detail missing dependency follow-up: %q", source.PostPatchDetail)
	}

	missing, err := s.MissingFixesForTask(ctx, source)
	if err != nil {
		t.Fatalf("missing fixes: %v", err)
	}
	if len(missing) != 1 || missing[0].AssetName != "libldb2" || missing[0].Reason != "dependency" {
		t.Fatalf("missing fixes = %+v, want only libldb2 dependency", missing)
	}

	ok, err := s.BeginPostPatchFollowUpAttempt(ctx, source.ID)
	if err != nil || !ok {
		t.Fatalf("begin follow-up attempt = %v,%v want true,nil", ok, err)
	}
	followFixSet := []patch.FixSetItem{
		{AssetName: "samba", FixType: "version", FixValue: "1.0", Action: "upgrade_package"},
		{AssetName: "libldb2", FixType: "version", FixValue: "", Action: "upgrade_package"},
	}
	campaign, tasks, err := s.CreatePatchCampaignWithTasks(ctx,
		"post-patch-followup-test", json.RawMessage(`{"source_task_id":`+fmt.Sprint(source.ID)+`}`),
		"post-patch-followup", 1, []CampaignTaskInput{{
			AgentID: agentID, AssetName: "samba", FixType: "version", FixValue: ">= 1.0",
			Action: "upgrade_package", CVEIDs: []string{"CVE-FU-0002"},
			Command: "true", Commands: [][]string{{"true"}},
			ApprovalRequired: false, CreatedBy: "post-patch-followup",
			FixSet: followFixSet, FixSetHash: patch.HashFixSet(followFixSet),
		}}, source.ID)
	if err != nil {
		t.Fatalf("create follow-up campaign: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("follow-up tasks = %d, want 1", len(tasks))
	}
	listed, err := s.ListCampaignTasks(ctx, campaign.ID, "", "", 100, 0)
	if err != nil {
		t.Fatalf("list campaign tasks: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("listed campaign tasks = %d, want 1", len(listed))
	}
	if tasks[0].PostPatchFollowUpDepth != 1 ||
		tasks[0].PostPatchSourceTaskID == nil || *tasks[0].PostPatchSourceTaskID != source.ID {
		t.Fatalf("follow-up task link/depth = %+v", tasks[0])
	}

	source, err = s.GetPatchTask(ctx, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if source.PostPatchFollowUpStatus != "created" ||
		source.PostPatchFollowUpCampaignID == nil || *source.PostPatchFollowUpCampaignID != campaign.ID ||
		source.PostPatchFollowUpAttempts != 1 {
		t.Fatalf("source follow-up state = %+v", source)
	}

	if _, _, err := s.CreatePatchCampaignWithTasks(ctx,
		"post-patch-followup-dup", json.RawMessage(`{}`), "post-patch-followup", 1,
		[]CampaignTaskInput{{
			AgentID: agentID, AssetName: "samba", FixType: "version", FixValue: ">= 1.0",
			Action: "upgrade_package", CVEIDs: []string{"CVE-FU-0002"},
			Command: "true", Commands: [][]string{{"true"}},
			ApprovalRequired: false, CreatedBy: "post-patch-followup",
			FixSet: followFixSet, FixSetHash: patch.HashFixSet(followFixSet),
		}}, source.ID); !errors.Is(err, ErrPostPatchFollowUpAlreadyHandled) {
		t.Fatalf("duplicate follow-up error = %v, want ErrPostPatchFollowUpAlreadyHandled", err)
	}

	pending, err := s.ListPendingPostPatchFollowUps(ctx)
	if err != nil {
		t.Fatalf("list pending follow-ups: %v", err)
	}
	for _, p := range pending {
		if p.ID == source.ID {
			t.Fatal("source task still pending after follow-up created")
		}
	}
}

func seedInstalledAssets(t *testing.T, ctx context.Context, s *Store, agentID string, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO assets (asset_key, asset_type, name, agent_id, lifecycle)
			VALUES ($1, 'software', $2, $3, 'active')
			ON CONFLICT (asset_key) DO NOTHING
		`, agentID+"-"+name, name, agentID); err != nil {
			t.Fatalf("seed asset %s: %v", name, err)
		}
	}
}

func seedActiveCVEResult(t *testing.T, ctx context.Context, s *Store, agentID, cveID, asset, fixed string) {
	t.Helper()
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO cve_results (agent_id, cve_id, asset_name, asset_version,
			fixed_version, severity, cvss_score, source, status)
		VALUES ($1,$2,$3,'1.0.0',$4,'HIGH',7.0,'test','active')
		ON CONFLICT (agent_id, cve_id, asset_name, asset_version)
		DO UPDATE SET fixed_version=$4, status='active'
	`, agentID, cveID, asset, fixed); err != nil {
		t.Fatalf("seed active CVE %s: %v", cveID, err)
	}
}
