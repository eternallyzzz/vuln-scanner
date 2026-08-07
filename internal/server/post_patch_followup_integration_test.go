package server

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"vuln-scanner/internal/patch"
	"vuln-scanner/internal/store"
)

func TestPostPatchFollowUpIntegration(t *testing.T) {
	st, _ := newMultiTenantIntegrationServer(t)
	ctx := context.Background()
	agentID := fmt.Sprintf("agent-followup-it-%d", time.Now().UnixNano())
	seedFollowUpAgent(t, st, ctx, agentID)

	sourceFixSet := []patch.FixSetItem{
		{AssetName: "samba", FixType: "version", FixValue: "1.0", Action: "upgrade_package"},
	}
	source, err := st.CreatePatchTask(ctx, store.PatchTaskInput{
		AgentID: agentID, AssetName: "samba", FixType: "version", FixValue: ">= 1.0",
		Action: "upgrade_package", CVEIDs: []string{"CVE-FU-IT-0001"},
		Command: "true", Commands: [][]string{{"true"}},
		ApprovalRequired: false, CreatedBy: "test",
		FixSet: sourceFixSet, FixSetHash: patch.HashFixSet(sourceFixSet),
	})
	if err != nil {
		t.Fatalf("create source task: %v", err)
	}
	if err := st.CompletePatchTask(ctx, source.ID, "success", map[string]interface{}{
		"exit_code": 0, "output": "test",
	}); err != nil {
		t.Fatalf("complete source task: %v", err)
	}
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO cve_results (agent_id, cve_id, asset_name, asset_version,
			fixed_version, severity, cvss_score, source, status)
		VALUES ($1,$2,$3,'1.0.0',$4,'HIGH',7.0,'test','active')
	`, agentID, "CVE-FU-IT-0001", "samba", "1.0"); err != nil {
		t.Fatalf("seed active CVE: %v", err)
	}
	if err := st.VerifyPendingPostPatchTasks(ctx, agentID); err != nil {
		t.Fatalf("verify post-patch: %v", err)
	}

	cfg := &patch.Config{
		Enabled: true, DefaultApprovalRequired: true, AgentTimeoutSeconds: 600,
		AptCommand: "apt-get install -y --only-upgrade", DnfCommand: "dnf -y update",
		YumCommand: "yum -y update", ApkCommand: "apk upgrade",
	}
	w := &Worker{store: st, patchCfg: cfg}
	w.processPostPatchFollowUps(ctx)

	source, err = st.GetPatchTask(ctx, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if source.PostPatchFollowUpStatus != "created" || source.PostPatchFollowUpCampaignID == nil {
		t.Fatalf("source follow-up state = %+v", source)
	}
	tasks, err := st.ListCampaignTasks(ctx, *source.PostPatchFollowUpCampaignID, "", "", 100, 0)
	if err != nil {
		t.Fatalf("list follow-up tasks: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("follow-up tasks = %d, want 1", len(tasks))
	}
	task := tasks[0]
	if task.AssetName != "samba" || task.PostPatchFollowUpDepth != 1 ||
		task.PostPatchSourceTaskID == nil || *task.PostPatchSourceTaskID != source.ID {
		t.Fatalf("follow-up task = %+v", task)
	}
	if !strings.Contains(string(task.FixSet), "libldb2") {
		t.Fatalf("follow-up fix set missing dependency: %s", task.FixSet)
	}
}

func TestPostPatchFollowUpSkipsWithoutMissingFixes(t *testing.T) {
	st, _ := newMultiTenantIntegrationServer(t)
	ctx := context.Background()
	agentID := fmt.Sprintf("agent-followup-skip-it-%d", time.Now().UnixNano())
	seedFollowUpAgent(t, st, ctx, agentID)

	fixSet := []patch.FixSetItem{
		{AssetName: "busybox", FixType: "version", FixValue: "99.99.99", Action: "upgrade_package"},
	}
	task, err := st.CreatePatchTask(ctx, store.PatchTaskInput{
		AgentID: agentID, AssetName: "busybox", FixType: "version", FixValue: ">= 99.99.99",
		Action: "upgrade_package", CVEIDs: []string{"CVE-FU-IT-0002"},
		Command: "true", Commands: [][]string{{"true"}},
		ApprovalRequired: false, CreatedBy: "test",
		FixSet: fixSet, FixSetHash: patch.HashFixSet(fixSet),
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	if err := st.CompletePatchTask(ctx, task.ID, "success", map[string]interface{}{
		"exit_code": 0, "output": "test",
	}); err != nil {
		t.Fatalf("complete task: %v", err)
	}
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO cve_results (agent_id, cve_id, asset_name, asset_version,
			fixed_version, severity, cvss_score, source, status)
		VALUES ($1,$2,$3,'1.0.0',$4,'HIGH',7.0,'test','active')
	`, agentID, "CVE-FU-IT-0002", "busybox", "99.99.99"); err != nil {
		t.Fatalf("seed active CVE: %v", err)
	}
	if err := st.VerifyPendingPostPatchTasks(ctx, agentID); err != nil {
		t.Fatalf("verify post-patch: %v", err)
	}

	cfg := &patch.Config{
		Enabled: true, DefaultApprovalRequired: true, AgentTimeoutSeconds: 600,
		AptCommand: "apt-get install -y --only-upgrade", DnfCommand: "dnf -y update",
		YumCommand: "yum -y update", ApkCommand: "apk upgrade",
	}
	w := &Worker{store: st, patchCfg: cfg}
	w.processPostPatchFollowUps(ctx)

	task, err = st.GetPatchTask(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if task.PostPatchFollowUpStatus != "skipped" {
		t.Fatalf("follow-up status = %q, want skipped", task.PostPatchFollowUpStatus)
	}
	pending, err := st.ListPendingPostPatchFollowUps(ctx)
	if err != nil {
		t.Fatalf("list pending follow-ups: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending follow-ups = %d, want 0", len(pending))
	}
}

func seedFollowUpAgent(t *testing.T, st *store.Store, ctx context.Context, agentID string) {
	t.Helper()
	now := time.Now().UTC()
	if err := st.CreateAgent(ctx, &store.Agent{
		ID: agentID, Hostname: agentID + ".local", OSType: "linux",
		OSVersion: "Debian 12", Arch: "amd64", Status: "online",
		TokenHash: "followup-it-token", LastSeen: now, CreatedAt: now, UpdatedAt: now,
	}, 1); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	t.Cleanup(func() { _ = st.DeleteAgent(ctx, agentID) })
	for _, name := range []string{"samba", "libldb2", "busybox"} {
		if _, err := st.Pool().Exec(ctx, `
			INSERT INTO assets (asset_key, asset_type, name, agent_id, lifecycle)
			VALUES ($1, 'software', $2, $3, 'active')
			ON CONFLICT (asset_key) DO NOTHING
		`, agentID+"-"+name, name, agentID); err != nil {
			t.Fatalf("seed asset %s: %v", name, err)
		}
	}
}
