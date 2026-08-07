package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	pb "vuln-scanner/api/gen/vulnscan/v1"
	"vuln-scanner/internal/cve"
	"vuln-scanner/internal/store"
)

// TestCoreLoopIntegration exercises the default core closed loop against a
// real PostgreSQL database:
//
//	asset snapshot -> CVE matching -> recommendation -> patch task ->
//	approval -> agent gRPC claim -> success report.
//
// It is skipped unless VULNSCAN_TEST_DATABASE_URL is set (the CI test-db job
// provides a PostgreSQL 16 service).
func TestCoreLoopIntegration(t *testing.T) {
	st, srv := newMultiTenantIntegrationServer(t)
	ctx := context.Background()
	const agentID = "agent-core-loop"
	now := time.Now().UTC()

	if err := st.CreateAgent(ctx, &store.Agent{
		ID:        agentID,
		Hostname:  "core-loop-host",
		OSType:    "linux",
		OSVersion: "Ubuntu 22.04",
		Arch:      "amd64",
		Status:    "online",
		TokenHash: "core-loop-token",
		LastSeen:  now,
		CreatedAt: now,
		UpdatedAt: now,
	}, 1); err != nil {
		t.Fatalf("create agent: %v", err)
	}

	feed := cve.NewFeedManager(st)
	if err := feed.Upsert(ctx, &cve.FeedEntry{
		Source:      "nvd",
		SourceKey:   "core-loop-smoke",
		CVEID:       "CVE-2099-0001",
		CVEURL:      "https://example.invalid/CVE-2099-0001",
		Affected:    json.RawMessage(`[{"name":"nginx","min_ver":"1.0.0","max_ver":"1.24.0","fixed_in":"1.24.1"}]`),
		Severity:    "HIGH",
		CVSSScore:   8.0,
		Summary:     "core loop smoke CVE",
		PublishedAt: now,
		FetchedAt:   now,
		TTLSeconds:  86400,
	}); err != nil {
		t.Fatalf("upsert cve feed: %v", err)
	}

	assetsJSON := json.RawMessage(`{"assets":[{"name":"nginx","version":"1.22.0","format":"deb","vendor":"nginx"}]}`)
	if err := st.UpsertAssetSnapshot(ctx, &store.AssetSnapshot{
		AgentID:   agentID,
		Mode:      "FULL",
		Assets:    assetsJSON,
		Checksum:  "core-loop",
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("upsert asset snapshot: %v", err)
	}

	matcher := cve.NewMatcher(st, nil, feed)
	matched, err := matcher.Match(ctx, agentID, cve.AssetsFromJSON(assetsJSON), nil)
	if err != nil {
		t.Fatalf("match assets: %v", err)
	}
	if len(matched) == 0 {
		t.Fatal("no CVE matched for seeded nginx 1.22.0")
	}
	if err := matcher.SaveResults(ctx, agentID, matched); err != nil {
		t.Fatalf("save match results: %v", err)
	}

	results, _, err := st.GetCVEResults(ctx, agentID, "", false, 0, 100)
	if err != nil {
		t.Fatalf("list cve results: %v", err)
	}
	found := false
	for _, r := range results {
		if r.CVEID == "CVE-2099-0001" && r.AssetName == "nginx" && r.Status == "active" {
			found = true
		}
	}
	if !found {
		t.Fatalf("CVE-2099-0001 not present in results: %#v", results)
	}

	rr := integrationRequest(t, srv, http.MethodPost,
		"/api/v1/agents/"+agentID+"/patch-tasks/generate",
		"legacy-global-api-key",
		`{"asset_names":["nginx"],"cve_ids":["CVE-2099-0001"],"approval_required":true}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("generate patch tasks = %d (body %s)", rr.Code, rr.Body.String())
	}
	var generated struct {
		Created int               `json:"created"`
		Tasks   []store.PatchTask `json:"tasks"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &generated); err != nil {
		t.Fatalf("decode generate response: %v", err)
	}
	if generated.Created != 1 || len(generated.Tasks) != 1 {
		t.Fatalf("generated tasks = %d/%d, want 1/1 (body %s)",
			generated.Created, len(generated.Tasks), rr.Body.String())
	}
	taskID := generated.Tasks[0].ID

	rr = integrationRequest(t, srv, http.MethodPost,
		fmt.Sprintf("/api/v1/patch-tasks/%d/approve", taskID),
		"legacy-global-api-key", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("approve patch task = %d (body %s)", rr.Code, rr.Body.String())
	}

	grpcSrv := NewAgentGRPCServer(NewAgentAuth("jwt-secret"), st, nil, srv.cfg.Patch)
	authResp, err := grpcSrv.Auth(ctx, &pb.AuthRequest{
		AgentId:     agentID,
		Fingerprint: "core-loop-fingerprint",
	})
	if err != nil {
		t.Fatalf("agent auth: %v", err)
	}
	fetchResp, err := grpcSrv.FetchPatchTasks(ctx, &pb.FetchPatchTasksRequest{
		AgentId: agentID,
		Token:   authResp.Token,
	})
	if err != nil {
		t.Fatalf("fetch patch tasks: %v", err)
	}
	if len(fetchResp.Tasks) != 1 || fetchResp.Tasks[0].Id != taskID {
		t.Fatalf("claimed tasks = %#v, want task %d", fetchResp.Tasks, taskID)
	}
	if _, err := grpcSrv.ReportPatchTask(ctx, &pb.ReportPatchTaskRequest{
		TaskId:   taskID,
		AgentId:  agentID,
		Token:    authResp.Token,
		Status:   "success",
		ExitCode: 0,
		Output:   "core loop patch ok",
	}); err != nil {
		t.Fatalf("report patch task: %v", err)
	}

	task, err := st.GetPatchTask(ctx, taskID)
	if err != nil {
		t.Fatalf("get patch task: %v", err)
	}
	if task.Status != "success" {
		t.Fatalf("patch task status = %q, want success", task.Status)
	}
	if task.PostPatchStatus != "pending" {
		t.Fatalf("post-patch status = %q, want pending after success", task.PostPatchStatus)
	}

	// The CVE result is still active in this test, so post-patch verification
	// must fail with the remaining CVE listed.
	if err := st.VerifyPendingPostPatchTasks(ctx, agentID); err != nil {
		t.Fatalf("verify pending post-patch tasks: %v", err)
	}
	task, err = st.GetPatchTask(ctx, taskID)
	if err != nil {
		t.Fatalf("get patch task after verification: %v", err)
	}
	if task.PostPatchStatus != "failed" || !strings.Contains(task.PostPatchDetail, "CVE-2099-0001") {
		t.Fatalf("post-patch verification = %q/%q, want failed with CVE-2099-0001",
			task.PostPatchStatus, task.PostPatchDetail)
	}
}
