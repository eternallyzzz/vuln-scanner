package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"vuln-scanner/internal/patch"
	"vuln-scanner/internal/store"
)

type generatePatchTasksInput struct {
	AssetNames       []string `json:"asset_names"`
	CVEIDs           []string `json:"cve_ids"`
	ApprovalRequired *bool    `json:"approval_required"`
	WindowStart      string   `json:"window_start"`
	WindowEnd        string   `json:"window_end"`
}

func (s *RESTServer) generatePatchTasks(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Patch == nil || !s.cfg.Patch.Enabled {
		writeError(w, 400, "patch deployment is disabled")
		return
	}
	agentID := chi.URLParam(r, "id")
	if err := s.requireAgent(r, agentID); err != nil {
		writeScopeError(w, err)
		return
	}

	var in generatePatchTasksInput
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&in)
	}
	approvalRequired := s.cfg.Patch.DefaultApprovalRequired
	if in.ApprovalRequired != nil {
		approvalRequired = *in.ApprovalRequired
	}
	var windowStart, windowEnd *time.Time
	var err error
	if in.WindowStart != "" {
		t, e := time.Parse(time.RFC3339, in.WindowStart)
		if e != nil {
			writeError(w, 400, "window_start must be RFC3339")
			return
		}
		windowStart = &t
	}
	if in.WindowEnd != "" {
		t, e := time.Parse(time.RFC3339, in.WindowEnd)
		if e != nil {
			writeError(w, 400, "window_end must be RFC3339")
			return
		}
		windowEnd = &t
	}
	if windowStart != nil && windowEnd != nil && !windowEnd.After(*windowStart) {
		writeError(w, 400, "window_end must be after window_start")
		return
	}

	wantAssets := map[string]bool{}
	for _, a := range in.AssetNames {
		wantAssets[a] = true
	}
	wantCVEs := map[string]bool{}
	for _, c := range in.CVEIDs {
		wantCVEs[c] = true
	}

	recs, err := s.store.GetAgentRecommendations(r.Context(), agentID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	agent, err := s.store.GetAgent(r.Context(), agentID)
	if err != nil || agent == nil {
		writeError(w, 404, "agent not found")
		return
	}
	cveMap, err := s.store.ActiveCVEsByAsset(r.Context(), agentID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	kbMeta := loadKBMetadata(r.Context(), s.store, recs)

	created := 0
	var tasks []store.PatchTask
	for _, rec := range recs {
		if len(wantAssets) > 0 && !wantAssets[rec.AssetName] {
			continue
		}
		cves := cveMap[rec.AssetName]
		if len(wantCVEs) > 0 {
			var filtered []string
			for _, c := range cves {
				if wantCVEs[c] {
					filtered = append(filtered, c)
				}
			}
			cves = filtered
		}
		if len(cves) == 0 {
			continue
		}
		if rec.FixType == "kb" {
			enrichKBLinks(rec.KBs, kbMeta)
			if len(rec.KBs) > 0 {
				if m, ok := kbMeta[rec.KBs[0].Kb]; ok {
					rec.PatchURL = bestPatchURL(m)
					rec.PatchSHA256 = m.DownloadSHA256
				}
				if rec.PatchURL == "" {
					rec.PatchURL = rec.KBs[0].PatchURL
				}
			}
		}
		cmd, err := patch.BuildCommandForAgent(s.cfg.Patch, rec.FixType,
			rec.FixedVersion, rec.AssetName, rec.PatchURL, rec.PatchSHA256,
			agent.OSType, agent.OSVersion)
		if err != nil {
			writeError(w, 500, "asset "+rec.AssetName+": "+err.Error())
			return
		}
		task, err := s.store.CreatePatchTask(r.Context(), store.PatchTaskInput{
			AgentID:          agentID,
			AssetName:        rec.AssetName,
			FixType:          rec.FixType,
			FixValue:         rec.FixValue,
			Action:           rec.Action,
			CVEIDs:           cves,
			Command:          cmd.Display,
			Commands:         cmd.ArgvLists,
			ApprovalRequired: approvalRequired,
			WindowStart:      windowStart,
			WindowEnd:        windowEnd,
			CreatedBy:        "api",
		})
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		created++
		tasks = append(tasks, task)
	}
	writeJSON(w, 201, map[string]interface{}{"created": created, "tasks": tasks})
}

func (s *RESTServer) listPatchTasks(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	if err := s.requireAgent(r, agentID); err != nil {
		writeScopeError(w, err)
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	tasks, err := s.store.ListPatchTasks(r.Context(), agentID, q.Get("status"), limit, offset)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"tasks": tasks, "total": len(tasks)})
}

func (s *RESTServer) getPatchTask(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "taskId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, 400, "invalid task id")
		return
	}
	task, err := s.store.GetPatchTask(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "task not found")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if err := s.requirePatchTask(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	writeJSON(w, 200, task)
}

func (s *RESTServer) setPatchTaskStatus(w http.ResponseWriter, r *http.Request, status string) {
	id, err := strconv.ParseInt(chi.URLParam(r, "taskId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, 400, "invalid task id")
		return
	}
	task, err := s.store.GetPatchTask(r.Context(), id)
	if err != nil {
		writeError(w, 404, "task not found")
		return
	}
	if err := s.requirePatchTask(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	next := status
	if status == "retry" {
		if task.Status != "failed" && task.Status != "cancelled" {
			writeError(w, 400, "only failed or cancelled tasks can be retried")
			return
		}
		next = "pending"
	}
	actor := actorFromRequest(r)
	if err := s.store.SetPatchTaskStatus(r.Context(), id, next, actor); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"task_id": id, "status": next})
}

func (s *RESTServer) approvePatchTask(w http.ResponseWriter, r *http.Request) {
	s.setPatchTaskStatus(w, r, "approved")
}

func (s *RESTServer) rejectPatchTask(w http.ResponseWriter, r *http.Request) {
	s.setPatchTaskStatus(w, r, "rejected")
}

func (s *RESTServer) cancelPatchTask(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "taskId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, 400, "invalid task id")
		return
	}
	task, err := s.store.GetPatchTask(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, 404, "task not found")
			return
		}
		writeError(w, 500, err.Error())
		return
	}
	if err := s.requirePatchTask(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	if task.Status == "running" {
		s.requestPatchTaskCancel(w, r, task)
		return
	}
	s.setPatchTaskStatus(w, r, "cancelled")
}

func (s *RESTServer) retryPatchTask(w http.ResponseWriter, r *http.Request) {
	s.setPatchTaskStatus(w, r, "retry")
}

// verifyPatchTask manually re-runs runtime verification for a succeeded
// patch task: it flips the task back to pending and immediately evaluates
// the latest stored host_system_info snapshot against the claim-time
// baseline. This doubles as the smoke-test entry point for the mechanism.
func (s *RESTServer) verifyPatchTask(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "taskId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, 400, "invalid task id")
		return
	}
	task, err := s.store.GetPatchTask(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "task not found")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if err := s.requirePatchTask(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	if task.Status != "success" {
		writeError(w, 409, "only succeeded patch tasks can be runtime verified")
		return
	}
	if err := s.store.SetPatchTaskRuntimeVerifyPending(r.Context(), task.ID); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	baseline, err := patch.ParseRuntimeBaseline(task.RuntimeVerifyBaseline)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	snapshot := patch.RuntimeSnapshot{}
	if info, err := s.store.GetHostSystemInfo(r.Context(), task.AgentID); err == nil {
		snapshot.Services = info.Services
		snapshot.Processes = info.Processes
	} else if !store.IsHostSystemInfoNotFound(err) {
		slog.Warn("load host system info for runtime verify failed", "agent_id", task.AgentID, "error", err)
	}
	result := patch.EvaluateRuntimeVerification(baseline, snapshot, task.AssetName)
	if err := s.store.CompleteRuntimeVerification(r.Context(), task.ID, result.Status, result.Detail); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"task_id": task.ID, "status": result.Status,
		"detail": result.Detail, "verified_at": time.Now(),
	})
}

// stopPatchTask requests cancellation of a running patch task. The agent
// picks the flag up on its next progress heartbeat and terminates the
// process tree, then reports the task as cancelled.
func (s *RESTServer) stopPatchTask(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "taskId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, 400, "invalid task id")
		return
	}
	task, err := s.store.GetPatchTask(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, 404, "task not found")
			return
		}
		writeError(w, 500, err.Error())
		return
	}
	if err := s.requirePatchTask(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	if task.Status != "running" {
		writeError(w, 409, "task is not running")
		return
	}
	s.requestPatchTaskCancel(w, r, task)
}

func (s *RESTServer) requestPatchTaskCancel(w http.ResponseWriter, r *http.Request, task store.PatchTask) {
	ok, err := s.store.RequestPatchTaskCancel(r.Context(), task.ID, actorFromRequest(r))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if !ok {
		writeError(w, 409, "task is not running")
		return
	}
	writeJSON(w, 200, map[string]interface{}{"task_id": task.ID, "cancel_requested": true})
}

// listPatchTaskEvents returns execution events after a cursor id, oldest
// first, so clients can poll the live patch stream with `after`.
func (s *RESTServer) listPatchTaskEvents(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "taskId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, 400, "invalid task id")
		return
	}
	if _, err := s.store.GetPatchTask(r.Context(), id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, 404, "task not found")
			return
		}
		writeError(w, 500, err.Error())
		return
	}
	if err := s.requirePatchTask(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if after < 0 {
		after = 0
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.store.ListPatchTaskEvents(r.Context(), id, after, limit)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	next := int64(0)
	if len(events) > 0 {
		next = events[len(events)-1].ID
	}
	writeJSON(w, 200, map[string]interface{}{"events": events, "next_cursor": next})
}
