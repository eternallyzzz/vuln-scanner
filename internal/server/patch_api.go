package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
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
	if err != nil {
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
	writeJSON(w, 200, task)
}

func (s *RESTServer) setPatchTaskStatus(w http.ResponseWriter, r *http.Request, status string) {
	id, err := strconv.ParseInt(chi.URLParam(r, "taskId"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid task id")
		return
	}
	task, err := s.store.GetPatchTask(r.Context(), id)
	if err != nil {
		writeError(w, 404, "task not found")
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
	actor := strings.TrimSpace(r.Header.Get("X-User"))
	if actor == "" {
		actor = "api"
	}
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
	s.setPatchTaskStatus(w, r, "cancelled")
}

func (s *RESTServer) retryPatchTask(w http.ResponseWriter, r *http.Request) {
	s.setPatchTaskStatus(w, r, "retry")
}
