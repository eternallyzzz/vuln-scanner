package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

type scanPolicyInput struct {
	IntervalMinutes int   `json:"interval_minutes"`
	Enabled         *bool `json:"enabled"`
}

func (s *RESTServer) listScanPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.store.ListScanPolicies(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"policies": policies})
}

func (s *RESTServer) upsertScanPolicy(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var in scanPolicyInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	if in.IntervalMinutes < 10 {
		writeError(w, 400, "interval_minutes must be >= 10")
		return
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	agent, err := s.store.GetAgent(r.Context(), agentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, 404, "agent not found")
			return
		}
		writeError(w, 500, err.Error())
		return
	}
	if agent == nil {
		writeError(w, 404, "agent not found")
		return
	}
	if err := s.store.UpsertScanPolicy(r.Context(), agentID, in.IntervalMinutes, enabled); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"agent_id":         agentID,
		"interval_minutes": in.IntervalMinutes,
		"enabled":          enabled,
	})
}

func (s *RESTServer) triggerAgentScan(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	agent, err := s.store.GetAgent(r.Context(), agentID)
	if err != nil {
		writeError(w, 404, "agent not found")
		return
	}
	if agent == nil || agent.Status != "online" {
		writeError(w, 400, "agent not online")
		return
	}
	s.worker.TriggerMatch(agentID)
	writeJSON(w, 200, map[string]string{"status": "scan_triggered", "agent_id": agentID})
}
