package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

func (s *RESTServer) getRiskSummary(w http.ResponseWriter, r *http.Request) {
	sum, err := s.store.RiskSummary(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, sum)
}

func (s *RESTServer) getRiskTop(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	kevOnly := strings.EqualFold(q.Get("kev"), "true") || q.Get("kev") == "1"
	rows, err := s.store.RiskTop(r.Context(), limit, strings.ToUpper(q.Get("level")), kevOnly)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"total": len(rows), "rows": rows})
}

func (s *RESTServer) getRiskExport(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.RiskExportCSV(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="risk-export.csv"`)
	w.WriteHeader(200)
	_, _ = w.Write(data)
}

func (s *RESTServer) getRiskTrend(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	points, err := s.store.RiskTrend(r.Context(), days)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"days": points})
}

func (s *RESTServer) listExceptions(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListExceptions(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"exceptions": items})
}

func (s *RESTServer) createException(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CVEID     string `json:"cve_id"`
		AssetKey  string `json:"asset_key"`
		Reason    string `json:"reason"`
		ExpiresAt string `json:"expires_at"`
		CreatedBy string `json:"created_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	in.CVEID = strings.TrimSpace(in.CVEID)
	in.Reason = strings.TrimSpace(in.Reason)
	if in.CVEID == "" || in.Reason == "" {
		writeError(w, 400, "cve_id and reason are required")
		return
	}
	expiresAt, err := time.Parse(time.RFC3339, in.ExpiresAt)
	if err != nil {
		writeError(w, 400, "expires_at must be RFC3339")
		return
	}
	item, err := s.store.CreateException(r.Context(), in.CVEID, strings.TrimSpace(in.AssetKey),
		in.Reason, expiresAt, in.CreatedBy)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, item)
}

func (s *RESTServer) revokeException(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "exceptionId"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid exception id")
		return
	}
	if err := s.store.RevokeException(r.Context(), id, r.Header.Get("X-User")); err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, 404, "exception not found or already revoked")
			return
		}
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"exception_id": id, "status": "revoked"})
}

func (s *RESTServer) listSLAPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.store.ListSLAPolicies(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"policies": policies})
}

func (s *RESTServer) updateSLAPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "policyId"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid policy id")
		return
	}
	var in struct {
		Name   string `json:"name"`
		Hours  int    `json:"max_remediation_hours"`
		Enable *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	if in.Hours <= 0 {
		writeError(w, 400, "max_remediation_hours must be positive")
		return
	}
	enabled := true
	if in.Enable != nil {
		enabled = *in.Enable
	}
	policy, err := s.store.UpdateSLAPolicy(r.Context(), id, in.Name, in.Hours, enabled)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, 404, "policy not found")
			return
		}
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, policy)
}

// checkSLA manually triggers one overdue scan and returns its counts.
func (s *RESTServer) checkSLA(w http.ResponseWriter, r *http.Request) {
	if s.worker == nil || s.worker.alerts == nil {
		writeError(w, 400, "alerting is not configured")
		return
	}
	res, err := s.worker.alerts.CheckSLA(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"status":   "sla_check_completed",
		"created":  res.Created,
		"updated":  res.Updated,
		"resolved": res.Resolved,
	})
}

func (s *RESTServer) refreshIntel(w http.ResponseWriter, r *http.Request) {
	if s.worker == nil {
		writeError(w, 500, "worker unavailable")
		return
	}
	go func() {
		ctx := r.Context()
		if err := s.worker.RefreshIntel(ctx); err != nil {
			// Best effort async refresh; errors surface in server logs.
			_ = err
		}
	}()
	writeJSON(w, 202, map[string]string{"status": "intel_refresh_started"})
}
