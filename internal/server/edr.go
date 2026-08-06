package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	pb "vuln-scanner/api/gen/vulnscan/v1"
	"vuln-scanner/internal/edr"
	"vuln-scanner/internal/store"
)

type edrFindingInput struct {
	AgentID     string `json:"agent_id"`
	Hostname    string `json:"hostname"`
	Source      string `json:"source"`
	FindingType string `json:"finding_type"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Path        string `json:"path"`
	Hash        string `json:"hash"`
	Detail      string `json:"detail"`
}

// reportEDRFinding accepts an EDR malware finding over REST, stores it
// idempotently and, for HIGH/CRITICAL severities, creates or refreshes the
// linked open alert through the built-in edr-malware rule.
func (s *RESTServer) reportEDRFinding(w http.ResponseWriter, r *http.Request) {
	var in edrFindingInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		writeError(w, 400, "name is required")
		return
	}
	if strings.TrimSpace(in.AgentID) == "" && strings.TrimSpace(in.Hostname) == "" {
		writeError(w, 400, "agent_id or hostname is required")
		return
	}

	agentID := strings.TrimSpace(in.AgentID)
	hostname := ""
	if agentID == "" {
		agent, err := s.store.GetAgentByHostname(r.Context(), strings.TrimSpace(in.Hostname))
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, 404, "agent not found for hostname")
			return
		}
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		agentID = agent.ID
		hostname = agent.Hostname
	} else {
		agent, err := s.store.GetAgent(r.Context(), agentID)
		if errors.Is(err, pgx.ErrNoRows) || agent == nil {
			writeError(w, 404, "agent not found")
			return
		}
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		hostname = agent.Hostname
	}
	if hostname == "" {
		hostname = agentID
	}
	if err := s.requireAgent(r, agentID); err != nil {
		writeScopeError(w, err)
		return
	}

	finding, created, err := s.store.UpsertEDRFinding(r.Context(), store.EDRFindingInput{
		AgentID:     agentID,
		Source:      in.Source,
		FindingType: in.FindingType,
		Name:        in.Name,
		Severity:    in.Severity,
		Path:        in.Path,
		Hash:        in.Hash,
		Detail:      in.Detail,
	})
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if err := syncEDRFindingAlert(r.Context(), s.store, finding); err != nil {
		slog.Warn("edr finding alert sync failed", "finding_id", finding.ID, "error", err)
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]interface{}{
		"finding": finding,
		"created": created,
		"alerted": edr.ShouldAlert(finding.Severity),
	})
}

func (s *RESTServer) listEDRFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	tid, err := s.tid(r)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	findings, err := s.store.ListEDRFindings(r.Context(),
		q.Get("status"), q.Get("source"), q.Get("agent_id"),
		q.Get("severity"), q.Get("q"), limit, offset, tid)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"findings": findings, "total": len(findings)})
}

func (s *RESTServer) getEDRFinding(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "findingId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, 400, "invalid finding id")
		return
	}
	if err := s.requireEDRFinding(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	finding, err := s.store.GetEDRFinding(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "finding not found")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, finding)
}

func (s *RESTServer) setEDRFindingStatus(w http.ResponseWriter, r *http.Request, status string) {
	id, err := strconv.ParseInt(chi.URLParam(r, "findingId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, 400, "invalid finding id")
		return
	}
	if err := s.requireEDRFinding(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	if err := s.store.SetEDRFindingStatus(r.Context(), id, status, actorFromRequest(r)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, 404, "finding not found")
			return
		}
		writeError(w, 500, err.Error())
		return
	}
	finding, err := s.store.GetEDRFinding(r.Context(), id)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"finding": finding, "status": status})
}

func (s *RESTServer) ackEDRFinding(w http.ResponseWriter, r *http.Request) {
	s.setEDRFindingStatus(w, r, "acknowledged")
}

func (s *RESTServer) ignoreEDRFinding(w http.ResponseWriter, r *http.Request) {
	s.setEDRFindingStatus(w, r, "ignored")
}

func (s *RESTServer) resolveEDRFinding(w http.ResponseWriter, r *http.Request) {
	s.setEDRFindingStatus(w, r, "resolved")
}

// syncEDRFindingAlert is the shared alert linkage for REST reports and agent
// ClamAV uploads: HIGH/CRITICAL findings get an open alert under the
// edr-malware rule (cve_id empty, asset_name = hostname). The rule only
// exists when alerting is enabled, so a non-alerting deployment simply skips.
func syncEDRFindingAlert(ctx context.Context, st *store.Store, finding store.EDRFinding) error {
	if !edr.ShouldAlert(finding.Severity) {
		return nil
	}
	tenantID := int64(1)
	assetName := finding.AgentID
	if agent, err := st.GetAgent(ctx, finding.AgentID); err == nil && agent != nil {
		if agent.TenantID > 0 {
			tenantID = agent.TenantID
		}
		if agent.Hostname != "" {
			assetName = agent.Hostname
		}
	}
	rule, err := st.GetAlertRuleByName(ctx, tenantID, "edr-malware")
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !rule.Enabled {
		return nil
	}
	alertID, created, err := st.UpsertEDRFindingAlert(ctx, rule.ID,
		finding.AgentID, assetName, finding.Severity, finding.ID)
	if err != nil {
		return err
	}
	if created {
		if err := st.CreateAlertDeliveries(ctx, alertID, rule.Channels); err != nil {
			slog.Warn("edr alert delivery creation failed", "alert_id", alertID, "error", err)
		}
		slog.Info("edr alert created", "alert_id", alertID, "finding_id", finding.ID,
			"agent_id", finding.AgentID, "severity", finding.Severity)
	}
	return nil
}

// ingestEDRFindings stores agent-collected ClamAV findings reported inside a
// full inventory sync.
func (s *AgentGRPCServer) ingestEDRFindings(ctx context.Context, agentID string, items []*pb.EDRFinding) error {
	if len(items) == 0 {
		return nil
	}
	created := 0
	for _, item := range items {
		if item == nil || strings.TrimSpace(item.GetName()) == "" {
			continue
		}
		finding, isNew, err := s.store.UpsertEDRFinding(ctx, store.EDRFindingInput{
			AgentID:     agentID,
			Source:      item.GetSource(),
			FindingType: item.GetFindingType(),
			Name:        item.GetName(),
			Severity:    item.GetSeverity(),
			Path:        item.GetPath(),
			Hash:        item.GetHash(),
			Detail:      item.GetDetail(),
		})
		if err != nil {
			slog.Warn("edr finding ingest failed", "agent_id", agentID, "error", err)
			continue
		}
		if isNew {
			created++
		}
		if err := syncEDRFindingAlert(ctx, s.store, finding); err != nil {
			slog.Warn("edr finding alert sync failed", "finding_id", finding.ID, "error", err)
		}
	}
	if created > 0 {
		slog.Info("edr findings ingested", "agent_id", agentID, "created", created, "total", len(items))
	}
	return nil
}
