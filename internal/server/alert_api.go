package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"vuln-scanner/internal/store"
)

type alertRuleInput struct {
	Name              string   `json:"name"`
	Enabled           *bool    `json:"enabled"`
	SeverityFilter    string   `json:"severity_filter"`
	SourceFilter      string   `json:"source_filter"`
	AgentIDFilter     string   `json:"agent_id_filter"`
	AssetFilter       string   `json:"asset_filter"`
	MinCVSS           *float64 `json:"min_cvss"`
	CooldownMinutes   *int     `json:"cooldown_minutes"`
	Channels          []string `json:"channels"`
	AssetTagFilter    []string `json:"asset_tag_filter"`
	EnvironmentFilter string   `json:"environment_filter"`
	AutoRemediate     *bool    `json:"auto_remediate"`
	TicketEnabled     *bool    `json:"ticket_enabled"`
}

func (s *RESTServer) validateRuleInput(in *alertRuleInput) error {
	if strings.TrimSpace(in.Name) == "" {
		return errors.New("name is required")
	}
	if in.SeverityFilter == "" {
		in.SeverityFilter = "HIGH"
	}
	switch in.SeverityFilter {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
	default:
		return errors.New("severity_filter must be LOW/MEDIUM/HIGH/CRITICAL")
	}
	switch in.SourceFilter {
	case "", "msrc", "nvd", "osv", "debian":
	default:
		return errors.New("source_filter must be msrc/nvd/osv/debian or empty")
	}
	if in.MinCVSS == nil {
		zero := 0.0
		in.MinCVSS = &zero
	}
	if *in.MinCVSS < 0 || *in.MinCVSS > 10 {
		return errors.New("min_cvss must be within [0,10]")
	}
	if in.CooldownMinutes == nil {
		def := 1440
		in.CooldownMinutes = &def
	}
	if *in.CooldownMinutes < 0 {
		return errors.New("cooldown_minutes must be >= 0")
	}
	ticketEnabled := in.TicketEnabled != nil && *in.TicketEnabled
	if len(in.Channels) == 0 && !ticketEnabled {
		in.Channels = []string{"webhook"}
	}
	if len(in.EnvironmentFilter) > 100 {
		return errors.New("environment_filter too long (max 100)")
	}
	if in.AutoRemediate != nil && *in.AutoRemediate {
		if s.cfg.Patch == nil || !s.cfg.Patch.Enabled ||
			s.cfg.Patch.AutoRemediation == nil || !s.cfg.Patch.AutoRemediation.Enabled {
			return errors.New("auto_remediate requires patch.auto_remediation.enabled on the server")
		}
	}
	if ticketEnabled && (s.tickets == nil || !s.tickets.Enabled()) {
		return errors.New("ticket_enabled requires ticketing enabled on the server")
	}
	allowed := map[string]bool{}
	if s.alerts != nil {
		for _, ch := range s.alerts.ChannelNames() {
			allowed[ch] = true
		}
	}
	for _, ch := range in.Channels {
		if !allowed[ch] {
			return errors.New("channel " + ch + " is not configured on the server")
		}
	}
	return nil
}

func (s *RESTServer) ruleFromInput(in *alertRuleInput) store.AlertRule {
	r := store.AlertRule{
		Name:              strings.TrimSpace(in.Name),
		SeverityFilter:    in.SeverityFilter,
		SourceFilter:      in.SourceFilter,
		AgentIDFilter:     in.AgentIDFilter,
		AssetFilter:       in.AssetFilter,
		MinCVSS:           *in.MinCVSS,
		CooldownMinutes:   *in.CooldownMinutes,
		Channels:          in.Channels,
		AssetTagFilter:    dedupTags(in.AssetTagFilter),
		EnvironmentFilter: strings.TrimSpace(in.EnvironmentFilter),
		AutoRemediate:     in.AutoRemediate != nil && *in.AutoRemediate,
		TicketEnabled:     in.TicketEnabled != nil && *in.TicketEnabled,
	}
	if in.Enabled != nil {
		r.Enabled = *in.Enabled
	} else {
		r.Enabled = true
	}
	return r
}

func dedupTags(tags []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

func (s *RESTServer) listAlertRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListAlertRules(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"rules": rules})
}

func (s *RESTServer) createAlertRule(w http.ResponseWriter, r *http.Request) {
	var in alertRuleInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	if err := s.validateRuleInput(&in); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	rule, err := s.store.CreateAlertRule(r.Context(), s.ruleFromInput(&in))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, rule)
}

func ruleIDParam(r *http.Request) (int64, error) {
	return strconv.ParseInt(chi.URLParam(r, "ruleId"), 10, 64)
}

func (s *RESTServer) getAlertRule(w http.ResponseWriter, r *http.Request) {
	id, err := ruleIDParam(r)
	if err != nil {
		writeError(w, 400, "invalid rule id")
		return
	}
	rule, err := s.store.GetAlertRule(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "rule not found")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rule)
}

func (s *RESTServer) updateAlertRule(w http.ResponseWriter, r *http.Request) {
	id, err := ruleIDParam(r)
	if err != nil {
		writeError(w, 400, "invalid rule id")
		return
	}
	var in alertRuleInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, 400, "invalid body: "+err.Error())
		return
	}
	if err := s.validateRuleInput(&in); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	rule, err := s.store.UpdateAlertRule(r.Context(), id, s.ruleFromInput(&in))
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "rule not found")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rule)
}

func (s *RESTServer) deleteAlertRule(w http.ResponseWriter, r *http.Request) {
	id, err := ruleIDParam(r)
	if err != nil {
		writeError(w, 400, "invalid rule id")
		return
	}
	if err := s.store.DeleteAlertRule(r.Context(), id); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"deleted": true})
}

func (s *RESTServer) testAlertRule(w http.ResponseWriter, r *http.Request) {
	if s.alerts == nil || !s.alerts.Enabled() {
		writeError(w, 400, "alerting is disabled")
		return
	}
	channel := r.URL.Query().Get("channel")
	if err := s.alerts.SendTest(r.Context(), channel); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "sent"})
}

func (s *RESTServer) listAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	tid, err := s.tid(r)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	alerts, err := s.store.ListAlerts(r.Context(),
		q.Get("status"), q.Get("agent_id"), q.Get("severity"), q.Get("asset_filter"), limit, offset, tid)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"alerts": alerts, "total": len(alerts)})
}

func (s *RESTServer) setAlertStatus(w http.ResponseWriter, r *http.Request, status string) {
	id, err := strconv.ParseInt(chi.URLParam(r, "alertId"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid alert id")
		return
	}
	if err := s.requireAlert(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	if err := s.store.SetAlertStatus(r.Context(), id, status, actorFromRequest(r)); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"alert_id": id, "status": status})
}

func (s *RESTServer) ackAlert(w http.ResponseWriter, r *http.Request) {
	s.setAlertStatus(w, r, "ack")
}

func (s *RESTServer) resolveAlert(w http.ResponseWriter, r *http.Request) {
	s.setAlertStatus(w, r, "resolved")
}

// retryAlertTicket resets the create/sync retry budget for one alert and
// wakes the background ticket worker.
func (s *RESTServer) retryAlertTicket(w http.ResponseWriter, r *http.Request) {
	if s.tickets == nil || !s.tickets.Enabled() {
		writeError(w, 400, "ticketing is disabled")
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "alertId"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid alert id")
		return
	}
	if err := s.requireAlert(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	detail, err := s.store.GetAlertDetail(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "alert not found")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	rule, err := s.store.GetAlertRule(r.Context(), detail.RuleID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "alert rule not found")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if !rule.TicketEnabled {
		writeError(w, 400, "alert rule does not enable tickets")
		return
	}
	if detail.TicketKey == "" && detail.Status != "open" {
		writeError(w, 400, "ticket can only be retried for open alerts without a ticket or existing tickets pending sync")
		return
	}
	if err := s.store.ResetTicketRetry(r.Context(), id); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if s.worker != nil {
		s.worker.TriggerTicket()
	}
	writeJSON(w, 200, map[string]interface{}{
		"alert_id": id, "ticket_key": detail.TicketKey, "status": detail.Status,
	})
}

// remediateAlert manually triggers the alert -> patch campaign pipeline for
// one alert. It is synchronous and bypasses the rule's auto_remediate flag,
// but still respects the global patch configuration and approval defaults.
func (s *RESTServer) remediateAlert(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Patch == nil || !s.cfg.Patch.Enabled {
		writeError(w, 400, "patch deployment is disabled")
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "alertId"), 10, 64)
	if err != nil {
		writeError(w, 400, "invalid alert id")
		return
	}
	if err := s.requireAlert(r, id); err != nil {
		writeScopeError(w, err)
		return
	}
	detail, err := s.store.GetAlertDetail(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "alert not found")
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if detail.Status != "open" {
		writeError(w, 400, "alert is not open")
		return
	}
	if detail.RemediationCampaignID != nil {
		writeJSON(w, 200, map[string]interface{}{
			"alert_id": id, "already_remediated": true,
			"campaign_id": *detail.RemediationCampaignID,
		})
		return
	}

	approval := true
	if s.cfg.Patch.AutoRemediation != nil {
		approval = s.cfg.Patch.AutoRemediation.ApprovalRequiredResolved()
	}
	var body struct {
		ApprovalRequired *bool `json:"approval_required"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&body)
	}
	if body.ApprovalRequired != nil {
		approval = *body.ApprovalRequired
	}
	in := campaignGenerateInput{
		Name:             fmt.Sprintf("manual-alert-%d-%s", id, detail.CVEID),
		AgentIDs:         []string{detail.AgentID},
		AssetNames:       []string{detail.AssetName},
		CVEIDs:           []string{detail.CVEID},
		ApprovalRequired: &approval,
	}
	agent, err := s.store.GetAgent(r.Context(), detail.AgentID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	res, err := runCampaignGeneration(r.Context(), s.store, s.cfg.Patch, in, requestActor(r), agent.TenantID)
	if err != nil {
		if errors.Is(err, errNoAgentsMatch) {
			writeError(w, 404, err.Error())
			return
		}
		writeError(w, 500, err.Error())
		return
	}
	if res.Created > 0 {
		cid := res.Campaign.ID
		if err := s.store.SetAlertRemediation(r.Context(), id, &cid, ""); err != nil {
			writeError(w, 500, err.Error())
			return
		}
		writeJSON(w, 201, map[string]interface{}{
			"alert_id": id, "campaign": res.Campaign, "created": res.Created,
			"counts": res.Counts, "errors": res.Errors,
		})
		return
	}
	reason := "skipped: no matching fix"
	if len(res.Errors) > 0 {
		reason = strings.Join(res.Errors, "; ")
	} else if res.Counts["skipped_dedup"] > 0 {
		reason = "skipped: open patch task exists"
	} else if res.Counts["skipped_non_deployable"] > 0 {
		reason = "skipped: no deployable fix"
	}
	if err := s.store.SetAlertRemediation(r.Context(), id, nil, reason); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"alert_id": id, "created": 0, "reason": reason,
		"counts": res.Counts, "errors": res.Errors,
	})
}
