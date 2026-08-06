package server

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"vuln-scanner/internal/store"
)

type remediationRequest struct {
	AlertID   int64
	Rule      store.AlertRule
	AgentID   string
	CVEID     string
	AssetName string
	Severity  string
	CVSS      float64
}

// hourlyLimiter is an in-memory sliding-window counter used to cap how many
// auto-generated campaigns the server actually creates per hour. Dedupe or
// non-deployable skips do not consume budget.
type hourlyLimiter struct {
	mu     sync.Mutex
	max    int
	stamps []time.Time
}

func (l *hourlyLimiter) Remaining(now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.max <= 0 {
		l.max = 50
	}
	cutoff := now.Add(-time.Hour)
	kept := l.stamps[:0]
	for _, t := range l.stamps {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	l.stamps = kept
	return l.max - len(l.stamps)
}

func (l *hourlyLimiter) Record(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.max <= 0 {
		l.max = 50
	}
	l.stamps = append(l.stamps, now)
}

// handleNewAlert is registered on the alert service and fires once per newly
// created alert. It enqueues remediation work only when both the rule and the
// server configuration opt into auto remediation.
func (w *Worker) handleNewAlert(ctx context.Context, rule store.AlertRule, alertID int64,
	agentID, cveID, assetName, severity string, cvss float64) {
	if w.patchCfg == nil || !w.patchCfg.Enabled ||
		w.patchCfg.AutoRemediation == nil || !w.patchCfg.AutoRemediation.Enabled {
		return
	}
	if !rule.AutoRemediate {
		return
	}
	req := remediationRequest{
		AlertID: alertID, Rule: rule, AgentID: agentID, CVEID: cveID,
		AssetName: assetName, Severity: severity, CVSS: cvss,
	}
	select {
	case w.remediationCh <- req:
	default:
		slog.Warn("remediation queue full, dropping alert", "alert_id", alertID)
	}
}

func (w *Worker) remediationLoop(ctx context.Context) {
	slog.Info("remediation loop started")
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case req := <-w.remediationCh:
			w.processRemediation(ctx, req)
		}
	}
}

func (w *Worker) processRemediation(ctx context.Context, req remediationRequest) {
	auto := w.patchCfg.AutoRemediation
	if auto == nil || !auto.Enabled {
		return
	}
	if !req.Rule.AutoRemediate {
		return
	}
	if severityRank(req.Severity) < severityRank(auto.MinSeverityResolved()) {
		if err := w.store.SetAlertRemediation(ctx, req.AlertID, nil,
			"skipped: severity below min_severity"); err != nil {
			slog.Warn("remediation: record skip failed", "alert_id", req.AlertID, "error", err)
		}
		return
	}
	detail, err := w.store.GetAlertDetail(ctx, req.AlertID)
	if err != nil {
		slog.Warn("remediation: alert lookup failed", "alert_id", req.AlertID, "error", err)
		return
	}
	if detail.Status != "open" {
		return
	}
	if detail.RemediationCampaignID != nil {
		return
	}
	if w.rateLimiter == nil || w.rateLimiter.Remaining(time.Now()) <= 0 {
		if err := w.store.SetAlertRemediation(ctx, req.AlertID, nil,
			"skipped: rate limited"); err != nil {
			slog.Warn("remediation: record rate limit failed", "alert_id", req.AlertID, "error", err)
		}
		return
	}

	approval := auto.ApprovalRequiredResolved()
	in := campaignGenerateInput{
		Name:             fmt.Sprintf("auto-alert-%d-%s", req.AlertID, req.CVEID),
		AgentIDs:         []string{req.AgentID},
		AssetNames:       []string{req.AssetName},
		CVEIDs:           []string{req.CVEID},
		ApprovalRequired: &approval,
	}
	agent, err := w.store.GetAgent(ctx, req.AgentID)
	if err != nil {
		slog.Warn("remediation: agent lookup failed", "agent_id", req.AgentID, "error", err)
		return
	}
	res, err := runCampaignGeneration(ctx, w.store, w.patchCfg, in, "auto-remediation", agent.TenantID)
	if err != nil {
		msg := "generation failed: " + err.Error()
		if e := w.store.SetAlertRemediation(ctx, req.AlertID, nil, msg); e != nil {
			slog.Warn("remediation: record failure failed", "alert_id", req.AlertID, "error", e)
		}
		slog.Warn("remediation generation failed", "alert_id", req.AlertID, "error", err)
		return
	}

	var reason string
	switch {
	case res.Created > 0:
		if w.rateLimiter != nil {
			w.rateLimiter.Record(time.Now())
		}
		cid := res.Campaign.ID
		if err := w.store.SetAlertRemediation(ctx, req.AlertID, &cid, ""); err != nil {
			slog.Warn("remediation: record campaign failed", "alert_id", req.AlertID, "error", err)
		}
		slog.Info("remediation campaign created", "alert_id", req.AlertID,
			"campaign_id", cid, "tasks", res.Created)
		return
	case len(res.Errors) > 0:
		reason = strings.Join(res.Errors, "; ")
	case res.Counts["skipped_dedup"] > 0:
		reason = "skipped: open patch task exists"
	case res.Counts["skipped_non_deployable"] > 0:
		reason = "skipped: no deployable fix"
	default:
		reason = "skipped: no matching fix"
	}
	if err := w.store.SetAlertRemediation(ctx, req.AlertID, nil, reason); err != nil {
		slog.Warn("remediation: record skip failed", "alert_id", req.AlertID, "error", err)
	}
	slog.Info("remediation skipped", "alert_id", req.AlertID, "reason", reason)
}
