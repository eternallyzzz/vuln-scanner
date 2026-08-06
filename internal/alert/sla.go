package alert

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"vuln-scanner/internal/store"
)

const slaRuleName = "sla-breach"

var defaultRuleSpecs = []struct {
	name     string
	severity string
	source   string
}{
	{name: "default-critical", severity: "CRITICAL"},
	{name: "default-high", severity: "HIGH"},
	{name: "default-medium", severity: "MEDIUM"},
	{name: "edr-malware", severity: "HIGH"},
	{name: slaRuleName, source: "sla"},
}

func (s *Service) SLACheckInterval() time.Duration {
	return s.cfg.SLACheckInterval()
}

// SLACheckInterval returns how often the overdue scan runs (default 15m,
// minimum 1m).
func (c *Config) SLACheckInterval() time.Duration {
	minutes := c.SLACheckIntervalMinutes
	if minutes <= 0 {
		minutes = 15
	}
	if minutes < 1 {
		minutes = 1
	}
	return time.Duration(minutes) * time.Minute
}

// EnsureDefaultRules idempotently seeds global alert rules (CRITICAL/HIGH/
// MEDIUM) plus the internal sla-breach rule, using the channels configured at
// runtime. Existing rules with the same name are never overwritten.
func (s *Service) EnsureDefaultRules(ctx context.Context) error {
	if !s.cfg.Enabled {
		return nil
	}
	channels := s.cfg.ChannelNames()
	for _, d := range defaultRuleSpecs {
		if _, err := s.store.GetAlertRuleByName(ctx, d.name); err == nil {
			continue
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err := s.store.CreateAlertRule(ctx, store.AlertRule{
			Name:            d.name,
			Enabled:         true,
			SeverityFilter:  d.severity,
			SourceFilter:    d.source,
			MinCVSS:         0,
			CooldownMinutes: 1440,
			Channels:        channels,
			AssetTagFilter:  []string{},
			AutoRemediate:   false,
		}); err != nil {
			return err
		}
		slog.Info("alert: default rule created", "rule", d.name)
	}
	return nil
}

// SLACheckResult is the outcome of one overdue scan.
type SLACheckResult struct {
	Created  int `json:"created"`
	Updated  int `json:"updated"`
	Resolved int `json:"resolved"`
}

// CheckSLA scans active CVEs past their SLA deadline, creates/refreshes
// sla-breach alerts (delivering only on first breach), and resolves SLA
// alerts whose CVE is no longer overdue (fixed/resolved/exempt/policy off).
func (s *Service) CheckSLA(ctx context.Context) (SLACheckResult, error) {
	var res SLACheckResult
	if !s.cfg.Enabled {
		return res, nil
	}
	if err := s.EnsureDefaultRules(ctx); err != nil {
		return res, err
	}
	rule, err := s.store.GetAlertRuleByName(ctx, slaRuleName)
	if err != nil {
		return res, err
	}
	overdue, err := s.store.OverdueCVEs(ctx)
	if err != nil {
		return res, err
	}

	active := make(map[string]bool, len(overdue))
	for _, o := range overdue {
		key := o.AgentID + "|" + o.CVEID + "|" + o.AssetName
		exempt, err := s.store.IsExempt(ctx, o.AgentID, o.AssetName, o.CVEID)
		if err != nil {
			slog.Warn("sla: exemption lookup failed", "agent", o.AgentID,
				"cve", o.CVEID, "error", err)
			// Be safe: keep alerting and treat as active so an existing
			// alert is not resolved on a lookup error.
		} else if exempt {
			continue
		}
		active[key] = true
		alertID, created, err := s.store.UpsertSLABreachAlert(ctx, rule.ID,
			o.AgentID, o.CVEID, o.AssetName, o.Severity, o.CVSSScore)
		if err != nil {
			slog.Warn("sla: alert upsert failed", "agent", o.AgentID,
				"cve", o.CVEID, "error", err)
			continue
		}
		if created {
			if err := s.store.CreateAlertDeliveries(ctx, alertID, s.cfg.ChannelNames()); err != nil {
				slog.Warn("sla: delivery creation failed", "alert_id", alertID, "error", err)
			}
			res.Created++
			slog.Info("sla: breach alert created", "agent", o.AgentID,
				"cve", o.CVEID, "asset", o.AssetName, "due_at", o.DueAt)
		} else {
			res.Updated++
		}
	}
	resolved, err := s.store.ResolveSLABreachAlerts(ctx, rule.ID, active)
	if err != nil {
		return res, err
	}
	res.Resolved = int(resolved)
	if res.Created+res.Updated+res.Resolved > 0 {
		slog.Info("sla: check completed", "created", res.Created,
			"updated", res.Updated, "resolved", res.Resolved)
	}
	return res, nil
}
