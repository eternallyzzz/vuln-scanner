package report

import (
	"context"
	"time"

	"vuln-scanner/internal/store"
)

const (
	htmlTopRisks = 20
	csvRiskLimit = 10000
	trendDays    = 30
	eolTop       = 50
	alertTop     = 20
)

// Data is the fully assembled panorama report payload.
type Data struct {
	GeneratedAt  time.Time
	Period       string
	Summary      Summary
	Risk         store.RiskSummary
	TopRisks     []store.RiskRow
	Risks        []store.RiskRow
	Trend        []store.RiskTrendPoint
	EOLAgents    []store.EOLAgentRow
	Alerts       []store.AlertDetail
	Patch        store.PatchSummary
	AuditLast24h int64
}

// Summary holds the headline counts shown at the top of the email.
type Summary struct {
	AgentsTotal       int
	AgentsOnline      int
	AssetsTotal       int
	ActiveCVEs        int
	FixedCVEs         int
	OpenAlerts        int
	Rules             int
	EOLAgents         int
	UnsupportedAgents int
	Exceptions        int
	Campaigns         int
}

// Build gathers every data source used by the daily report. HTML and CSV are
// rendered separately from the same snapshot so both formats agree.
func Build(ctx context.Context, s *store.Store) (*Data, error) {
	ds, err := s.DemoSummary(ctx)
	if err != nil {
		return nil, err
	}
	risk, err := s.RiskSummary(ctx)
	if err != nil {
		return nil, err
	}
	risks, err := s.RiskTop(ctx, csvRiskLimit, "", false)
	if err != nil {
		return nil, err
	}
	topRisks := risks
	if len(topRisks) > htmlTopRisks {
		topRisks = topRisks[:htmlTopRisks]
	}
	trend, err := s.RiskTrend(ctx, trendDays)
	if err != nil {
		return nil, err
	}
	eolAll, err := s.ListAgentsEOL(ctx)
	if err != nil {
		return nil, err
	}
	eolAgents := eolAll
	if len(eolAgents) > eolTop {
		eolAgents = eolAgents[:eolTop]
	}
	alerts, err := s.ListAlerts(ctx, "open", "", "", "", alertTop, 0)
	if err != nil {
		return nil, err
	}
	since := time.Now().Add(-24 * time.Hour)
	auditCount, err := s.CountAuditLogs(ctx, store.AuditLogFilter{Since: &since})
	if err != nil {
		return nil, err
	}

	return &Data{
		GeneratedAt: time.Now(),
		Period:      time.Now().Format("2006-01-02"),
		Summary: Summary{
			AgentsTotal:       ds.Agents.Total,
			AgentsOnline:      ds.Agents.Online,
			AssetsTotal:       ds.Assets.Total,
			ActiveCVEs:        ds.CVEs.Active,
			FixedCVEs:         ds.CVEs.Fixed,
			OpenAlerts:        ds.Alerts.ByStatus["open"],
			Rules:             ds.Alerts.Rules,
			EOLAgents:         risk.EOLAgents,
			UnsupportedAgents: risk.UnsupportedAgents,
			Exceptions:        risk.Exempted,
			Campaigns:         ds.Patch.Campaigns,
		},
		Risk:         risk,
		TopRisks:     topRisks,
		Risks:        risks,
		Trend:        trend,
		EOLAgents:    eolAgents,
		Alerts:       alerts,
		Patch:        ds.Patch,
		AuditLast24h: auditCount,
	}, nil
}
