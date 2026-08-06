package alert

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"vuln-scanner/internal/store"
)

type Result struct {
	CVEID     string
	AssetName string
	Severity  string
	Source    string
	CVSSScore float64
	Status    string
}

// NewAlertFunc is invoked once for every newly created alert (not for
// recurring updates of an already-open alert).
type NewAlertFunc func(ctx context.Context, rule store.AlertRule, alertID int64,
	agentID, cveID, assetName, severity string, cvss float64)

type Service struct {
	store      *store.Store
	cfg        *Config
	notifiers  map[string]Notifier
	onNewAlert NewAlertFunc
	workerID   string
}

func NewService(s *store.Store, cfg *Config) (*Service, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	svc := &Service{store: s, cfg: cfg, notifiers: map[string]Notifier{}}
	if cfg.WebhookURL != "" {
		n, err := NewWebhookNotifier(cfg.WebhookURL, cfg.WebhookSecret)
		if err != nil {
			return nil, err
		}
		svc.notifiers["webhook"] = n
	}
	if cfg.SMTP != nil && cfg.SMTP.Host != "" {
		svc.notifiers["smtp"] = NewSMTPNotifier(cfg.SMTP)
	}
	return svc, nil
}

func (s *Service) Enabled() bool {
	return s.cfg.Enabled
}

func (s *Service) SetOnNewAlert(fn NewAlertFunc) {
	s.onNewAlert = fn
}

// SetWorkerID tags claimed deliveries with this instance so two workers
// never deliver the same row concurrently.
func (s *Service) SetWorkerID(workerID string) {
	s.workerID = workerID
}

func (s *Service) Notifier(channel string) (Notifier, bool) {
	n, ok := s.notifiers[channel]
	return n, ok
}

func (s *Service) ChannelNames() []string {
	return s.cfg.ChannelNames()
}

func (s *Service) Evaluate(ctx context.Context, agentID string, results []Result) error {
	if !s.cfg.Enabled {
		return nil
	}
	return s.evaluate(ctx, agentID, results)
}

func (s *Service) evaluate(ctx context.Context, agentID string, results []Result) error {
	rules, err := s.store.ListEnabledAlertRules(ctx)
	if err != nil {
		return fmt.Errorf("list alert rules: %w", err)
	}
	if len(rules) == 0 {
		return nil
	}

	activeKeys := make([]string, 0, len(results))
	needMeta := false
	for _, rule := range rules {
		if len(rule.AssetTagFilter) > 0 || rule.EnvironmentFilter != "" {
			needMeta = true
			break
		}
	}
	var metaMap map[string]store.AssetMeta
	if needMeta {
		var err error
		metaMap, err = s.store.AssetMetaByAgent(ctx, agentID)
		if err != nil {
			slog.Warn("asset meta lookup failed", "agent_id", agentID, "error", err)
			metaMap = map[string]store.AssetMeta{}
		}
	}
	for _, rule := range rules {
		for i := range results {
			res := &results[i]
			if res.Status != "" && res.Status != "active" {
				continue
			}
			if !ruleMatches(rule, agentID, *res, metaMap[res.AssetName]) {
				continue
			}
			exempt, err := s.store.IsExempt(ctx, agentID, res.AssetName, res.CVEID)
			if err != nil {
				slog.Warn("exemption lookup failed", "agent_id", agentID,
					"cve", res.CVEID, "error", err)
			} else if exempt {
				continue
			}
			key := fmt.Sprintf("%d|%s|%s", rule.ID, res.CVEID, res.AssetName)
			activeKeys = append(activeKeys, key)

			alertID, created, err := s.store.UpsertAlertFromResult(ctx, rule,
				agentID, res.CVEID, res.AssetName, res.Severity, res.Source, res.CVSSScore)
			if err != nil {
				slog.Error("alert upsert failed", "agent_id", agentID,
					"cve", res.CVEID, "error", err)
				continue
			}
			if created {
				if err := s.store.CreateAlertDeliveries(ctx, alertID, s.cfg.ChannelNames()); err != nil {
					slog.Error("alert deliveries failed", "alert_id", alertID, "error", err)
				}
				slog.Info("alert created", "alert_id", alertID, "agent_id", agentID,
					"cve", res.CVEID, "asset", res.AssetName, "severity", res.Severity)
				if s.onNewAlert != nil {
					s.onNewAlert(ctx, rule, alertID, agentID,
						res.CVEID, res.AssetName, res.Severity, res.CVSSScore)
				}
			}
		}
	}

	if err := s.store.ResolveInactiveAlerts(ctx, agentID, activeKeys); err != nil {
		slog.Error("resolve inactive alerts failed", "agent_id", agentID, "error", err)
	}
	return nil
}

func (s *Service) RunDeliveryLoop(ctx context.Context) {
	if !s.cfg.Enabled {
		return
	}
	interval := time.Duration(s.cfg.DeliveryIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}
	maxAttempts := s.cfg.MaxAttempts
	if maxAttempts < 1 {
		maxAttempts = 3
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.deliverPending(ctx, maxAttempts)
		}
	}
}

func (s *Service) deliverPending(ctx context.Context, maxAttempts int) {
	deliveries, err := s.store.ClaimPendingAlertDeliveries(ctx, 20, s.workerID, store.StaleClaimLease)
	if err != nil {
		slog.Error("list pending deliveries failed", "error", err)
		return
	}
	for _, d := range deliveries {
		notifier, ok := s.notifiers[d.Channel]
		if !ok {
			s.store.MarkAlertDeliveryFailed(ctx, d.ID, s.workerID, "channel not configured", maxAttempts)
			continue
		}
		detail, err := s.store.GetAlertDetail(ctx, d.AlertID)
		if err != nil {
			s.store.MarkAlertDeliveryFailed(ctx, d.ID, s.workerID, err.Error(), maxAttempts)
			continue
		}
		payload := Payload{
			Type:          "alert",
			AlertID:       detail.ID,
			RuleName:      detail.RuleName,
			AgentID:       detail.AgentID,
			AgentHostname: detail.AgentHostname,
			CVEID:         detail.CVEID,
			AssetName:     detail.AssetName,
			Severity:      detail.Severity,
			CVSSScore:     detail.CVSSScore,
			Source:        detail.Source,
			DetectedAt:    detail.FirstSeen,
		}
		sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err = notifier.Send(sendCtx, payload)
		cancel()
		if err != nil {
			slog.Warn("alert delivery failed", "delivery_id", d.ID,
				"channel", d.Channel, "attempt", d.AttemptCount+1, "error", err)
			if e := s.store.MarkAlertDeliveryFailed(ctx, d.ID, s.workerID, err.Error(), maxAttempts); e != nil {
				slog.Error("mark delivery failed error", "error", e)
			}
			continue
		}
		if err := s.store.MarkAlertDeliverySent(ctx, d.ID, s.workerID); err != nil {
			slog.Error("mark delivery sent error", "error", err)
		}
	}
}

func (s *Service) SendTest(ctx context.Context, channel string) error {
	if !s.cfg.Enabled {
		return fmt.Errorf("alerting is disabled")
	}
	payload := Payload{
		Type:       "test",
		Severity:   "HIGH",
		CVEID:      "CVE-TEST-0001",
		AssetName:  "test-asset",
		DetectedAt: time.Now(),
	}
	channels := s.cfg.ChannelNames()
	if channel != "" {
		channels = []string{channel}
	}
	if len(channels) == 0 {
		return fmt.Errorf("no alert channel configured")
	}
	for _, ch := range channels {
		n, ok := s.notifiers[ch]
		if !ok {
			return fmt.Errorf("channel %q not configured", ch)
		}
		sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := n.Send(sendCtx, payload)
		cancel()
		if err != nil {
			return fmt.Errorf("channel %s: %w", ch, err)
		}
	}
	return nil
}
