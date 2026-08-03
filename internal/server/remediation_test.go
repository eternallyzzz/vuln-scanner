package server

import (
	"testing"
	"time"

	"vuln-scanner/internal/alert"
	"vuln-scanner/internal/patch"
	"vuln-scanner/internal/store"
)

func TestHourlyLimiter(t *testing.T) {
	now := time.Now()
	l := &hourlyLimiter{max: 2}
	if got := l.Remaining(now); got != 2 {
		t.Fatalf("remaining = %d, want 2", got)
	}
	l.Record(now)
	l.Record(now.Add(time.Second))
	if got := l.Remaining(now.Add(2 * time.Second)); got != 0 {
		t.Fatalf("remaining = %d, want 0 after two records", got)
	}
	if got := l.Remaining(now.Add(2 * time.Hour)); got != 2 {
		t.Fatalf("remaining = %d, want 2 after window elapses", got)
	}
}

func TestValidateRuleInputAutoRemediate(t *testing.T) {
	alertSvc, err := alert.NewService(&store.Store{}, &alert.Config{
		Enabled:       true,
		WebhookURL:    "http://127.0.0.1:9/none",
		WebhookSecret: "secret",
		MaxAttempts:   3,
	})
	if err != nil {
		t.Fatalf("alert service init: %v", err)
	}
	base := func() *alertRuleInput {
		enabled := true
		return &alertRuleInput{
			Name: "test", Enabled: &enabled, AutoRemediate: &enabled,
			Channels: []string{"webhook"},
		}
	}

	s := &RESTServer{alerts: alertSvc}
	s.cfg = &Config{Patch: &patch.Config{Enabled: false}}
	if err := s.validateRuleInput(base()); err == nil {
		t.Error("expected error when auto_remediate set but patch disabled")
	}

	s.cfg.Patch.Enabled = true
	s.cfg.Patch.AutoRemediation = &patch.AutoRemediationConfig{Enabled: false}
	if err := s.validateRuleInput(base()); err == nil {
		t.Error("expected error when auto_remediation disabled")
	}

	s.cfg.Patch.AutoRemediation.Enabled = true
	if err := s.validateRuleInput(base()); err != nil {
		t.Errorf("valid auto_remediate rule rejected: %v", err)
	}

	disabled := false
	in := base()
	in.AutoRemediate = &disabled
	s.cfg.Patch.Enabled = false
	if err := s.validateRuleInput(in); err != nil {
		t.Errorf("auto_remediate=false must not require patch config: %v", err)
	}
}

func TestRuleFromInputAutoRemediate(t *testing.T) {
	enabled := true
	in := alertRuleInput{
		Name: "auto", AutoRemediate: &enabled,
	}
	zero := 0.0
	cooldown := 60
	in.MinCVSS = &zero
	in.CooldownMinutes = &cooldown
	in.Channels = []string{"webhook"}
	rule := (&RESTServer{}).ruleFromInput(&in)
	if !rule.AutoRemediate {
		t.Error("rule.AutoRemediate = false, want true")
	}
}
