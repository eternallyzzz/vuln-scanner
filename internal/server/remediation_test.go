package server

import (
	"testing"

	"vuln-scanner/internal/alert"
	"vuln-scanner/internal/patch"
	"vuln-scanner/internal/store"
)

func TestAutoRemediationExceeded(t *testing.T) {
	for _, c := range []struct {
		count int64
		max   int
		want  bool
	}{
		{0, 2, false},
		{1, 2, false},
		{2, 2, true},
		{3, 2, true},
		{49, 0, false},
		{50, 0, true},
		{0, -1, false},
	} {
		if got := autoRemediationExceeded(c.count, c.max); got != c.want {
			t.Errorf("autoRemediationExceeded(%d,%d) = %v, want %v", c.count, c.max, got, c.want)
		}
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
