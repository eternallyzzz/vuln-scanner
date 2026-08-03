package patch

import "testing"

func TestAutoRemediationResolvedDefaults(t *testing.T) {
	a := &AutoRemediationConfig{}
	if got := a.ApprovalRequiredResolved(); !got {
		t.Error("ApprovalRequiredResolved default = false, want true")
	}
	if got := a.MinSeverityResolved(); got != "HIGH" {
		t.Errorf("MinSeverityResolved default = %q, want HIGH", got)
	}
	if got := a.MaxCampaignsPerHourResolved(); got != 50 {
		t.Errorf("MaxCampaignsPerHourResolved default = %d, want 50", got)
	}

	approval := false
	a = &AutoRemediationConfig{ApprovalRequired: &approval, MinSeverity: " low ", MaxCampaignsPerHour: 3}
	if got := a.ApprovalRequiredResolved(); got {
		t.Error("ApprovalRequiredResolved = true, want false")
	}
	if got := a.MinSeverityResolved(); got != "LOW" {
		t.Errorf("MinSeverityResolved = %q, want LOW", got)
	}
	if got := a.MaxCampaignsPerHourResolved(); got != 3 {
		t.Errorf("MaxCampaignsPerHourResolved = %d, want 3", got)
	}
}

func TestConfigValidateAutoRemediation(t *testing.T) {
	cfg := &Config{
		Enabled:             true,
		AgentTimeoutSeconds: 600,
		AutoRemediation:     &AutoRemediationConfig{Enabled: true, MinSeverity: "urgent"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid min_severity")
	}

	cfg.AutoRemediation.MinSeverity = "CRITICAL"
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid auto remediation rejected: %v", err)
	}
}
