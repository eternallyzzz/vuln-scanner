package server

import (
	"testing"

	"vuln-scanner/internal/ticket"
)

func TestValidateRuleInputTicketRequiresEnabled(t *testing.T) {
	s := NewRESTServer(nil, nil, DefaultConfig(), nil, nil)
	in := &alertRuleInput{
		Name:           "ticket-only",
		SeverityFilter: "HIGH",
		TicketEnabled:  boolPtr(true),
	}
	if err := s.validateRuleInput(in); err == nil {
		t.Fatal("ticket_enabled must fail when ticketing is disabled")
	}

	t.Setenv("TICKET_PASSWORD", "pw")
	cfg := DefaultConfig()
	cfg.Ticketing = ticket.DefaultConfig()
	cfg.Ticketing.Enabled = true
	cfg.Ticketing.Provider = "jira"
	cfg.Ticketing.BaseURL = "https://jira.example.com"
	cfg.Ticketing.Username = "svc"
	cfg.Ticketing.Project = "SEC"
	svc, err := ticket.NewService(cfg.Ticketing)
	if err != nil {
		t.Fatal(err)
	}
	s = NewRESTServer(nil, nil, cfg, nil, nil)
	s.SetTicketService(svc)
	if err := s.validateRuleInput(in); err != nil {
		t.Fatalf("ticket-only rule must validate when ticketing is enabled: %v", err)
	}
	if len(in.Channels) != 0 {
		t.Fatalf("ticket-only rule channels = %#v, want empty", in.Channels)
	}
	rule := s.ruleFromInput(in)
	if !rule.TicketEnabled {
		t.Fatal("ruleFromInput must preserve ticket_enabled")
	}
}

func boolPtr(v bool) *bool {
	return &v
}
