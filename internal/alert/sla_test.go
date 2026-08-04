package alert

import (
	"testing"
	"time"
)

func TestSLACheckInterval(t *testing.T) {
	if got := (&Config{}).SLACheckInterval(); got != 15*time.Minute {
		t.Fatalf("default interval must be 15m, got %v", got)
	}
	if got := (&Config{SLACheckIntervalMinutes: 1}).SLACheckInterval(); got != time.Minute {
		t.Fatalf("configured interval wrong, got %v", got)
	}
	if got := (&Config{SLACheckIntervalMinutes: -5}).SLACheckInterval(); got != 15*time.Minute {
		t.Fatalf("negative interval must fall back to 15m, got %v", got)
	}
}

func TestDefaultRuleSpecs(t *testing.T) {
	if len(defaultRuleSpecs) != 4 {
		t.Fatalf("expected 4 default rules, got %d", len(defaultRuleSpecs))
	}
	seen := map[string]bool{}
	for _, d := range defaultRuleSpecs {
		if seen[d.name] {
			t.Fatalf("duplicate default rule name %q", d.name)
		}
		seen[d.name] = true
		if d.name != slaRuleName && d.severity == "" {
			t.Fatalf("rule %q must carry a severity filter", d.name)
		}
	}
	if !seen[slaRuleName] {
		t.Fatal("sla-breach rule must be part of defaults")
	}
}
