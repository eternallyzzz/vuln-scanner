package edr

import "testing"

func TestDedupeKey(t *testing.T) {
	withHash := DedupeKey("agent-1", "clamav", "abc123", "Virus.A")
	withoutHash := DedupeKey("agent-1", "clamav", "", "Virus.A")
	if withHash == withoutHash {
		t.Fatal("hash and name dedupe keys must differ")
	}
	if withoutHash != DedupeKey("agent-1", "clamav", "   ", "Virus.A") {
		t.Fatal("blank hash must fall back to name")
	}
	if DedupeKey("agent-1", "clamav", "abc123", "Virus.A") != DedupeKey("agent-1", "clamav", "abc123", "Virus.B") {
		t.Fatal("hash must win over name in dedupe key")
	}
	if DedupeKey("agent-1", "clamav", "", "Virus.A") == DedupeKey("agent-1", "edr_api", "", "Virus.A") {
		t.Fatal("source must be part of dedupe key")
	}
	if DedupeKey("agent-1", "clamav", "", "Virus.A") == DedupeKey("agent-2", "clamav", "", "Virus.A") {
		t.Fatal("agent must be part of dedupe key")
	}
}

func TestShouldAlert(t *testing.T) {
	if !ShouldAlert("HIGH") || !ShouldAlert("CRITICAL") || !ShouldAlert(" critical ") {
		t.Fatal("HIGH/CRITICAL must alert")
	}
	if ShouldAlert("LOW") || ShouldAlert("MEDIUM") || ShouldAlert("") || ShouldAlert("bogus") {
		t.Fatal("LOW/MEDIUM/unknown must not alert")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	if NormalizeSeverity("high") != "HIGH" || NormalizeSeverity("CRITICAL") != "CRITICAL" {
		t.Fatal("severity normalization failed")
	}
	if NormalizeSeverity("") != "MEDIUM" || NormalizeSeverity("nope") != "MEDIUM" {
		t.Fatal("invalid severity must fall back to MEDIUM")
	}
}

func TestValidStatus(t *testing.T) {
	for _, s := range []string{"open", "acknowledged", "ignored", "resolved"} {
		if !ValidStatus(s) {
			t.Fatalf("status %q must be valid", s)
		}
	}
	if ValidStatus("bogus") {
		t.Fatal("bogus status must be invalid")
	}
}
