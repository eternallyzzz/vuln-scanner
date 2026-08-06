// Package edr contains the pure helpers shared by the EDR findings data
// plane: dedupe keys, severity threshold and status normalization.
package edr

import "strings"

// DedupeKey returns the identity used to collapse repeated EDR reports for
// one agent+source: the file hash when present, otherwise the finding name.
func DedupeKey(agentID, source, hash, name string) string {
	key := strings.TrimSpace(hash)
	if key == "" {
		key = strings.TrimSpace(name)
	}
	return agentID + "\x00" + source + "\x00" + key
}

// ShouldAlert reports whether a finding severity crosses the alerting
// threshold. Only HIGH and CRITICAL findings automatically generate or
// refresh an open alert; LOW/MEDIUM findings are stored for later triage.
func ShouldAlert(severity string) bool {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "HIGH", "CRITICAL":
		return true
	default:
		return false
	}
}

// NormalizeSeverity validates a severity string against the accepted set and
// falls back to MEDIUM when the caller did not supply one.
func NormalizeSeverity(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return strings.ToUpper(strings.TrimSpace(severity))
	default:
		return "MEDIUM"
	}
}

// ValidStatus reports whether a finding status is one of the triage states.
func ValidStatus(status string) bool {
	switch status {
	case "open", "acknowledged", "ignored", "resolved":
		return true
	default:
		return false
	}
}
