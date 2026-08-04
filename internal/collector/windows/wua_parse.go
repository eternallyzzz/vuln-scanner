package windows

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"vuln-scanner/internal/collector"
)

// wuaKBPattern matches a KB article number inside WUA titles or identity
// strings ("KB5034441", "kb5034441").
var wuaKBPattern = regexp.MustCompile(`(?i)\bKB(\d+)\b`)

type wuaRawUpdate struct {
	KB             string `json:"kb"`
	Title          string `json:"title"`
	State          string `json:"state"`
	Severity       string `json:"severity"`
	RebootRequired bool   `json:"reboot_required"`
	Source         string `json:"source"`
	Error          string `json:"error"`
}

// ParseWUAUpdates converts the compact JSON emitted by the PowerShell WUA
// collector into update facts. A single object is accepted as well as an
// array; an object carrying an "error" field is returned as a Go error so the
// caller can mark the update source unreachable without failing the host.
func ParseWUAUpdates(raw []byte, source string, collectedAt time.Time) ([]collector.UpdateFact, error) {
	raw = trimWUACLIXML(raw)
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}

	var probe struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &probe); err == nil && probe.Error != "" {
		return nil, errors.New(probe.Error)
	}

	var items []wuaRawUpdate
	if err := json.Unmarshal(raw, &items); err != nil {
		var single wuaRawUpdate
		if err2 := json.Unmarshal(raw, &single); err2 != nil {
			return nil, err
		}
		items = []wuaRawUpdate{single}
	}

	var out []collector.UpdateFact
	for _, it := range items {
		if it.Error != "" {
			return nil, errors.New(it.Error)
		}
		kb := normalizeUpdateKB(it.KB)
		if kb == "" {
			kb = normalizeUpdateKB(it.Title)
		}
		if kb == "" {
			continue
		}
		state := strings.ToLower(strings.TrimSpace(it.State))
		if state != "installed" {
			state = "pending"
		}
		factSource := strings.ToLower(strings.TrimSpace(it.Source))
		if factSource == "" {
			factSource = source
		}
		if factSource == "" {
			factSource = "wua"
		}
		out = append(out, collector.UpdateFact{
			KB:             kb,
			Title:          strings.TrimSpace(it.Title),
			State:          state,
			Severity:       strings.TrimSpace(it.Severity),
			RebootRequired: it.RebootRequired,
			Source:         factSource,
			CollectedAt:    collectedAt,
		})
	}
	return out, nil
}

// trimWUACLIXML strips PowerShell's "#< CLIXML" progress-record envelope that
// can precede/follow the JSON payload when the collector runs with progress
// stream rendering enabled.
func trimWUACLIXML(raw []byte) []byte {
	s := string(raw)
	start := strings.IndexAny(s, "[{")
	if start < 0 {
		return raw
	}
	end := strings.LastIndexAny(s, "]}")
	if end < start {
		return raw
	}
	return []byte(s[start : end+1])
}

// normalizeUpdateKB returns the canonical "KB1234567" form for any string
// containing a KB article number, or "" when none is present.
func normalizeUpdateKB(s string) string {
	m := wuaKBPattern.FindStringSubmatch(strings.TrimSpace(s))
	if len(m) < 2 {
		return ""
	}
	return "KB" + m[1]
}
