// Package monitor implements the server-side drift engine for periodic
// telemetry baselines: file integrity facts and behavior snapshots are
// diffed against the previous state and converted into findings.
package monitor

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// FileFact is one monitored file's integrity state (mirrors the agent fact).
type FileFact struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	SizeBytes  int64  `json:"size_bytes"`
	Mode       string `json:"mode"`
	ModifiedAt string `json:"modified_at"`
}

// BehaviorItem is one canonicalized behavior element (a process, port,
// startup item, account, ...) with a stable key and its payload.
type BehaviorItem struct {
	Key  string          `json:"key"`
	Data json.RawMessage `json:"data"`
}

// Drift is one detected change between two telemetry snapshots.
type Drift struct {
	Category string          `json:"category"`
	Kind     string          `json:"kind"` // added | removed | modified
	Key      string          `json:"key"`
	Path     string          `json:"path,omitempty"`
	Old      json.RawMessage `json:"old,omitempty"`
	New      json.RawMessage `json:"new,omitempty"`
	Severity string          `json:"severity"`
}

// CategorySeverity is the default severity for behavior drift findings.
var CategorySeverity = map[string]string{
	"processes":       "MEDIUM",
	"open_ports":      "MEDIUM",
	"startup_items":   "HIGH",
	"scheduled_tasks": "HIGH",
	"accounts":        "HIGH",
	"ssh_keys":        "HIGH",
	"services":        "LOW",
	"firewall_rules":  "LOW",
}

// SeverityForPath returns the finding severity for a file drift based on the
// path's sensitivity class. Identity, cron, sudo and system-startup paths
// are HIGH; everything else is MEDIUM.
func SeverityForPath(path string) string {
	lower := strings.ToLower(path)
	for _, token := range []string{
		"cron", "authorized_keys", "sshd_config", "/etc/passwd", "/etc/shadow",
		"/etc/sudoers", "systemd/system", "/usr/local/bin", "drivers/etc/hosts",
		"system32/config",
	} {
		if strings.Contains(lower, token) {
			return "HIGH"
		}
	}
	return "MEDIUM"
}

// DiffFiles compares the previous and current file facts. A warm-up baseline
// (prev empty) produces no drifts.
func DiffFiles(prev, cur map[string]FileFact) []Drift {
	if len(prev) == 0 {
		return nil
	}
	var out []Drift
	for path, curFact := range cur {
		prevFact, ok := prev[path]
		if !ok {
			out = append(out, Drift{
				Category: "file", Kind: "added", Key: path, Path: path,
				New: mustJSON(curFact), Severity: SeverityForPath(path),
			})
			continue
		}
		if prevFact.SHA256 != curFact.SHA256 || prevFact.SizeBytes != curFact.SizeBytes ||
			prevFact.Mode != curFact.Mode || prevFact.ModifiedAt != curFact.ModifiedAt {
			out = append(out, Drift{
				Category: "file", Kind: "modified", Key: path, Path: path,
				Old: mustJSON(prevFact), New: mustJSON(curFact),
				Severity: SeverityForPath(path),
			})
		}
	}
	for path := range prev {
		if _, ok := cur[path]; !ok {
			out = append(out, Drift{
				Category: "file", Kind: "removed", Key: path, Path: path,
				Old: mustJSON(prev[path]), Severity: SeverityForPath(path),
			})
		}
	}
	sortDrifts(out)
	return out
}

// DiffBehavior compares previous and current per-category behavior items.
// A warm-up baseline (prev empty) produces no drifts.
func DiffBehavior(prev, cur map[string]map[string]json.RawMessage) []Drift {
	if len(prev) == 0 {
		return nil
	}
	var out []Drift
	for category, curItems := range cur {
		prevItems := prev[category]
		severity := CategorySeverity[category]
		if severity == "" {
			severity = "MEDIUM"
		}
		for key, data := range curItems {
			old, ok := prevItems[key]
			if !ok {
				out = append(out, Drift{
					Category: category, Kind: "added", Key: key,
					New: data, Severity: severity,
				})
				continue
			}
			if !jsonEqual(old, data) {
				out = append(out, Drift{
					Category: category, Kind: "modified", Key: key,
					Old: old, New: data, Severity: severity,
				})
			}
		}
		for key, old := range prevItems {
			if _, ok := curItems[key]; !ok {
				out = append(out, Drift{
					Category: category, Kind: "removed", Key: key,
					Old: old, Severity: severity,
				})
			}
		}
	}
	sortDrifts(out)
	return out
}

// jsonEqual reports whether two JSON payloads are semantically equal. Stored
// JSONB round-trips through PostgreSQL's canonical text form, so raw byte
// comparison would flag harmless whitespace/key-order differences as drift.
func jsonEqual(a, b json.RawMessage) bool {
	if bytes.Equal(a, b) {
		return true
	}
	var av, bv interface{}
	if json.Unmarshal(a, &av) != nil || json.Unmarshal(b, &bv) != nil {
		return false
	}
	ca, err := json.Marshal(av)
	if err != nil {
		return false
	}
	cb, err := json.Marshal(bv)
	if err != nil {
		return false
	}
	return bytes.Equal(ca, cb)
}

func mustJSON(v interface{}) json.RawMessage {
	raw, _ := json.Marshal(v)
	return raw
}

func sortDrifts(drifts []Drift) {
	sort.Slice(drifts, func(i, j int) bool {
		if drifts[i].Category != drifts[j].Category {
			return drifts[i].Category < drifts[j].Category
		}
		if drifts[i].Kind != drifts[j].Kind {
			return drifts[i].Kind < drifts[j].Kind
		}
		return drifts[i].Key < drifts[j].Key
	})
}
