package alert

import (
	"strings"

	"vuln-scanner/internal/store"
)

var severityRank = map[string]int{
	"CRITICAL": 4,
	"HIGH":     3,
	"MEDIUM":   2,
	"LOW":      1,
	"":         0,
}

func ruleMatches(rule store.AlertRule, agentID string, res Result, meta store.AssetMeta) bool {
	if !rule.Enabled {
		return false
	}
	if res.Status != "" && res.Status != "active" {
		return false
	}
	if rule.SeverityFilter != "" && severityRank[res.Severity] < severityRank[rule.SeverityFilter] {
		return false
	}
	if rule.SourceFilter != "" && !strings.EqualFold(rule.SourceFilter, res.Source) {
		return false
	}
	if rule.AgentIDFilter != "" && !strings.EqualFold(rule.AgentIDFilter, agentID) {
		return false
	}
	if rule.AssetFilter != "" && !strings.Contains(strings.ToLower(res.AssetName), strings.ToLower(rule.AssetFilter)) {
		return false
	}
	if len(rule.AssetTagFilter) > 0 {
		matched := false
		for _, want := range rule.AssetTagFilter {
			for _, have := range meta.Tags {
				if strings.EqualFold(want, have) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	if rule.EnvironmentFilter != "" && !strings.EqualFold(rule.EnvironmentFilter, meta.Environment) {
		return false
	}
	if res.CVSSScore < rule.MinCVSS {
		return false
	}
	return res.CVEID != "" && res.AssetName != ""
}
