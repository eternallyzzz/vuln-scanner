package store

import (
	"context"
	"time"
)

// AgentSummary aggregates agent ledger counts for the demo showcase.
type AgentSummary struct {
	Total  int            `json:"total"`
	Online int            `json:"online"`
	ByOS   map[string]int `json:"by_os"`
}

// AssetSummary aggregates CMDB asset ledger counts for the demo showcase.
type AssetSummary struct {
	Total       int            `json:"total"`
	ByType      map[string]int `json:"by_type"`
	ByLifecycle map[string]int `json:"by_lifecycle"`
}

// CVESummary aggregates cve_results counts for the demo showcase.
type CVESummary struct {
	Total      int            `json:"total"`
	Active     int            `json:"active"`
	Fixed      int            `json:"fixed"`
	BySeverity map[string]int `json:"by_severity"`
	BySource   map[string]int `json:"by_source"`
}

// AlertSummary aggregates alerting counts for the demo showcase.
type AlertSummary struct {
	Total          int            `json:"total"`
	ByStatus       map[string]int `json:"by_status"`
	OpenBySeverity map[string]int `json:"open_by_severity"`
	Rules          int            `json:"rules"`
}

// PatchSummary aggregates the patch pipeline counts for the demo showcase.
type PatchSummary struct {
	TasksByStatus map[string]int `json:"tasks_by_status"`
	Campaigns     int            `json:"campaigns"`
}

// DemoSummary is the read-only aggregate view used by the /demo page.
// Container scan state lives in the worker and is merged by the REST layer.
type DemoSummary struct {
	Agents      AgentSummary    `json:"agents"`
	Assets      AssetSummary    `json:"assets"`
	CVEs        CVESummary      `json:"cves"`
	Alerts      AlertSummary    `json:"alerts"`
	Patch       PatchSummary    `json:"patch"`
	CMDB        ReconcileReport `json:"cmdb"`
	GeneratedAt time.Time       `json:"generated_at"`
}

// DemoSummary gathers the global counts shown on the showcase page.
func (s *Store) DemoSummary(ctx context.Context) (DemoSummary, error) {
	var ds DemoSummary
	ds.GeneratedAt = time.Now()
	ds.Agents.ByOS = map[string]int{}
	ds.Assets.ByType = map[string]int{}
	ds.Assets.ByLifecycle = map[string]int{}
	ds.CVEs.BySeverity = map[string]int{}
	ds.CVEs.BySource = map[string]int{}
	ds.Alerts.ByStatus = map[string]int{}
	ds.Alerts.OpenBySeverity = map[string]int{}
	ds.Patch.TasksByStatus = map[string]int{}

	rows, err := s.pool.Query(ctx, `
		SELECT os_type, COUNT(*), COUNT(*) FILTER (WHERE status='online')
		FROM agents GROUP BY os_type ORDER BY os_type
	`)
	if err != nil {
		return ds, err
	}
	for rows.Next() {
		var osType string
		var total, online int
		if err := rows.Scan(&osType, &total, &online); err != nil {
			rows.Close()
			return ds, err
		}
		ds.Agents.ByOS[osType] = total
		ds.Agents.Total += total
		ds.Agents.Online += online
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ds, err
	}

	groups, err := scanCountGroups(ctx, s, `
		SELECT asset_type, COUNT(*) FROM assets GROUP BY asset_type ORDER BY asset_type
	`)
	if err != nil {
		return ds, err
	}
	for k, v := range groups {
		ds.Assets.ByType[k] = v
		ds.Assets.Total += v
	}

	groups, err = scanCountGroups(ctx, s, `
		SELECT lifecycle, COUNT(*) FROM assets GROUP BY lifecycle ORDER BY lifecycle
	`)
	if err != nil {
		return ds, err
	}
	for k, v := range groups {
		ds.Assets.ByLifecycle[k] = v
	}

	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM cve_results`).Scan(&ds.CVEs.Total); err != nil {
		return ds, err
	}
	groups, err = scanCountGroups(ctx, s, `
		SELECT status, COUNT(*) FROM cve_results GROUP BY status ORDER BY status
	`)
	if err != nil {
		return ds, err
	}
	for k, v := range groups {
		switch k {
		case "active":
			ds.CVEs.Active = v
		case "fixed":
			ds.CVEs.Fixed = v
		}
	}
	groups, err = scanCountGroups(ctx, s, `
		SELECT severity, COUNT(*) FROM cve_results WHERE status='active'
		GROUP BY severity ORDER BY severity
	`)
	if err != nil {
		return ds, err
	}
	for k, v := range groups {
		ds.CVEs.BySeverity[k] = v
	}
	groups, err = scanCountGroups(ctx, s, `
		SELECT source, COUNT(*) FROM cve_results WHERE status='active'
		GROUP BY source ORDER BY source
	`)
	if err != nil {
		return ds, err
	}
	for k, v := range groups {
		ds.CVEs.BySource[k] = v
	}

	groups, err = scanCountGroups(ctx, s, `
		SELECT status, COUNT(*) FROM alerts GROUP BY status ORDER BY status
	`)
	if err != nil {
		return ds, err
	}
	for k, v := range groups {
		ds.Alerts.ByStatus[k] = v
		ds.Alerts.Total += v
	}
	groups, err = scanCountGroups(ctx, s, `
		SELECT severity, COUNT(*) FROM alerts WHERE status='open'
		GROUP BY severity ORDER BY severity
	`)
	if err != nil {
		return ds, err
	}
	for k, v := range groups {
		ds.Alerts.OpenBySeverity[k] = v
	}
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alert_rules`).Scan(&ds.Alerts.Rules); err != nil {
		return ds, err
	}

	groups, err = scanCountGroups(ctx, s, `
		SELECT status, COUNT(*) FROM patch_tasks GROUP BY status ORDER BY status
	`)
	if err != nil {
		return ds, err
	}
	for k, v := range groups {
		ds.Patch.TasksByStatus[k] = v
	}
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM patch_campaigns`).Scan(&ds.Patch.Campaigns); err != nil {
		return ds, err
	}

	ds.CMDB, err = s.CMDBReconcileReport(ctx)
	if err != nil {
		return ds, err
	}
	return ds, nil
}

func scanCountGroups(ctx context.Context, s *Store, query string) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var v int
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}
