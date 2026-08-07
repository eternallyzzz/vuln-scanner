package store

import (
	"context"

	"vuln-scanner/internal/patch"
)

// ListDependencyRules returns every enabled static patch dependency rule.
func (s *Store) ListDependencyRules(ctx context.Context) ([]patch.DependencyRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, asset_name, fix_type, fix_value,
			dependency_asset, dependency_fix_type, dependency_fix_value,
			required, reason, source_ref, enabled
		FROM patch_dependency_rules
		ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []patch.DependencyRule
	for rows.Next() {
		var r patch.DependencyRule
		if err := rows.Scan(&r.ID, &r.AssetName, &r.FixType, &r.FixValue,
			&r.DependencyAsset, &r.DependencyFixType, &r.DependencyFixValue,
			&r.Required, &r.Reason, &r.SourceRef, &r.Enabled); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AgentInstalledAssets returns the active software asset names of an agent,
// used to decide whether a dependency rule applies (a dependency that is not
// installed cannot be upgraded by the task).
func (s *Store) AgentInstalledAssets(ctx context.Context, agentID string) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT name FROM assets
		WHERE agent_id=$1 AND asset_type='software' AND lifecycle='active'
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}
