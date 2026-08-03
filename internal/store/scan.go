package store

import (
	"context"
	"time"
)

type ScanPolicy struct {
	AgentID         string    `json:"agent_id"`
	IntervalMinutes int       `json:"interval_minutes"`
	Enabled         bool      `json:"enabled"`
	NextRunAt       time.Time `json:"next_run_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (s *Store) ListScanPolicies(ctx context.Context) ([]ScanPolicy, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT agent_id, interval_minutes, enabled, next_run_at, updated_at
		FROM scan_policies ORDER BY agent_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ScanPolicy
	for rows.Next() {
		var p ScanPolicy
		if err := rows.Scan(&p.AgentID, &p.IntervalMinutes, &p.Enabled, &p.NextRunAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) UpsertScanPolicy(ctx context.Context, agentID string, intervalMinutes int, enabled bool) error {
	if intervalMinutes < 10 {
		intervalMinutes = 10
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO scan_policies (agent_id, interval_minutes, enabled, next_run_at, updated_at)
		VALUES ($1,$2,$3,NOW(),NOW())
		ON CONFLICT (agent_id) DO UPDATE
		SET interval_minutes=$2, enabled=$3, updated_at=NOW()
	`, agentID, intervalMinutes, enabled)
	return err
}

func (s *Store) HasEnabledScanPolicy(ctx context.Context, agentID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM scan_policies WHERE agent_id=$1 AND enabled=TRUE)
	`, agentID).Scan(&exists)
	return exists, err
}

func (s *Store) DueScanPolicies(ctx context.Context) ([]ScanPolicy, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT agent_id, interval_minutes, enabled, next_run_at, updated_at
		FROM scan_policies WHERE enabled=TRUE AND next_run_at <= NOW()
		ORDER BY next_run_at LIMIT 50
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ScanPolicy
	for rows.Next() {
		var p ScanPolicy
		if err := rows.Scan(&p.AgentID, &p.IntervalMinutes, &p.Enabled, &p.NextRunAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) BumpScanPolicyNextRun(ctx context.Context, agentID string, intervalMinutes int) error {
	if intervalMinutes < 10 {
		intervalMinutes = 10
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE scan_policies SET next_run_at = NOW() + ($2 * interval '1 minute')
		WHERE agent_id=$1
	`, agentID, intervalMinutes)
	return err
}
