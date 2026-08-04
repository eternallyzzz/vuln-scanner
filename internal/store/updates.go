package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"vuln-scanner/internal/collector"
)

// UpdateFact is the persisted form of one WUA/WSUS update fact.
type UpdateFact = collector.UpdateFact

// UpdateSourceStatus is the persisted reachability state of the WUA/WSUS
// update source for an agent.
type UpdateSourceStatus = collector.UpdateSourceStatus

// ReplaceAgentUpdateFacts replaces all WUA/WSUS facts for an agent with the
// latest batch. Facts are treated as a snapshot: entries that disappeared
// from WUA are removed from the table.
func (s *Store) ReplaceAgentUpdateFacts(ctx context.Context, agentID string, facts []UpdateFact) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM agent_update_facts WHERE agent_id=$1`, agentID); err != nil {
		return err
	}
	for _, f := range facts {
		if f.KB == "" {
			continue
		}
		collectedAt := f.CollectedAt
		if collectedAt.IsZero() {
			collectedAt = time.Now()
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO agent_update_facts
				(agent_id, kb, title, state, severity, reboot_required, source, collected_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (agent_id, kb, state) DO UPDATE SET
				title=$3, severity=$5, reboot_required=$6, source=$7, collected_at=$8
		`, agentID, f.KB, f.Title, f.State, f.Severity, f.RebootRequired, f.Source, collectedAt); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// UpsertAgentUpdateStatus records whether the update source was reachable at
// the latest collection.
func (s *Store) UpsertAgentUpdateStatus(ctx context.Context, agentID string, status UpdateSourceStatus) error {
	lastChecked := status.LastCheckedAt
	if lastChecked.IsZero() {
		lastChecked = time.Now()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agent_update_status (agent_id, source_reachable, last_checked_at, error)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (agent_id) DO UPDATE SET
			source_reachable=$2, last_checked_at=$3, error=$4
	`, agentID, status.SourceReachable, lastChecked, status.Error)
	return err
}

// GetAgentUpdateFacts returns the latest update facts for an agent, newest
// first by collected_at.
func (s *Store) GetAgentUpdateFacts(ctx context.Context, agentID string) ([]UpdateFact, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT kb, title, state, severity, reboot_required, source, collected_at
		FROM agent_update_facts
		WHERE agent_id=$1
		ORDER BY collected_at DESC, kb
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []UpdateFact
	for rows.Next() {
		var f UpdateFact
		if err := rows.Scan(&f.KB, &f.Title, &f.State, &f.Severity,
			&f.RebootRequired, &f.Source, &f.CollectedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// GetAgentUpdateStatus returns the latest update-source reachability record.
// A missing record is returned as (nil, nil) so callers can fall back to
// local inference.
func (s *Store) GetAgentUpdateStatus(ctx context.Context, agentID string) (*UpdateSourceStatus, error) {
	var status UpdateSourceStatus
	err := s.pool.QueryRow(ctx, `
		SELECT source_reachable, last_checked_at, error
		FROM agent_update_status WHERE agent_id=$1
	`, agentID).Scan(&status.SourceReachable, &status.LastCheckedAt, &status.Error)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &status, nil
}
