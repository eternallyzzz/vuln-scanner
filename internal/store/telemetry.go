package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"vuln-scanner/internal/monitor"
)

// TelemetryStatus summarizes the current baseline state of one agent.
type TelemetryStatus struct {
	Warm       bool      `json:"warm"`
	FileCount  int       `json:"file_count"`
	Categories []string  `json:"categories"`
	LastSyncAt time.Time `json:"last_sync_at"`
}

// ReplaceFileBaselines stores the latest file-integrity snapshot and returns
// the drift it introduces. The first snapshot only warms the baseline.
func (s *Store) ReplaceFileBaselines(ctx context.Context, agentID string, facts []monitor.FileFact) ([]monitor.Drift, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	prev := make(map[string]monitor.FileFact)
	rows, err := tx.Query(ctx, `
		SELECT path, sha256, size_bytes, mode, modified_at
		FROM file_baselines WHERE agent_id=$1
	`, agentID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var f monitor.FileFact
		if err := rows.Scan(&f.Path, &f.SHA256, &f.SizeBytes, &f.Mode, &f.ModifiedAt); err != nil {
			rows.Close()
			return nil, err
		}
		prev[f.Path] = f
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if _, err := tx.Exec(ctx, `DELETE FROM file_baselines WHERE agent_id=$1`, agentID); err != nil {
		return nil, err
	}
	for _, f := range facts {
		if f.Path == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO file_baselines (agent_id, path, sha256, size_bytes, mode, modified_at, first_seen, last_seen)
			VALUES ($1,$2,$3,$4,$5,$6,now(),now())
			ON CONFLICT (agent_id, path) DO UPDATE SET
				sha256=EXCLUDED.sha256, size_bytes=EXCLUDED.size_bytes,
				mode=EXCLUDED.mode, modified_at=EXCLUDED.modified_at, last_seen=now()
		`, agentID, f.Path, f.SHA256, f.SizeBytes, f.Mode, f.ModifiedAt); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	cur := make(map[string]monitor.FileFact, len(facts))
	for _, f := range facts {
		cur[f.Path] = f
	}
	return monitor.DiffFiles(prev, cur), nil
}

// ReplaceBehaviorBaselines stores the latest behavior snapshot per category
// and returns the item-level drift. The first snapshot only warms the
// baseline.
func (s *Store) ReplaceBehaviorBaselines(ctx context.Context, agentID string, categories map[string][]monitor.BehaviorItem) ([]monitor.Drift, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	prev := make(map[string]map[string]json.RawMessage)
	rows, err := tx.Query(ctx, `
		SELECT category, payload FROM behavior_baselines WHERE agent_id=$1
	`, agentID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var category string
		var payload []byte
		if err := rows.Scan(&category, &payload); err != nil {
			rows.Close()
			return nil, err
		}
		var items []monitor.BehaviorItem
		if err := json.Unmarshal(payload, &items); err != nil {
			rows.Close()
			return nil, err
		}
		prev[category] = behaviorIndex(items)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if _, err := tx.Exec(ctx, `DELETE FROM behavior_baselines WHERE agent_id=$1`, agentID); err != nil {
		return nil, err
	}
	for category, items := range categories {
		if category == "" || len(items) == 0 {
			continue
		}
		payload, err := json.Marshal(items)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(payload)
		if _, err := tx.Exec(ctx, `
			INSERT INTO behavior_baselines (agent_id, category, payload, checksum, captured_at)
			VALUES ($1,$2,$3,$4,now())
			ON CONFLICT (agent_id, category) DO UPDATE SET
				payload=EXCLUDED.payload, checksum=EXCLUDED.checksum, captured_at=now()
		`, agentID, category, payload, hex.EncodeToString(sum[:])); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	cur := make(map[string]map[string]json.RawMessage, len(categories))
	for category, items := range categories {
		cur[category] = behaviorIndex(items)
	}
	return monitor.DiffBehavior(prev, cur), nil
}

func behaviorIndex(items []monitor.BehaviorItem) map[string]json.RawMessage {
	idx := make(map[string]json.RawMessage, len(items))
	for _, it := range items {
		idx[it.Key] = it.Data
	}
	return idx
}

// RebaselineTelemetry clears both baselines and resolves the related open
// findings so the next sync re-warms without reproducing stale drifts.
func (s *Store) RebaselineTelemetry(ctx context.Context, agentID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM file_baselines WHERE agent_id=$1`, agentID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM behavior_baselines WHERE agent_id=$1`, agentID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE edr_findings SET status='resolved'
		WHERE agent_id=$1 AND source IN ('file_integrity','behavior')
		  AND status IN ('open','acknowledged')
	`, agentID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// GetTelemetryStatus reports whether an agent has a warm baseline and how
// much telemetry is stored.
func (s *Store) GetTelemetryStatus(ctx context.Context, agentID string) (TelemetryStatus, error) {
	var out TelemetryStatus
	var categoryCount int
	if err := s.pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM file_baselines WHERE agent_id=$1),
			(SELECT COUNT(*) FROM behavior_baselines WHERE agent_id=$1),
			COALESCE((SELECT MAX(last_seen) FROM file_baselines WHERE agent_id=$1),
				(SELECT MAX(captured_at) FROM behavior_baselines WHERE agent_id=$1), now())
	`, agentID).Scan(&out.FileCount, &categoryCount, &out.LastSyncAt); err != nil {
		return out, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT category FROM behavior_baselines WHERE agent_id=$1 ORDER BY category
	`, agentID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return out, err
		}
		out.Categories = append(out.Categories, c)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	out.Warm = out.FileCount > 0 || len(out.Categories) > 0
	return out, nil
}
