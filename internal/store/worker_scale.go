package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	// StaleClaimLease is how long a claimed row/job may sit untouched before
	// another worker may reclaim it after a crash.
	StaleClaimLease = 2 * time.Minute
)

// Job is one row in the PostgreSQL-backed job queue.
type Job struct {
	ID           int64           `json:"id"`
	Kind         string          `json:"kind"`
	Key          string          `json:"key"`
	Payload      json.RawMessage `json:"payload"`
	Status       string          `json:"status"`
	AttemptCount int             `json:"attempt_count"`
	LastError    string          `json:"last_error"`
	AvailableAt  time.Time       `json:"available_at"`
	ClaimedBy    string          `json:"claimed_by"`
	ClaimedAt    *time.Time      `json:"claimed_at,omitempty"`
	FinishedAt   *time.Time      `json:"finished_at,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
}

// LoopLease is one single-runner loop lease row.
type LoopLease struct {
	Loop        string    `json:"loop"`
	WorkerID    string    `json:"worker_id"`
	Hostname    string    `json:"hostname"`
	PID         int       `json:"pid"`
	AcquiredAt  time.Time `json:"acquired_at"`
	HeartbeatAt time.Time `json:"heartbeat_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// EnqueueJob inserts one coalesced job. A live job with the same (kind,key)
// already pending/claimed returns inserted=false. payload may be nil.
func (s *Store) EnqueueJob(ctx context.Context, kind, key string, payload interface{}) (int64, bool, error) {
	raw := []byte("{}")
	if payload != nil {
		var err error
		raw, err = json.Marshal(payload)
		if err != nil {
			return 0, false, err
		}
	}
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO job_queue (kind, key, payload)
		VALUES ($1,$2,$3)
		ON CONFLICT (kind, key) WHERE status IN ('pending','claimed') DO NOTHING
		RETURNING id
	`, kind, key, raw).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

// NotifyJobs broadcasts one PostgreSQL notification per kind on the shared
// job queue channel. It is best-effort; worker tickers are the fallback.
func (s *Store) NotifyJobs(ctx context.Context, kinds ...string) error {
	for _, kind := range kinds {
		if _, err := s.pool.Exec(ctx, `SELECT pg_notify('vulnscan_jobs', $1)`, kind); err != nil {
			return err
		}
	}
	return nil
}

// ClaimJobs atomically claims up to limit pending jobs of the given kinds
// using FOR UPDATE SKIP LOCKED.
func (s *Store) ClaimJobs(ctx context.Context, kinds []string, workerID string, limit int) ([]Job, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		UPDATE job_queue j SET status='claimed', claimed_by=$2, claimed_at=NOW()
		WHERE j.id IN (
			SELECT id FROM job_queue
			WHERE status='pending' AND available_at <= NOW() AND kind = ANY($1::text[])
			ORDER BY id LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, kind, key, payload, status, attempt_count, last_error,
			available_at, claimed_by, claimed_at, finished_at, created_at
	`, kinds, workerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanJobs(rows)
}

func scanJobs(rows pgx.Rows) ([]Job, error) {
	var out []Job
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.Kind, &j.Key, &j.Payload, &j.Status,
			&j.AttemptCount, &j.LastError, &j.AvailableAt, &j.ClaimedBy,
			&j.ClaimedAt, &j.FinishedAt, &j.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// FinishJob removes a successful job and records a failed one. Failed rows
// are retained for observability and cleaned up by CleanupFinishedJobs.
func (s *Store) FinishJob(ctx context.Context, id int64, errText string) error {
	if errText == "" {
		_, err := s.pool.Exec(ctx, `DELETE FROM job_queue WHERE id=$1`, id)
		return err
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE job_queue SET status='failed', attempt_count=attempt_count+1,
			last_error=$2, finished_at=NOW(), claimed_by='', claimed_at=NULL
		WHERE id=$1
	`, id, errText)
	return err
}

// RequeueStaleJobs resets claimed jobs whose claim lease has expired so a
// crashed worker does not lose them forever.
func (s *Store) RequeueStaleJobs(ctx context.Context, lease time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE job_queue SET status='pending', claimed_by='', claimed_at=NULL
		WHERE status='claimed' AND claimed_at < NOW() - $1::interval
	`, lease)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// CleanupFinishedJobs removes done/failed job rows older than the window.
func (s *Store) CleanupFinishedJobs(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM job_queue
		WHERE status IN ('done','failed') AND finished_at < NOW() - $1::interval
	`, olderThan)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PendingJobCounts returns pending job counts grouped by kind.
func (s *Store) PendingJobCounts(ctx context.Context) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT kind, COUNT(*) FROM job_queue WHERE status='pending' GROUP BY kind ORDER BY kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var kind string
		var n int64
		if err := rows.Scan(&kind, &n); err != nil {
			return nil, err
		}
		out[kind] = n
	}
	return out, rows.Err()
}

// AcquireLoopLease tries to take (or keep) the lease for one single-runner
// loop. It returns true when this worker holds the lease.
func (s *Store) AcquireLoopLease(ctx context.Context, loop, workerID, hostname string, pid int, lease time.Duration) (bool, error) {
	var acquired string
	err := s.pool.QueryRow(ctx, `
		UPDATE worker_leases
		SET worker_id=$2, hostname=$3, pid=$4, acquired_at=NOW(), heartbeat_at=NOW(),
			expires_at=NOW() + $5::interval
		WHERE loop=$1 AND (expires_at < NOW() OR worker_id=$2)
		RETURNING worker_id
	`, loop, workerID, hostname, pid, lease).Scan(&acquired)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO worker_leases (loop, worker_id, hostname, pid, acquired_at, heartbeat_at, expires_at)
		VALUES ($1,$2,$3,$4,NOW(),NOW(),NOW() + $5::interval)
		ON CONFLICT (loop) DO NOTHING
		RETURNING worker_id
	`, loop, workerID, hostname, pid, lease).Scan(&acquired)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// RenewLoopLease refreshes a lease this worker already holds.
func (s *Store) RenewLoopLease(ctx context.Context, loop, workerID string, lease time.Duration) (bool, error) {
	var renewed string
	err := s.pool.QueryRow(ctx, `
		UPDATE worker_leases SET heartbeat_at=NOW(), expires_at=NOW() + $3::interval
		WHERE loop=$1 AND worker_id=$2
		RETURNING worker_id
	`, loop, workerID, lease).Scan(&renewed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ReleaseLoopLease releases one loop lease held by this worker.
func (s *Store) ReleaseLoopLease(ctx context.Context, loop, workerID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM worker_leases WHERE loop=$1 AND worker_id=$2`, loop, workerID)
	return err
}

// ReleaseWorkerLeases drops every lease held by a worker (used on shutdown).
func (s *Store) ReleaseWorkerLeases(ctx context.Context, workerID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM worker_leases WHERE worker_id=$1`, workerID)
	return err
}

// ListWorkerLeases returns all current loop leases for observability.
func (s *Store) ListWorkerLeases(ctx context.Context) ([]LoopLease, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT loop, worker_id, hostname, pid, acquired_at, heartbeat_at, expires_at
		FROM worker_leases ORDER BY loop`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LoopLease
	for rows.Next() {
		var l LoopLease
		if err := rows.Scan(&l.Loop, &l.WorkerID, &l.Hostname, &l.PID,
			&l.AcquiredAt, &l.HeartbeatAt, &l.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// SetWorkerState upserts one cross-instance state value.
func (s *Store) SetWorkerState(ctx context.Context, key string, value interface{}) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO worker_state (key, value, updated_at)
		VALUES ($1,$2,NOW())
		ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()
	`, key, raw)
	return err
}

// GetWorkerStateBool reads a boolean cross-instance state value.
func (s *Store) GetWorkerStateBool(ctx context.Context, key string) (bool, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT value FROM worker_state WHERE key=$1`, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var v bool
	if err := json.Unmarshal(raw, &v); err != nil {
		return false, err
	}
	return v, nil
}
