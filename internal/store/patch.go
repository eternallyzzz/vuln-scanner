package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

type PatchTask struct {
	ID               int64           `json:"id"`
	AgentID          string          `json:"agent_id"`
	AssetName        string          `json:"asset_name"`
	FixType          string          `json:"fix_type"`
	FixValue         string          `json:"fix_value"`
	Action           string          `json:"action"`
	CVEIDs           []string        `json:"cve_ids"`
	Command          string          `json:"command"`
	Commands         [][]string      `json:"commands"`
	Status           string          `json:"status"`
	ApprovalRequired bool            `json:"approval_required"`
	WindowStart      *time.Time      `json:"window_start,omitempty"`
	WindowEnd        *time.Time      `json:"window_end,omitempty"`
	CampaignID       *int64          `json:"campaign_id,omitempty"`
	Result           json.RawMessage `json:"result"`
	CreatedBy        string          `json:"created_by"`
	ApprovedBy       string          `json:"approved_by"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
	CancelRequested  bool            `json:"cancel_requested"`
}

type PatchTaskInput struct {
	AgentID          string
	AssetName        string
	FixType          string
	FixValue         string
	Action           string
	CVEIDs           []string
	Command          string
	Commands         [][]string
	ApprovalRequired bool
	WindowStart      *time.Time
	WindowEnd        *time.Time
	CreatedBy        string
}

func scanPatchTask(row pgx.Row) (PatchTask, error) {
	var t PatchTask
	var commandsRaw []byte
	var resultRaw []byte
	err := row.Scan(&t.ID, &t.AgentID, &t.AssetName, &t.FixType, &t.FixValue,
		&t.Action, &t.CVEIDs, &t.Command, &commandsRaw, &t.Status,
		&t.ApprovalRequired, &t.WindowStart, &t.WindowEnd, &resultRaw,
		&t.CreatedBy, &t.ApprovedBy, &t.CreatedAt, &t.UpdatedAt, &t.CampaignID,
		&t.CancelRequested)
	if err != nil {
		return t, err
	}
	json.Unmarshal(commandsRaw, &t.Commands)
	t.Result = resultRaw
	return t, nil
}

const patchTaskColumns = `id, agent_id, asset_name, fix_type, fix_value, action, cve_ids,
	command, commands, status, approval_required, window_start, window_end,
	result, created_by, approved_by, created_at, updated_at, campaign_id, cancel_requested`

// PatchTaskEvent is one incremental execution event (stdout/stderr chunk or
// heartbeat). id is the monotonic cursor used by the REST event stream.
type PatchTaskEvent struct {
	ID        int64     `json:"id"`
	TaskID    int64     `json:"task_id"`
	Stream    string    `json:"stream"`
	Data      string    `json:"data"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) CreatePatchTask(ctx context.Context, in PatchTaskInput) (PatchTask, error) {
	commands, _ := json.Marshal(in.Commands)
	if len(in.CVEIDs) == 0 {
		in.CVEIDs = []string{}
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO patch_tasks (agent_id, asset_name, fix_type, fix_value, action,
			cve_ids, command, commands, status, approval_required, window_start, window_end, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$10,$11,$12)
		RETURNING `+patchTaskColumns,
		in.AgentID, in.AssetName, in.FixType, in.FixValue, in.Action,
		in.CVEIDs, in.Command, commands, in.ApprovalRequired, in.WindowStart, in.WindowEnd, in.CreatedBy)
	return scanPatchTask(row)
}

func (s *Store) GetPatchTask(ctx context.Context, id int64) (PatchTask, error) {
	return scanPatchTask(s.pool.QueryRow(ctx,
		`SELECT `+patchTaskColumns+` FROM patch_tasks WHERE id=$1`, id))
}

func (s *Store) ListPatchTasks(ctx context.Context, agentID, status string, limit, offset int) ([]PatchTask, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+patchTaskColumns+` FROM patch_tasks
		WHERE (''=$1 OR agent_id=$1) AND (''=$2 OR status=$2)
		ORDER BY id DESC LIMIT $3 OFFSET $4
	`, agentID, status, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []PatchTask
	for rows.Next() {
		t, err := scanPatchTask(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}

func (s *Store) SetPatchTaskStatus(ctx context.Context, id int64, status, actor string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE patch_tasks SET status=$2,
			approved_by=CASE WHEN $2='approved' THEN $3 ELSE approved_by END,
			cancel_requested=FALSE,
			updated_at=NOW()
		WHERE id=$1
	`, id, status, actor)
	return err
}

// ClaimNextPatchTask atomically reserves the oldest approved, in-window task
// for an agent and returns it with status running.
func (s *Store) ClaimNextPatchTask(ctx context.Context, agentID string) (PatchTask, error) {
	row := s.pool.QueryRow(ctx, `
		WITH claim AS (
			SELECT id FROM patch_tasks
			WHERE agent_id=$1 AND status='approved'
			  AND (window_start IS NULL OR window_start <= NOW())
			  AND (window_end IS NULL OR window_end > NOW())
			ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED
		)
		UPDATE patch_tasks SET status='running', updated_at=NOW()
		FROM claim WHERE patch_tasks.id = claim.id
		RETURNING patch_tasks.*`, agentID)
	return scanPatchTask(row)
}

func (s *Store) CompletePatchTask(ctx context.Context, id int64, status string, result map[string]interface{}) error {
	raw, _ := json.Marshal(result)
	_, err := s.pool.Exec(ctx, `
		UPDATE patch_tasks SET status=$2, result=$3, cancel_requested=FALSE, updated_at=NOW()
		WHERE id=$1
	`, id, status, raw)
	return err
}

// AppendPatchTaskEvents appends one batch of execution events inside a
// transaction so the stream cursor stays consistent.
func (s *Store) AppendPatchTaskEvents(ctx context.Context, taskID int64, events []PatchTaskEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, e := range events {
		if _, err := tx.Exec(ctx, `
			INSERT INTO patch_task_events (task_id, stream, data)
			VALUES ($1,$2,$3)
		`, taskID, e.Stream, e.Data); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ListPatchTaskEvents returns events after the given cursor id, oldest
// first. limit defaults to 200 and is capped at 1000.
func (s *Store) ListPatchTaskEvents(ctx context.Context, taskID, afterID int64, limit int) ([]PatchTaskEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, task_id, stream, data, created_at
		FROM patch_task_events
		WHERE task_id=$1 AND id>$2
		ORDER BY id
		LIMIT $3
	`, taskID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PatchTaskEvent
	for rows.Next() {
		var e PatchTaskEvent
		if err := rows.Scan(&e.ID, &e.TaskID, &e.Stream, &e.Data, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RequestPatchTaskCancel sets the cancel flag on a running task. It reports
// whether the task was actually running (and therefore flagged).
func (s *Store) RequestPatchTaskCancel(ctx context.Context, id int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE patch_tasks SET cancel_requested=TRUE, updated_at=NOW()
		WHERE id=$1 AND status='running'
	`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// PatchTaskCancelRequested reports whether a task has a pending cancel
// request. It is returned with every progress acknowledgment.
func (s *Store) PatchTaskCancelRequested(ctx context.Context, id int64) (bool, error) {
	var v bool
	if err := s.pool.QueryRow(ctx, `
		SELECT cancel_requested FROM patch_tasks WHERE id=$1
	`, id).Scan(&v); err != nil {
		return false, err
	}
	return v, nil
}

func (s *Store) ReapStalePatchTasks(ctx context.Context, timeout time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE patch_tasks SET status='approved', updated_at=NOW()
		WHERE status='running' AND updated_at < NOW() - $1::interval
	`, timeout.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
