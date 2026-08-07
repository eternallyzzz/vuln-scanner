package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type PatchTask struct {
	ID                    int64           `json:"id"`
	AgentID               string          `json:"agent_id"`
	AssetName             string          `json:"asset_name"`
	FixType               string          `json:"fix_type"`
	FixValue              string          `json:"fix_value"`
	Action                string          `json:"action"`
	CVEIDs                []string        `json:"cve_ids"`
	Command               string          `json:"command"`
	Commands              [][]string      `json:"commands"`
	Status                string          `json:"status"`
	ApprovalRequired      bool            `json:"approval_required"`
	WindowStart           *time.Time      `json:"window_start,omitempty"`
	WindowEnd             *time.Time      `json:"window_end,omitempty"`
	CampaignID            *int64          `json:"campaign_id,omitempty"`
	Result                json.RawMessage `json:"result"`
	CreatedBy             string          `json:"created_by"`
	ApprovedBy            string          `json:"approved_by"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
	CancelRequested       bool            `json:"cancel_requested"`
	RuntimeVerifyBaseline json.RawMessage `json:"runtime_verify_baseline,omitempty"`
	RuntimeVerifyStatus   string          `json:"runtime_verify_status,omitempty"`
	RuntimeVerifyDetail   string          `json:"runtime_verify_detail,omitempty"`
	RuntimeVerifyAt       *time.Time      `json:"runtime_verify_at,omitempty"`
	PostPatchStatus       string          `json:"post_patch_status,omitempty"`
	PostPatchDetail       string          `json:"post_patch_detail,omitempty"`
	PostPatchAt           *time.Time      `json:"post_patch_at,omitempty"`
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
	var baselineRaw []byte
	err := row.Scan(&t.ID, &t.AgentID, &t.AssetName, &t.FixType, &t.FixValue,
		&t.Action, &t.CVEIDs, &t.Command, &commandsRaw, &t.Status,
		&t.ApprovalRequired, &t.WindowStart, &t.WindowEnd, &resultRaw,
		&t.CreatedBy, &t.ApprovedBy, &t.CreatedAt, &t.UpdatedAt, &t.CampaignID,
		&t.CancelRequested, &baselineRaw, &t.RuntimeVerifyStatus,
		&t.RuntimeVerifyDetail, &t.RuntimeVerifyAt,
		&t.PostPatchStatus, &t.PostPatchDetail, &t.PostPatchAt)
	if err != nil {
		return t, err
	}
	json.Unmarshal(commandsRaw, &t.Commands)
	t.Result = resultRaw
	t.RuntimeVerifyBaseline = baselineRaw
	return t, nil
}

const patchTaskColumns = `id, agent_id, asset_name, fix_type, fix_value, action, cve_ids,
	command, commands, status, approval_required, window_start, window_end,
	result, created_by, approved_by, created_at, updated_at, campaign_id, cancel_requested,
	runtime_verify_baseline, runtime_verify_status, runtime_verify_detail, runtime_verify_at,
	post_patch_status, post_patch_detail, post_patch_at`

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
	task, err := scanPatchTask(row)
	if err != nil {
		return task, err
	}
	if e := s.appendSiemPatchTask(ctx, "patch_task.created", task, task.CreatedBy); e != nil {
		slog.Warn("siem patch task created event failed", "task_id", task.ID, "error", e)
	}
	return task, nil
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
	if err != nil {
		return err
	}
	task, err := s.GetPatchTask(ctx, id)
	if err != nil {
		return err
	}
	if e := s.appendSiemPatchTask(ctx, patchTaskEventType(status), task, actor); e != nil {
		slog.Warn("siem patch task status event failed", "task_id", id, "status", status, "error", e)
	}
	return nil
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
	task, err := scanPatchTask(row)
	if err != nil {
		return task, err
	}
	if e := s.appendSiemPatchTask(ctx, "patch_task.running", task, "agent:"+agentID); e != nil {
		slog.Warn("siem patch task running event failed", "task_id", task.ID, "error", e)
	}
	// Capture the runtime verification baseline (latest known services and
	// processes) before the agent executes the patch. The agent compares a
	// fresh snapshot against it after a successful run.
	if err := s.captureRuntimeBaseline(ctx, task.ID, agentID); err != nil {
		slog.Warn("runtime verify baseline capture failed", "task_id", task.ID,
			"agent_id", agentID, "error", err)
	}
	return task, nil
}

func (s *Store) CompletePatchTask(ctx context.Context, id int64, status string, result map[string]interface{}) error {
	raw, _ := json.Marshal(result)
	_, err := s.pool.Exec(ctx, `
		UPDATE patch_tasks SET status=$2, result=$3, cancel_requested=FALSE,
			runtime_verify_status=CASE WHEN $2='success' THEN 'pending' ELSE runtime_verify_status END,
			runtime_verify_detail=CASE WHEN $2='success' THEN '' ELSE runtime_verify_detail END,
			runtime_verify_at=CASE WHEN $2='success' THEN NULL ELSE runtime_verify_at END,
			post_patch_status=CASE WHEN $2='success' THEN 'pending' ELSE post_patch_status END,
			post_patch_detail=CASE WHEN $2='success' THEN '' ELSE post_patch_detail END,
			post_patch_at=CASE WHEN $2='success' THEN NULL ELSE post_patch_at END,
			updated_at=NOW()
		WHERE id=$1
	`, id, status, raw)
	if err != nil {
		return err
	}
	task, err := s.GetPatchTask(ctx, id)
	if err != nil {
		return err
	}
	if e := s.appendSiemPatchTask(ctx, patchTaskEventType(status), task, "agent"); e != nil {
		slog.Warn("siem patch task completion event failed", "task_id", id, "status", status, "error", e)
	}
	return nil
}

// captureRuntimeBaseline stores the latest host_system_info services and
// processes as the runtime verification baseline for a task. A missing
// baseline stays empty so verification reports "na" instead of failing.
func (s *Store) captureRuntimeBaseline(ctx context.Context, taskID int64, agentID string) error {
	info, err := s.GetHostSystemInfo(ctx, agentID)
	if err != nil {
		if IsHostSystemInfoNotFound(err) {
			_, err = s.pool.Exec(ctx, `
				UPDATE patch_tasks SET runtime_verify_baseline='{}'::jsonb, updated_at=NOW()
				WHERE id=$1
			`, taskID)
			return err
		}
		return err
	}
	baseline, err := json.Marshal(map[string]interface{}{
		"services":  info.Services,
		"processes": info.Processes,
	})
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE patch_tasks SET runtime_verify_baseline=$2, updated_at=NOW()
		WHERE id=$1
	`, taskID, baseline)
	return err
}

// ListPendingRuntimeVerifyTasks returns tasks whose patch succeeded and the
// agent has not reported a runtime verification snapshot yet.
func (s *Store) ListPendingRuntimeVerifyTasks(ctx context.Context, agentID string) ([]PatchTask, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+patchTaskColumns+` FROM patch_tasks
		WHERE agent_id=$1 AND status='success' AND runtime_verify_status='pending'
		ORDER BY id
	`, agentID)
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

// SetPatchTaskRuntimeVerifyPending resets a task to the pending verification
// state. It is used by the manual operator endpoint before evaluating the
// current snapshot.
func (s *Store) SetPatchTaskRuntimeVerifyPending(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE patch_tasks SET runtime_verify_status='pending',
			runtime_verify_detail='', runtime_verify_at=NULL, updated_at=NOW()
		WHERE id=$1
	`, id)
	return err
}

// CompleteRuntimeVerification writes the evaluation result (passed/failed/na)
// and appends a patch_task.verified outbox event.
func (s *Store) CompleteRuntimeVerification(ctx context.Context, id int64, status, detail string) error {
	if status != "passed" && status != "failed" && status != "na" {
		return fmt.Errorf("invalid runtime verification status %q", status)
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE patch_tasks SET runtime_verify_status=$2, runtime_verify_detail=$3,
			runtime_verify_at=NOW(), updated_at=NOW()
		WHERE id=$1
	`, id, status, detail)
	if err != nil {
		return err
	}
	task, err := s.GetPatchTask(ctx, id)
	if err != nil {
		return err
	}
	if e := s.appendSiemPatchTask(ctx, "patch_task.verified", task, "runtime-verify"); e != nil {
		slog.Warn("siem patch task verified event failed", "task_id", id, "error", e)
	}
	return nil
}

const (
	// PostPatchVerifyStaleAfter is how long a successful task may stay in
	// post-patch pending before the reaper marks it failed.
	PostPatchVerifyStaleAfter = 24 * time.Hour

	postPatchRemainingPrefix = "remaining active CVEs: "
	postPatchNoRescanDetail  = "no post-patch re-scan observed"
)

// postPatchVerdict evaluates the task's own CVE IDs against the active CVEs
// left after the latest match. It is a pure function so each branch is easy
// to unit test.
func postPatchVerdict(taskCVEIDs, remainingActive []string) (status, detail string) {
	if len(taskCVEIDs) == 0 {
		return "na", "no CVEs bound to patch task"
	}
	if len(remainingActive) == 0 {
		return "passed", ""
	}
	return "failed", postPatchRemainingPrefix + strings.Join(remainingActive, ", ")
}

// remainingCVEsFromDetail extracts the machine-readable remaining CVE list
// from the detail string written by postPatchVerdict. It is used by the SIEM
// payload so consumers do not have to parse free text.
func remainingCVEsFromDetail(detail string) []string {
	if !strings.HasPrefix(detail, postPatchRemainingPrefix) {
		return []string{}
	}
	rest := strings.TrimPrefix(detail, postPatchRemainingPrefix)
	if rest == "" {
		return []string{}
	}
	return strings.Split(rest, ", ")
}

// ListPendingPostPatchTasks returns succeeded tasks whose post-patch
// verification has not been completed for one agent.
func (s *Store) ListPendingPostPatchTasks(ctx context.Context, agentID string) ([]PatchTask, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+patchTaskColumns+` FROM patch_tasks
		WHERE agent_id=$1 AND status='success' AND post_patch_status='pending'
		ORDER BY id
	`, agentID)
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

// activeCVEsForPatchTask returns the task's own CVE IDs that are still
// status=active on the same agent and asset.
func (s *Store) activeCVEsForPatchTask(ctx context.Context, t PatchTask) ([]string, error) {
	if len(t.CVEIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT cve_id FROM cve_results
		WHERE agent_id=$1 AND asset_name=$2 AND status='active'
		  AND cve_id = ANY($3::text[])
		ORDER BY cve_id
	`, t.AgentID, t.AssetName, t.CVEIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			return nil, err
		}
		out = append(out, cveID)
	}
	return out, rows.Err()
}

// VerifyPendingPostPatchTasks evaluates every pending post-patch task for an
// agent against the latest cve_results and records passed/failed/na.
func (s *Store) VerifyPendingPostPatchTasks(ctx context.Context, agentID string) error {
	tasks, err := s.ListPendingPostPatchTasks(ctx, agentID)
	if err != nil {
		return err
	}
	for _, t := range tasks {
		remaining, err := s.activeCVEsForPatchTask(ctx, t)
		if err != nil {
			return err
		}
		status, detail := postPatchVerdict(t.CVEIDs, remaining)
		if err := s.CompletePostPatchVerification(ctx, t.ID, status, detail); err != nil {
			return err
		}
	}
	return nil
}

// CompletePostPatchVerification writes the post-patch result and appends a
// patch_task.post_patch outbox event. The pending guard makes concurrent
// verifiers idempotent.
func (s *Store) CompletePostPatchVerification(ctx context.Context, id int64, status, detail string) error {
	if status != "passed" && status != "failed" && status != "na" {
		return fmt.Errorf("invalid post-patch verification status %q", status)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE patch_tasks SET post_patch_status=$2, post_patch_detail=$3,
			post_patch_at=NOW(), updated_at=NOW()
		WHERE id=$1 AND post_patch_status='pending'
	`, id, status, detail)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	task, err := s.GetPatchTask(ctx, id)
	if err != nil {
		return err
	}
	if e := s.appendSiemPatchTask(ctx, "patch_task.post_patch", task, "post-patch"); e != nil {
		slog.Warn("siem patch task post-patch event failed", "task_id", id, "error", e)
	}
	return nil
}

// ReapStalePostPatchVerifications marks successful tasks failed when no
// re-scan has completed within the given timeout. updated_at is the pending
// start time written by CompletePatchTask.
func (s *Store) ReapStalePostPatchVerifications(ctx context.Context, timeout time.Duration) (int64, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE patch_tasks SET post_patch_status='failed',
			post_patch_detail=$2, post_patch_at=NOW(), updated_at=NOW()
		WHERE status='success' AND post_patch_status='pending'
		  AND updated_at < NOW() - $1::interval
		RETURNING id
	`, timeout, postPatchNoRescanDetail)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var count int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return count, err
		}
		count++
		task, err := s.GetPatchTask(ctx, id)
		if err != nil {
			return count, err
		}
		if e := s.appendSiemPatchTask(ctx, "patch_task.post_patch", task, "reaper"); e != nil {
			slog.Warn("siem patch task post-patch reap event failed", "task_id", id, "error", e)
		}
	}
	return count, rows.Err()
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
func (s *Store) RequestPatchTaskCancel(ctx context.Context, id int64, actor string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE patch_tasks SET cancel_requested=TRUE, updated_at=NOW()
		WHERE id=$1 AND status='running'
	`, id)
	if err != nil {
		return false, err
	}
	cancelled := tag.RowsAffected() > 0
	if cancelled {
		task, err := s.GetPatchTask(ctx, id)
		if err != nil {
			return cancelled, err
		}
		if e := s.appendSiemPatchTask(ctx, "patch_task.cancel_requested", task, actor); e != nil {
			slog.Warn("siem patch task cancel event failed", "task_id", id, "error", e)
		}
	}
	return cancelled, nil
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
	rows, err := s.pool.Query(ctx, `
		UPDATE patch_tasks SET status='approved', updated_at=NOW()
		WHERE status='running' AND updated_at < NOW() - $1::interval
		RETURNING id
	`, timeout)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var count int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return count, err
		}
		count++
		task, err := s.GetPatchTask(ctx, id)
		if err != nil {
			return count, err
		}
		if e := s.appendSiemPatchTask(ctx, "patch_task.approved", task, "reaper"); e != nil {
			slog.Warn("siem patch task reap event failed", "task_id", id, "error", e)
		}
	}
	return count, rows.Err()
}

func patchTaskEventType(status string) string {
	switch status {
	case "approved":
		return "patch_task.approved"
	case "rejected":
		return "patch_task.rejected"
	case "cancelled":
		return "patch_task.cancelled"
	case "pending":
		return "patch_task.pending"
	case "success":
		return "patch_task.succeeded"
	case "failed":
		return "patch_task.failed"
	case "running":
		return "patch_task.running"
	default:
		return "patch_task.updated"
	}
}
