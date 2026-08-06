package store

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

type PatchCampaign struct {
	ID        int64           `json:"id"`
	Name      string          `json:"name"`
	Filters   json.RawMessage `json:"filters"`
	CreatedBy string          `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
	TenantID  int64           `json:"tenant_id"`
}

type CampaignSummary struct {
	StatusCounts map[string]int64 `json:"status_counts"`
	AgentCount   int64            `json:"agent_count"`
	TaskCount    int64            `json:"task_count"`
}

type CampaignAuditEntry struct {
	ID            int64           `json:"id"`
	CampaignID    int64           `json:"campaign_id"`
	Action        string          `json:"action"`
	Actor         string          `json:"actor"`
	AffectedCount int64           `json:"affected_count"`
	Detail        json.RawMessage `json:"detail"`
	CreatedAt     time.Time       `json:"created_at"`
}

type CampaignTaskInput struct {
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

func scanPatchCampaign(row pgx.Row) (PatchCampaign, error) {
	var c PatchCampaign
	var filtersRaw []byte
	if err := row.Scan(&c.ID, &c.Name, &filtersRaw, &c.CreatedBy, &c.CreatedAt, &c.TenantID); err != nil {
		return c, err
	}
	c.Filters = json.RawMessage(filtersRaw)
	return c, nil
}

// CreatePatchCampaignWithTasks atomically creates a campaign and its tasks.
// Tasks with ApprovalRequired=false are created directly in 'approved' state
// so agents can claim them immediately.
func (s *Store) CreatePatchCampaignWithTasks(ctx context.Context, name string, filters json.RawMessage, createdBy string, tenantID int64, tasks []CampaignTaskInput) (PatchCampaign, []PatchTask, error) {
	if tenantID <= 0 {
		tenantID = 1
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return PatchCampaign{}, nil, err
	}
	defer tx.Rollback(ctx)

	campaign, err := scanPatchCampaign(tx.QueryRow(ctx, `
		INSERT INTO patch_campaigns (name, filters, created_by, tenant_id)
		VALUES ($1,$2,$3,$4)
		RETURNING id, name, filters, created_by, created_at, tenant_id
	`, name, filters, createdBy, tenantID))
	if err != nil {
		return PatchCampaign{}, nil, err
	}

	created := make([]PatchTask, 0, len(tasks))
	for _, in := range tasks {
		commands, _ := json.Marshal(in.Commands)
		if len(in.CVEIDs) == 0 {
			in.CVEIDs = []string{}
		}
		task, err := scanPatchTask(tx.QueryRow(ctx, `
			INSERT INTO patch_tasks (agent_id, asset_name, fix_type, fix_value, action,
				cve_ids, command, commands, status, approval_required, window_start, window_end,
				created_by, campaign_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,
				CASE WHEN $9 THEN 'pending' ELSE 'approved' END,
				$9,$10,$11,$12,$13)
			RETURNING `+patchTaskColumns,
			in.AgentID, in.AssetName, in.FixType, in.FixValue, in.Action,
			in.CVEIDs, in.Command, commands, in.ApprovalRequired,
			in.WindowStart, in.WindowEnd, in.CreatedBy, campaign.ID))
		if err != nil {
			return PatchCampaign{}, nil, err
		}
		created = append(created, task)
	}

	if err := tx.Commit(ctx); err != nil {
		return PatchCampaign{}, nil, err
	}
	for _, task := range created {
		if e := s.appendSiemPatchTask(ctx, "patch_task.created", task, createdBy); e != nil {
			slog.Warn("siem campaign task created event failed", "task_id", task.ID, "error", e)
		}
	}
	return campaign, created, nil
}

func (s *Store) GetPatchCampaign(ctx context.Context, id int64) (PatchCampaign, error) {
	return scanPatchCampaign(s.pool.QueryRow(ctx, `
		SELECT id, name, filters, created_by, created_at, tenant_id
		FROM patch_campaigns WHERE id=$1
	`, id))
}

func (s *Store) ListPatchCampaigns(ctx context.Context, limit, offset int, tenantID *int64) ([]PatchCampaign, int, error) {
	if limit <= 0 {
		limit = 100
	}
	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM patch_campaigns
		WHERE ($1::bigint IS NULL OR tenant_id=$1)
	`, tenantID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, filters, created_by, created_at, tenant_id
		FROM patch_campaigns
		WHERE ($1::bigint IS NULL OR tenant_id=$1)
		ORDER BY id DESC LIMIT $2 OFFSET $3
	`, tenantID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []PatchCampaign
	for rows.Next() {
		c, err := scanPatchCampaign(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

func (s *Store) CampaignSummary(ctx context.Context, campaignID int64) (CampaignSummary, error) {
	var out CampaignSummary
	out.StatusCounts = map[string]int64{}

	rows, err := s.pool.Query(ctx, `
		SELECT status, COUNT(*) FROM patch_tasks
		WHERE campaign_id=$1 GROUP BY status
	`, campaignID)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var status string
		var n int64
		if err := rows.Scan(&status, &n); err != nil {
			rows.Close()
			return out, err
		}
		out.StatusCounts[status] = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}

	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT agent_id), COUNT(*) FROM patch_tasks WHERE campaign_id=$1
	`, campaignID).Scan(&out.AgentCount, &out.TaskCount); err != nil {
		return out, err
	}
	return out, nil
}

func (s *Store) ListCampaignTasks(ctx context.Context, campaignID int64, status, assetName string, limit, offset int) ([]PatchTask, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+patchTaskColumns+` FROM patch_tasks
		WHERE campaign_id=$1 AND (''=$2 OR status=$2) AND (''=$3 OR asset_name=$3)
		ORDER BY id DESC LIMIT $4 OFFSET $5
	`, campaignID, status, assetName, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PatchTask
	for rows.Next() {
		t, err := scanPatchTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// BulkSetPatchTaskStatus transitions all tasks of a campaign that are in one
// of the given states. Approving also records the actor.
func (s *Store) BulkSetPatchTaskStatus(ctx context.Context, campaignID int64, from []string, to, actor string) (int64, error) {
	if len(from) == 0 {
		return 0, nil
	}
	rows, err := s.pool.Query(ctx, `
		UPDATE patch_tasks SET
			status=$2,
			approved_by=CASE WHEN $2='approved' THEN $3 ELSE approved_by END,
			updated_at=NOW()
		WHERE campaign_id=$1 AND status = ANY($4::text[])
		RETURNING id
	`, campaignID, to, actor, from)
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
		if e := s.appendSiemPatchTask(ctx, patchTaskEventType(to), task, actor); e != nil {
			slog.Warn("siem patch task bulk event failed", "task_id", id, "status", to, "error", e)
		}
	}
	return count, rows.Err()
}

func (s *Store) AppendCampaignAudit(ctx context.Context, campaignID int64, action, actor string, affected int64, detail json.RawMessage) error {
	if detail == nil {
		detail = json.RawMessage(`{}`)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO campaign_audit_log (campaign_id, action, actor, affected_count, detail)
		VALUES ($1,$2,$3,$4,$5)
	`, campaignID, action, actor, affected, detail)
	return err
}

func (s *Store) GetCampaignAudit(ctx context.Context, campaignID int64, limit int) ([]CampaignAuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, campaign_id, action, actor, affected_count, detail, created_at
		FROM campaign_audit_log WHERE campaign_id=$1
		ORDER BY id DESC LIMIT $2
	`, campaignID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CampaignAuditEntry
	for rows.Next() {
		var e CampaignAuditEntry
		var detailRaw []byte
		if err := rows.Scan(&e.ID, &e.CampaignID, &e.Action, &e.Actor,
			&e.AffectedCount, &detailRaw, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Detail = json.RawMessage(detailRaw)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListPatchTasksFiltered is the global task list; empty agentID/status/assetName
// and campaignID=0 mean "any".
func (s *Store) ListPatchTasksFiltered(ctx context.Context, agentID string, campaignID int64, status, assetName string, limit, offset int, tenantID *int64) ([]PatchTask, int, error) {
	if limit <= 0 {
		limit = 100
	}
	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM patch_tasks
		WHERE (''=$1 OR agent_id=$1)
		  AND ($2=0 OR campaign_id=$2)
		  AND (''=$3 OR status=$3)
		  AND (''=$4 OR asset_name=$4)
		  AND ($5::bigint IS NULL OR EXISTS (
		      SELECT 1 FROM agents a WHERE a.id=patch_tasks.agent_id AND a.tenant_id=$5))
	`, agentID, campaignID, status, assetName, tenantID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+patchTaskColumns+` FROM patch_tasks
		WHERE (''=$1 OR agent_id=$1)
		  AND ($2=0 OR campaign_id=$2)
		  AND (''=$3 OR status=$3)
		  AND (''=$4 OR asset_name=$4)
		  AND ($5::bigint IS NULL OR EXISTS (
		      SELECT 1 FROM agents a WHERE a.id=patch_tasks.agent_id AND a.tenant_id=$5))
		ORDER BY id DESC LIMIT $6 OFFSET $7
	`, agentID, campaignID, status, assetName, tenantID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []PatchTask
	for rows.Next() {
		t, err := scanPatchTask(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, t)
	}
	return out, total, rows.Err()
}

// HasOpenPatchTask reports whether an open (pending/approved/running) task
// already exists for the same agent and asset, used to dedupe campaigns.
func (s *Store) HasOpenPatchTask(ctx context.Context, agentID, assetName string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM patch_tasks
			WHERE agent_id=$1 AND asset_name=$2 AND status IN ('pending','approved','running')
		)
	`, agentID, assetName).Scan(&exists)
	return exists, err
}

// AutoRemediationCampaignCount returns how many auto-remediation campaigns
// were created since the given time. It is the multi-instance replacement
// for the old in-memory hourly limiter.
func (s *Store) AutoRemediationCampaignCount(ctx context.Context, since time.Time) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM patch_campaigns
		WHERE created_by='auto-remediation' AND created_at >= $1
	`, since).Scan(&n)
	return n, err
}

// AgentsByAssetFilters returns distinct agent ids that have at least one
// active software asset matching tags, environments or asset names (AND of
// non-empty selectors).
func (s *Store) AgentsByAssetFilters(ctx context.Context, tags, environments, assetNames []string, tenantID *int64) ([]string, error) {
	if len(tags) == 0 && len(environments) == 0 && len(assetNames) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT agent_id FROM assets
		JOIN agents a ON a.id=assets.agent_id
		WHERE asset_type='software' AND lifecycle='active'
		  AND ($4::bigint IS NULL OR a.tenant_id=$4)
		  AND (cardinality(COALESCE($1::text[],'{}'))=0 OR tags && COALESCE($1::text[],'{}'))
		  AND (cardinality(COALESCE($2::text[],'{}'))=0 OR environment = ANY(COALESCE($2::text[],'{}')))
		  AND (cardinality(COALESCE($3::text[],'{}'))=0 OR name = ANY(COALESCE($3::text[],'{}')))
	`, tags, environments, assetNames, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
