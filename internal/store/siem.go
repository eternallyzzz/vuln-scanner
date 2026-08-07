package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// SiemEvent is one pending/sent outbox entry for the SIEM/SOAR event stream.
type SiemEvent struct {
	ID           int64           `json:"id"`
	DedupeKey    string          `json:"dedupe_key"`
	EventType    string          `json:"event_type"`
	Payload      json.RawMessage `json:"payload"`
	Status       string          `json:"status"`
	AttemptCount int             `json:"attempt_count"`
	LastError    string          `json:"last_error"`
	CreatedAt    time.Time       `json:"created_at"`
	SentAt       *time.Time      `json:"sent_at,omitempty"`
}

// SetSiemEnabled toggles outbox recording. When disabled, AppendSiemEvent is
// a no-op so a non-SIEM deployment never accumulates rows.
func (s *Store) SetSiemEnabled(enabled bool) {
	if s == nil {
		return
	}
	s.siemEnabled = enabled
}

// AppendSiemEvent records one deduplicated outbox event. Payload is
// marshalled as JSONB; a duplicate dedupe_key is ignored.
func (s *Store) AppendSiemEvent(ctx context.Context, dedupeKey, eventType string, payload interface{}) error {
	if s == nil || !s.siemEnabled {
		return nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO siem_events (dedupe_key, event_type, payload)
		VALUES ($1,$2,$3)
		ON CONFLICT (dedupe_key) DO NOTHING
	`, dedupeKey, eventType, raw)
	return err
}

// ClaimSiemEvents atomically claims up to limit pending outbox events for one
// worker. Stale claims (crashed workers) are reclaimed after the lease.
func (s *Store) ClaimSiemEvents(ctx context.Context, limit int, workerID string, lease time.Duration) ([]SiemEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		UPDATE siem_events se SET claimed_by=$2, claimed_at=NOW()
		WHERE se.id IN (
			SELECT id FROM siem_events
			WHERE status='pending' AND (claimed_at IS NULL OR claimed_at < NOW() - $3::interval)
			ORDER BY id LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, dedupe_key, event_type, payload, status, attempt_count, last_error, created_at, sent_at
	`, limit, workerID, lease)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SiemEvent
	for rows.Next() {
		var e SiemEvent
		if err := rows.Scan(&e.ID, &e.DedupeKey, &e.EventType, &e.Payload,
			&e.Status, &e.AttemptCount, &e.LastError, &e.CreatedAt, &e.SentAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) MarkSiemEventSent(ctx context.Context, id int64, workerID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE siem_events SET status='sent', sent_at=NOW(), last_error='',
			claimed_by='', claimed_at=NULL
		WHERE id=$1 AND claimed_by=$2
	`, id, workerID)
	return err
}

func (s *Store) MarkSiemEventFailed(ctx context.Context, id int64, workerID, errMsg string, maxAttempts int) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE siem_events SET attempt_count=attempt_count+1, last_error=$2,
			status=CASE WHEN attempt_count+1 >= $3 THEN 'failed' ELSE 'pending' END
			, claimed_by='', claimed_at=NULL
		WHERE id=$1 AND claimed_by=$4
	`, id, errMsg, maxAttempts, workerID)
	return err
}

func (s *Store) appendSiemAlert(ctx context.Context, eventType string, alertID int64, status, actor string) error {
	detail, err := s.GetAlertDetail(ctx, alertID)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%s:%d:%s", eventType, alertID, detail.Status)
	payload := map[string]interface{}{
		"alert_id":       detail.ID,
		"rule_id":        detail.RuleID,
		"rule_name":      detail.RuleName,
		"agent_id":       detail.AgentID,
		"agent_hostname": detail.AgentHostname,
		"cve_id":         detail.CVEID,
		"asset_name":     detail.AssetName,
		"severity":       detail.Severity,
		"cvss_score":     detail.CVSSScore,
		"source":         detail.Source,
		"first_seen":     detail.FirstSeen,
		"status":         detail.Status,
		"actor":          actor,
	}
	return s.AppendSiemEvent(ctx, key, eventType, payload)
}

func (s *Store) appendSiemPatchTask(ctx context.Context, eventType string, t PatchTask, actor string) error {
	key := fmt.Sprintf("%s:%d:%s", eventType, t.ID, t.Status)
	if eventType == "patch_task.cancel_requested" {
		key += ":cancel"
	}
	payload := map[string]interface{}{
		"task_id":                          t.ID,
		"agent_id":                         t.AgentID,
		"asset_name":                       t.AssetName,
		"fix_type":                         t.FixType,
		"fix_value":                        t.FixValue,
		"action":                           t.Action,
		"cve_ids":                          t.CVEIDs,
		"status":                           t.Status,
		"approval_required":                t.ApprovalRequired,
		"window_start":                     t.WindowStart,
		"window_end":                       t.WindowEnd,
		"campaign_id":                      t.CampaignID,
		"created_by":                       t.CreatedBy,
		"approved_by":                      t.ApprovedBy,
		"cancel_requested":                 t.CancelRequested,
		"runtime_verify_status":            t.RuntimeVerifyStatus,
		"runtime_verify_detail":            t.RuntimeVerifyDetail,
		"runtime_verify_at":                t.RuntimeVerifyAt,
		"post_patch_status":                t.PostPatchStatus,
		"post_patch_detail":                t.PostPatchDetail,
		"post_patch_at":                    t.PostPatchAt,
		"post_patch_follow_up_status":      t.PostPatchFollowUpStatus,
		"post_patch_follow_up_campaign_id": t.PostPatchFollowUpCampaignID,
		"post_patch_follow_up_attempts":    t.PostPatchFollowUpAttempts,
		"post_patch_follow_up_depth":       t.PostPatchFollowUpDepth,
		"post_patch_follow_up_detail":      t.PostPatchFollowUpDetail,
		"post_patch_source_task_id":        t.PostPatchSourceTaskID,
		"fix_set_hash":                     t.FixSetHash,
		"fix_set":                          t.FixSet,
		"actor":                            actor,
	}
	if eventType == "patch_task.post_patch" {
		payload["remaining_cves"] = remainingCVEsFromDetail(t.PostPatchDetail)
		payload["missing_fixes"] = missingFixesFromDetail(t.PostPatchDetail)
	}
	return s.AppendSiemEvent(ctx, key, eventType, payload)
}
