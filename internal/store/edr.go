package store

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"vuln-scanner/internal/edr"
)

// EDRFinding is one malicious-software discovery reported through the REST
// API (source=edr_api) or collected by the agent (source=clamav).
type EDRFinding struct {
	ID              int64     `json:"id"`
	AgentID         string    `json:"agent_id"`
	Source          string    `json:"source"`
	FindingType     string    `json:"finding_type"`
	Name            string    `json:"name"`
	Severity        string    `json:"severity"`
	Path            string    `json:"path,omitempty"`
	Hash            string    `json:"hash,omitempty"`
	Detail          string    `json:"detail,omitempty"`
	Status          string    `json:"status"`
	OccurrenceCount int       `json:"occurrence_count"`
	AlertID         *int64    `json:"alert_id,omitempty"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
}

// EDRFindingInput carries the report fields before normalization.
type EDRFindingInput struct {
	AgentID     string
	Source      string
	FindingType string
	Name        string
	Severity    string
	Path        string
	Hash        string
	Detail      string
}

const edrFindingColumns = `id, agent_id, source, finding_type, name, severity, path, hash,
	detail, status, occurrence_count, alert_id, first_seen, last_seen`

func scanEDRFinding(row pgx.Row) (EDRFinding, error) {
	var f EDRFinding
	err := row.Scan(&f.ID, &f.AgentID, &f.Source, &f.FindingType, &f.Name,
		&f.Severity, &f.Path, &f.Hash, &f.Detail, &f.Status,
		&f.OccurrenceCount, &f.AlertID, &f.FirstSeen, &f.LastSeen)
	return f, err
}

// UpsertEDRFinding stores one finding idempotently. Repeated reports of the
// same dedupe key (agent+source+hash, else name) bump occurrence_count and
// last_seen while the finding is open/acknowledged; an ignored or resolved
// finding receives a fresh open row on the next report.
func (s *Store) UpsertEDRFinding(ctx context.Context, in EDRFindingInput) (EDRFinding, bool, error) {
	in.Source = strings.TrimSpace(in.Source)
	if in.Source == "" {
		in.Source = "edr_api"
	}
	in.FindingType = strings.TrimSpace(in.FindingType)
	if in.FindingType == "" {
		in.FindingType = "malware"
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Severity = edr.NormalizeSeverity(in.Severity)
	in.Path = strings.TrimSpace(in.Path)
	in.Hash = strings.TrimSpace(in.Hash)
	in.Detail = strings.TrimSpace(in.Detail)

	var f EDRFinding
	var created bool
	err := s.pool.QueryRow(ctx, `
		INSERT INTO edr_findings (agent_id, source, finding_type, name, severity, path, hash,
			detail, status, occurrence_count)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'open',1)
		ON CONFLICT (agent_id, source, COALESCE(NULLIF(hash,''), name))
			WHERE status IN ('open','acknowledged')
		DO UPDATE SET name=EXCLUDED.name, severity=EXCLUDED.severity,
			path=EXCLUDED.path, hash=EXCLUDED.hash, detail=EXCLUDED.detail,
			occurrence_count=edr_findings.occurrence_count+1, last_seen=NOW()
		RETURNING `+edrFindingColumns+`, (xmax=0)`,
		in.AgentID, in.Source, in.FindingType, in.Name, in.Severity, in.Path,
		in.Hash, in.Detail).Scan(&f.ID, &f.AgentID, &f.Source, &f.FindingType, &f.Name,
		&f.Severity, &f.Path, &f.Hash, &f.Detail, &f.Status,
		&f.OccurrenceCount, &f.AlertID, &f.FirstSeen, &f.LastSeen, &created)
	return f, created, err
}

// ListEDRFindings returns findings ordered by last report, with optional
// status/source/agent/severity filters and a free-text q over name/path/detail.
func (s *Store) ListEDRFindings(ctx context.Context, status, source, findingType, agentID, severity, q string, limit, offset int, tenantID *int64) ([]EDRFinding, error) {
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+edrFindingColumns+` FROM edr_findings
		WHERE (''=$1 OR status=$1) AND (''=$2 OR source=$2) AND (''=$3 OR agent_id=$3)
		  AND (''=$4 OR finding_type=$4)
		  AND (''=$5 OR severity=$5)
		  AND (''=$6 OR name ILIKE '%'||$6||'%' OR path ILIKE '%'||$6||'%'
		       OR detail ILIKE '%'||$6||'%')
		  AND ($7::bigint IS NULL OR EXISTS (
		      SELECT 1 FROM agents a WHERE a.id=edr_findings.agent_id AND a.tenant_id=$7))
		ORDER BY last_seen DESC, id DESC
		LIMIT $8 OFFSET $9
	`, status, source, agentID, findingType, severity, q, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EDRFinding
	for rows.Next() {
		f, err := scanEDRFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// GetEDRFinding returns one finding by id.
func (s *Store) GetEDRFinding(ctx context.Context, id int64) (EDRFinding, error) {
	return scanEDRFinding(s.pool.QueryRow(ctx,
		`SELECT `+edrFindingColumns+` FROM edr_findings WHERE id=$1`, id))
}

// SetEDRFindingStatus applies a triage disposition and keeps the linked
// alert in sync: acknowledged -> alert ack, ignored/resolved -> alert resolved.
func (s *Store) SetEDRFindingStatus(ctx context.Context, id int64, status, actor string) error {
	if !edr.ValidStatus(status) {
		return fmt.Errorf("invalid finding status %q", status)
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE edr_findings SET status=$2 WHERE id=$1
	`, id, status)
	if err != nil {
		return err
	}
	f, err := s.GetEDRFinding(ctx, id)
	if err != nil {
		return err
	}
	if f.AlertID != nil {
		alertStatus := "ack"
		if status == "ignored" || status == "resolved" {
			alertStatus = "resolved"
		}
		if err := s.SetAlertStatus(ctx, *f.AlertID, alertStatus, actor); err != nil {
			return err
		}
	}
	return nil
}

// UpsertEDRFindingAlert creates or refreshes the open alert linked to a
// HIGH/CRITICAL EDR finding. cve_id stays empty; the alert is deduplicated by
// rule+agent+finding through uq_alerts_edr_finding_open, and the finding row
// records the alert id when a new alert is created.
func (s *Store) UpsertEDRFindingAlert(ctx context.Context, ruleID int64, agentID, assetName, severity string, findingID int64) (int64, bool, error) {
	return s.UpsertFindingAlert(ctx, ruleID, agentID, assetName, severity, findingID, "edr")
}

// UpsertFindingAlert creates or refreshes the open alert linked to a
// HIGH/CRITICAL finding. cve_id stays empty; the alert is deduplicated by
// rule+agent+finding through uq_alerts_edr_finding_open.
func (s *Store) UpsertFindingAlert(ctx context.Context, ruleID int64, agentID, assetName, severity string, findingID int64, source string) (int64, bool, error) {
	if source == "" {
		source = "edr"
	}
	var id int64
	var created bool
	err := s.pool.QueryRow(ctx, `
		INSERT INTO alerts (rule_id, agent_id, cve_id, asset_name, severity, cvss_score,
			status, first_seen, last_seen, occurrence_count, source, edr_finding_id)
		VALUES ($1,$2,'',$3,$4,0,'open',NOW(),NOW(),1,$6,$5)
		ON CONFLICT (rule_id, agent_id, edr_finding_id)
			WHERE status='open' AND edr_finding_id IS NOT NULL
		DO UPDATE SET last_seen=NOW(), occurrence_count=alerts.occurrence_count+1,
			severity=EXCLUDED.severity, asset_name=EXCLUDED.asset_name, source=EXCLUDED.source
		RETURNING id, (xmax=0)
	`, ruleID, agentID, assetName, severity, findingID, source).Scan(&id, &created)
	if err != nil {
		return id, created, err
	}
	if created {
		if _, err := s.pool.Exec(ctx, `
			UPDATE edr_findings SET alert_id=$2 WHERE id=$1 AND alert_id IS NULL
		`, findingID, id); err != nil {
			return id, created, err
		}
		if e := s.appendSiemAlert(ctx, "alert.created", id, "open", source); e != nil {
			slog.Warn("siem finding alert created event failed", "alert_id", id, "error", e)
		}
	}
	return id, created, nil
}
