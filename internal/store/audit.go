package store

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// AuditLog is one unified write-operation audit entry. It complements the
// domain-specific campaign audit trail rather than replacing it.
type AuditLog struct {
	ID         int64           `json:"id"`
	CreatedAt  time.Time       `json:"created_at"`
	Actor      string          `json:"actor"`
	Method     string          `json:"method"`
	Path       string          `json:"path"`
	Status     int             `json:"status"`
	IP         string          `json:"ip"`
	DurationMS int64           `json:"duration_ms"`
	Detail     json.RawMessage `json:"detail"`
	TenantID   int64           `json:"tenant_id"`
}

// AuditLogFilter narrows the unified audit log. Empty fields are ignored;
// Since/Until are inclusive RFC3339 instants.
type AuditLogFilter struct {
	Actor  string
	Method string
	Path   string
	Since  *time.Time
	Until  *time.Time
	Limit  int
	Offset int
}

const auditLogColumns = `id, created_at, actor, method, path, status, ip, duration_ms, detail, tenant_id`

// AppendAuditLog inserts one audit entry. detail defaults to an empty JSON
// object when nil so the JSONB column always contains valid JSON.
func (s *Store) AppendAuditLog(ctx context.Context, e AuditLog) error {
	if e.Detail == nil {
		e.Detail = json.RawMessage(`{}`)
	}
	if e.TenantID <= 0 {
		e.TenantID = 1
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_logs (actor, method, path, status, ip, duration_ms, detail, tenant_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, e.Actor, e.Method, e.Path, e.Status, e.IP, e.DurationMS, e.Detail, e.TenantID)
	return err
}

// ListAuditLogs returns matching entries newest first. limit defaults to 200
// and is capped at 1000; offset enables pagination.
func (s *Store) ListAuditLogs(ctx context.Context, f AuditLogFilter) ([]AuditLog, error) {
	where, args := auditLogWhere(f)
	limit := normalizeAuditLimit(f.Limit)
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	query := `SELECT ` + auditLogColumns + ` FROM audit_logs`
	if where != "" {
		query += ` WHERE ` + where
	}
	query += fmt.Sprintf(` ORDER BY id DESC LIMIT $%d OFFSET $%d`,
		len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditLog
	for rows.Next() {
		e, err := scanAuditLog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

// CountAuditLogs returns the number of entries matching the same filters as
// ListAuditLogs, for pagination totals.
func (s *Store) CountAuditLogs(ctx context.Context, f AuditLogFilter) (int64, error) {
	where, args := auditLogWhere(f)
	query := `SELECT count(*) FROM audit_logs`
	if where != "" {
		query += ` WHERE ` + where
	}
	var n int64
	err := s.pool.QueryRow(ctx, query, args...).Scan(&n)
	return n, err
}

// AuditExportCSV renders the latest 5000 audit entries as CSV bytes.
func (s *Store) AuditExportCSV(ctx context.Context) ([]byte, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+auditLogColumns+` FROM audit_logs
		ORDER BY id DESC LIMIT 5000
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{
		"id", "created_at", "actor", "method", "path",
		"status", "ip", "duration_ms", "detail", "tenant_id",
	})
	for rows.Next() {
		e, err := scanAuditLog(rows)
		if err != nil {
			return nil, err
		}
		_ = w.Write([]string{
			fmt.Sprintf("%d", e.ID),
			e.CreatedAt.UTC().Format(time.RFC3339),
			e.Actor,
			e.Method,
			e.Path,
			fmt.Sprintf("%d", e.Status),
			e.IP,
			fmt.Sprintf("%d", e.DurationMS),
			string(e.Detail),
			fmt.Sprintf("%d", e.TenantID),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func auditLogWhere(f AuditLogFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	if f.Actor != "" {
		args = append(args, f.Actor)
		conds = append(conds, fmt.Sprintf("actor = $%d", len(args)))
	}
	if f.Method != "" {
		args = append(args, f.Method)
		conds = append(conds, fmt.Sprintf("method = $%d", len(args)))
	}
	if f.Path != "" {
		args = append(args, f.Path)
		conds = append(conds, fmt.Sprintf("POSITION(LOWER($%d) IN LOWER(path)) > 0", len(args)))
	}
	if f.Since != nil {
		args = append(args, *f.Since)
		conds = append(conds, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if f.Until != nil {
		args = append(args, *f.Until)
		conds = append(conds, fmt.Sprintf("created_at <= $%d", len(args)))
	}
	return strings.Join(conds, " AND "), args
}

func normalizeAuditLimit(limit int) int {
	if limit <= 0 {
		return 200
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func scanAuditLog(row pgx.Row) (*AuditLog, error) {
	var e AuditLog
	var detail []byte
	if err := row.Scan(&e.ID, &e.CreatedAt, &e.Actor, &e.Method, &e.Path,
		&e.Status, &e.IP, &e.DurationMS, &detail, &e.TenantID); err != nil {
		return nil, err
	}
	if len(detail) == 0 {
		detail = []byte(`{}`)
	}
	e.Detail = json.RawMessage(detail)
	return &e, nil
}
