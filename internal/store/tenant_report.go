package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// TenantReport is one tenant's report delivery settings. The global
// reporting.enabled switch and alerting.smtp settings remain server-wide;
// this row only controls schedule, timezone, and recipients.
type TenantReport struct {
	TenantID  int64     `json:"tenant_id"`
	Enabled   bool      `json:"enabled"`
	Schedule  string    `json:"schedule"`
	Timezone  string    `json:"timezone"`
	To        []string  `json:"to"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

const tenantReportColumns = `tenant_id, enabled, schedule, timezone, recipients, created_at, updated_at`

func scanTenantReport(row pgx.Row) (TenantReport, error) {
	var r TenantReport
	var toRaw []byte
	if err := row.Scan(&r.TenantID, &r.Enabled, &r.Schedule, &r.Timezone,
		&toRaw, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return r, err
	}
	if len(toRaw) == 0 {
		toRaw = []byte(`[]`)
	}
	_ = json.Unmarshal(toRaw, &r.To)
	return r, nil
}

// GetTenantReport returns the report settings for one tenant.
func (s *Store) GetTenantReport(ctx context.Context, tenantID int64) (TenantReport, error) {
	return scanTenantReport(s.pool.QueryRow(ctx, `
		SELECT `+tenantReportColumns+` FROM tenant_reports WHERE tenant_id=$1
	`, tenantID))
}

// UpsertTenantReport creates or replaces one tenant's report settings.
func (s *Store) UpsertTenantReport(ctx context.Context, r TenantReport) (TenantReport, error) {
	if r.TenantID <= 0 {
		r.TenantID = 1
	}
	if r.Schedule == "" {
		r.Schedule = "0 8 * * *"
	}
	if r.Timezone == "" {
		r.Timezone = "Local"
	}
	if r.To == nil {
		r.To = []string{}
	}
	toRaw, _ := json.Marshal(r.To)
	row := s.pool.QueryRow(ctx, `
		INSERT INTO tenant_reports (tenant_id, enabled, schedule, timezone, recipients)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (tenant_id) DO UPDATE SET
			enabled=EXCLUDED.enabled, schedule=EXCLUDED.schedule,
			timezone=EXCLUDED.timezone, recipients=EXCLUDED.recipients, updated_at=NOW()
		RETURNING `+tenantReportColumns,
		r.TenantID, r.Enabled, r.Schedule, r.Timezone, toRaw)
	return scanTenantReport(row)
}

// ListEnabledTenantReports returns settings for every tenant with report
// delivery enabled.
func (s *Store) ListEnabledTenantReports(ctx context.Context) ([]TenantReport, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+tenantReportColumns+` FROM tenant_reports
		WHERE enabled = TRUE ORDER BY tenant_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantReport
	for rows.Next() {
		r, err := scanTenantReport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
