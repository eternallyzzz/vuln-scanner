package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Tenant is one isolation boundary (MSP customer / organization). Users and
// agents carry a tenant_id; operator/viewer roles only see their own tenant,
// while admin stays global.
type Tenant struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

const tenantColumns = `id, name, slug, created_at, updated_at`

func scanTenant(row pgx.Row) (Tenant, error) {
	var t Tenant
	err := row.Scan(&t.ID, &t.Name, &t.Slug, &t.CreatedAt, &t.UpdatedAt)
	return t, err
}

func (s *Store) CreateTenant(ctx context.Context, name, slug string) (Tenant, error) {
	return scanTenant(s.pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug) VALUES ($1,$2)
		RETURNING `+tenantColumns, name, slug))
}

func (s *Store) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+tenantColumns+` FROM tenants ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetTenantByID(ctx context.Context, id int64) (Tenant, error) {
	return scanTenant(s.pool.QueryRow(ctx,
		`SELECT `+tenantColumns+` FROM tenants WHERE id=$1`, id))
}

func (s *Store) GetTenantBySlug(ctx context.Context, slug string) (Tenant, error) {
	return scanTenant(s.pool.QueryRow(ctx,
		`SELECT `+tenantColumns+` FROM tenants WHERE slug=$1`, slug))
}

// SetUserTenant reassigns a user to another tenant (admin operation).
func (s *Store) SetUserTenant(ctx context.Context, userID, tenantID int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET tenant_id=$2, updated_at=NOW() WHERE id=$1
	`, userID, tenantID)
	return err
}

// SetAgentTenant reassigns an agent to another tenant. All agent-scoped data
// (CVE results, alerts, patch tasks, host telemetry, EDR findings, CMDB
// assets) follows the agent, so no other rows need to move.
func (s *Store) SetAgentTenant(ctx context.Context, agentID string, tenantID int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE agents SET tenant_id=$2, updated_at=NOW() WHERE id=$1
	`, agentID, tenantID)
	return err
}

// TenantExists reports whether a tenant id exists (used to validate the
// optional X-Tenant-ID header for API-key automation).
func (s *Store) TenantExists(ctx context.Context, id int64) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)`, id).Scan(&exists)
	return exists, err
}
