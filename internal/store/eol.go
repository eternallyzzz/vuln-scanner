package store

import (
	"context"
	"time"
)

// OSLifecycle is one product/cycle row of the os_lifecycle table.
type OSLifecycle struct {
	Product     string     `json:"product"`
	Cycle       string     `json:"cycle"`
	EOLDate     *time.Time `json:"eol_date,omitempty"`
	SupportDate *time.Time `json:"support_date,omitempty"`
	LTS         bool       `json:"lts,omitempty"`
	Notes       string     `json:"notes,omitempty"`
}

// EOLSummary aggregates the agent EOL posture across the fleet.
type EOLSummary struct {
	TotalAgents       int            `json:"total_agents"`
	EOLAgents         int            `json:"eol_agents"`
	UnsupportedAgents int            `json:"unsupported_agents"`
	SupportedAgents   int            `json:"supported_agents"`
	UnknownAgents     int            `json:"unknown_agents"`
	ByProduct         map[string]int `json:"by_product"`
}

func (s *Store) LoadOSLifecycle(ctx context.Context) ([]OSLifecycle, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT product, cycle, eol_date, support_date, lts, notes
		FROM os_lifecycle ORDER BY product, cycle`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OSLifecycle
	for rows.Next() {
		var r OSLifecycle
		if err := rows.Scan(&r.Product, &r.Cycle, &r.EOLDate, &r.SupportDate, &r.LTS, &r.Notes); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateAgentEOL persists one agent's lifecycle verdict.
func (s *Store) UpdateAgentEOL(ctx context.Context, id, status, product, cycle string, eolDate *time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE agents
		SET eol_status = $2, eol_product = $3, eol_cycle = $4, eol_date = $5, updated_at = now()
		WHERE id = $1`, id, status, product, cycle, eolDate)
	return err
}

func (s *Store) EOLSummary(ctx context.Context, tenantID *int64) (EOLSummary, error) {
	var sum EOLSummary
	sum.ByProduct = map[string]int{}
	if err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE eol_status = 'eol'),
			COUNT(*) FILTER (WHERE eol_status = 'unsupported'),
			COUNT(*) FILTER (WHERE eol_status = 'supported'),
			COUNT(*) FILTER (WHERE eol_status = '' OR eol_status = 'unknown')
		FROM agents
		WHERE ($1::bigint IS NULL OR tenant_id=$1)
	`, tenantID).Scan(&sum.TotalAgents, &sum.EOLAgents, &sum.UnsupportedAgents,
		&sum.SupportedAgents, &sum.UnknownAgents); err != nil {
		return sum, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT COALESCE(eol_product, ''), COUNT(*)
		FROM agents
		WHERE eol_status = 'eol' AND ($1::bigint IS NULL OR tenant_id=$1)
		GROUP BY eol_product ORDER BY COUNT(*) DESC, eol_product`, tenantID)
	if err != nil {
		return sum, err
	}
	defer rows.Close()
	for rows.Next() {
		var product string
		var n int
		if err := rows.Scan(&product, &n); err != nil {
			return sum, err
		}
		sum.ByProduct[product] = n
	}
	return sum, rows.Err()
}

// EOLAgentRow is one evaluated agent for the /eol/agents listing.
type EOLAgentRow struct {
	AgentID    string     `json:"agent_id"`
	Hostname   string     `json:"hostname"`
	OSType     string     `json:"os_type"`
	OSVersion  string     `json:"os_version"`
	EOLStatus  string     `json:"eol_status"`
	EOLDate    *time.Time `json:"eol_date,omitempty"`
	EOLProduct string     `json:"eol_product,omitempty"`
	EOLCycle   string     `json:"eol_cycle,omitempty"`
	LastSeen   time.Time  `json:"last_seen"`
}

func (s *Store) ListAgentsEOL(ctx context.Context, tenantID *int64) ([]EOLAgentRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, os_type, os_version, eol_status, eol_date, eol_product, eol_cycle, last_seen
		FROM agents WHERE eol_status <> '' AND ($1::bigint IS NULL OR tenant_id=$1)
		ORDER BY eol_status = 'eol' DESC, hostname`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EOLAgentRow
	for rows.Next() {
		var r EOLAgentRow
		if err := rows.Scan(&r.AgentID, &r.Hostname, &r.OSType, &r.OSVersion,
			&r.EOLStatus, &r.EOLDate, &r.EOLProduct, &r.EOLCycle, &r.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
