package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CustomIntel is one built-in proprietary vulnerability fingerprint rule.
// Rules are maintained as migration seeds (code-only); the server mirrors
// enabled rows into cve_feed (source='custom') at startup.
type CustomIntel struct {
	ID          int64           `json:"id"`
	IntelID     string          `json:"intel_id"`
	Title       string          `json:"title"`
	Summary     string          `json:"summary"`
	Severity    string          `json:"severity"`
	CVSSScore   float64         `json:"cvss_score"`
	AdvisoryURL string          `json:"advisory_url"`
	SourceRef   string          `json:"source_ref"`
	Affected    json.RawMessage `json:"affected"`
	Enabled     bool            `json:"enabled"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

const customIntelColumns = `id, intel_id, title, summary, severity, cvss_score, advisory_url, source_ref, affected, enabled, created_at, updated_at`

func scanCustomIntel(row interface{ Scan(...interface{}) error }) (*CustomIntel, error) {
	var r CustomIntel
	var affected []byte
	if err := row.Scan(&r.ID, &r.IntelID, &r.Title, &r.Summary, &r.Severity,
		&r.CVSSScore, &r.AdvisoryURL, &r.SourceRef, &affected, &r.Enabled,
		&r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	r.Affected = json.RawMessage(affected)
	return &r, nil
}

// ListCustomIntel returns built-in intel rules newest first with optional
// enabled ("true"/"false") and free-text filters.
func (s *Store) ListCustomIntel(ctx context.Context, enabled, q string, limit, offset int) ([]CustomIntel, int64, error) {
	where := []string{}
	args := []interface{}{}
	if enabled != "" {
		args = append(args, strings.EqualFold(enabled, "true"))
		where = append(where, fmt.Sprintf("enabled=$%d", len(args)))
	}
	if q != "" {
		args = append(args, "%"+q+"%")
		where = append(where, fmt.Sprintf("(intel_id ILIKE $%d OR title ILIKE $%d OR summary ILIKE $%d)", len(args), len(args), len(args)))
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM custom_intel`+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT ` + customIntelColumns + ` FROM custom_intel` + whereSQL +
		` ORDER BY id DESC LIMIT $` + fmt.Sprint(len(args)+1) + ` OFFSET $` + fmt.Sprint(len(args)+2)
	args = append(args, limit, offset)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []CustomIntel
	for rows.Next() {
		r, err := scanCustomIntel(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *r)
	}
	return out, total, rows.Err()
}

// EnabledCustomIntel returns every enabled rule without paging; it feeds the
// startup mirror into cve_feed.
func (s *Store) EnabledCustomIntel(ctx context.Context) ([]CustomIntel, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+customIntelColumns+` FROM custom_intel WHERE enabled=TRUE ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CustomIntel
	for rows.Next() {
		r, err := scanCustomIntel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}
