package store

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"sort"
	"strconv"
	"time"
)

// ComplianceCheck is one baseline item stored with the agent report.
type ComplianceCheck struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Group    string `json:"group"`
	Status   string `json:"status"` // pass | fail | na
	Evidence string `json:"evidence,omitempty"`
}

// ComplianceReport is the latest agent-side baseline evaluation.
type ComplianceReport struct {
	AgentID   string            `json:"agent_id"`
	Benchmark string            `json:"benchmark"`
	Score     float64           `json:"score"`
	Total     int               `json:"total"`
	Passed    int               `json:"passed"`
	Failed    int               `json:"failed"`
	NA        int               `json:"na"`
	Checks    []ComplianceCheck `json:"checks"`
	CheckedAt time.Time         `json:"checked_at"`
}

// ComplianceAgentRow is one fleet row for the compliance listing/CSV.
type ComplianceAgentRow struct {
	AgentID   string    `json:"agent_id"`
	Hostname  string    `json:"hostname"`
	OSType    string    `json:"os_type"`
	OSVersion string    `json:"os_version"`
	Score     float64   `json:"score"`
	Total     int       `json:"total"`
	Passed    int       `json:"passed"`
	Failed    int       `json:"failed"`
	NA        int       `json:"na"`
	CheckedAt time.Time `json:"checked_at"`
}

// FailedCheckCount aggregates how many agents fail one check.
type FailedCheckCount struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Count int    `json:"count"`
}

// ComplianceSummary aggregates the fleet compliance posture.
type ComplianceSummary struct {
	TotalAgents     int                `json:"total_agents"`
	ReportedAgents  int                `json:"reported_agents"`
	AvgScore        float64            `json:"avg_score"`
	MinScore        float64            `json:"min_score"`
	MaxScore        float64            `json:"max_score"`
	TotalChecks     int                `json:"total_checks"`
	PassedChecks    int                `json:"passed_checks"`
	FailedChecks    int                `json:"failed_checks"`
	NAChecks        int                `json:"na_checks"`
	TopFailedChecks []FailedCheckCount `json:"top_failed_checks"`
}

// UpsertComplianceReport stores the newest report for one agent.
func (s *Store) UpsertComplianceReport(ctx context.Context, r *ComplianceReport) error {
	checks, err := json.Marshal(r.Checks)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO compliance_reports (agent_id, benchmark, score, total, passed, failed, na, checks, checked_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (agent_id) DO UPDATE SET
			benchmark=$2, score=$3, total=$4, passed=$5, failed=$6, na=$7, checks=$8, checked_at=$9
	`, r.AgentID, r.Benchmark, r.Score, r.Total, r.Passed, r.Failed, r.NA, checks, r.CheckedAt)
	return err
}

// ListComplianceAgents returns one row per reported agent, lowest score
// first so the weakest hosts are easiest to find.
func (s *Store) ListComplianceAgents(ctx context.Context) ([]ComplianceAgentRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT c.agent_id, COALESCE(a.hostname,''), COALESCE(a.os_type,''), COALESCE(a.os_version,''),
		       c.score, c.total, c.passed, c.failed, c.na, c.checked_at
		FROM compliance_reports c
		JOIN agents a ON a.id = c.agent_id
		ORDER BY c.score ASC, a.hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ComplianceAgentRow
	for rows.Next() {
		var r ComplianceAgentRow
		if err := rows.Scan(&r.AgentID, &r.Hostname, &r.OSType, &r.OSVersion,
			&r.Score, &r.Total, &r.Passed, &r.Failed, &r.NA, &r.CheckedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetComplianceReport returns the latest report for one agent including the
// per-check details.
func (s *Store) GetComplianceReport(ctx context.Context, agentID string) (*ComplianceReport, error) {
	var r ComplianceReport
	var checks []byte
	err := s.pool.QueryRow(ctx, `
		SELECT agent_id, benchmark, score, total, passed, failed, na, checks, checked_at
		FROM compliance_reports WHERE agent_id = $1`, agentID).
		Scan(&r.AgentID, &r.Benchmark, &r.Score, &r.Total, &r.Passed, &r.Failed,
			&r.NA, &checks, &r.CheckedAt)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(checks, &r.Checks); err != nil {
		return nil, err
	}
	return &r, nil
}

// ComplianceSummary aggregates fleet counts and the most common failing
// checks. Check details live in JSONB, so the aggregation walks the latest
// reports in Go; fleet sizes here stay small.
func (s *Store) ComplianceSummary(ctx context.Context) (ComplianceSummary, error) {
	var sum ComplianceSummary
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents`).Scan(&sum.TotalAgents); err != nil {
		return sum, err
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*), COALESCE(AVG(score),0), COALESCE(MIN(score),0), COALESCE(MAX(score),0),
		       COALESCE(SUM(total),0), COALESCE(SUM(passed),0), COALESCE(SUM(failed),0), COALESCE(SUM(na),0)
		FROM compliance_reports`).
		Scan(&sum.ReportedAgents, &sum.AvgScore, &sum.MinScore, &sum.MaxScore,
			&sum.TotalChecks, &sum.PassedChecks, &sum.FailedChecks, &sum.NAChecks); err != nil {
		return sum, err
	}

	rows, err := s.pool.Query(ctx, `SELECT agent_id, checks FROM compliance_reports`)
	if err != nil {
		return sum, err
	}
	defer rows.Close()
	failCounts := map[string]int{}
	titles := map[string]string{}
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return sum, err
		}
		var checks []ComplianceCheck
		if err := json.Unmarshal(raw, &checks); err != nil {
			return sum, err
		}
		for _, c := range checks {
			if c.Status != "fail" {
				continue
			}
			failCounts[c.ID]++
			if titles[c.ID] == "" {
				titles[c.ID] = c.Title
			}
		}
	}
	if err := rows.Err(); err != nil {
		return sum, err
	}
	for id, n := range failCounts {
		sum.TopFailedChecks = append(sum.TopFailedChecks, FailedCheckCount{ID: id, Title: titles[id], Count: n})
	}
	sort.Slice(sum.TopFailedChecks, func(i, j int) bool {
		if sum.TopFailedChecks[i].Count != sum.TopFailedChecks[j].Count {
			return sum.TopFailedChecks[i].Count > sum.TopFailedChecks[j].Count
		}
		return sum.TopFailedChecks[i].ID < sum.TopFailedChecks[j].ID
	})
	if len(sum.TopFailedChecks) > 10 {
		sum.TopFailedChecks = sum.TopFailedChecks[:10]
	}
	return sum, nil
}

// ComplianceExportCSV renders the latest report rows as CSV, same columns as
// the compliance agents API.
func (s *Store) ComplianceExportCSV(ctx context.Context) ([]byte, error) {
	rows, err := s.ListComplianceAgents(ctx)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{
		"agent_id", "hostname", "os_type", "os_version",
		"score", "total", "passed", "failed", "na", "checked_at",
	})
	for _, r := range rows {
		_ = w.Write([]string{
			r.AgentID, r.Hostname, r.OSType, r.OSVersion,
			strconv.FormatFloat(r.Score, 'f', 1, 64),
			strconv.Itoa(r.Total), strconv.Itoa(r.Passed),
			strconv.Itoa(r.Failed), strconv.Itoa(r.NA),
			r.CheckedAt.UTC().Format(time.RFC3339),
		})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}
