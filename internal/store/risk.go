package store

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"vuln-scanner/internal/collector"
)

// CVEIntel is the EPSS/KEV intelligence for one CVE.
type CVEIntel struct {
	CVEID           string    `json:"cve_id"`
	EPSSScore       float64   `json:"epss_score"`
	EPSSPercentile  float64   `json:"epss_percentile"`
	KEV             bool      `json:"kev"`
	KEVAdded        string    `json:"kev_added,omitempty"`
	KnownRansomware bool      `json:"known_ransomware,omitempty"`
	UpdatedAt       time.Time `json:"updated_at,omitempty"`
}

// RiskRow is one ranked active vulnerability with governance context.
type RiskRow struct {
	CVEID            string     `json:"cve_id"`
	CanonicalCVEID   string     `json:"canonical_cve_id"`
	AgentID          string     `json:"agent_id"`
	Hostname         string     `json:"hostname"`
	AssetName        string     `json:"asset_name"`
	Severity         string     `json:"severity"`
	RiskLevel        string     `json:"risk_level"`
	CVSSScore        float64    `json:"cvss_score"`
	EPSSScore        float64    `json:"epss_score"`
	KEV              bool       `json:"kev"`
	ExposureScore    float64    `json:"exposure_score"`
	AssetCriticality float64    `json:"asset_criticality"`
	RiskScore        float64    `json:"risk_score"`
	DetectedAt       time.Time  `json:"detected_at"`
	DueAt            *time.Time `json:"due_at,omitempty"`
	Overdue          bool       `json:"overdue"`
	FixedVersion     string     `json:"fixed_version,omitempty"`
	PatchURL         string     `json:"patch_url,omitempty"`
}

// RiskSummary aggregates the governance dashboard counts.
type RiskSummary struct {
	TotalActive int            `json:"total_active"`
	TotalFixed  int            `json:"total_fixed"`
	ByRiskLevel map[string]int `json:"by_risk_level"`
	BySeverity  map[string]int `json:"by_severity"`
	KEVCount    int            `json:"kev_count"`
	Overdue     int            `json:"overdue"`
	Exempted    int            `json:"exempted"`
	AverageEPSS float64        `json:"average_epss"`
	FixRate     float64        `json:"fix_rate"`
}

// RiskTrendPoint is one day of the active/new/fixed trend.
type RiskTrendPoint struct {
	Date   string `json:"date"`
	Active int    `json:"active"`
	New    int    `json:"new"`
	Fixed  int    `json:"fixed"`
}

// VulnerabilityException is a risk acceptance record.
type VulnerabilityException struct {
	ID        int64      `json:"id"`
	CVEID     string     `json:"cve_id"`
	AssetKey  string     `json:"asset_key"`
	Reason    string     `json:"reason"`
	ExpiresAt time.Time  `json:"expires_at"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// SLAPolicy maps a severity to a remediation deadline.
type SLAPolicy struct {
	ID                  int64     `json:"id"`
	Name                string    `json:"name"`
	Severity            string    `json:"severity"`
	MaxRemediationHours int       `json:"max_remediation_hours"`
	Enabled             bool      `json:"enabled"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// CanonicalCVEID normalizes DEBIAN/UBUNTU/ALPINE-CVE aliases to CVE-xxxx.
func CanonicalCVEID(cveID string) string {
	for _, prefix := range []string{"DEBIAN-CVE-", "UBUNTU-CVE-", "ALPINE-CVE-"} {
		if strings.HasPrefix(cveID, prefix) {
			return "CVE-" + strings.TrimPrefix(cveID, prefix)
		}
	}
	return cveID
}

// RiskScore combines CVSS, EPSS, asset criticality and exposure (0-10).
func RiskScore(cvss, epss, criticality, exposure float64, kev bool) float64 {
	score := cvss*0.40 + epss*10*0.25 + criticality*0.20 + exposure*0.15
	if kev && score < 9.0 {
		score = 9.0
	}
	return math.Round(score*10) / 10
}

// RiskLevel buckets a risk score.
func RiskLevel(score float64) string {
	switch {
	case score >= 8.5:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// AssetCriticality derives 0-10 from CMDB metadata.
func AssetCriticality(environment string, tags []string, assetType string) float64 {
	score := 4.0
	switch strings.ToLower(strings.TrimSpace(environment)) {
	case "production", "prod":
		score = 9
	case "staging", "preprod":
		score = 5
	case "test", "qa":
		score = 2
	case "development", "dev":
		score = 3
	}
	for _, t := range tags {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "critical", "core":
			score = maxF(score, 10)
		case "dmz", "db":
			score = maxF(score, 9)
		case "app":
			score = maxF(score, 7)
		}
	}
	switch strings.ToLower(assetType) {
	case "host":
		score = maxF(score, 8)
	case "container":
		score = maxF(score, 7)
	case "software":
		score = maxF(score, 5)
	}
	return score
}

// ExposureScore estimates reachability from host telemetry.
func ExposureScore(ports []collector.PortInfo, processes []collector.ProcessInfo,
	assetName, assetType string, hasTelemetry bool) float64 {
	lower := strings.ToLower(strings.TrimSpace(assetName))
	for _, p := range ports {
		if p.Process != "" && (strings.Contains(strings.ToLower(p.Process), lower) ||
			(lower != "" && strings.Contains(lower, strings.ToLower(p.Process)))) {
			return 9
		}
	}
	for _, pr := range processes {
		if lower != "" && strings.Contains(strings.ToLower(pr.Name), lower) {
			return 6
		}
	}
	if strings.ToLower(assetType) == "container" {
		return 7
	}
	if !hasTelemetry {
		return 3
	}
	return 2
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// UpsertCVEIntelBatch merges EPSS/KEV intelligence rows.
func (s *Store) UpsertCVEIntelBatch(ctx context.Context, entries []CVEIntel) error {
	if len(entries) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	now := time.Now()
	for _, e := range entries {
		var added interface{}
		if e.KEVAdded != "" {
			added = e.KEVAdded
		}
		batch.Queue(`
			INSERT INTO cve_intel (cve_id, epss_score, epss_percentile, kev, kev_added, known_ransomware, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (cve_id) DO UPDATE SET
				epss_score=$2, epss_percentile=$3, kev=$4, kev_added=$5,
				known_ransomware=$6, updated_at=$7
		`, e.CVEID, e.EPSSScore, e.EPSSPercentile, e.KEV, added, e.KnownRansomware, now)
	}
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < len(entries); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("intel batch row %d: %w", i, err)
		}
	}
	return nil
}

// GetCVEIntel returns the intel map for a set of CVE ids.
func (s *Store) GetCVEIntel(ctx context.Context, cveIDs []string) (map[string]CVEIntel, error) {
	out := map[string]CVEIntel{}
	if len(cveIDs) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT cve_id, epss_score, epss_percentile, kev,
			COALESCE(to_char(kev_added, 'YYYY-MM-DD'), ''), known_ransomware
		FROM cve_intel WHERE cve_id = ANY($1)
	`, cveIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e CVEIntel
		if err := rows.Scan(&e.CVEID, &e.EPSSScore, &e.EPSSPercentile, &e.KEV,
			&e.KEVAdded, &e.KnownRansomware); err != nil {
			return nil, err
		}
		out[e.CVEID] = e
	}
	return out, rows.Err()
}

// RecordAlias maintains the canonical alias ledger (best effort).
func (s *Store) RecordAlias(ctx context.Context, aliasID, canonical, source string) error {
	if aliasID == "" || aliasID == canonical {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO cve_alias (alias_id, canonical_cve_id, source)
		VALUES ($1,$2,$3) ON CONFLICT (alias_id) DO NOTHING
	`, aliasID, canonical, source)
	return err
}

// RecalcAgentRisk recomputes intel and risk columns for one agent.
func (s *Store) RecalcAgentRisk(ctx context.Context, agentID string) (int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, cve_id, asset_name, severity, cvss_score
		FROM cve_results WHERE agent_id=$1 AND status='active'
	`, agentID)
	if err != nil {
		return 0, err
	}
	type row struct {
		id       int64
		cveID    string
		asset    string
		severity string
		cvss     float64
	}
	var items []row
	var cveIDs []string
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.cveID, &r.asset, &r.severity, &r.cvss); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, r)
		cveIDs = append(cveIDs, r.cveID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(items) == 0 {
		return 0, nil
	}

	intel, err := s.GetCVEIntel(ctx, cveIDs)
	if err != nil {
		return 0, err
	}
	assetMeta := map[string]struct {
		typ  string
		env  string
		tags []string
	}{}
	arows, err := s.pool.Query(ctx, `
		SELECT name, asset_type, environment, tags FROM assets WHERE agent_id=$1
	`, agentID)
	if err != nil {
		return 0, err
	}
	for arows.Next() {
		var name, typ, env string
		var tags []string
		if err := arows.Scan(&name, &typ, &env, &tags); err != nil {
			arows.Close()
			return 0, err
		}
		assetMeta[name] = struct {
			typ  string
			env  string
			tags []string
		}{typ: typ, env: env, tags: tags}
	}
	arows.Close()

	var ports []collector.PortInfo
	var procs []collector.ProcessInfo
	hasTelemetry := false
	if info, err := s.GetHostSystemInfo(ctx, agentID); err == nil && info != nil {
		ports = info.OpenPorts
		procs = info.Processes
		hasTelemetry = true
	}

	ids := make([]int64, 0, len(items))
	epssArr := make([]float64, 0, len(items))
	pctArr := make([]float64, 0, len(items))
	kevArr := make([]bool, 0, len(items))
	expArr := make([]float64, 0, len(items))
	critArr := make([]float64, 0, len(items))
	riskArr := make([]float64, 0, len(items))
	lvlArr := make([]string, 0, len(items))
	for _, r := range items {
		meta := assetMeta[r.asset]
		crit := AssetCriticality(meta.env, meta.tags, meta.typ)
		exp := ExposureScore(ports, procs, r.asset, meta.typ, hasTelemetry)
		i := intel[r.cveID]
		risk := RiskScore(r.cvss, i.EPSSScore, crit, exp, i.KEV)
		ids = append(ids, r.id)
		epssArr = append(epssArr, i.EPSSScore)
		pctArr = append(pctArr, i.EPSSPercentile)
		kevArr = append(kevArr, i.KEV)
		expArr = append(expArr, exp)
		critArr = append(critArr, crit)
		riskArr = append(riskArr, risk)
		lvlArr = append(lvlArr, RiskLevel(risk))
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE cve_results cr SET
			epss_score=e.epss, epss_percentile=e.pct, kev=e.kev,
			exposure_score=e.exposure, asset_criticality=e.crit,
			risk_score=e.risk, risk_level=e.level
		FROM unnest($1::bigint[], $2::double precision[], $3::double precision[],
			$4::boolean[], $5::double precision[], $6::double precision[],
			$7::double precision[], $8::text[]) AS e(id, epss, pct, kev, exposure, crit, risk, level)
		WHERE cr.id=e.id
	`, ids, epssArr, pctArr, kevArr, expArr, critArr, riskArr, lvlArr)
	return len(items), err
}

// RecalcAllRisk recomputes risk for every agent.
func (s *Store) RecalcAllRisk(ctx context.Context) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM agents`)
	if err != nil {
		return 0, err
	}
	var agents []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		agents = append(agents, id)
	}
	rows.Close()
	total := 0
	for _, id := range agents {
		n, err := s.RecalcAgentRisk(ctx, id)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// RiskSummary aggregates the governance dashboard counts.
func (s *Store) RiskSummary(ctx context.Context) (RiskSummary, error) {
	var sum RiskSummary
	sum.ByRiskLevel = map[string]int{}
	sum.BySeverity = map[string]int{}
	var crit, high, med, low int
	err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE status='active'),
			COUNT(*) FILTER (WHERE status='fixed'),
			COUNT(*) FILTER (WHERE status='active' AND kev),
			COUNT(*) FILTER (WHERE status='active' AND risk_level='CRITICAL'),
			COUNT(*) FILTER (WHERE status='active' AND risk_level='HIGH'),
			COUNT(*) FILTER (WHERE status='active' AND risk_level='MEDIUM'),
			COUNT(*) FILTER (WHERE status='active' AND risk_level='LOW'),
			COALESCE(AVG(epss_score) FILTER (WHERE status='active' AND epss_score>0), 0)
		FROM cve_results
	`).Scan(&sum.TotalActive, &sum.TotalFixed, &sum.KEVCount,
		&crit, &high, &med, &low, &sum.AverageEPSS)
	if err != nil {
		return sum, err
	}
	sum.ByRiskLevel["CRITICAL"] = crit
	sum.ByRiskLevel["HIGH"] = high
	sum.ByRiskLevel["MEDIUM"] = med
	sum.ByRiskLevel["LOW"] = low
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM cve_results cr
		JOIN sla_policies sp ON sp.severity=cr.severity AND sp.enabled
		WHERE cr.status='active' AND
			cr.detected_at + (sp.max_remediation_hours * INTERVAL '1 hour') < NOW()
	`).Scan(&sum.Overdue); err != nil {
		return sum, err
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM vulnerability_exceptions
		WHERE revoked_at IS NULL AND expires_at > NOW()
	`).Scan(&sum.Exempted); err != nil {
		return sum, err
	}
	groups, err := scanCountGroups(ctx, s, `
		SELECT severity, COUNT(*) FROM cve_results WHERE status='active'
		GROUP BY severity ORDER BY severity
	`)
	if err != nil {
		return sum, err
	}
	for k, v := range groups {
		sum.BySeverity[k] = v
	}
	total := sum.TotalActive + sum.TotalFixed
	if total > 0 {
		sum.FixRate = math.Round(float64(sum.TotalFixed)/float64(total)*1000) / 10
	}
	return sum, nil
}

// RiskTop returns the highest-risk active vulnerabilities.
func (s *Store) RiskTop(ctx context.Context, limit int, level string, kevOnly bool) ([]RiskRow, error) {
	if limit <= 0 || limit > 100000 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT cr.cve_id, cr.canonical_cve_id, cr.agent_id, a.hostname, cr.asset_name,
			cr.severity, cr.risk_level, cr.cvss_score, cr.epss_score, cr.kev,
			cr.exposure_score, cr.asset_criticality, cr.risk_score, cr.detected_at,
			cr.fixed_version, cr.kb_article
		FROM cve_results cr JOIN agents a ON a.id=cr.agent_id
		WHERE cr.status='active' AND ($2='' OR cr.risk_level=$2) AND ($3=false OR cr.kev)
		ORDER BY cr.risk_score DESC, cr.epss_score DESC, cr.cve_id
		LIMIT $1
	`, limit, level, kevOnly)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sla, err := s.SLAHours(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var out []RiskRow
	for rows.Next() {
		var r RiskRow
		var kb string
		if err := rows.Scan(&r.CVEID, &r.CanonicalCVEID, &r.AgentID, &r.Hostname,
			&r.AssetName, &r.Severity, &r.RiskLevel, &r.CVSSScore, &r.EPSSScore,
			&r.KEV, &r.ExposureScore, &r.AssetCriticality, &r.RiskScore,
			&r.DetectedAt, &r.FixedVersion, &kb); err != nil {
			return nil, err
		}
		if kb != "" {
			num := strings.TrimPrefix(kb, "KB")
			if num != "" {
				r.PatchURL = "https://support.microsoft.com/help/" + num
			}
		}
		if hours, ok := sla[r.Severity]; ok && hours > 0 {
			due := r.DetectedAt.Add(time.Duration(hours) * time.Hour)
			r.DueAt = &due
			r.Overdue = due.Before(now)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SLAHours returns severity -> remediation hours for enabled policies.
func (s *Store) SLAHours(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT severity, max_remediation_hours FROM sla_policies WHERE enabled
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var sev string
		var h int
		if err := rows.Scan(&sev, &h); err != nil {
			return nil, err
		}
		out[sev] = h
	}
	return out, rows.Err()
}

// RiskExportCSV renders the top risk rows as CSV bytes.
func (s *Store) RiskExportCSV(ctx context.Context) ([]byte, error) {
	rows, err := s.RiskTop(ctx, 100000, "", false)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"cve_id", "canonical_cve_id", "agent_id", "hostname", "asset_name",
		"severity", "risk_level", "cvss_score", "epss_score", "kev", "exposure_score",
		"asset_criticality", "risk_score", "detected_at", "due_at", "overdue", "fixed_version", "patch_url"})
	for _, r := range rows {
		due := ""
		if r.DueAt != nil {
			due = r.DueAt.Format(time.RFC3339)
		}
		_ = w.Write([]string{r.CVEID, r.CanonicalCVEID, r.AgentID, r.Hostname, r.AssetName,
			r.Severity, r.RiskLevel, f2s(r.CVSSScore), f2s(r.EPSSScore), b2s(r.KEV),
			f2s(r.ExposureScore), f2s(r.AssetCriticality), f2s(r.RiskScore),
			r.DetectedAt.Format(time.RFC3339), due, b2s(r.Overdue), r.FixedVersion, r.PatchURL})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func f2s(v float64) string {
	return fmt.Sprintf("%.2f", v)
}

func b2s(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// RiskTrend returns daily active/new/fixed counts for the last N days.
func (s *Store) RiskTrend(ctx context.Context, days int) ([]RiskTrendPoint, error) {
	if days <= 0 || days > 365 {
		days = 30
	}
	rows, err := s.pool.Query(ctx, `
		WITH days AS (
			SELECT generate_series(NOW()::date - ($1 - 1), NOW()::date, '1 day')::date AS d
		)
		SELECT d.d,
			(SELECT COUNT(*) FROM cve_results WHERE detected_at::date <= d.d
				AND (fixed_at IS NULL OR fixed_at::date > d.d)) AS active,
			(SELECT COUNT(*) FROM cve_results WHERE detected_at::date = d.d) AS new_count,
			(SELECT COUNT(*) FROM cve_results WHERE fixed_at::date = d.d) AS fixed_count
		FROM days d ORDER BY d.d
	`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RiskTrendPoint
	for rows.Next() {
		var p RiskTrendPoint
		var d time.Time
		if err := rows.Scan(&d, &p.Active, &p.New, &p.Fixed); err != nil {
			return nil, err
		}
		p.Date = d.Format("2006-01-02")
		out = append(out, p)
	}
	return out, rows.Err()
}

// CreateException records a risk acceptance.
func (s *Store) CreateException(ctx context.Context, cveID, assetKey, reason string,
	expiresAt time.Time, createdBy string) (*VulnerabilityException, error) {
	if createdBy == "" {
		createdBy = "api"
	}
	var e VulnerabilityException
	err := s.pool.QueryRow(ctx, `
		INSERT INTO vulnerability_exceptions (cve_id, asset_key, reason, expires_at, created_by)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id, cve_id, asset_key, reason, expires_at, created_by, created_at, revoked_at
	`, cveID, assetKey, reason, expiresAt, createdBy).Scan(&e.ID, &e.CVEID, &e.AssetKey,
		&e.Reason, &e.ExpiresAt, &e.CreatedBy, &e.CreatedAt, &e.RevokedAt)
	return &e, err
}

// ListExceptions returns exemption records, newest first.
func (s *Store) ListExceptions(ctx context.Context) ([]VulnerabilityException, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, cve_id, asset_key, reason, expires_at, created_by, created_at, revoked_at
		FROM vulnerability_exceptions ORDER BY id DESC LIMIT 500
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VulnerabilityException
	for rows.Next() {
		var e VulnerabilityException
		if err := rows.Scan(&e.ID, &e.CVEID, &e.AssetKey, &e.Reason, &e.ExpiresAt,
			&e.CreatedBy, &e.CreatedAt, &e.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RevokeException soft-revokes an exemption.
func (s *Store) RevokeException(ctx context.Context, id int64, by string) error {
	if by == "" {
		by = "api"
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE vulnerability_exceptions SET revoked_at=NOW()
		WHERE id=$1 AND revoked_at IS NULL
	`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// IsExempt checks whether a (cve, asset) is covered by an active exemption.
func (s *Store) IsExempt(ctx context.Context, agentID, assetName, cveID string) (bool, error) {
	var assetKey string
	_ = s.pool.QueryRow(ctx, `
		SELECT asset_key FROM assets WHERE agent_id=$1 AND name=$2 LIMIT 1
	`, agentID, assetName).Scan(&assetKey)
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM vulnerability_exceptions
			WHERE revoked_at IS NULL AND expires_at > NOW()
				AND cve_id=$1 AND (asset_key='' OR asset_key=$2)
		)
	`, cveID, assetKey).Scan(&exists)
	return exists, err
}

// ListSLAPolicies returns all SLA policies ordered by severity.
func (s *Store) ListSLAPolicies(ctx context.Context) ([]SLAPolicy, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, severity, max_remediation_hours, enabled, updated_at
		FROM sla_policies ORDER BY CASE severity
			WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SLAPolicy
	for rows.Next() {
		var p SLAPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.Severity, &p.MaxRemediationHours,
			&p.Enabled, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdateSLAPolicy updates one SLA policy.
func (s *Store) UpdateSLAPolicy(ctx context.Context, id int64, name string,
	hours int, enabled bool) (*SLAPolicy, error) {
	var p SLAPolicy
	err := s.pool.QueryRow(ctx, `
		UPDATE sla_policies SET name=$2, max_remediation_hours=$3, enabled=$4, updated_at=NOW()
		WHERE id=$1
		RETURNING id, name, severity, max_remediation_hours, enabled, updated_at
	`, id, name, hours, enabled).Scan(&p.ID, &p.Name, &p.Severity,
		&p.MaxRemediationHours, &p.Enabled, &p.UpdatedAt)
	return &p, err
}
