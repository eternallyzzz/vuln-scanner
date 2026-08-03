package store

import (
	"context"
	"strings"
	"time"
)

func (s *Store) UpsertCVEResult(ctx context.Context, r *CVEResult) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO cve_results (agent_id, cve_id, asset_name, asset_version,
			fixed_version, fix_state, kb_article, kb_url, severity, cvss_score, summary, source, status, detected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (agent_id, cve_id, asset_name, asset_version) DO UPDATE
		SET fixed_version=$5, fix_state=$6, kb_article=$7, kb_url=$8, severity=$9,
			cvss_score=$10, summary=$11, source=$12, status=$13, detected_at=$14
	`, r.AgentID, r.CVEID, r.AssetName, r.AssetVersion,
		r.FixedVersion, r.FixState, r.KBArticle, r.KBURL, r.Severity,
		r.CVSSScore, r.Summary, r.Source, r.Status, time.Now())
	return err
}

func (s *Store) GetCVEResults(ctx context.Context, agentID string, severity string, hasFix bool, offset, limit int) ([]CVEResult, int, error) {
	var total int
	countRow := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM cve_results WHERE agent_id=$1
		AND (''=$2 OR severity=$2) AND (NOT $3 OR fixed_version!='')
	`, agentID, severity, hasFix)
	if err := countRow.Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, agent_id, cve_id, asset_name, asset_version,
			fixed_version, fix_state, kb_article, kb_url, severity, cvss_score, summary, source, status, detected_at
		FROM cve_results WHERE agent_id=$1
		AND (''=$2 OR severity=$2) AND (NOT $3 OR fixed_version!='')
		ORDER BY CASE severity
			WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4
		END, cve_id
		LIMIT $4 OFFSET $5
	`, agentID, severity, hasFix, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []CVEResult
	for rows.Next() {
		var r CVEResult
		if err := rows.Scan(&r.ID, &r.AgentID, &r.CVEID, &r.AssetName, &r.AssetVersion,
			&r.FixedVersion, &r.FixState, &r.KBArticle, &r.KBURL, &r.Severity, &r.CVSSScore,
			&r.Summary, &r.Source, &r.Status, &r.DetectedAt); err != nil {
			return nil, 0, err
		}
		results = append(results, r)
	}
	return results, total, nil
}

func (s *Store) GetCVEResult(ctx context.Context, agentID, cveID string) (*CVEResult, error) {
	var r CVEResult
	err := s.pool.QueryRow(ctx, `
		SELECT id, agent_id, cve_id, asset_name, asset_version,
			fixed_version, fix_state, kb_article, kb_url, severity, cvss_score, summary, source, status, detected_at
		FROM cve_results WHERE agent_id=$1 AND cve_id=$2
	`, agentID, cveID).Scan(&r.ID, &r.AgentID, &r.CVEID, &r.AssetName, &r.AssetVersion,
		&r.FixedVersion, &r.FixState, &r.KBArticle, &r.KBURL, &r.Severity, &r.CVSSScore,
		&r.Summary, &r.Source, &r.Status, &r.DetectedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) SearchByCVE(ctx context.Context, cveID string) ([]CVEResult, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.id, r.agent_id, r.cve_id, r.asset_name, r.asset_version,
			r.fixed_version, r.fix_state, r.kb_article, r.kb_url, r.severity, r.cvss_score,
			r.summary, r.source, r.status, r.detected_at
		FROM cve_results r WHERE r.cve_id=$1
	`, cveID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []CVEResult
	for rows.Next() {
		var r CVEResult
		if err := rows.Scan(&r.ID, &r.AgentID, &r.CVEID, &r.AssetName, &r.AssetVersion,
			&r.FixedVersion, &r.FixState, &r.KBArticle, &r.KBURL, &r.Severity, &r.CVSSScore,
			&r.Summary, &r.Source, &r.Status, &r.DetectedAt); err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, nil
}

func (s *Store) ResolveCVEsForAsset(ctx context.Context, agentID, assetName, assetVersion string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE cve_results SET status='resolved', detected_at=$1
		WHERE agent_id=$2 AND asset_name=$3 AND asset_version=$4 AND status='active'
	`, time.Now(), agentID, assetName, assetVersion)
	return err
}

func (s *Store) GetCVEStats(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT severity, COUNT(*) FROM cve_results WHERE status='active' GROUP BY severity
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, err
		}
		stats[sev] = count
	}
	return stats, nil
}

func (s *Store) DeleteCVEResultsByAgent(ctx context.Context, agentID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM cve_results WHERE agent_id=$1`, agentID)
	return err
}

func (s *Store) BulkUpsertCVEResults(ctx context.Context, entries []*CVEResult) error {
	if len(entries) == 0 {
		return nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	agentID := entries[0].AgentID
	_, err = tx.Exec(ctx, `DELETE FROM cve_results WHERE agent_id=$1`, agentID)
	if err != nil {
		return err
	}

	for _, r := range entries {
		_, err := tx.Exec(ctx, `
			INSERT INTO cve_results (agent_id, cve_id, asset_name, asset_version,
				fixed_version, fix_state, kb_article, kb_url, severity, cvss_score, summary, source, status, detected_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		`, r.AgentID, r.CVEID, r.AssetName, r.AssetVersion,
			r.FixedVersion, r.FixState, r.KBArticle, r.KBURL, r.Severity,
			r.CVSSScore, r.Summary, r.Source, r.Status, time.Now())
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (s *Store) DeleteCVEResults(ctx context.Context, agentID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM cve_results WHERE agent_id=$1`, agentID)
	return err
}

func (s *Store) AgentOSType(ctx context.Context, agentID string) string {
	var osType string
	s.pool.QueryRow(ctx, `SELECT os_type FROM agents WHERE id=$1`, agentID).Scan(&osType)
	return osType
}

type FixRecommendation struct {
	AssetName    string  `json:"asset_name"`
	Format       string  `json:"format,omitempty"`
	ActiveCVEs   int     `json:"active_cves"`
	FixType      string  `json:"fix_type"`
	FixValue     string  `json:"fix_value"`
	FixedVersion string  `json:"fixed_version"`
	Action       string  `json:"action"`
	MaxCVSS      float64 `json:"max_cvss_score"`
	Risk         string  `json:"risk"`
	ExampleCVE   string  `json:"example_cve"`
	ReferenceURL string  `json:"reference_url,omitempty"`
	Deployable   bool    `json:"deployable"`
	PatchURL     string  `json:"patch_url,omitempty"`
}

func (s *Store) GetAgentRecommendations(ctx context.Context, agentID string) ([]FixRecommendation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.asset_name,
			COUNT(*) as active_cves,
			COALESCE(MAX(NULLIF(r.fixed_version, '')), '') as fix_version,
			COALESCE(MAX(r.cvss_score), 0) as max_cvss,
			MAX(r.cve_id) as example_cve,
			COALESCE(MAX(NULLIF(r.kb_url, '')), '') as ref_url,
			COALESCE((SELECT a.format FROM assets a
				WHERE a.agent_id = $1 AND a.name = r.asset_name
				LIMIT 1), '') as asset_format
		FROM cve_results r
		WHERE r.agent_id = $1 AND r.status = 'active'
		GROUP BY r.asset_name
		ORDER BY active_cves DESC
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var recs []FixRecommendation
	for rows.Next() {
		var r FixRecommendation
		var rawFix, refURL, assetFormat string
		if err := rows.Scan(&r.AssetName, &r.ActiveCVEs, &rawFix, &r.MaxCVSS,
			&r.ExampleCVE, &refURL, &assetFormat); err != nil {
			continue
		}
		r.FixedVersion = rawFix
		r.Risk = riskFromCVSS(r.MaxCVSS)
		r.Format = assetFormat
		if assetFormat == "container" {
			r.FixType = "rebuild"
			r.FixValue = "rebuild image"
			r.Action = "rebuild_image"
		} else if strings.HasPrefix(rawFix, "KB") {
			r.FixType = "kb"
			r.FixValue = rawFix
			r.Action = "install_patch"
		} else if rawFix == "0" || rawFix == "" {
			r.FixType = "none"
			r.Action = "monitor"
		} else {
			r.FixType = "version"
			r.FixValue = ">= " + rawFix
			r.Action = "upgrade_package"
		}
		if refURL != "" {
			r.ReferenceURL = refURL
		}
		recs = append(recs, r)
	}
	return recs, nil
}

func (s *Store) ActiveCVEsByAsset(ctx context.Context, agentID string) (map[string][]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT asset_name, array_agg(DISTINCT cve_id)
		FROM cve_results
		WHERE agent_id=$1 AND status='active'
		GROUP BY asset_name
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string][]string)
	for rows.Next() {
		var asset string
		var cves []string
		if err := rows.Scan(&asset, &cves); err != nil {
			return nil, err
		}
		out[asset] = cves
	}
	return out, rows.Err()
}

// ActiveCVEsByAssetFiltered returns active CVE ids per asset, restricted by
// severity (empty = any), minimum CVSS and an optional CVE allowlist.
func (s *Store) ActiveCVEsByAssetFiltered(ctx context.Context, agentID, minSeverity string, minCVSS float64, cveIDs []string) (map[string][]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT asset_name, array_agg(DISTINCT cve_id)
		FROM cve_results
		WHERE agent_id=$1 AND status='active'
		  AND ($2='' OR
			(CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
			  WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END)
			>= (CASE $2 WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
			  WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END))
		  AND cvss_score >= $3
		  AND (cardinality(COALESCE($4::text[],'{}'))=0 OR cve_id = ANY(COALESCE($4::text[],'{}')))
		GROUP BY asset_name
	`, agentID, minSeverity, minCVSS, cveIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string][]string)
	for rows.Next() {
		var asset string
		var cves []string
		if err := rows.Scan(&asset, &cves); err != nil {
			return nil, err
		}
		out[asset] = cves
	}
	return out, rows.Err()
}

func riskFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
