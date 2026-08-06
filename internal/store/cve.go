package store

import (
	"context"
	"strings"
	"time"
)

func (s *Store) UpsertCVEResult(ctx context.Context, r *CVEResult) error {
	canonical := CanonicalCVEID(r.CVEID)
	var fixedAt interface{}
	if r.Status == "fixed" {
		fixedAt = time.Now()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO cve_results (agent_id, cve_id, asset_name, asset_version,
			fixed_version, fix_state, kb_article, kb_url, severity, cvss_score, summary, source, status, detected_at,
			canonical_cve_id, fixed_at, verification_source)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		ON CONFLICT (agent_id, cve_id, asset_name, asset_version) DO UPDATE
		SET fixed_version=$5, fix_state=$6, kb_article=$7, kb_url=$8, severity=$9,
			cvss_score=$10, summary=$11, source=$12, status=$13, detected_at=$14,
			canonical_cve_id=$15, fixed_at=$16, verification_source=$17
	`, r.AgentID, r.CVEID, r.AssetName, r.AssetVersion,
		r.FixedVersion, r.FixState, r.KBArticle, r.KBURL, r.Severity,
		r.CVSSScore, r.Summary, r.Source, r.Status, time.Now(), canonical, fixedAt,
		r.VerificationSource)
	if err != nil {
		return err
	}
	return s.RecordAlias(ctx, r.CVEID, canonical, r.Source)
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
			fixed_version, fix_state, kb_article, kb_url, verification_source,
			severity, cvss_score, summary, source, status, detected_at,
			intel_threat_level, intel_exploited, intel_notes
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
			&r.FixedVersion, &r.FixState, &r.KBArticle, &r.KBURL, &r.VerificationSource,
			&r.Severity, &r.CVSSScore, &r.Summary, &r.Source, &r.Status, &r.DetectedAt,
			&r.IntelThreatLevel, &r.IntelExploited, &r.IntelNotes); err != nil {
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
			fixed_version, fix_state, kb_article, kb_url, verification_source,
			severity, cvss_score, summary, source, status, detected_at,
			intel_threat_level, intel_exploited, intel_notes
		FROM cve_results WHERE agent_id=$1 AND cve_id=$2
	`, agentID, cveID).Scan(&r.ID, &r.AgentID, &r.CVEID, &r.AssetName, &r.AssetVersion,
		&r.FixedVersion, &r.FixState, &r.KBArticle, &r.KBURL, &r.VerificationSource,
		&r.Severity, &r.CVSSScore, &r.Summary, &r.Source, &r.Status, &r.DetectedAt,
		&r.IntelThreatLevel, &r.IntelExploited, &r.IntelNotes)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) SearchByCVE(ctx context.Context, cveID string, tenantID *int64) ([]CVEResult, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.id, r.agent_id, r.cve_id, r.asset_name, r.asset_version,
			r.fixed_version, r.fix_state, r.kb_article, r.kb_url, r.verification_source,
			r.severity, r.cvss_score, r.summary, r.source, r.status, r.detected_at,
			r.intel_threat_level, r.intel_exploited, r.intel_notes
		FROM cve_results r
		WHERE r.cve_id=$1
		  AND ($2::bigint IS NULL OR EXISTS (
		      SELECT 1 FROM agents a WHERE a.id=r.agent_id AND a.tenant_id=$2))
	`, cveID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []CVEResult
	for rows.Next() {
		var r CVEResult
		if err := rows.Scan(&r.ID, &r.AgentID, &r.CVEID, &r.AssetName, &r.AssetVersion,
			&r.FixedVersion, &r.FixState, &r.KBArticle, &r.KBURL, &r.VerificationSource,
			&r.Severity, &r.CVSSScore, &r.Summary, &r.Source, &r.Status, &r.DetectedAt,
			&r.IntelThreatLevel, &r.IntelExploited, &r.IntelNotes); err != nil {
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

func (s *Store) GetCVEStats(ctx context.Context, tenantID *int64) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT severity, COUNT(*) FROM cve_results
		WHERE status='active'
		  AND ($1::bigint IS NULL OR EXISTS (
		      SELECT 1 FROM agents a WHERE a.id=cve_results.agent_id AND a.tenant_id=$1))
		GROUP BY severity
	`, tenantID)
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
		canonical := CanonicalCVEID(r.CVEID)
		var fixedAt interface{}
		if r.Status == "fixed" {
			fixedAt = time.Now()
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO cve_results (agent_id, cve_id, asset_name, asset_version,
				fixed_version, fix_state, kb_article, kb_url, severity, cvss_score, summary, source, status, detected_at,
				canonical_cve_id, fixed_at, verification_source)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		`, r.AgentID, r.CVEID, r.AssetName, r.AssetVersion,
			r.FixedVersion, r.FixState, r.KBArticle, r.KBURL, r.Severity,
			r.CVSSScore, r.Summary, r.Source, r.Status, time.Now(), canonical, fixedAt,
			r.VerificationSource)
		if err != nil {
			return err
		}
		if canonical != r.CVEID {
			if _, err := tx.Exec(ctx, `
				INSERT INTO cve_alias (alias_id, canonical_cve_id, source)
				VALUES ($1,$2,$3) ON CONFLICT (alias_id) DO NOTHING
			`, r.CVEID, canonical, r.Source); err != nil {
				return err
			}
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
	AssetName          string                  `json:"asset_name"`
	Format             string                  `json:"format,omitempty"`
	ActiveCVEs         int                     `json:"active_cves"`
	FixType            string                  `json:"fix_type"`
	FixValue           string                  `json:"fix_value"`
	FixedVersion       string                  `json:"fixed_version"`
	Action             string                  `json:"action"`
	MaxCVSS            float64                 `json:"max_cvss_score"`
	Risk               string                  `json:"risk"`
	ExampleCVE         string                  `json:"example_cve"`
	ReferenceURL       string                  `json:"reference_url,omitempty"`
	Deployable         bool                    `json:"deployable"`
	VerificationSource string                  `json:"verification_source,omitempty"`
	PatchURL           string                  `json:"patch_url,omitempty"`
	PatchSHA256        string                  `json:"patch_sha256,omitempty"`
	KBs                []KBPatchRecommendation `json:"kbs,omitempty"`
}

// PatchLink is one typed link (advisory/support/catalog/download) shown for
// a KB recommendation.
type PatchLink struct {
	Type     string `json:"type"`
	URL      string `json:"url"`
	Verified bool   `json:"verified,omitempty"`
}

// KBPatchRecommendation lists one KB's active CVE set for an asset.
type KBPatchRecommendation struct {
	Kb           string      `json:"kb"`
	AssetName    string      `json:"asset_name"`
	CVECount     int         `json:"cve_count"`
	CVEIDs       []string    `json:"cve_ids"`
	MaxCVSS      float64     `json:"max_cvss_score"`
	MaxSeverity  string      `json:"max_severity"`
	ReferenceURL string      `json:"reference_url,omitempty"`
	PatchURL     string      `json:"patch_url,omitempty"`
	Links        []PatchLink `json:"links,omitempty"`
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
				LIMIT 1), '') as asset_format,
			COALESCE(MAX(NULLIF(r.verification_source, '')), '') as verification_source
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
	hasKB := false
	for rows.Next() {
		var r FixRecommendation
		var rawFix, refURL, assetFormat, verificationSource string
		if err := rows.Scan(&r.AssetName, &r.ActiveCVEs, &rawFix, &r.MaxCVSS,
			&r.ExampleCVE, &refURL, &assetFormat, &verificationSource); err != nil {
			continue
		}
		r.FixedVersion = rawFix
		r.VerificationSource = verificationSource
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
			hasKB = true
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if hasKB {
		kbs, err := s.GetKBPatchRecommendations(ctx, agentID)
		if err != nil {
			return nil, err
		}
		byAsset := make(map[string][]KBPatchRecommendation)
		for _, kb := range kbs {
			byAsset[kb.AssetName] = append(byAsset[kb.AssetName], kb)
		}
		for i := range recs {
			if recs[i].FixType == "kb" {
				recs[i].KBs = byAsset[recs[i].AssetName]
			}
		}
	}
	return recs, nil
}

// GetKBPatchRecommendations returns the active CVE list grouped per
// (asset, KB) for MSRC patch recommendations.
func (s *Store) GetKBPatchRecommendations(ctx context.Context, agentID string) ([]KBPatchRecommendation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.asset_name,
			COALESCE(NULLIF(r.fixed_version, ''), NULLIF(r.kb_article, '')) AS kb,
			COUNT(DISTINCT r.cve_id) AS cve_count,
			array_agg(DISTINCT r.cve_id ORDER BY r.cve_id) AS cve_ids,
			COALESCE(MAX(r.cvss_score), 0) AS max_cvss,
			COALESCE(MAX(r.severity), '') AS max_severity
		FROM cve_results r
		WHERE r.agent_id = $1 AND r.status = 'active'
		  AND (r.fixed_version LIKE 'KB%' OR r.kb_article LIKE 'KB%')
		GROUP BY r.asset_name, kb
		ORDER BY cve_count DESC, kb
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []KBPatchRecommendation
	for rows.Next() {
		var k KBPatchRecommendation
		if err := rows.Scan(&k.AssetName, &k.Kb, &k.CVECount, &k.CVEIDs,
			&k.MaxCVSS, &k.MaxSeverity); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
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
