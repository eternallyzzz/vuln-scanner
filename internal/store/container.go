package store

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"time"
)

// UpsertContainerAgent creates or refreshes the synthetic agent that carries
// container scan results. It never participates in heartbeat or patch loops.
func (s *Store) UpsertContainerAgent(ctx context.Context, id, hostname, osVersion, arch string, tenantID int64) error {
	if tenantID <= 0 {
		tenantID = 1
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agents (id, hostname, os_type, os_version, arch, agent_ver, ip,
			token_hash, status, fingerprint_hash, tenant_id, last_seen, created_at, updated_at)
		VALUES ($1,$2,'container',$3,$4,'container-scanner','','','online','',$5,NOW(),NOW(),NOW())
		ON CONFLICT (id) DO UPDATE
		SET hostname=$2, os_type='container', os_version=$3, arch=$4,
			status='online', last_seen=NOW(), updated_at=NOW()
	`, id, hostname, osVersion, arch, tenantID)
	return err
}

func ContainerAssetKey(agentID, name string) string {
	h := sha1.Sum([]byte(name))
	return "container:" + agentID + ":" + hex.EncodeToString(h[:])
}

// UpsertContainerAsset records one image as a container asset, keyed by agent
// and image ref so rescans update in place.
func (s *Store) UpsertContainerAsset(ctx context.Context, agentID, name, version, location string) error {
	key := ContainerAssetKey(agentID, name)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO assets (asset_key, asset_type, name, version, format, location,
			agent_id, lifecycle, first_seen, last_seen, updated_at)
		VALUES ($1,'container',$2,$3,'container',$4,$5,'active',NOW(),NOW(),NOW())
		ON CONFLICT (asset_key) DO UPDATE
		SET name=$2, version=$3, location=$4, last_seen=NOW(), updated_at=NOW(),
			lifecycle='active'
	`, key, name, version, location, agentID)
	return err
}

// ReplaceContainerVulns atomically replaces all active trivy findings for one
// image, so rescans never leave stale rows behind.
func (s *Store) ReplaceContainerVulns(ctx context.Context, agentID, imageName string, results []*CVEResult) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		DELETE FROM cve_results WHERE agent_id=$1 AND asset_name=$2
	`, agentID, imageName); err != nil {
		return err
	}
	now := time.Now()
	// One CVE can affect several packages inside the same image, but the
	// cve_results unique key is (agent, cve, asset). Keep the highest-CVSS
	// row and prefer one that carries a fixed version.
	byCVE := map[string]*CVEResult{}
	for _, r := range results {
		if r == nil || r.CVEID == "" {
			continue
		}
		cur, ok := byCVE[r.CVEID]
		if !ok || r.CVSSScore > cur.CVSSScore ||
			(r.FixedVersion != "" && cur.FixedVersion == "") {
			byCVE[r.CVEID] = r
		}
	}
	for _, r := range byCVE {
		canonical := CanonicalCVEID(r.CVEID)
		if _, err := tx.Exec(ctx, `
			INSERT INTO cve_results (agent_id, cve_id, asset_name, asset_version,
				fixed_version, kb_article, kb_url, severity, cvss_score, summary,
				source, status, detected_at, canonical_cve_id)
			VALUES ($1,$2,$3,$4,$5,'','',$6,$7,$8,'trivy','active',$9,$10)
		`, agentID, r.CVEID, imageName, r.AssetVersion, r.FixedVersion,
			r.Severity, r.CVSSScore, r.Summary, now, canonical); err != nil {
			return err
		}
		if canonical != r.CVEID {
			if _, err := tx.Exec(ctx, `
				INSERT INTO cve_alias (alias_id, canonical_cve_id, source)
				VALUES ($1,$2,'trivy') ON CONFLICT (alias_id) DO NOTHING
			`, r.CVEID, canonical); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

// GetContainerImages lists container assets for the scanner agent.
func (s *Store) GetContainerImages(ctx context.Context, agentID string) ([]Asset, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, asset_key, asset_type, name, version, os_type, os_version, format,
			vendor, arch, location, agent_id, lifecycle, environment, business_unit, owner, tags,
			first_seen, last_seen, updated_at
		FROM assets WHERE agent_id=$1 AND asset_type='container'
		ORDER BY name
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetContainerVulnCount(ctx context.Context, agentID string) (int64, error) {
	var n int64
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM cve_results WHERE agent_id=$1 AND status='active'
	`, agentID).Scan(&n); err != nil {
		return 0, fmt.Errorf("container vuln count: %w", err)
	}
	return n, nil
}
