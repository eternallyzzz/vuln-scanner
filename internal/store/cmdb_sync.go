package store

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ReconcileAgentFromSnapshot replays the latest stored snapshot of an agent
// through the FULL CMDB sync, retiring software CIs no longer present. This
// backfills assets for agents that uploaded snapshots before CMDB sync
// existed (e.g. Windows hosts with 0 software CIs).
func (s *Store) ReconcileAgentFromSnapshot(ctx context.Context, agentID string) (ReconcileCounts, error) {
	snap, err := s.GetAssetSnapshot(ctx, agentID)
	if err != nil {
		return ReconcileCounts{}, err
	}
	return s.SyncCMDBFromSnapshot(ctx, agentID, snap.Assets, true)
}

// ExternalAssetInput is one row of an external CMDB import.
type ExternalAssetInput struct {
	AssetKey     string   `json:"asset_key,omitempty"`
	Name         string   `json:"name"`
	Version      string   `json:"version,omitempty"`
	AssetType    string   `json:"asset_type,omitempty"`
	Hostname     string   `json:"hostname,omitempty"`
	IP           string   `json:"ip,omitempty"`
	Format       string   `json:"format,omitempty"`
	Vendor       string   `json:"vendor,omitempty"`
	Arch         string   `json:"arch,omitempty"`
	Location     string   `json:"location,omitempty"`
	Environment  string   `json:"environment,omitempty"`
	BusinessUnit string   `json:"business_unit,omitempty"`
	Owner        string   `json:"owner,omitempty"`
	Lifecycle    string   `json:"lifecycle,omitempty"`
	Tags         []string `json:"tags,omitempty"`
}

// ExternalAssetKey derives a stable key for an external CMDB asset. Version is
// deliberately excluded so a version bump updates the same CI instead of
// creating a new one.
func ExternalAssetKey(name, assetType, hostname, ip string) string {
	h := sha1.Sum([]byte(name + "\x00" + assetType + "\x00" + hostname + "\x00" + ip))
	return "ext:" + hex.EncodeToString(h[:])
}

// ImportResult summarizes one external CMDB import.
type ImportResult struct {
	Imported int      `json:"imported"`
	Updated  int      `json:"updated"`
	Retired  int      `json:"retired"`
	Changes  int      `json:"changes"`
	Errors   []string `json:"errors,omitempty"`
}

// ImportExternalAssets upserts external CMDB assets (source='cmdb_import',
// agent_id NULL). In full mode, previously imported active assets absent from
// the payload are retired. Every change is recorded with the given actor and
// change_source='cmdb_import'.
func (s *Store) ImportExternalAssets(ctx context.Context, items []ExternalAssetInput, full bool, actor string) (ImportResult, error) {
	var res ImportResult
	if actor == "" {
		actor = "api"
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)

	keys := make([]string, 0, len(items))
	var changes []assetChangeRecord
	for i, in := range items {
		item, err := normalizeExternalAssetInput(in)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("row %d: %v", i+1, err))
			continue
		}
		key := item.AssetKey
		if key == "" {
			key = ExternalAssetKey(item.Name, item.AssetType, item.Hostname, item.IP)
		}
		keys = append(keys, key)

		var oldVer, oldSource string
		err = tx.QueryRow(ctx, `
			SELECT version, source FROM assets WHERE asset_key=$1 FOR UPDATE
		`, key).Scan(&oldVer, &oldSource)
		existed := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return res, err
		}
		if existed && oldSource != "cmdb_import" {
			res.Errors = append(res.Errors, fmt.Sprintf(
				"row %d: asset_key %s belongs to source %q, refusing to overwrite", i+1, key, oldSource))
			continue
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO assets (asset_key, asset_type, name, version, source, hostname, ip,
				agent_id, format, vendor, arch, location, environment, business_unit, owner, lifecycle, tags,
				first_seen, last_seen, updated_at)
			VALUES ($1,$2,$3,$4,'cmdb_import',$5,$6,NULL,$7,$8,$9,$10,$11,$12,$13,$14,$15,NOW(),NOW(),NOW())
			ON CONFLICT (asset_key) DO UPDATE
			SET name=$3, version=$4, hostname=$5, ip=$6, format=$7, vendor=$8, arch=$9,
				location=$10, environment=$11, business_unit=$12, owner=$13, lifecycle=$14,
				tags=$15, last_seen=NOW(), updated_at=NOW()
			WHERE assets.source='cmdb_import'
		`, key, item.AssetType, item.Name, item.Version, item.Hostname, item.IP,
			item.Format, item.Vendor, item.Arch, item.Location, item.Environment,
			item.BusinessUnit, item.Owner, item.Lifecycle, item.Tags); err != nil {
			return res, err
		}

		if !existed {
			res.Imported++
			changes = append(changes, assetChangeRecord{
				Key: key, Name: item.Name, Old: "", New: item.Version,
				Format: item.Format, ChangeType: "added",
			})
		} else if oldVer != item.Version {
			res.Updated++
			changes = append(changes, assetChangeRecord{
				Key: key, Name: item.Name, Old: oldVer, New: item.Version,
				Format: item.Format, ChangeType: "updated",
			})
		}
	}

	if full {
		retired, err := tx.Query(ctx, `
			UPDATE assets SET lifecycle='retired', updated_at=NOW()
			WHERE source='cmdb_import' AND lifecycle='active' AND asset_key <> ALL($1::text[])
			RETURNING asset_key, name, version, format
		`, keys)
		if err != nil {
			return res, err
		}
		for retired.Next() {
			var k, n, v, f string
			if err := retired.Scan(&k, &n, &v, &f); err != nil {
				retired.Close()
				return res, err
			}
			res.Retired++
			changes = append(changes, assetChangeRecord{
				Key: k, Name: n, Old: v, New: "", Format: f, ChangeType: "retired",
			})
		}
		retired.Close()
		if err := retired.Err(); err != nil {
			return res, err
		}
	}

	if len(changes) > 0 {
		if err := insertExternalAssetChangesTx(ctx, tx, changes, time.Now(), actor); err != nil {
			return res, err
		}
	}
	res.Changes = len(changes)
	return res, tx.Commit(ctx)
}

// insertExternalAssetChangesTx records import changes with a NULL agent_id
// (external CIs are not tied to a scanned agent).
func insertExternalAssetChangesTx(ctx context.Context, tx pgx.Tx, changes []assetChangeRecord, now time.Time, actor string) error {
	for _, c := range changes {
		if _, err := tx.Exec(ctx, `
			INSERT INTO asset_changes (agent_id, change_type, asset_name, old_version, new_version,
				format, detected_at, asset_key, change_source, actor)
			VALUES (NULL,$1,$2,$3,$4,$5,$6,$7,'cmdb_import',$8)
		`, c.ChangeType, c.Name, c.Old, c.New, c.Format, now, c.Key, actor); err != nil {
			return err
		}
	}
	return nil
}

// normalizeExternalAssetInput trims and validates one external import row.
func normalizeExternalAssetInput(in ExternalAssetInput) (ExternalAssetInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return in, fmt.Errorf("name is required")
	}
	in.AssetType = strings.ToLower(strings.TrimSpace(in.AssetType))
	if in.AssetType == "" {
		in.AssetType = "software"
	}
	switch in.AssetType {
	case "software", "host", "external":
	default:
		return in, fmt.Errorf("asset_type must be software, host or external")
	}
	in.Lifecycle = strings.ToLower(strings.TrimSpace(in.Lifecycle))
	if in.Lifecycle == "" {
		in.Lifecycle = "active"
	}
	if !validLifecycles[in.Lifecycle] {
		return in, fmt.Errorf("lifecycle must be active or retired")
	}
	in.AssetKey = strings.TrimSpace(in.AssetKey)
	if in.AssetKey != "" && !strings.HasPrefix(in.AssetKey, "ext:") {
		// Only external keys are honored; anything else is replaced by the
		// derived key so agent-derived assets can never be overwritten.
		in.AssetKey = ""
	}
	seen := make(map[string]bool)
	tags := make([]string, 0, len(in.Tags))
	for _, t := range in.Tags {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		tags = append(tags, t)
	}
	in.Tags = tags
	return in, nil
}

// ReconcileReport compares external host CIs with scanned agents by hostname.
type ReconcileReport struct {
	ExternalHosts     int      `json:"external_hosts"`
	ScannedAgents     int      `json:"scanned_agents"`
	Matched           int      `json:"matched"`
	UnmatchedExternal []string `json:"unmatched_external"`
	UnmatchedScanned  []string `json:"unmatched_scanned"`
}

// BuildReconcileReport matches external hostnames against agent hostnames,
// case-insensitively and after trimming.
func BuildReconcileReport(externalHosts, scannedHosts []string) ReconcileReport {
	ext := uniqueLowerNonEmpty(externalHosts)
	scanned := uniqueLowerNonEmpty(scannedHosts)
	extSet := make(map[string]bool, len(ext))
	for _, h := range ext {
		extSet[h] = true
	}
	scannedSet := make(map[string]bool, len(scanned))
	for _, h := range scanned {
		scannedSet[h] = true
	}
	var r ReconcileReport
	r.ExternalHosts = len(ext)
	r.ScannedAgents = len(scanned)
	for _, h := range ext {
		if scannedSet[h] {
			r.Matched++
		} else {
			r.UnmatchedExternal = append(r.UnmatchedExternal, h)
		}
	}
	for _, h := range scanned {
		if !extSet[h] {
			r.UnmatchedScanned = append(r.UnmatchedScanned, h)
		}
	}
	sort.Strings(r.UnmatchedExternal)
	sort.Strings(r.UnmatchedScanned)
	return r
}

func uniqueLowerNonEmpty(list []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range list {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// CMDBReconcileReport builds the external-vs-scanned host report from the
// current ledger.
func (s *Store) CMDBReconcileReport(ctx context.Context) (ReconcileReport, error) {
	var external []string
	rows, err := s.pool.Query(ctx, `
		SELECT name FROM assets
		WHERE source='cmdb_import' AND asset_type='host' AND lifecycle='active' AND name <> ''
	`)
	if err != nil {
		return ReconcileReport{}, err
	}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return ReconcileReport{}, err
		}
		external = append(external, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ReconcileReport{}, err
	}

	var scanned []string
	rows, err = s.pool.Query(ctx, `SELECT hostname FROM agents WHERE hostname <> ''`)
	if err != nil {
		return ReconcileReport{}, err
	}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return ReconcileReport{}, err
		}
		scanned = append(scanned, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ReconcileReport{}, err
	}
	return BuildReconcileReport(external, scanned), nil
}
