package store

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type Asset struct {
	ID           int64     `json:"id"`
	AssetKey     string    `json:"asset_key"`
	AssetType    string    `json:"asset_type"`
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	OSType       string    `json:"os_type,omitempty"`
	OSVersion    string    `json:"os_version,omitempty"`
	Format       string    `json:"format,omitempty"`
	Vendor       string    `json:"vendor,omitempty"`
	Arch         string    `json:"arch,omitempty"`
	Location     string    `json:"location,omitempty"`
	Source       string    `json:"source"`
	Hostname     string    `json:"hostname,omitempty"`
	IP           string    `json:"ip,omitempty"`
	AgentID      string    `json:"agent_id"`
	Lifecycle    string    `json:"lifecycle"`
	Environment  string    `json:"environment"`
	BusinessUnit string    `json:"business_unit"`
	Owner        string    `json:"owner"`
	Tags         []string  `json:"tags"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type AssetRelation struct {
	ParentKey    string    `json:"parent_key"`
	ChildKey     string    `json:"child_key"`
	RelationType string    `json:"relation_type"`
	CreatedAt    time.Time `json:"created_at"`
}

type AssetMeta struct {
	Tags        []string `json:"tags"`
	Environment string   `json:"environment"`
}

type AssetChange struct {
	AgentID      string    `json:"agent_id"`
	AssetName    string    `json:"asset_name"`
	OldVersion   string    `json:"old_version"`
	NewVersion   string    `json:"new_version"`
	Format       string    `json:"format"`
	DetectedAt   time.Time `json:"detected_at"`
	AssetKey     string    `json:"asset_key"`
	ChangeSource string    `json:"change_source"`
	Actor        string    `json:"actor"`
}

type AssetSummaryRow struct {
	AssetType   string `json:"asset_type"`
	Environment string `json:"environment"`
	Lifecycle   string `json:"lifecycle"`
	Count       int64  `json:"count"`
}

type snapshotSoftware struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Arch     string `json:"arch"`
	Format   string `json:"format"`
	Vendor   string `json:"vendor"`
	Location string `json:"location"`
}

// ReconcileCounts summarizes one snapshot-to-CMDB sync.
type ReconcileCounts struct {
	Upserted  int `json:"upserted"`
	Retired   int `json:"retired"`
	Relations int `json:"relations"`
	Changes   int `json:"changes"`
}

func HostAssetKey(agentID string) string {
	return "host:" + agentID
}

func SoftwareAssetKey(agentID, name, format, arch, location string) string {
	h := sha1.Sum([]byte(name + "\x00" + format + "\x00" + arch + "\x00" + location))
	return "sw:" + agentID + ":" + hex.EncodeToString(h[:])
}

// SyncCMDBFromSnapshot materializes the agent snapshot into the assets table.
// FULL mode reconciles (retires software CIs no longer present, rebuilds
// relations); INCREMENTAL only upserts the given inventory.
func (s *Store) SyncCMDBFromSnapshot(ctx context.Context, agentID string, assetsJSON []byte, full bool) (ReconcileCounts, error) {
	var cur struct {
		Assets []snapshotSoftware `json:"assets"`
	}
	if len(assetsJSON) > 0 {
		if err := json.Unmarshal(assetsJSON, &cur); err != nil {
			return ReconcileCounts{}, fmt.Errorf("parse snapshot assets: %w", err)
		}
	}

	agent, err := s.GetAgent(ctx, agentID)
	if err != nil {
		return ReconcileCounts{}, fmt.Errorf("get agent: %w", err)
	}
	hostname := ""
	osType := ""
	osVersion := ""
	if agent != nil {
		hostname = agent.Hostname
		osType = agent.OSType
		osVersion = agent.OSVersion
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ReconcileCounts{}, err
	}
	defer tx.Rollback(ctx)

	now := time.Now()

	// Existing software versions for change detection.
	rows, err := tx.Query(ctx, `
		SELECT asset_key, version FROM assets
		WHERE agent_id=$1 AND asset_type='software'
	`, agentID)
	if err != nil {
		return ReconcileCounts{}, err
	}
	existing := map[string]string{}
	for rows.Next() {
		var key, ver string
		if err := rows.Scan(&key, &ver); err != nil {
			rows.Close()
			return ReconcileCounts{}, err
		}
		existing[key] = ver
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ReconcileCounts{}, err
	}

	keys := make([]string, 0, len(cur.Assets))
	var changes []assetChangeRecord
	for _, sw := range cur.Assets {
		if sw.Name == "" {
			continue
		}
		key := SoftwareAssetKey(agentID, sw.Name, sw.Format, sw.Arch, sw.Location)
		keys = append(keys, key)

		if _, err := tx.Exec(ctx, `
			INSERT INTO assets (asset_key, asset_type, name, version, format, vendor, arch,
				location, agent_id, lifecycle, first_seen, last_seen, updated_at)
			VALUES ($1,'software',$2,$3,$4,$5,$6,$7,$8,'active',NOW(),NOW(),NOW())
			ON CONFLICT (asset_key) DO UPDATE
			SET version=EXCLUDED.version, format=EXCLUDED.format, vendor=EXCLUDED.vendor,
				arch=EXCLUDED.arch, location=EXCLUDED.location, last_seen=NOW(), updated_at=NOW()
		`, key, sw.Name, sw.Version, sw.Format, sw.Vendor, sw.Arch, sw.Location, agentID); err != nil {
			return ReconcileCounts{}, err
		}

		prev, ok := existing[key]
		if !ok {
			changes = append(changes, assetChangeRecord{
				Key: key, Name: sw.Name, Old: "", New: sw.Version, Format: sw.Format, ChangeType: "added",
			})
		} else if prev != sw.Version {
			changes = append(changes, assetChangeRecord{
				Key: key, Name: sw.Name, Old: prev, New: sw.Version, Format: sw.Format, ChangeType: "updated",
			})
		}
	}

	if len(changes) > 0 {
		if err := insertAssetChangesTx(ctx, tx, agentID, changes, now, "agent", ""); err != nil {
			return ReconcileCounts{}, err
		}
	}

	hostKey := HostAssetKey(agentID)
	if _, err := tx.Exec(ctx, `
		INSERT INTO assets (asset_key, asset_type, name, version, os_type, os_version,
			hostname, agent_id, lifecycle, first_seen, last_seen, updated_at)
		VALUES ($1,'host',$2,$3,$4,$5,$2,$6,'active',NOW(),NOW(),NOW())
		ON CONFLICT (asset_key) DO UPDATE
		SET name=$2, version=$3, os_type=$4, os_version=$5, hostname=$2, last_seen=NOW(),
			updated_at=NOW(), lifecycle='active'
	`, hostKey, hostname, osVersion, osType, osVersion, agentID); err != nil {
		return ReconcileCounts{}, err
	}

	if full {
		if _, err := tx.Exec(ctx, `DELETE FROM asset_relations WHERE parent_key=$1`, hostKey); err != nil {
			return ReconcileCounts{}, err
		}
	}
	if len(keys) > 0 {
		for _, key := range keys {
			if _, err := tx.Exec(ctx, `
				INSERT INTO asset_relations (parent_key, child_key, relation_type)
				VALUES ($1,$2,'installs')
				ON CONFLICT (parent_key, child_key, relation_type) DO NOTHING
			`, hostKey, key); err != nil {
				return ReconcileCounts{}, err
			}
		}
	}

	var retiredChanges []assetChangeRecord
	if full {
		retired, err := tx.Query(ctx, `
			UPDATE assets SET lifecycle='retired', updated_at=NOW()
			WHERE agent_id=$1 AND asset_type='software' AND asset_key <> ALL($2::text[])
			RETURNING asset_key, name, version, format
		`, agentID, keys)
		if err != nil {
			return ReconcileCounts{}, err
		}
		for retired.Next() {
			var k, n, v, f string
			if err := retired.Scan(&k, &n, &v, &f); err != nil {
				retired.Close()
				return ReconcileCounts{}, err
			}
			retiredChanges = append(retiredChanges, assetChangeRecord{
				Key: k, Name: n, Old: v, New: "", Format: f, ChangeType: "retired",
			})
		}
		retired.Close()
		if err := retired.Err(); err != nil {
			return ReconcileCounts{}, err
		}
		if len(retiredChanges) > 0 {
			if err := insertAssetChangesTx(ctx, tx, agentID, retiredChanges, now, "agent", ""); err != nil {
				return ReconcileCounts{}, err
			}
		}
	}

	upserted := 0
	for _, c := range changes {
		if c.ChangeType == "added" || c.ChangeType == "updated" {
			upserted++
		}
	}
	counts := ReconcileCounts{
		Upserted:  upserted,
		Retired:   len(retiredChanges),
		Relations: len(keys),
		Changes:   len(changes) + len(retiredChanges),
	}
	return counts, tx.Commit(ctx)
}

type assetChangeRecord struct {
	Key, Name, Old, New, Format, ChangeType string
}

func insertAssetChangesTx(ctx context.Context, tx pgx.Tx, agentID string, changes []assetChangeRecord, now time.Time, source, actor string) error {
	for _, c := range changes {
		if _, err := tx.Exec(ctx, `
			INSERT INTO asset_changes (agent_id, change_type, asset_name, old_version, new_version,
				format, detected_at, asset_key, change_source, actor)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		`, agentID, c.ChangeType, c.Name, c.Old, c.New, c.Format, now, c.Key, source, actor); err != nil {
			return err
		}
	}
	return nil
}

type AssetFilters struct {
	AssetType    string
	Environment  string
	BusinessUnit string
	Owner        string
	Lifecycle    string
	AgentID      string
	Tag          string
	Q            string
	Limit        int
	Offset       int
}

func (f AssetFilters) whereClause(args *[]interface{}) string {
	var conds []string
	add := func(expr string, v interface{}) {
		*args = append(*args, v)
		conds = append(conds, fmt.Sprintf(expr, len(*args)))
	}
	if f.AssetType != "" {
		add("asset_type=$%d", f.AssetType)
	}
	if f.Environment != "" {
		add("environment=$%d", f.Environment)
	}
	if f.BusinessUnit != "" {
		add("business_unit=$%d", f.BusinessUnit)
	}
	if f.Owner != "" {
		add("owner=$%d", f.Owner)
	}
	if f.Lifecycle != "" {
		add("lifecycle=$%d", f.Lifecycle)
	}
	if f.AgentID != "" {
		add("agent_id=$%d", f.AgentID)
	}
	if f.Tag != "" {
		add("tags @> ARRAY[$%d]", f.Tag)
	}
	if f.Q != "" {
		add("name ILIKE '%%' || $%d || '%%'", f.Q)
	}
	if len(conds) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(conds, " AND ")
}

func (s *Store) ListAssets(ctx context.Context, f AssetFilters) ([]Asset, int, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	var countArgs []interface{}
	countWhere := f.whereClause(&countArgs)
	var total int
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM assets"+countWhere, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	var listArgs []interface{}
	where := f.whereClause(&listArgs)
	listArgs = append(listArgs, f.Limit, f.Offset)
	query := "SELECT id, asset_key, asset_type, name, version, os_type, os_version, format, " +
		"vendor, arch, location, source, hostname, ip, agent_id, lifecycle, environment, business_unit, owner, tags, " +
		"first_seen, last_seen, updated_at FROM assets" + where +
		fmt.Sprintf(" ORDER BY name LIMIT $%d OFFSET $%d", len(listArgs)-1, len(listArgs))
	rows, err := s.pool.Query(ctx, query, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

func scanAsset(row interface{ Scan(...interface{}) error }) (Asset, error) {
	var a Asset
	err := row.Scan(&a.ID, &a.AssetKey, &a.AssetType, &a.Name, &a.Version,
		&a.OSType, &a.OSVersion, &a.Format, &a.Vendor, &a.Arch, &a.Location,
		&a.Source, &a.Hostname, &a.IP, &a.AgentID, &a.Lifecycle, &a.Environment, &a.BusinessUnit, &a.Owner,
		&a.Tags, &a.FirstSeen, &a.LastSeen, &a.UpdatedAt)
	return a, err
}

func (s *Store) GetAsset(ctx context.Context, id int64) (Asset, error) {
	return scanAsset(s.pool.QueryRow(ctx, `
		SELECT id, asset_key, asset_type, name, version, os_type, os_version, format,
			vendor, arch, location, source, hostname, ip, agent_id, lifecycle, environment, business_unit, owner, tags,
			first_seen, last_seen, updated_at FROM assets WHERE id=$1
	`, id))
}

var validLifecycles = map[string]bool{"active": true, "retired": true}

func (s *Store) UpdateAssetMeta(ctx context.Context, id int64, env, businessUnit, owner, lifecycle string, tags []string, actor string) (Asset, error) {
	cur, err := s.GetAsset(ctx, id)
	if err != nil {
		return Asset{}, err
	}
	if lifecycle == "" {
		lifecycle = cur.Lifecycle
	}
	if !validLifecycles[lifecycle] {
		return Asset{}, fmt.Errorf("lifecycle must be active or retired")
	}
	if env == "" {
		env = cur.Environment
	}
	if businessUnit == "" {
		businessUnit = cur.BusinessUnit
	}
	if owner == "" {
		owner = cur.Owner
	}
	if tags == nil {
		tags = cur.Tags
	}
	seen := map[string]bool{}
	var cleanTags []string
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		cleanTags = append(cleanTags, t)
	}

	oldMeta, _ := json.Marshal(map[string]interface{}{
		"environment": cur.Environment, "business_unit": cur.BusinessUnit,
		"owner": cur.Owner, "lifecycle": cur.Lifecycle, "tags": cur.Tags,
	})
	newMeta, _ := json.Marshal(map[string]interface{}{
		"environment": env, "business_unit": businessUnit,
		"owner": owner, "lifecycle": lifecycle, "tags": cleanTags,
	})

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Asset{}, err
	}
	defer tx.Rollback(ctx)

	a, err := scanAsset(tx.QueryRow(ctx, `
		UPDATE assets SET environment=$2, business_unit=$3, owner=$4, lifecycle=$5,
			tags=$6, updated_at=NOW()
		WHERE id=$1
		RETURNING id, asset_key, asset_type, name, version, os_type, os_version, format,
			vendor, arch, location, source, hostname, ip, agent_id, lifecycle, environment, business_unit, owner, tags,
			first_seen, last_seen, updated_at
	`, id, env, businessUnit, owner, lifecycle, cleanTags))
	if err != nil {
		return Asset{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO asset_changes (agent_id, change_type, asset_name, old_version, new_version,
			format, detected_at, asset_key, change_source, actor)
		VALUES ($1,'meta_update',$2,$3,$4,'meta',NOW(),$5,'api',$6)
	`, a.AgentID, a.Name, string(oldMeta), string(newMeta), a.AssetKey, actor); err != nil {
		return Asset{}, err
	}
	return a, tx.Commit(ctx)
}

type AssetMetaUpdate struct {
	AssetKey     string
	Environment  string
	BusinessUnit string
	Owner        string
	Lifecycle    string
	Tags         []string // nil = keep unchanged, non-nil = replace
}

// BulkUpdateAssetMeta applies metadata updates to multiple assets in one
// transaction. Empty scalar fields keep their current values; a non-nil Tags
// slice replaces the existing tag set. Every changed asset is recorded in
// asset_changes with the given actor.
func (s *Store) BulkUpdateAssetMeta(ctx context.Context, items []AssetMetaUpdate, actor string) (int64, error) {
	if len(items) == 0 {
		return 0, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	updated := int64(0)
	for _, item := range items {
		if item.AssetKey == "" {
			continue
		}
		var cur Asset
		err := tx.QueryRow(ctx, `
			SELECT id, asset_key, asset_type, name, version, os_type, os_version, format,
				vendor, arch, location, source, hostname, ip, agent_id, lifecycle, environment, business_unit, owner, tags,
				first_seen, last_seen, updated_at
			FROM assets WHERE asset_key=$1 FOR UPDATE
		`, item.AssetKey).Scan(&cur.ID, &cur.AssetKey, &cur.AssetType, &cur.Name, &cur.Version,
			&cur.OSType, &cur.OSVersion, &cur.Format, &cur.Vendor, &cur.Arch, &cur.Location,
			&cur.Source, &cur.Hostname, &cur.IP, &cur.AgentID, &cur.Lifecycle, &cur.Environment, &cur.BusinessUnit, &cur.Owner,
			&cur.Tags, &cur.FirstSeen, &cur.LastSeen, &cur.UpdatedAt)
		if err != nil {
			if err == pgx.ErrNoRows {
				continue
			}
			return 0, err
		}

		lifecycle := item.Lifecycle
		if lifecycle == "" {
			lifecycle = cur.Lifecycle
		}
		if !validLifecycles[lifecycle] {
			return 0, fmt.Errorf("asset %s: lifecycle must be active or retired", item.AssetKey)
		}
		env := item.Environment
		if env == "" {
			env = cur.Environment
		}
		businessUnit := item.BusinessUnit
		if businessUnit == "" {
			businessUnit = cur.BusinessUnit
		}
		owner := item.Owner
		if owner == "" {
			owner = cur.Owner
		}
		tags := item.Tags
		if tags == nil {
			tags = cur.Tags
		}
		seen := map[string]bool{}
		var cleanTags []string
		for _, t := range tags {
			t = strings.TrimSpace(t)
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			cleanTags = append(cleanTags, t)
		}

		oldMeta, _ := json.Marshal(map[string]interface{}{
			"environment": cur.Environment, "business_unit": cur.BusinessUnit,
			"owner": cur.Owner, "lifecycle": cur.Lifecycle, "tags": cur.Tags,
		})
		newMeta, _ := json.Marshal(map[string]interface{}{
			"environment": env, "business_unit": businessUnit,
			"owner": owner, "lifecycle": lifecycle, "tags": cleanTags,
		})

		if _, err := tx.Exec(ctx, `
			UPDATE assets SET environment=$2, business_unit=$3, owner=$4, lifecycle=$5,
				tags=$6, updated_at=NOW()
			WHERE asset_key=$1
		`, item.AssetKey, env, businessUnit, owner, lifecycle, cleanTags); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO asset_changes (agent_id, change_type, asset_name, old_version, new_version,
				format, detected_at, asset_key, change_source, actor)
			VALUES ($1,'meta_update',$2,$3,$4,'meta',NOW(),$5,'api',$6)
		`, cur.AgentID, cur.Name, string(oldMeta), string(newMeta), item.AssetKey, actor); err != nil {
			return 0, err
		}
		updated++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return updated, nil
}

func (s *Store) ListAssetChanges(ctx context.Context, assetKey string, limit int) ([]AssetChange, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT agent_id, asset_name, old_version, new_version, format, detected_at,
			asset_key, change_source, actor
		FROM asset_changes WHERE asset_key=$1 ORDER BY detected_at DESC LIMIT $2
	`, assetKey, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AssetChange
	for rows.Next() {
		var c AssetChange
		if err := rows.Scan(&c.AgentID, &c.AssetName, &c.OldVersion, &c.NewVersion,
			&c.Format, &c.DetectedAt, &c.AssetKey, &c.ChangeSource, &c.Actor); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) ListAssetRelations(ctx context.Context, assetKey string) ([]AssetRelation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT parent_key, child_key, relation_type, created_at
		FROM asset_relations WHERE parent_key=$1 OR child_key=$1
		ORDER BY relation_type, child_key
	`, assetKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AssetRelation
	for rows.Next() {
		var r AssetRelation
		if err := rows.Scan(&r.ParentKey, &r.ChildKey, &r.RelationType, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) AssetSummary(ctx context.Context) ([]AssetSummaryRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT asset_type, environment, lifecycle, COUNT(*)
		FROM assets GROUP BY 1,2,3 ORDER BY asset_type, environment, lifecycle
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AssetSummaryRow
	for rows.Next() {
		var r AssetSummaryRow
		if err := rows.Scan(&r.AssetType, &r.Environment, &r.Lifecycle, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AssetMetaByAgent returns aggregated tags (union) and the first non-empty
// environment per software asset name for an agent.
func (s *Store) AssetMetaByAgent(ctx context.Context, agentID string) (map[string]AssetMeta, error) {
	out := map[string]AssetMeta{}

	envRows, err := s.pool.Query(ctx, `
		SELECT name, MAX(environment)
		FROM assets WHERE agent_id=$1 AND asset_type='software' AND lifecycle='active'
		  AND environment <> ''
		GROUP BY name
	`, agentID)
	if err != nil {
		return nil, err
	}
	for envRows.Next() {
		var name, env string
		if err := envRows.Scan(&name, &env); err != nil {
			envRows.Close()
			return nil, err
		}
		m := out[name]
		m.Environment = env
		out[name] = m
	}
	envRows.Close()
	if err := envRows.Err(); err != nil {
		return nil, err
	}

	tagRows, err := s.pool.Query(ctx, `
		SELECT a.name, t
		FROM assets a, unnest(a.tags) AS t
		WHERE a.agent_id=$1 AND a.asset_type='software' AND a.lifecycle='active'
	`, agentID)
	if err != nil {
		return nil, err
	}
	for tagRows.Next() {
		var name, tag string
		if err := tagRows.Scan(&name, &tag); err != nil {
			tagRows.Close()
			return nil, err
		}
		m := out[name]
		if !containsString(m.Tags, tag) {
			m.Tags = append(m.Tags, tag)
		}
		out[name] = m
	}
	tagRows.Close()
	return out, tagRows.Err()
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
