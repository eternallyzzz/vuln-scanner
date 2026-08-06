package store

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"vuln-scanner/internal/cloudscan"
)

// CloudAccount is one cloud provider account whose credentials are stored
// as AES-GCM ciphertext.
type CloudAccount struct {
	ID                     int64      `json:"id"`
	Provider               string     `json:"provider"`
	Name                   string     `json:"name"`
	AccountID              string     `json:"account_id"`
	Regions                []string   `json:"regions"`
	CredentialCiphertext   string     `json:"-"`
	Enabled                bool       `json:"enabled"`
	RefreshIntervalMinutes int        `json:"refresh_interval_minutes"`
	LastRefreshAt          *time.Time `json:"last_refresh_at,omitempty"`
	LastError              string     `json:"last_error,omitempty"`
	CreatedBy              string     `json:"created_by"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

// CloudResource is one discovered cloud resource.
type CloudResource struct {
	ID           int64             `json:"id"`
	AccountID    int64             `json:"account_id"`
	Provider     string            `json:"provider"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	Name         string            `json:"name"`
	Region       string            `json:"region"`
	Status       string            `json:"status"`
	Tags         map[string]string `json:"tags"`
	Metadata     json.RawMessage   `json:"metadata"`
	AssetKey     string            `json:"asset_key"`
	FirstSeen    time.Time         `json:"first_seen"`
	LastSeen     time.Time         `json:"last_seen"`
}

const cloudAccountColumns = `id, provider, name, account_id, regions,
	credential_ciphertext, enabled, refresh_interval_minutes, last_refresh_at,
	last_error, created_by, created_at, updated_at`

const cloudResourceColumns = `id, account_id, provider, resource_type, resource_id,
	name, region, status, tags, metadata, asset_key, first_seen, last_seen`

func scanCloudAccount(row pgx.Row) (*CloudAccount, error) {
	var a CloudAccount
	if err := row.Scan(&a.ID, &a.Provider, &a.Name, &a.AccountID, &a.Regions,
		&a.CredentialCiphertext, &a.Enabled, &a.RefreshIntervalMinutes,
		&a.LastRefreshAt, &a.LastError, &a.CreatedBy, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return nil, err
	}
	return &a, nil
}

func scanCloudResource(row pgx.Row) (*CloudResource, error) {
	var r CloudResource
	var tagsRaw, metaRaw []byte
	if err := row.Scan(&r.ID, &r.AccountID, &r.Provider, &r.ResourceType, &r.ResourceID,
		&r.Name, &r.Region, &r.Status, &tagsRaw, &metaRaw, &r.AssetKey,
		&r.FirstSeen, &r.LastSeen); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(tagsRaw, &r.Tags)
	r.Metadata = json.RawMessage(metaRaw)
	return &r, nil
}

func (s *Store) CreateCloudAccount(ctx context.Context, provider, name, accountID string,
	regions []string, credCipher string, refreshMinutes int, createdBy string) (*CloudAccount, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO cloud_accounts (provider, name, account_id, regions, credential_ciphertext, refresh_interval_minutes, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING `+cloudAccountColumns,
		provider, name, accountID, regions, credCipher, refreshMinutes, createdBy)
	return scanCloudAccount(row)
}

func (s *Store) ListCloudAccounts(ctx context.Context) ([]CloudAccount, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+cloudAccountColumns+` FROM cloud_accounts ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CloudAccount
	for rows.Next() {
		a, err := scanCloudAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (s *Store) GetCloudAccount(ctx context.Context, id int64) (*CloudAccount, error) {
	return scanCloudAccount(s.pool.QueryRow(ctx,
		`SELECT `+cloudAccountColumns+` FROM cloud_accounts WHERE id=$1`, id))
}

func (s *Store) UpdateCloudAccount(ctx context.Context, id int64, name string,
	regions []string, refreshMinutes int, enabled bool, credCipher string) (*CloudAccount, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE cloud_accounts
		SET name=$2, regions=$3, refresh_interval_minutes=$4, enabled=$5,
			credential_ciphertext=$6, updated_at=NOW()
		WHERE id=$1
		RETURNING `+cloudAccountColumns,
		id, name, regions, refreshMinutes, enabled, credCipher)
	return scanCloudAccount(row)
}

func (s *Store) DisableCloudAccount(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE cloud_accounts SET enabled=FALSE, updated_at=NOW() WHERE id=$1`, id)
	return err
}

func (s *Store) CloudAccountsDue(ctx context.Context, now time.Time) ([]CloudAccount, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+cloudAccountColumns+`
		FROM cloud_accounts
		WHERE enabled AND (last_refresh_at IS NULL OR
			last_refresh_at + (refresh_interval_minutes * interval '1 minute') <= $1)
		ORDER BY id`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CloudAccount
	for rows.Next() {
		a, err := scanCloudAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (s *Store) MarkCloudAccountRefreshed(ctx context.Context, id int64, errText string) error {
	if errText == "" {
		_, err := s.pool.Exec(ctx, `
			UPDATE cloud_accounts SET last_refresh_at=NOW(), last_error='', updated_at=NOW()
			WHERE id=$1`, id)
		return err
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE cloud_accounts SET last_error=$2, updated_at=NOW() WHERE id=$1`, id, errText)
	return err
}

func (s *Store) UpsertCloudResources(ctx context.Context, accountID int64, accountKey, provider string, resources []cloudscan.Resource) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	ids := make([]int64, 0, len(resources))
	for _, r := range resources {
		tags, _ := json.Marshal(r.Tags)
		meta, _ := json.Marshal(r.Metadata)
		assetKey := CloudAssetKey(provider, accountKey, r.Type, r.ID)
		var id int64
		if err := tx.QueryRow(ctx, `
			INSERT INTO cloud_resources (account_id, provider, resource_type, resource_id,
				name, region, status, tags, metadata, asset_key)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (account_id, resource_type, resource_id) DO UPDATE
			SET name=EXCLUDED.name, region=EXCLUDED.region, status=EXCLUDED.status,
				tags=EXCLUDED.tags, metadata=EXCLUDED.metadata, asset_key=EXCLUDED.asset_key,
				last_seen=NOW()
			RETURNING id
		`, accountID, provider, r.Type, r.ID, r.Name, r.Region, r.Status,
			tags, meta, assetKey).Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if len(ids) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE cloud_resources SET status='retired', last_seen=NOW()
			WHERE account_id=$1 AND status<>'retired' AND id <> ALL($2::bigint[])
		`, accountID, ids); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(ctx, `
			UPDATE cloud_resources SET status='retired', last_seen=NOW()
			WHERE account_id=$1 AND status<>'retired'
		`, accountID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) ListCloudResources(ctx context.Context, f CloudResourceFilter) ([]CloudResource, int64, error) {
	where := ""
	args := []interface{}{}
	add := func(expr string, v interface{}) {
		args = append(args, v)
		where += fmt.Sprintf(" AND %s", fmt.Sprintf(expr, len(args)))
	}
	if f.Provider != "" {
		add("provider=$%d", f.Provider)
	}
	if f.AccountID != 0 {
		add("account_id=$%d", f.AccountID)
	}
	if f.ResourceType != "" {
		add("resource_type=$%d", f.ResourceType)
	}
	if f.Region != "" {
		add("region=$%d", f.Region)
	}
	if f.Status != "" {
		add("status=$%d", f.Status)
	}
	if f.Q != "" {
		add("name ILIKE '%%' || $%d || '%%'", f.Q)
	}
	if f.TenantID != nil {
		add("EXISTS (SELECT 1 FROM assets at JOIN agents ag ON ag.id=at.agent_id "+
			"WHERE at.asset_key=cloud_resources.asset_key AND ag.tenant_id=$%d)", *f.TenantID)
	}
	if where != "" {
		where = " WHERE " + where[5:]
	}
	var total int64
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM cloud_resources"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit, offset := f.Limit, f.Offset
	if limit <= 0 || limit > 10000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)
	rows, err := s.pool.Query(ctx, `
		SELECT `+cloudResourceColumns+` FROM cloud_resources`+where+
		fmt.Sprintf(" ORDER BY last_seen DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []CloudResource
	for rows.Next() {
		r, err := scanCloudResource(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *r)
	}
	return out, total, rows.Err()
}

// CloudResourceFilter narrows the cloud resource list.
type CloudResourceFilter struct {
	Provider     string
	AccountID    int64
	ResourceType string
	Region       string
	Status       string
	Q            string
	TenantID     *int64
	Limit        int
	Offset       int
}

func CloudAgentID(provider, accountID string) string {
	h := sha1.Sum([]byte(provider + ":" + accountID))
	return "agent-cloud-" + hex.EncodeToString(h[:])[:12]
}

func CloudAssetKey(provider, accountID, resourceType, resourceID string) string {
	h := sha1.Sum([]byte(provider + "\x00" + accountID + "\x00" + resourceType + "\x00" + resourceID))
	return "cloud:" + provider + ":" + hex.EncodeToString(h[:])[:16]
}

func (s *Store) UpsertCloudAgent(ctx context.Context, provider, accountID, name string) error {
	id := CloudAgentID(provider, accountID)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agents (id, hostname, os_type, os_version, status)
		VALUES ($1,$2,$3,'', 'active')
		ON CONFLICT (id) DO UPDATE SET hostname=$2, status='active', updated_at=NOW()
	`, id, name, provider)
	return err
}

func (s *Store) SyncCloudCMDB(ctx context.Context, account CloudAccount, resources []cloudscan.Resource) error {
	agentID := CloudAgentID(account.Provider, account.AccountID)
	if err := s.UpsertCloudAgent(ctx, account.Provider, account.AccountID, account.Name); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	now := time.Now()
	keys := make([]string, 0, len(resources))
	var changes []assetChangeRecord
	for _, r := range resources {
		key := CloudAssetKey(account.Provider, account.AccountID, r.Type, r.ID)
		keys = append(keys, key)
		assetType := cloudAssetType(r.Type)
		lifecycle := "active"
		if r.Status == "retired" {
			lifecycle = "retired"
		}
		var prev string
		if err := tx.QueryRow(ctx, `SELECT lifecycle FROM assets WHERE asset_key=$1`, key).Scan(&prev); err != nil {
			if err != pgx.ErrNoRows {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO assets (asset_key, asset_type, name, location, agent_id, lifecycle,
				environment, tags, first_seen, last_seen, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW(),NOW(),NOW())
			ON CONFLICT (asset_key) DO UPDATE
			SET name=EXCLUDED.name, location=EXCLUDED.location, lifecycle=EXCLUDED.lifecycle,
				environment=EXCLUDED.environment, tags=EXCLUDED.tags, last_seen=NOW(), updated_at=NOW()
		`, key, assetType, r.Name, r.Region, agentID, lifecycle,
			r.Tags["environment"], tagSlice(r.Tags)); err != nil {
			return err
		}
		if prev == "" {
			changes = append(changes, assetChangeRecord{
				Key: key, Name: r.Name, Old: "", New: lifecycle, ChangeType: "added",
			})
		} else if prev != lifecycle {
			changes = append(changes, assetChangeRecord{
				Key: key, Name: r.Name, Old: prev, New: lifecycle, ChangeType: "updated",
			})
		}
	}
	if len(keys) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE assets SET lifecycle='retired', updated_at=NOW()
			WHERE agent_id=$1 AND asset_type IN ('cloud_instance','cloud_storage','cloud_database')
			  AND lifecycle='active' AND asset_key <> ALL($2::text[])
		`, agentID, keys); err != nil {
			return err
		}
	}
	if len(changes) > 0 {
		if err := insertAssetChangesTx(ctx, tx, agentID, changes, now, "cloud", "cloud-worker"); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func cloudAssetType(resourceType string) string {
	switch resourceType {
	case "ec2_instance", "azure_vm", "gcp_instance":
		return "cloud_instance"
	case "s3_bucket", "azure_storage", "gcp_bucket":
		return "cloud_storage"
	case "rds_instance", "azure_sql", "gcp_sql":
		return "cloud_database"
	default:
		return "cloud_resource"
	}
}

func tagSlice(tags map[string]string) []string {
	out := make([]string, 0, len(tags))
	for k, v := range tags {
		out = append(out, k+"="+v)
	}
	return out
}
