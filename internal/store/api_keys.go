package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// APIKey is a tenant-scoped (or global) automation credential. Only the
// SHA-256 hash is persisted; plaintext keys are shown once at creation.
type APIKey struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	KeyHash    string     `json:"-"`
	TenantID   *int64     `json:"tenant_id,omitempty"`
	Enabled    bool       `json:"enabled"`
	CreatedBy  string     `json:"created_by"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

const apiKeyColumns = `id, name, key_hash, tenant_id, enabled, created_by,
	last_used_at, revoked_at, created_at, updated_at`

func scanAPIKey(row pgx.Row) (*APIKey, error) {
	var k APIKey
	if err := row.Scan(&k.ID, &k.Name, &k.KeyHash, &k.TenantID, &k.Enabled,
		&k.CreatedBy, &k.LastUsedAt, &k.RevokedAt, &k.CreatedAt, &k.UpdatedAt); err != nil {
		return nil, err
	}
	return &k, nil
}

func scanAPIKeys(rows pgx.Rows) ([]APIKey, error) {
	var out []APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

// GenerateAPIKey returns a new random API key with a recognizable prefix.
func GenerateAPIKey() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "vsk_" + hex.EncodeToString(raw), nil
}

// HashAPIKey returns the SHA-256 hex digest used for lookup and storage.
func HashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// CreateAPIKey stores a new key and returns it together with the plaintext
// value. The plaintext is never persisted or returned again.
func (s *Store) CreateAPIKey(ctx context.Context, name string, tenantID *int64, createdBy string) (APIKey, string, error) {
	if tenantID != nil && *tenantID <= 0 {
		tenantID = nil
	}
	plain, err := GenerateAPIKey()
	if err != nil {
		return APIKey{}, "", err
	}
	hash := HashAPIKey(plain)
	row := s.pool.QueryRow(ctx, `
		INSERT INTO api_keys (name, key_hash, tenant_id, created_by)
		VALUES ($1,$2,$3,$4)
		RETURNING `+apiKeyColumns,
		name, hash, tenantID, createdBy)
	k, err := scanAPIKey(row)
	if err != nil {
		return APIKey{}, "", err
	}
	return *k, plain, nil
}

// GetAPIKeyByHash returns one key row by its hash, including revoked keys so
// the auth middleware can distinguish them from unknown keys.
func (s *Store) GetAPIKeyByHash(ctx context.Context, hash string) (*APIKey, error) {
	k, err := scanAPIKey(s.pool.QueryRow(ctx, `
		SELECT `+apiKeyColumns+` FROM api_keys WHERE key_hash=$1
	`, hash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return k, err
}

// GetAPIKey returns one key row by id.
func (s *Store) GetAPIKey(ctx context.Context, id int64) (*APIKey, error) {
	return scanAPIKey(s.pool.QueryRow(ctx, `
		SELECT `+apiKeyColumns+` FROM api_keys WHERE id=$1
	`, id))
}

// ListAPIKeys returns keys, optionally scoped to one tenant. A non-nil
// tenant id includes only that tenant; nil includes global + all tenants.
func (s *Store) ListAPIKeys(ctx context.Context, tenantID *int64) ([]APIKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+apiKeyColumns+` FROM api_keys
		WHERE ($1::bigint IS NULL OR tenant_id=$1)
		ORDER BY id DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAPIKeys(rows)
}

// RevokeAPIKey soft-revokes one key.
func (s *Store) RevokeAPIKey(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE api_keys SET revoked_at=NOW(), updated_at=NOW()
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

// TouchAPIKeyLastUsed records the last successful use of a key.
func (s *Store) TouchAPIKeyLastUsed(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE api_keys SET last_used_at=NOW(), updated_at=NOW() WHERE id=$1
	`, id)
	return err
}
