package store

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	// ErrRemoteCredentialNotFound is returned when a credential id does not
	// exist (or is already revoked for task creation).
	ErrRemoteCredentialNotFound = errors.New("remote credential not found")
	// ErrRemoteCredentialRevoked is returned when creating tasks with a
	// revoked credential.
	ErrRemoteCredentialRevoked = errors.New("remote credential revoked")
)

// RemoteCredential is one stored remote login. Secret fields hold AES-GCM
// ciphertext and are never exposed by the API.
type RemoteCredential struct {
	ID                   int64      `json:"id"`
	TenantID             int64      `json:"tenant_id"`
	Name                 string     `json:"name"`
	Username             string     `json:"username"`
	AuthType             string     `json:"auth_type"`
	PasswordCiphertext   string     `json:"-"`
	PrivateKeyCiphertext string     `json:"-"`
	PassphraseCiphertext string     `json:"-"`
	CreatedBy            string     `json:"created_by"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	RevokedAt            *time.Time `json:"revoked_at"`
}

// RemoteHost is one successfully collected remote target.
type RemoteHost struct {
	ID           int64     `json:"id"`
	Address      string    `json:"address"`
	CredentialID int64     `json:"credential_id"`
	HostKey      string    `json:"-"`
	AgentID      string    `json:"agent_id"`
	Hostname     string    `json:"hostname"`
	OSType       string    `json:"os_type"`
	OSVersion    string    `json:"os_version"`
	Arch         string    `json:"arch"`
	PackageCount int       `json:"package_count"`
	Status       string    `json:"status"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

// RemoteScanTask is one server-side SSH collection run.
type RemoteScanTask struct {
	ID            int64           `json:"id"`
	CredentialID  int64           `json:"credential_id"`
	Address       string          `json:"address"`
	Status        string          `json:"status"`
	CreatedBy     string          `json:"created_by"`
	Error         string          `json:"error"`
	ResultSummary json.RawMessage `json:"result_summary"`
	CreatedAt     time.Time       `json:"created_at"`
	StartedAt     *time.Time      `json:"started_at"`
	FinishedAt    *time.Time      `json:"finished_at"`
}

const remoteCredentialColumns = `id, tenant_id, name, username, auth_type, password_ciphertext, private_key_ciphertext, passphrase_ciphertext, created_by, created_at, updated_at, revoked_at`

const remoteTaskColumns = `id, credential_id, address, status, created_by, error, COALESCE(result_summary, '{}'), created_at, started_at, finished_at`

const remoteHostColumns = `id, address, credential_id, agent_id, hostname, os_type, os_version, arch, package_count, status, first_seen, last_seen`

func scanRemoteCredential(row interface{ Scan(...interface{}) error }) (*RemoteCredential, error) {
	var c RemoteCredential
	if err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.Username, &c.AuthType,
		&c.PasswordCiphertext, &c.PrivateKeyCiphertext, &c.PassphraseCiphertext,
		&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &c.RevokedAt); err != nil {
		return nil, err
	}
	return &c, nil
}

func scanRemoteTask(row interface{ Scan(...interface{}) error }) (*RemoteScanTask, error) {
	var t RemoteScanTask
	var summary []byte
	if err := row.Scan(&t.ID, &t.CredentialID, &t.Address, &t.Status, &t.CreatedBy,
		&t.Error, &summary, &t.CreatedAt, &t.StartedAt, &t.FinishedAt); err != nil {
		return nil, err
	}
	t.ResultSummary = json.RawMessage(summary)
	return &t, nil
}

// CreateRemoteCredential stores an encrypted credential for one tenant.
func (s *Store) CreateRemoteCredential(ctx context.Context, tenantID int64, name, username, authType, passwordCipher, keyCipher, passCipher, createdBy string) (*RemoteCredential, error) {
	if tenantID <= 0 {
		tenantID = 1
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO remote_credentials (tenant_id, name, username, auth_type, password_ciphertext, private_key_ciphertext, passphrase_ciphertext, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING `+remoteCredentialColumns,
		tenantID, name, username, authType, passwordCipher, keyCipher, passCipher, createdBy)
	return scanRemoteCredential(row)
}

// GetRemoteCredential returns one credential including ciphertext for the
// scan worker. ErrRemoteCredentialNotFound is returned for unknown ids.
func (s *Store) GetRemoteCredential(ctx context.Context, id int64) (*RemoteCredential, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+remoteCredentialColumns+` FROM remote_credentials WHERE id=$1`, id)
	c, err := scanRemoteCredential(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRemoteCredentialNotFound
	}
	return c, err
}

// ListRemoteCredentials returns credentials (optionally scoped to one
// tenant) without filtering revoked ones; the API masks secret fields and
// exposes revoked_at.
func (s *Store) ListRemoteCredentials(ctx context.Context, tenantID *int64) ([]RemoteCredential, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+remoteCredentialColumns+` FROM remote_credentials
		WHERE ($1::bigint IS NULL OR tenant_id=$1)
		ORDER BY id DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RemoteCredential
	for rows.Next() {
		c, err := scanRemoteCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// UpdateRemoteCredential rewrites metadata and ciphertexts. Unknown ids
// return ErrRemoteCredentialNotFound.
func (s *Store) UpdateRemoteCredential(ctx context.Context, id int64, name, username, passwordCipher, keyCipher, passCipher string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE remote_credentials
		SET name=$2, username=$3, password_ciphertext=$4, private_key_ciphertext=$5,
			passphrase_ciphertext=$6, updated_at=NOW()
		WHERE id=$1
	`, id, name, username, passwordCipher, keyCipher, passCipher)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRemoteCredentialNotFound
	}
	return nil
}

// RevokeRemoteCredential soft-deletes a credential so no new tasks can be
// created while history stays intact.
func (s *Store) RevokeRemoteCredential(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE remote_credentials SET revoked_at=NOW(), updated_at=NOW()
		WHERE id=$1 AND revoked_at IS NULL`, id)
	return err
}

// CreateRemoteScanTasks validates the credential and inserts one pending task
// per target. Unknown or revoked credentials are rejected.
func (s *Store) CreateRemoteScanTasks(ctx context.Context, credentialID int64, targets []string, createdBy string) ([]RemoteScanTask, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var revokedAt *time.Time
	err = tx.QueryRow(ctx, `SELECT revoked_at FROM remote_credentials WHERE id=$1`, credentialID).Scan(&revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRemoteCredentialNotFound
	}
	if err != nil {
		return nil, err
	}
	if revokedAt != nil {
		return nil, ErrRemoteCredentialRevoked
	}

	var tasks []RemoteScanTask
	for _, target := range targets {
		row := tx.QueryRow(ctx, `
			INSERT INTO remote_scan_tasks (credential_id, address, created_by)
			VALUES ($1,$2,$3)
			RETURNING `+remoteTaskColumns,
			credentialID, target, createdBy)
		t, err := scanRemoteTask(row)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, *t)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return tasks, nil
}

// ClaimRemoteScanTasks atomically claims pending tasks for the server-side
// worker. limit is capped at 64 (the maximum configured concurrency).
func (s *Store) ClaimRemoteScanTasks(ctx context.Context, limit int) ([]RemoteScanTask, error) {
	if limit <= 0 || limit > 64 {
		limit = 8
	}
	rows, err := s.pool.Query(ctx, `
		UPDATE remote_scan_tasks
		SET status='running', started_at=NOW()
		WHERE id IN (
			SELECT id FROM remote_scan_tasks
			WHERE status='pending'
			ORDER BY id
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING `+remoteTaskColumns,
		limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tasks []RemoteScanTask
	for rows.Next() {
		t, err := scanRemoteTask(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, *t)
	}
	return tasks, rows.Err()
}

// CompleteRemoteScanTask marks a task done or failed with a summary.
func (s *Store) CompleteRemoteScanTask(ctx context.Context, id int64, scanErr string, summary json.RawMessage) error {
	if len(summary) == 0 {
		summary = json.RawMessage(`{}`)
	}
	status := "done"
	if scanErr != "" {
		status = "failed"
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE remote_scan_tasks
		SET status=$2, error=$3, result_summary=$4, finished_at=NOW()
		WHERE id=$1
	`, id, status, scanErr, string(summary))
	return err
}

// ListRemoteScanTasks returns tasks newest first with optional status and
// tenant filters.
func (s *Store) ListRemoteScanTasks(ctx context.Context, status string, limit, offset int, tenantID *int64) ([]RemoteScanTask, int64, error) {
	where := ""
	args := []interface{}{}
	if status != "" {
		where = " WHERE status=$1"
		args = append(args, status)
	}
	if tenantID != nil {
		if where == "" {
			where = " WHERE "
		} else {
			where += " AND "
		}
		args = append(args, *tenantID)
		where += fmt.Sprintf("EXISTS (SELECT 1 FROM remote_credentials rc WHERE rc.id=remote_scan_tasks.credential_id AND rc.tenant_id=$%d)", len(args))
	}
	var total int64
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM remote_scan_tasks`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT ` + remoteTaskColumns + ` FROM remote_scan_tasks` + where +
		` ORDER BY id DESC LIMIT $` + fmt.Sprint(len(args)+1) + ` OFFSET $` + fmt.Sprint(len(args)+2)
	args = append(args, limit, offset)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []RemoteScanTask
	for rows.Next() {
		t, err := scanRemoteTask(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *t)
	}
	return out, total, rows.Err()
}

// RemoteAgentID derives the stable synthetic agent id for one address.
func RemoteAgentID(address string) string {
	h := sha1.Sum([]byte(address))
	return "agent-ssh-" + hex.EncodeToString(h[:])[:12]
}

// GetRemoteHostKey returns the stored marshaled host public key (nil when
// unknown) for trust-on-first-use verification.
func (s *Store) GetRemoteHostKey(ctx context.Context, address string, credentialID int64) ([]byte, error) {
	var raw string
	err := s.pool.QueryRow(ctx, `
		SELECT host_key FROM remote_hosts WHERE address=$1 AND credential_id=$2`,
		address, credentialID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(raw)
}

// PutRemoteHostKey stores a marshaled host public key after a successful
// authenticated collection.
func (s *Store) PutRemoteHostKey(ctx context.Context, address string, credentialID int64, key []byte) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO remote_hosts (address, credential_id, host_key)
		VALUES ($1,$2,$3)
		ON CONFLICT (address, credential_id) DO UPDATE SET host_key=$3
	`, address, credentialID, base64.StdEncoding.EncodeToString(key))
	return err
}

// UpsertRemoteHost records the latest successful collection for an address.
func (s *Store) UpsertRemoteHost(ctx context.Context, h RemoteHost) error {
	if h.OSType == "" {
		h.OSType = "unknown"
	}
	if h.Status == "" {
		h.Status = "active"
	}
	agentID := RemoteAgentID(h.Address)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO remote_hosts (address, credential_id, agent_id, hostname, os_type, os_version, arch, package_count, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (address, credential_id) DO UPDATE
		SET agent_id=$3, hostname=$4, os_type=$5, os_version=$6, arch=$7,
			package_count=$8, status=$9, last_seen=NOW(), updated_at=NOW()
	`, h.Address, h.CredentialID, agentID, h.Hostname, h.OSType, h.OSVersion,
		h.Arch, h.PackageCount, h.Status)
	return err
}

// ListRemoteHosts returns collected hosts newest first.
func (s *Store) ListRemoteHosts(ctx context.Context, limit, offset int, tenantID *int64) ([]RemoteHost, int64, error) {
	var total int64
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM remote_hosts
		WHERE ($1::bigint IS NULL OR EXISTS (
			SELECT 1 FROM agents a WHERE a.id=remote_hosts.agent_id AND a.tenant_id=$1))
	`, tenantID).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+remoteHostColumns+` FROM remote_hosts
		WHERE ($1::bigint IS NULL OR EXISTS (
			SELECT 1 FROM agents a WHERE a.id=remote_hosts.agent_id AND a.tenant_id=$1))
		ORDER BY last_seen DESC, address
		LIMIT $2 OFFSET $3
	`, tenantID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []RemoteHost
	for rows.Next() {
		var h RemoteHost
		if err := rows.Scan(&h.ID, &h.Address, &h.CredentialID, &h.AgentID, &h.Hostname,
			&h.OSType, &h.OSVersion, &h.Arch, &h.PackageCount, &h.Status,
			&h.FirstSeen, &h.LastSeen); err != nil {
			return nil, 0, err
		}
		out = append(out, h)
	}
	return out, total, rows.Err()
}

// UpsertRemoteAgent creates or refreshes the synthetic agent carrying one
// remote host's match results. Tenant is set on first creation only.
func (s *Store) UpsertRemoteAgent(ctx context.Context, id, hostname, address, osType, osVersion, arch string, tenantID int64) error {
	if osType == "" {
		osType = "unknown"
	}
	if tenantID <= 0 {
		tenantID = 1
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agents (id, hostname, os_type, os_version, arch, agent_ver, ip,
			token_hash, status, fingerprint_hash, tenant_id, last_seen, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,'remote-scanner',$6,'','online','',$7,NOW(),NOW(),NOW())
		ON CONFLICT (id) DO UPDATE
		SET hostname=$2, os_type=$3, os_version=$4, arch=$5, ip=$6,
			status='online', last_seen=NOW(), updated_at=NOW()
	`, id, hostname, osType, osVersion, arch, address, tenantID)
	return err
}
