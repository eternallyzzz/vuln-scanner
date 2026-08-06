package store

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	// ErrWebDBCredentialNotFound is returned when a credential id does not
	// exist (or is already revoked for task creation).
	ErrWebDBCredentialNotFound = errors.New("webdb credential not found")
	// ErrWebDBCredentialRevoked is returned when creating tasks with a
	// revoked credential.
	ErrWebDBCredentialRevoked = errors.New("webdb credential revoked")
)

// WebDBCredential is one stored web/database login. Secret fields hold
// AES-GCM ciphertext and are never exposed by the API.
type WebDBCredential struct {
	ID                 int64      `json:"id"`
	Name               string     `json:"name"`
	Username           string     `json:"username"`
	PasswordCiphertext string     `json:"-"`
	CreatedBy          string     `json:"created_by"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	RevokedAt          *time.Time `json:"revoked_at"`
}

// WebDBTaskInput is one scan task to create (web or db).
type WebDBTaskInput struct {
	Kind         string
	Target       string
	DBType       string
	CredentialID int64
}

// WebDBTask is one server-side web/database scan run.
type WebDBTask struct {
	ID            int64           `json:"id"`
	Kind          string          `json:"kind"`
	Target        string          `json:"target"`
	DBType        string          `json:"db_type"`
	CredentialID  int64           `json:"credential_id"`
	Status        string          `json:"status"`
	CreatedBy     string          `json:"created_by"`
	Error         string          `json:"error"`
	ResultSummary json.RawMessage `json:"result_summary"`
	CreatedAt     time.Time       `json:"created_at"`
	StartedAt     *time.Time      `json:"started_at"`
	FinishedAt    *time.Time      `json:"finished_at"`
}

// WebDBTarget is one known web/database service with its latest fingerprint.
type WebDBTarget struct {
	ID           int64           `json:"id"`
	Kind         string          `json:"kind"`
	Target       string          `json:"target"`
	DBType       string          `json:"db_type"`
	CredentialID int64           `json:"credential_id"`
	AgentID      string          `json:"agent_id"`
	Status       string          `json:"status"`
	Title        string          `json:"title"`
	Detail       json.RawMessage `json:"detail"`
	FirstSeen    time.Time       `json:"first_seen"`
	LastSeen     time.Time       `json:"last_seen"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

const webDBCredentialColumns = `id, name, username, password_ciphertext, created_by, created_at, updated_at, revoked_at`

const webDBTaskColumns = `id, kind, target, db_type, COALESCE(credential_id, 0), status, created_by, error, COALESCE(result_summary, '{}'), created_at, started_at, finished_at`

const webDBTargetColumns = `id, kind, target, db_type, credential_id, agent_id, status, title, COALESCE(detail, '{}'), first_seen, last_seen, updated_at`

func scanWebDBCredential(row interface{ Scan(...interface{}) error }) (*WebDBCredential, error) {
	var c WebDBCredential
	if err := row.Scan(&c.ID, &c.Name, &c.Username, &c.PasswordCiphertext,
		&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &c.RevokedAt); err != nil {
		return nil, err
	}
	return &c, nil
}

func scanWebDBTask(row interface{ Scan(...interface{}) error }) (*WebDBTask, error) {
	var t WebDBTask
	var summary []byte
	if err := row.Scan(&t.ID, &t.Kind, &t.Target, &t.DBType, &t.CredentialID, &t.Status,
		&t.CreatedBy, &t.Error, &summary, &t.CreatedAt, &t.StartedAt, &t.FinishedAt); err != nil {
		return nil, err
	}
	t.ResultSummary = json.RawMessage(summary)
	return &t, nil
}

// CreateWebDBCredential stores an encrypted credential.
func (s *Store) CreateWebDBCredential(ctx context.Context, name, username, passwordCipher, createdBy string) (*WebDBCredential, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO webdb_credentials (name, username, password_ciphertext, created_by)
		VALUES ($1,$2,$3,$4)
		RETURNING `+webDBCredentialColumns,
		name, username, passwordCipher, createdBy)
	return scanWebDBCredential(row)
}

// GetWebDBCredential returns one credential including ciphertext for the
// scan worker. ErrWebDBCredentialNotFound is returned for unknown ids.
func (s *Store) GetWebDBCredential(ctx context.Context, id int64) (*WebDBCredential, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+webDBCredentialColumns+` FROM webdb_credentials WHERE id=$1`, id)
	c, err := scanWebDBCredential(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrWebDBCredentialNotFound
	}
	return c, err
}

// ListWebDBCredentials returns all credentials without filtering revoked
// ones; the API masks secret fields and exposes revoked_at.
func (s *Store) ListWebDBCredentials(ctx context.Context) ([]WebDBCredential, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+webDBCredentialColumns+` FROM webdb_credentials ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WebDBCredential
	for rows.Next() {
		c, err := scanWebDBCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// UpdateWebDBCredential rewrites metadata and the password ciphertext.
// Unknown ids return ErrWebDBCredentialNotFound.
func (s *Store) UpdateWebDBCredential(ctx context.Context, id int64, name, username, passwordCipher string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE webdb_credentials
		SET name=$2, username=$3, password_ciphertext=$4, updated_at=NOW()
		WHERE id=$1
	`, id, name, username, passwordCipher)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrWebDBCredentialNotFound
	}
	return nil
}

// RevokeWebDBCredential soft-deletes a credential so no new tasks can be
// created while history stays intact.
func (s *Store) RevokeWebDBCredential(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE webdb_credentials SET revoked_at=NOW(), updated_at=NOW()
		WHERE id=$1 AND revoked_at IS NULL`, id)
	return err
}

// CreateWebDBScanTasks validates optional credentials and inserts one pending
// task per input. Unknown or revoked credentials are rejected.
func (s *Store) CreateWebDBScanTasks(ctx context.Context, inputs []WebDBTaskInput, createdBy string) ([]WebDBTask, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	checked := map[int64]*time.Time{}
	var tasks []WebDBTask
	for _, in := range inputs {
		kind := strings.ToLower(strings.TrimSpace(in.Kind))
		if kind != "web" && kind != "db" {
			return nil, fmt.Errorf("kind must be web or db")
		}
		if kind == "db" && strings.TrimSpace(in.DBType) == "" {
			return nil, fmt.Errorf("db_type is required for db tasks")
		}
		if in.CredentialID > 0 {
			revoked, ok := checked[in.CredentialID]
			if !ok {
				var r *time.Time
				err := tx.QueryRow(ctx, `SELECT revoked_at FROM webdb_credentials WHERE id=$1`, in.CredentialID).Scan(&r)
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, ErrWebDBCredentialNotFound
				}
				if err != nil {
					return nil, err
				}
				checked[in.CredentialID] = r
				revoked = r
			}
			if revoked != nil {
				return nil, ErrWebDBCredentialRevoked
			}
		}
		row := tx.QueryRow(ctx, `
			INSERT INTO webdb_scan_tasks (kind, target, db_type, credential_id, created_by)
			VALUES ($1,$2,$3,NULLIF($4,0),$5)
			RETURNING `+webDBTaskColumns,
			kind, in.Target, in.DBType, in.CredentialID, createdBy)
		t, err := scanWebDBTask(row)
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

// ClaimWebDBScanTasks atomically claims pending tasks for the server-side
// worker. limit is capped at 64.
func (s *Store) ClaimWebDBScanTasks(ctx context.Context, limit int) ([]WebDBTask, error) {
	if limit <= 0 || limit > 64 {
		limit = 8
	}
	rows, err := s.pool.Query(ctx, `
		UPDATE webdb_scan_tasks
		SET status='running', started_at=NOW()
		WHERE id IN (
			SELECT id FROM webdb_scan_tasks
			WHERE status='pending'
			ORDER BY id
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING `+webDBTaskColumns,
		limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tasks []WebDBTask
	for rows.Next() {
		t, err := scanWebDBTask(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, *t)
	}
	return tasks, rows.Err()
}

// CompleteWebDBScanTask marks a task done or failed with a summary.
func (s *Store) CompleteWebDBScanTask(ctx context.Context, id int64, scanErr string, summary json.RawMessage) error {
	if len(summary) == 0 {
		summary = json.RawMessage(`{}`)
	}
	status := "done"
	if scanErr != "" {
		status = "failed"
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE webdb_scan_tasks
		SET status=$2, error=$3, result_summary=$4, finished_at=NOW()
		WHERE id=$1
	`, id, status, scanErr, string(summary))
	return err
}

// ListWebDBScanTasks returns tasks newest first with optional status/kind
// filters.
func (s *Store) ListWebDBScanTasks(ctx context.Context, status, kind string, limit, offset int) ([]WebDBTask, int64, error) {
	where := []string{}
	args := []interface{}{}
	if status != "" {
		args = append(args, status)
		where = append(where, fmt.Sprintf("status=$%d", len(args)))
	}
	if kind != "" {
		args = append(args, kind)
		where = append(where, fmt.Sprintf("kind=$%d", len(args)))
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM webdb_scan_tasks`+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT ` + webDBTaskColumns + ` FROM webdb_scan_tasks` + whereSQL +
		` ORDER BY id DESC LIMIT $` + fmt.Sprint(len(args)+1) + ` OFFSET $` + fmt.Sprint(len(args)+2)
	args = append(args, limit, offset)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []WebDBTask
	for rows.Next() {
		t, err := scanWebDBTask(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *t)
	}
	return out, total, rows.Err()
}

// UpsertWebDBTarget records the latest fingerprint for one kind+target.
func (s *Store) UpsertWebDBTarget(ctx context.Context, t WebDBTarget) error {
	if t.Status == "" {
		t.Status = "active"
	}
	detail := "{}"
	if len(t.Detail) > 0 {
		detail = string(t.Detail)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO webdb_targets (kind, target, db_type, credential_id, agent_id, status, title, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (kind, target) DO UPDATE
		SET db_type=$3, credential_id=$4, agent_id=$5, status=$6, title=$7,
			detail=$8, last_seen=NOW(), updated_at=NOW()
	`, t.Kind, t.Target, t.DBType, t.CredentialID, t.AgentID, t.Status, t.Title, detail)
	return err
}

// ListWebDBTargets returns known web/database services newest first with
// optional kind and free-text filters.
func (s *Store) ListWebDBTargets(ctx context.Context, kind, q string, limit, offset int) ([]WebDBTarget, int64, error) {
	where := []string{}
	args := []interface{}{}
	if kind != "" {
		args = append(args, kind)
		where = append(where, fmt.Sprintf("kind=$%d", len(args)))
	}
	if q != "" {
		args = append(args, "%"+q+"%")
		where = append(where, fmt.Sprintf("(target ILIKE $%d OR title ILIKE $%d)", len(args), len(args)))
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}
	var total int64
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM webdb_targets`+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT ` + webDBTargetColumns + ` FROM webdb_targets` + whereSQL +
		` ORDER BY last_seen DESC, id DESC LIMIT $` + fmt.Sprint(len(args)+1) + ` OFFSET $` + fmt.Sprint(len(args)+2)
	args = append(args, limit, offset)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []WebDBTarget
	for rows.Next() {
		var t WebDBTarget
		var detail []byte
		if err := rows.Scan(&t.ID, &t.Kind, &t.Target, &t.DBType, &t.CredentialID,
			&t.AgentID, &t.Status, &t.Title, &detail, &t.FirstSeen, &t.LastSeen, &t.UpdatedAt); err != nil {
			return nil, 0, err
		}
		t.Detail = json.RawMessage(detail)
		out = append(out, t)
	}
	return out, total, rows.Err()
}

// WebAgentID derives the stable synthetic agent id for one web/db target.
func WebAgentID(kind, target string) string {
	prefix := "agent-web-"
	if strings.EqualFold(kind, "db") {
		prefix = "agent-db-"
	}
	h := sha1.Sum([]byte(strings.ToLower(kind) + "\x00" + target))
	return prefix + hex.EncodeToString(h[:])[:12]
}

// UpsertWebDBAgent creates or refreshes the synthetic agent carrying one
// web/db target's match results.
func (s *Store) UpsertWebDBAgent(ctx context.Context, id, target string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agents (id, hostname, os_type, os_version, arch, agent_ver, ip,
			token_hash, status, fingerprint_hash, last_seen, created_at, updated_at)
		VALUES ($1,$2,'unknown','','','webdb-scanner',$2,'','online','',NOW(),NOW(),NOW())
		ON CONFLICT (id) DO UPDATE
		SET hostname=$2, os_type='unknown', os_version='', arch='', ip=$2,
			status='online', last_seen=NOW(), updated_at=NOW()
	`, id, target)
	return err
}
