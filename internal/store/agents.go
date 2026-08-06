package store

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *Store) CreateAgent(ctx context.Context, agent *Agent) error {
	h := sha256.Sum256([]byte(agent.TokenHash))
	agent.TokenHash = fmt.Sprintf("%x", h[:])

	_, err := s.pool.Exec(ctx, `
		INSERT INTO agents (id, hostname, os_type, os_version, arch, agent_ver, ip,
			token_hash, status, fingerprint_hash, last_seen, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
	`, agent.ID, agent.Hostname, agent.OSType, agent.OSVersion, agent.Arch,
		agent.AgentVer, agent.IP, agent.TokenHash, agent.Status, agent.FingerprintHash,
		agent.LastSeen, agent.CreatedAt, agent.UpdatedAt)
	return err
}

func (s *Store) GetAgent(ctx context.Context, id string) (*Agent, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, hostname, os_type, os_version, arch, agent_ver, ip, token_hash,
			status, fingerprint_hash, last_seen, created_at, updated_at,
			eol_status, eol_date, eol_product, eol_cycle
		FROM agents WHERE id=$1
	`, id)

	var a Agent
	err := row.Scan(&a.ID, &a.Hostname, &a.OSType, &a.OSVersion, &a.Arch,
		&a.AgentVer, &a.IP, &a.TokenHash, &a.Status, &a.FingerprintHash,
		&a.LastSeen, &a.CreatedAt, &a.UpdatedAt,
		&a.EOLStatus, &a.EOLDate, &a.EOLProduct, &a.EOLCycle)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// GetAgentByHostname resolves an agent by its registered hostname. It is
// used by integrations that know the host but not the agent id.
func (s *Store) GetAgentByHostname(ctx context.Context, hostname string) (*Agent, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, hostname, os_type, os_version, arch, agent_ver, ip, token_hash,
			status, fingerprint_hash, last_seen, created_at, updated_at,
			eol_status, eol_date, eol_product, eol_cycle
		FROM agents WHERE hostname=$1 ORDER BY updated_at DESC LIMIT 1
	`, hostname)

	var a Agent
	err := row.Scan(&a.ID, &a.Hostname, &a.OSType, &a.OSVersion, &a.Arch,
		&a.AgentVer, &a.IP, &a.TokenHash, &a.Status, &a.FingerprintHash,
		&a.LastSeen, &a.CreatedAt, &a.UpdatedAt,
		&a.EOLStatus, &a.EOLDate, &a.EOLProduct, &a.EOLCycle)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) ListAgents(ctx context.Context) ([]Agent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, os_type, os_version, arch, agent_ver, ip, token_hash,
			status, fingerprint_hash, last_seen, created_at, updated_at,
			eol_status, eol_date, eol_product, eol_cycle
		FROM agents ORDER BY hostname
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.Hostname, &a.OSType, &a.OSVersion, &a.Arch,
			&a.AgentVer, &a.IP, &a.TokenHash, &a.Status, &a.FingerprintHash,
			&a.LastSeen, &a.CreatedAt, &a.UpdatedAt,
			&a.EOLStatus, &a.EOLDate, &a.EOLProduct, &a.EOLCycle); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, nil
}

func (s *Store) UpdateAgentStatus(ctx context.Context, id, status string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE agents SET status=$1, last_seen=$2, updated_at=$3 WHERE id=$4
	`, status, time.Now(), time.Now(), id)
	return err
}

func (s *Store) UpdateAgentHeartbeat(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE agents SET status='online', last_seen=$1, updated_at=$2 WHERE id=$3
	`, time.Now(), time.Now(), id)
	return err
}

func (s *Store) UpdateAgentOSInfo(ctx context.Context, id, osType, osVersion string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE agents SET os_type=$1, os_version=$2, updated_at=$3 WHERE id=$4
	`, osType, osVersion, time.Now(), id)
	return err
}

func (s *Store) DeleteAgent(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM agents WHERE id=$1`, id)
	return err
}

func (s *Store) GetAgentByFingerprint(ctx context.Context, agentID string) (string, error) {
	var fp string
	err := s.pool.QueryRow(ctx, `
		SELECT fingerprint_hash FROM agents WHERE id=$1
	`, agentID).Scan(&fp)
	if err != nil {
		return "", err
	}
	return fp, nil
}

func (s *Store) ArchiveStaleAgents(ctx context.Context, maxAge time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE agents SET status='archived', updated_at=$1
		WHERE status='offline' AND last_seen < $2
	`, time.Now(), time.Now().Add(-maxAge))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) GetDecayingAgents(ctx context.Context, decay time.Duration) ([]Agent, error) {
	return s.queryAgents(ctx, `
		SELECT id, hostname, os_type, os_version, arch, agent_ver, ip, token_hash,
			status, fingerprint_hash, last_seen, created_at, updated_at,
			eol_status, eol_date, eol_product, eol_cycle
		FROM agents WHERE status='offline' AND last_seen < $1 AND last_seen > $2
	`, time.Now().Add(-decay), time.Now().Add(-90*24*time.Hour))
}

func (s *Store) queryAgents(ctx context.Context, query string, args ...interface{}) ([]Agent, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.Hostname, &a.OSType, &a.OSVersion, &a.Arch,
			&a.AgentVer, &a.IP, &a.TokenHash, &a.Status, &a.FingerprintHash,
			&a.LastSeen, &a.CreatedAt, &a.UpdatedAt,
			&a.EOLStatus, &a.EOLDate, &a.EOLProduct, &a.EOLCycle); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, nil
}

func (s *Store) UpsertAgentToken(ctx context.Context, agentID, tokenHash string) error {
	h := sha256.Sum256([]byte(tokenHash))
	hash := fmt.Sprintf("%x", h[:])

	_, err := s.pool.Exec(ctx, `
		UPDATE agents SET token_hash=$1, updated_at=$2 WHERE id=$3
	`, hash, time.Now(), agentID)

	if err != nil && err == pgx.ErrNoRows {
		return fmt.Errorf("agent not found: %s", agentID)
	}
	return err
}
