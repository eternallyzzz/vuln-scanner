package store

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"vuln-scanner/internal/netscan"
)

// NetworkScanTask is one server-dispatched discovery task claimed by an
// agent. ports is stored as a comma-separated string for portability.
type NetworkScanTask struct {
	ID              int64           `json:"id"`
	Target          string          `json:"target"`
	Ports           []int32         `json:"ports"`
	Status          string          `json:"status"`
	AssignedAgentID string          `json:"assigned_agent_id"`
	CreatedBy       string          `json:"created_by"`
	Error           string          `json:"error"`
	ResultSummary   json.RawMessage `json:"result_summary"`
	CreatedAt       time.Time       `json:"created_at"`
	StartedAt       *time.Time      `json:"started_at"`
	FinishedAt      *time.Time      `json:"finished_at"`
}

// NetworkHost is one discovered host. Services is stored as JSONB.
type NetworkHost struct {
	ID             int64             `json:"id"`
	IP             string            `json:"ip"`
	Hostname       string            `json:"hostname"`
	OSType         string            `json:"os_type"`
	Services       []netscan.Service `json:"services"`
	ScannerAgentID string            `json:"scanner_agent_id"`
	AgentID        string            `json:"agent_id"`
	Status         string            `json:"status"`
	FirstSeen      time.Time         `json:"first_seen"`
	LastSeen       time.Time         `json:"last_seen"`
}

const networkTaskColumns = `id, target, ports, status, assigned_agent_id, created_by, error, COALESCE(result_summary, '{}'), created_at, started_at, finished_at`

const networkHostColumns = `id, ip, hostname, os_type, services, scanner_agent_id, agent_id, status, first_seen, last_seen`

// NetworkAgentID derives the stable synthetic agent id for a discovered IP.
func NetworkAgentID(ip string) string {
	h := sha1.Sum([]byte(ip))
	return "agent-net-" + hex.EncodeToString(h[:])[:12]
}

func formatPorts(ports []int32) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(int(p)))
	}
	return strings.Join(parts, ",")
}

func parsePorts(raw string) []int32 {
	var out []int32
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err == nil && n > 0 && n <= 65535 {
			out = append(out, int32(n))
		}
	}
	return out
}

func scanNetworkTask(row interface{ Scan(...interface{}) error }) (*NetworkScanTask, error) {
	var t NetworkScanTask
	var ports string
	var summary []byte
	if err := row.Scan(&t.ID, &t.Target, &ports, &t.Status, &t.AssignedAgentID,
		&t.CreatedBy, &t.Error, &summary, &t.CreatedAt, &t.StartedAt, &t.FinishedAt); err != nil {
		return nil, err
	}
	t.Ports = parsePorts(ports)
	t.ResultSummary = json.RawMessage(summary)
	return &t, nil
}

func (s *Store) CreateNetworkScanTask(ctx context.Context, target string, ports []int32, createdBy string) (*NetworkScanTask, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO network_scan_tasks (target, ports, created_by)
		VALUES ($1,$2,$3)
		RETURNING `+networkTaskColumns,
		target, formatPorts(ports), createdBy)
	return scanNetworkTask(row)
}

// ClaimNetworkScanTasks atomically assigns pending tasks to an agent.
func (s *Store) ClaimNetworkScanTasks(ctx context.Context, agentID string, limit int) ([]NetworkScanTask, error) {
	if limit <= 0 || limit > 10 {
		limit = 5
	}
	rows, err := s.pool.Query(ctx, `
		UPDATE network_scan_tasks
		SET status='running', assigned_agent_id=$1, started_at=NOW()
		WHERE id IN (
			SELECT id FROM network_scan_tasks
			WHERE status='pending'
			ORDER BY id
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		RETURNING `+networkTaskColumns,
		agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tasks []NetworkScanTask
	for rows.Next() {
		t, err := scanNetworkTask(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, *t)
	}
	return tasks, rows.Err()
}

func (s *Store) CompleteNetworkScanTask(ctx context.Context, id int64, scanErr string, summary json.RawMessage) error {
	if len(summary) == 0 {
		summary = json.RawMessage(`{}`)
	}
	status := "done"
	if scanErr != "" {
		status = "failed"
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE network_scan_tasks
		SET status=$2, error=$3, result_summary=$4, finished_at=NOW()
		WHERE id=$1
	`, id, status, scanErr, string(summary))
	return err
}

func (s *Store) ListNetworkScanTasks(ctx context.Context, status string, limit, offset int) ([]NetworkScanTask, int64, error) {
	where := ""
	args := []interface{}{}
	if status != "" {
		where = " WHERE status=$1"
		args = append(args, status)
	}
	var total int64
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM network_scan_tasks`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT ` + networkTaskColumns + ` FROM network_scan_tasks` + where +
		` ORDER BY id DESC LIMIT $` + fmt.Sprint(len(args)+1) + ` OFFSET $` + fmt.Sprint(len(args)+2)
	args = append(args, limit, offset)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []NetworkScanTask
	for rows.Next() {
		t, err := scanNetworkTask(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *t)
	}
	return out, total, rows.Err()
}

// UpsertNetworkHosts upserts discovered hosts and returns their synthetic
// agent ids in the same order. The most recent report wins per IP.
func (s *Store) UpsertNetworkHosts(ctx context.Context, hosts []NetworkHost, scannerAgentID string) ([]string, error) {
	agentIDs := make([]string, 0, len(hosts))
	for _, h := range hosts {
		services, err := json.Marshal(h.Services)
		if err != nil {
			return nil, err
		}
		if h.Services == nil {
			services = json.RawMessage(`[]`)
		}
		agentID := NetworkAgentID(h.IP)
		_, err = s.pool.Exec(ctx, `
			INSERT INTO network_hosts (ip, hostname, os_type, services, scanner_agent_id, agent_id)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (ip) DO UPDATE
			SET hostname=$2, os_type=$3, services=$4, scanner_agent_id=$5,
				agent_id=$6, status='active', last_seen=NOW(), updated_at=NOW()
		`, h.IP, h.Hostname, h.OSType, services, scannerAgentID, agentID)
		if err != nil {
			return nil, err
		}
		agentIDs = append(agentIDs, agentID)
	}
	return agentIDs, nil
}

func (s *Store) ListNetworkHosts(ctx context.Context, limit, offset int) ([]NetworkHost, int64, error) {
	var total int64
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM network_hosts`).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+networkHostColumns+` FROM network_hosts
		ORDER BY last_seen DESC, ip
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []NetworkHost
	for rows.Next() {
		var h NetworkHost
		var services []byte
		if err := rows.Scan(&h.ID, &h.IP, &h.Hostname, &h.OSType, &services,
			&h.ScannerAgentID, &h.AgentID, &h.Status, &h.FirstSeen, &h.LastSeen); err != nil {
			return nil, 0, err
		}
		if err := json.Unmarshal(services, &h.Services); err != nil {
			return nil, 0, err
		}
		out = append(out, h)
	}
	return out, total, rows.Err()
}

// UpsertNetworkAgent creates or refreshes the synthetic agent that carries
// one discovered host's match results.
func (s *Store) UpsertNetworkAgent(ctx context.Context, id, hostname, ip, osType string) error {
	if osType == "" {
		osType = "unknown"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agents (id, hostname, os_type, os_version, arch, agent_ver, ip,
			token_hash, status, fingerprint_hash, last_seen, created_at, updated_at)
		VALUES ($1,$2,$3,'','','network-scanner',$4,'','online','',NOW(),NOW(),NOW())
		ON CONFLICT (id) DO UPDATE
		SET hostname=$2, os_type=$3, ip=$4, status='online', last_seen=NOW(), updated_at=NOW()
	`, id, hostname, osType, ip)
	return err
}
