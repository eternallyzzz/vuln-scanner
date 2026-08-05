package store

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.up.sql
var migrationFiles embed.FS

type Agent struct {
	ID              string     `json:"id"`
	Hostname        string     `json:"hostname"`
	OSType          string     `json:"os_type"`
	OSVersion       string     `json:"os_version"`
	Arch            string     `json:"arch"`
	AgentVer        string     `json:"agent_ver"`
	IP              string     `json:"ip"`
	TokenHash       string     `json:"-"`
	Status          string     `json:"status"`
	FingerprintHash string     `json:"-"`
	LastSeen        time.Time  `json:"last_seen"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	EOLStatus       string     `json:"eol_status,omitempty"`
	EOLDate         *time.Time `json:"eol_date,omitempty"`
	EOLProduct      string     `json:"eol_product,omitempty"`
	EOLCycle        string     `json:"eol_cycle,omitempty"`
}

type AssetSnapshot struct {
	AgentID   string    `json:"agent_id"`
	Mode      string    `json:"mode"`
	Assets    []byte    `json:"assets"`
	Checksum  string    `json:"checksum"`
	CreatedAt time.Time `json:"created_at"`
}

type CVEResult struct {
	ID                 int64     `json:"id"`
	AgentID            string    `json:"agent_id"`
	CVEID              string    `json:"cve_id"`
	AssetName          string    `json:"asset_name"`
	AssetVersion       string    `json:"asset_version"`
	FixedVersion       string    `json:"fixed_version,omitempty"`
	FixState           string    `json:"fix_state,omitempty"`
	KBArticle          string    `json:"kb_article,omitempty"`
	KBURL              string    `json:"kb_url,omitempty"`
	VerificationSource string    `json:"verification_source,omitempty"`
	AdvisoryURL        string    `json:"advisory_url,omitempty"`
	Severity           string    `json:"severity"`
	CVSSScore          float64   `json:"cvss_score"`
	Summary            string    `json:"summary"`
	Source             string    `json:"source"`
	Status             string    `json:"status"`
	DetectedAt         time.Time `json:"detected_at"`
	CanonicalCVEID     string    `json:"canonical_cve_id,omitempty"`
	EPSSScore          float64   `json:"epss_score,omitempty"`
	EPSSPercentile     float64   `json:"epss_percentile,omitempty"`
	KEV                bool      `json:"kev,omitempty"`
	ExposureScore      float64   `json:"exposure_score,omitempty"`
	AssetCriticality   float64   `json:"asset_criticality,omitempty"`
	RiskScore          float64   `json:"risk_score,omitempty"`
	RiskLevel          string    `json:"risk_level,omitempty"`
}

type AnalysisLog struct {
	ID         string    `json:"id"`
	AgentID    string    `json:"agent_id"`
	CVEIDs     []string  `json:"cve_ids"`
	Prompt     string    `json:"-"`
	Response   string    `json:"-"`
	Summary    string    `json:"summary"`
	Provider   string    `json:"provider"`
	Model      string    `json:"model"`
	TokensUsed int       `json:"tokens_used"`
	DurationMS int       `json:"duration_ms"`
	CreatedAt  time.Time `json:"created_at"`
}

type Store struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("pgxpool: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) RunMigrations(ctx context.Context) error {
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read %s: %w", entry.Name(), err)
		}

		slog.Info("running migration", "file", entry.Name())
		if _, err := s.pool.Exec(ctx, string(data)); err != nil {
			return fmt.Errorf("run %s: %w", entry.Name(), err)
		}
	}

	slog.Info("migrations completed")
	return nil
}

func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}
