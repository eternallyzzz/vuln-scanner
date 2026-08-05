package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigEnvWithoutFile(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/vulnscan?sslmode=disable")
	t.Setenv("JWT_SECRET", "env-jwt")
	t.Setenv("API_KEY", "env-api")
	t.Setenv("SERVER_URL", "https://vuln.example.com")
	t.Setenv("NVD_API_KEY", "env-nvd")

	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseURL != "postgres://u:p@db:5432/vulnscan?sslmode=disable" {
		t.Fatalf("database_url = %q, want env value", cfg.DatabaseURL)
	}
	if cfg.JWTSecret != "env-jwt" {
		t.Fatalf("jwt_secret = %q, want env value", cfg.JWTSecret)
	}
	if cfg.APIKey != "env-api" {
		t.Fatalf("api_key = %q, want env value", cfg.APIKey)
	}
	if cfg.ServerURL != "https://vuln.example.com" {
		t.Fatalf("server_url = %q, want env value", cfg.ServerURL)
	}
	if cfg.CVE.NVDAPIKey != "env-nvd" {
		t.Fatalf("cve.nvd_api_key = %q, want env value", cfg.CVE.NVDAPIKey)
	}
}

func TestLoadConfigEnvExpansionAndPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	content := []byte(`
jwt_secret: "${JWT_SECRET}"
api_key: "sk-file"
database_url: "postgres://file:file@localhost:5432/file?sslmode=disable"
server_url: "https://file.example.com/"
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("JWT_SECRET", "expanded-jwt")
	t.Setenv("API_KEY", "env-api")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.JWTSecret != "expanded-jwt" {
		t.Fatalf("jwt_secret = %q, want ${ENV} expansion", cfg.JWTSecret)
	}
	if cfg.APIKey != "env-api" {
		t.Fatalf("api_key = %q, want env precedence over file", cfg.APIKey)
	}
	if cfg.DatabaseURL != "postgres://file:file@localhost:5432/file?sslmode=disable" {
		t.Fatalf("database_url = %q, want file value", cfg.DatabaseURL)
	}
	if cfg.ServerURL != "https://file.example.com/" {
		t.Fatalf("server_url = %q, want file value", cfg.ServerURL)
	}
}

func TestServerURLFallbackAndTrim(t *testing.T) {
	cfg := DefaultConfig()
	if got := serverURL(cfg); got != "http://localhost:8080" {
		t.Fatalf("serverURL() = %q, want localhost fallback", got)
	}
	cfg.ServerURL = "https://vuln.example.com/"
	if got := serverURL(cfg); got != "https://vuln.example.com" {
		t.Fatalf("serverURL() = %q, want trailing slash trimmed", got)
	}
}

func TestCVEScanConfigFeedConfig(t *testing.T) {
	c := &CVEScanConfig{
		MSRCRefreshMinutes: 120,
		NVDTTLHours:        1,
	}
	cfg := c.FeedConfig()
	if cfg.MSRCRefresh != 2*time.Hour {
		t.Fatalf("MSRC refresh = %v, want 2h", cfg.MSRCRefresh)
	}
	if cfg.NVDTTL < cfg.NVDRefresh {
		t.Fatalf("NVD TTL %v must be >= refresh %v", cfg.NVDTTL, cfg.NVDRefresh)
	}
}

func TestNilCVEScanConfigFeedConfig(t *testing.T) {
	var c *CVEScanConfig
	if got := c.FeedConfig(); got == nil {
		t.Fatal("nil config must return defaults")
	}
}

func TestLoadConfigReportingEnv(t *testing.T) {
	t.Setenv("REPORTING_ENABLED", "true")
	t.Setenv("REPORTING_SCHEDULE", "0 9 * * *")
	t.Setenv("REPORTING_TIMEZONE", "UTC")
	t.Setenv("REPORTING_TO", "a@example.com,b@example.com")

	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Reporting == nil || !cfg.Reporting.Enabled {
		t.Fatal("REPORTING_ENABLED must enable reporting")
	}
	if cfg.Reporting.Schedule != "0 9 * * *" || cfg.Reporting.Timezone != "UTC" {
		t.Fatalf("reporting env not applied: %+v", cfg.Reporting)
	}
	if len(cfg.Reporting.To) != 2 ||
		!strings.Contains(cfg.Reporting.To[0], "a@example.com") ||
		!strings.Contains(cfg.Reporting.To[1], "b@example.com") {
		t.Fatalf("REPORTING_TO not split: %#v", cfg.Reporting.To)
	}
}

func TestLoadConfigReportingFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	content := []byte(`
reporting:
  enabled: true
  schedule: "0 9 * * *"
  timezone: "UTC"
  to:
    - reports@example.com
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Reporting.Enabled || cfg.Reporting.Schedule != "0 9 * * *" ||
		cfg.Reporting.Timezone != "UTC" || len(cfg.Reporting.To) != 1 ||
		cfg.Reporting.To[0] != "reports@example.com" {
		t.Fatalf("reporting file config not applied: %+v", cfg.Reporting)
	}
}
