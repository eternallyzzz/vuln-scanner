package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigWebDBScanFromFileAndEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	content := []byte(`
webdb_scan:
  enabled: true
  master_key_env: "WEBDB_KEY"
  timeout_seconds: 15
  concurrency: 4
  tls_skip_verify: false
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WEBDB_KEY", strings.Repeat("a", 64))
	t.Setenv("WEBDB_SCAN_CONCURRENCY", "3")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WebDBScan == nil || !cfg.WebDBScan.Enabled || cfg.WebDBScan.MasterKeyEnv != "WEBDB_KEY" ||
		cfg.WebDBScan.Concurrency != 3 || cfg.WebDBScan.TimeoutSeconds != 15 ||
		cfg.WebDBScan.TLSInsecureSkipVerify {
		t.Fatalf("webdb scan config not applied: %+v", cfg.WebDBScan)
	}
}

func TestLoadConfigWebDBScanEnvOnly(t *testing.T) {
	t.Setenv("WEBDB_SCAN_ENABLED", "true")
	t.Setenv("WEBDB_SCAN_MASTER_KEY", strings.Repeat("b", 64))
	t.Setenv("WEBDB_SCAN_TIMEOUT_SECONDS", "20")
	t.Setenv("WEBDB_SCAN_TLS_SKIP_VERIFY", "false")

	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WebDBScan == nil || !cfg.WebDBScan.Enabled ||
		cfg.WebDBScan.MasterKeyEnv != "WEBDB_SCAN_MASTER_KEY" ||
		cfg.WebDBScan.TimeoutSeconds != 20 || cfg.WebDBScan.TLSInsecureSkipVerify {
		t.Fatalf("webdb scan env-only config not applied: %+v", cfg.WebDBScan)
	}
}

func TestLoadConfigWebDBScanInvalidEnv(t *testing.T) {
	t.Setenv("WEBDB_SCAN_ENABLED", "true")
	t.Setenv("WEBDB_SCAN_MASTER_KEY", strings.Repeat("c", 64))
	t.Setenv("WEBDB_SCAN_CONCURRENCY", "99")
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("invalid WEBDB_SCAN_CONCURRENCY must fail config load")
	}
	t.Setenv("WEBDB_SCAN_CONCURRENCY", "")
	t.Setenv("WEBDB_SCAN_ENABLED", "maybe")
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("invalid WEBDB_SCAN_ENABLED must fail config load")
	}
	t.Setenv("WEBDB_SCAN_ENABLED", "true")
	t.Setenv("WEBDB_SCAN_MASTER_KEY", "")
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing master key must fail config load")
	}
}
