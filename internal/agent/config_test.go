package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigUsesVULNSCANAgentConfigAndWUADefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(`
server:
  addr: localhost:19090
agent:
  wua_collect: false
  wua_timeout_seconds: 45
`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VULNSCAN_AGENT_CONFIG", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Addr != "localhost:19090" {
		t.Fatalf("server addr wrong: %q", cfg.Server.Addr)
	}
	if cfg.Agent.WUAEnabled {
		t.Fatal("wua_collect: false must disable WUA collection")
	}
	if cfg.Agent.WUATimeoutSeconds != 45 {
		t.Fatalf("wua_timeout_seconds wrong: %d", cfg.Agent.WUATimeoutSeconds)
	}
	if cfg.EDRScan.Enabled {
		t.Fatal("edr_scan must default to disabled")
	}
	if cfg.EDRScan.TimeoutSeconds != 120 {
		t.Fatalf("edr_scan timeout default wrong: %d", cfg.EDRScan.TimeoutSeconds)
	}
}

func TestLoadConfigDefaultsWhenFileMissing(t *testing.T) {
	t.Setenv("VULNSCAN_AGENT_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Agent.WUAEnabled || cfg.Agent.WUATimeoutSeconds != 60 {
		t.Fatalf("WUA defaults wrong: enabled=%v timeout=%d",
			cfg.Agent.WUAEnabled, cfg.Agent.WUATimeoutSeconds)
	}
	if cfg.EDRScan.Enabled || cfg.EDRScan.TimeoutSeconds != 120 {
		t.Fatalf("EDR scan defaults wrong: enabled=%v timeout=%d",
			cfg.EDRScan.Enabled, cfg.EDRScan.TimeoutSeconds)
	}
}

func TestSaveConfigWritesEnvPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	t.Setenv("VULNSCAN_AGENT_CONFIG", path)
	cfg := &Config{}
	cfg.Server.Addr = "localhost:19090"
	cfg.Agent.WUAEnabled = true
	cfg.Agent.WUATimeoutSeconds = 60
	if err := SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "localhost:19090") ||
		!strings.Contains(string(data), "wua_timeout_seconds: 60") {
		t.Fatalf("saved config missing expected values:\n%s", data)
	}
}
