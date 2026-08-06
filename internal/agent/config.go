package agent

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	Server struct {
		Addr   string `mapstructure:"addr"`
		UseTLS bool   `mapstructure:"tls"`
	} `mapstructure:"server"`

	Agent struct {
		ID                  string `mapstructure:"id"`
		Token               string `mapstructure:"token"`
		Hostname            string `mapstructure:"hostname"`
		CollectionInterval  int    `mapstructure:"collection_interval"`
		PatchEnabled        bool   `mapstructure:"patch_enabled"`
		PatchTimeoutSeconds int    `mapstructure:"patch_timeout_seconds"`
		WUAEnabled          bool   `mapstructure:"wua_collect"`
		WUATimeoutSeconds   int    `mapstructure:"wua_timeout_seconds"`
	} `mapstructure:"agent"`

	NetworkScan struct {
		Enabled         bool     `mapstructure:"enabled"`
		IntervalMinutes int      `mapstructure:"interval_minutes"`
		Targets         []string `mapstructure:"targets"`
		Ports           []int    `mapstructure:"ports"`
		Exclude         []string `mapstructure:"exclude"`
		TimeoutSeconds  int      `mapstructure:"timeout_seconds"`
		Concurrency     int      `mapstructure:"concurrency"`
		MaxHosts        int      `mapstructure:"max_hosts"`
	} `mapstructure:"network_scan"`

	EDRScan struct {
		Enabled        bool     `mapstructure:"enabled"`
		Paths          []string `mapstructure:"paths"`
		TimeoutSeconds int      `mapstructure:"timeout_seconds"`
	} `mapstructure:"edr_scan"`
}

func ConfigDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".vuln-scanner")
	}
	return ""
}

func ConfigPath() string {
	return filepath.Join(ConfigDir(), "agent.yaml")
}

// configPath returns the agent config location. VULNSCAN_AGENT_CONFIG lets
// tests and isolated e2e runs point the agent at a temporary config without
// touching the user's default configuration.
func configPath() string {
	if p := os.Getenv("VULNSCAN_AGENT_CONFIG"); p != "" {
		return p
	}
	return ConfigPath()
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}
	cfg.Agent.CollectionInterval = 3600
	cfg.Agent.PatchTimeoutSeconds = 600
	cfg.Agent.WUAEnabled = true
	cfg.Agent.WUATimeoutSeconds = 60
	cfg.NetworkScan.IntervalMinutes = 60
	cfg.NetworkScan.TimeoutSeconds = 2
	cfg.NetworkScan.Concurrency = 32
	cfg.NetworkScan.MaxHosts = 1024
	cfg.EDRScan.Enabled = false
	cfg.EDRScan.TimeoutSeconds = 120

	v := viper.New()
	v.SetConfigFile(configPath())
	v.SetConfigType("yaml")

	if err := v.ReadInConfig(); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	}

	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}

	if cfg.Agent.Hostname == "" {
		hostname, _ := os.Hostname()
		cfg.Agent.Hostname = hostname
	}

	if cfg.Server.Addr == "" {
		cfg.Server.Addr = "localhost:9090"
	}

	return cfg, nil
}

func SaveConfig(cfg *Config) error {
	if err := os.MkdirAll(ConfigDir(), 0700); err != nil {
		return err
	}

	v := viper.New()
	v.Set("server.addr", cfg.Server.Addr)
	v.Set("agent.id", cfg.Agent.ID)
	v.Set("agent.token", cfg.Agent.Token)
	v.Set("agent.hostname", cfg.Agent.Hostname)
	v.Set("agent.collection_interval", cfg.Agent.CollectionInterval)
	v.Set("agent.patch_enabled", cfg.Agent.PatchEnabled)
	v.Set("agent.patch_timeout_seconds", cfg.Agent.PatchTimeoutSeconds)
	v.Set("agent.wua_collect", cfg.Agent.WUAEnabled)
	v.Set("agent.wua_timeout_seconds", cfg.Agent.WUATimeoutSeconds)
	v.Set("network_scan.enabled", cfg.NetworkScan.Enabled)
	v.Set("network_scan.interval_minutes", cfg.NetworkScan.IntervalMinutes)
	v.Set("network_scan.targets", cfg.NetworkScan.Targets)
	v.Set("network_scan.ports", cfg.NetworkScan.Ports)
	v.Set("network_scan.exclude", cfg.NetworkScan.Exclude)
	v.Set("network_scan.timeout_seconds", cfg.NetworkScan.TimeoutSeconds)
	v.Set("network_scan.concurrency", cfg.NetworkScan.Concurrency)
	v.Set("network_scan.max_hosts", cfg.NetworkScan.MaxHosts)
	v.Set("edr_scan.enabled", cfg.EDRScan.Enabled)
	v.Set("edr_scan.paths", cfg.EDRScan.Paths)
	v.Set("edr_scan.timeout_seconds", cfg.EDRScan.TimeoutSeconds)

	return v.WriteConfigAs(configPath())
}

func Fingerprint() string {
	machineID := machineID()
	h := sha256.New()
	hostname, _ := os.Hostname()
	h.Write([]byte(machineID))
	h.Write([]byte(hostname))
	return fmt.Sprintf("%x", h.Sum(nil))
}
