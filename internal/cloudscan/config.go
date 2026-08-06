package cloudscan

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"vuln-scanner/internal/remotescan"
)

// Config controls the optional cloud asset discovery. The AES-256-GCM
// master key used to encrypt cloud credentials is read from the environment
// variable named by MasterKeyEnv and never written to server.yaml.
type Config struct {
	Enabled                       bool   `mapstructure:"enabled"`
	MasterKeyEnv                  string `mapstructure:"master_key_env"`
	Concurrency                   int    `mapstructure:"concurrency"`
	DefaultRefreshIntervalMinutes int    `mapstructure:"default_refresh_interval_minutes"`
	TimeoutSeconds                int    `mapstructure:"timeout_seconds"`
}

// DefaultConfig returns the defaults used when the cloud_scan section is
// absent. The feature is off unless explicitly enabled.
func DefaultConfig() *Config {
	return &Config{
		MasterKeyEnv:                  "CLOUD_SCAN_MASTER_KEY",
		Concurrency:                   2,
		DefaultRefreshIntervalMinutes: 60,
		TimeoutSeconds:                30,
	}
}

// Normalized returns a copy with safe defaults filled in.
func (c *Config) Normalized() *Config {
	if c == nil {
		return DefaultConfig()
	}
	out := *c
	if strings.TrimSpace(out.MasterKeyEnv) == "" {
		out.MasterKeyEnv = "CLOUD_SCAN_MASTER_KEY"
	}
	if out.Concurrency <= 0 {
		out.Concurrency = 2
	}
	if out.DefaultRefreshIntervalMinutes <= 0 {
		out.DefaultRefreshIntervalMinutes = 60
	}
	if out.TimeoutSeconds <= 0 {
		out.TimeoutSeconds = 30
	}
	return &out
}

// MasterKey resolves the credential master key from the environment.
func (c *Config) MasterKey() string {
	if c == nil || c.MasterKeyEnv == "" {
		return ""
	}
	return os.Getenv(c.MasterKeyEnv)
}

// Timeout returns the per-account discovery timeout, defaulting to 30s.
func (c *Config) Timeout() time.Duration {
	if c == nil || c.TimeoutSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// Validate checks the enabled cloud scan configuration.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.MasterKeyEnv) == "" {
		return errors.New("cloud_scan.master_key_env is required when cloud_scan.enabled is true")
	}
	raw := strings.TrimSpace(c.MasterKey())
	if raw == "" {
		return fmt.Errorf("cloud scan master key environment %s is not set", c.MasterKeyEnv)
	}
	if _, err := remotescan.ParseMasterKey(raw); err != nil {
		return fmt.Errorf("cloud scan master key: %w", err)
	}
	if c.Concurrency <= 0 || c.Concurrency > 16 {
		return errors.New("cloud_scan.concurrency must be in 1-16")
	}
	if c.DefaultRefreshIntervalMinutes <= 0 {
		return errors.New("cloud_scan.default_refresh_interval_minutes must be positive")
	}
	if c.TimeoutSeconds <= 0 {
		return errors.New("cloud_scan.timeout_seconds must be positive")
	}
	return nil
}
