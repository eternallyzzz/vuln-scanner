package webdbscan

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"vuln-scanner/internal/remotescan"
)

// Config controls the optional server-side web/database scanning. The
// AES-256-GCM master key used to encrypt optional credentials is read from
// the environment variable named by MasterKeyEnv and never written to
// server.yaml.
type Config struct {
	Enabled               bool   `mapstructure:"enabled"`
	MasterKeyEnv          string `mapstructure:"master_key_env"`
	TimeoutSeconds        int    `mapstructure:"timeout_seconds"`
	Concurrency           int    `mapstructure:"concurrency"`
	TLSInsecureSkipVerify bool   `mapstructure:"tls_skip_verify"`
}

// DefaultConfig returns the defaults used when the webdb_scan section is
// absent. The feature is off unless explicitly enabled.
func DefaultConfig() *Config {
	return &Config{
		MasterKeyEnv:          "WEBDB_SCAN_MASTER_KEY",
		TimeoutSeconds:        10,
		Concurrency:           8,
		TLSInsecureSkipVerify: true,
	}
}

// Normalized returns a copy with safe defaults filled in.
func (c *Config) Normalized() *Config {
	if c == nil {
		return DefaultConfig()
	}
	out := *c
	if strings.TrimSpace(out.MasterKeyEnv) == "" {
		out.MasterKeyEnv = "WEBDB_SCAN_MASTER_KEY"
	}
	if out.TimeoutSeconds <= 0 {
		out.TimeoutSeconds = 10
	}
	if out.Concurrency <= 0 {
		out.Concurrency = 8
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

// Timeout returns the per-target scan timeout, defaulting to 10s.
func (c *Config) Timeout() time.Duration {
	if c == nil || c.TimeoutSeconds <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// Validate checks the enabled webdb scan configuration.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.MasterKeyEnv) == "" {
		return errors.New("webdb_scan.master_key_env is required when webdb_scan.enabled is true")
	}
	raw := strings.TrimSpace(c.MasterKey())
	if raw == "" {
		return fmt.Errorf("webdb scan master key environment %s is not set", c.MasterKeyEnv)
	}
	if _, err := remotescan.ParseMasterKey(raw); err != nil {
		return fmt.Errorf("webdb scan master key: %w", err)
	}
	if c.TimeoutSeconds <= 0 {
		return errors.New("webdb_scan.timeout_seconds must be positive")
	}
	if c.Concurrency <= 0 || c.Concurrency > 16 {
		return errors.New("webdb_scan.concurrency must be in 1-16")
	}
	return nil
}
