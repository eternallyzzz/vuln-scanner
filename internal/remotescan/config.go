package remotescan

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Config controls the server-side credential remote scan. The master key
// itself is never written to server.yaml; it is read from the environment
// variable named by MasterKeyEnv.
type Config struct {
	Enabled        bool   `mapstructure:"enabled"`
	MasterKeyEnv   string `mapstructure:"master_key_env"`
	TimeoutSeconds int    `mapstructure:"timeout_seconds"`
	Concurrency    int    `mapstructure:"concurrency"`
}

// DefaultConfig returns the defaults used when the remote_scan section is
// absent. The feature is off unless explicitly enabled.
func DefaultConfig() *Config {
	return &Config{
		MasterKeyEnv:   "REMOTE_SCAN_MASTER_KEY",
		TimeoutSeconds: 30,
		Concurrency:    8,
	}
}

// Normalized returns a copy with safe defaults filled in.
func (c *Config) Normalized() *Config {
	if c == nil {
		return DefaultConfig()
	}
	out := *c
	if strings.TrimSpace(out.MasterKeyEnv) == "" {
		out.MasterKeyEnv = "REMOTE_SCAN_MASTER_KEY"
	}
	if out.TimeoutSeconds <= 0 {
		out.TimeoutSeconds = 30
	}
	if out.Concurrency <= 0 || out.Concurrency > 64 {
		out.Concurrency = 8
	}
	return &out
}

// Validate checks the enabled configuration, including that the master key
// environment variable is present and decodes to a 32-byte AES-256 key.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.MasterKeyEnv) == "" {
		return errors.New("remote_scan.master_key_env is required when remote_scan.enabled is true")
	}
	if c.TimeoutSeconds <= 0 {
		return errors.New("remote_scan.timeout_seconds must be positive")
	}
	if c.Concurrency <= 0 || c.Concurrency > 64 {
		return errors.New("remote_scan.concurrency must be in 1-64")
	}
	raw := strings.TrimSpace(os.Getenv(c.MasterKeyEnv))
	if raw == "" {
		return fmt.Errorf("remote scan master key environment %s is not set", c.MasterKeyEnv)
	}
	if _, err := ParseMasterKey(raw); err != nil {
		return fmt.Errorf("remote scan master key: %w", err)
	}
	return nil
}

// ParseMasterKey accepts 64 hex characters, base64 (standard or URL, with or
// without padding) of 32 bytes, or 32 raw bytes.
func ParseMasterKey(raw string) ([]byte, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("empty master key")
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	if len(s) == 32 {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("must be 32 raw bytes, 64 hex chars, or base64 of 32 bytes")
}
