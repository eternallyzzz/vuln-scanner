package webdbscan

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultConfigNormalized(t *testing.T) {
	c := DefaultConfig()
	if c.MasterKeyEnv != "WEBDB_SCAN_MASTER_KEY" {
		t.Fatalf("MasterKeyEnv = %q", c.MasterKeyEnv)
	}
	if c.TimeoutSeconds != 10 || c.Concurrency != 8 || !c.TLSInsecureSkipVerify {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	got := c.Normalized()
	if got.Timeout() != 10*time.Second {
		t.Fatalf("Timeout() = %v", got.Timeout())
	}
}

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		key     string
		wantErr bool
	}{
		{"disabled is valid", func(c *Config) { c.Enabled = false }, "", false},
		{"enabled without key env", func(c *Config) { c.Enabled = true }, "", true},
		{"enabled with valid key", func(c *Config) { c.Enabled = true }, strings.Repeat("a", 64), false},
		{"invalid key", func(c *Config) { c.Enabled = true }, "short", true},
		{"zero concurrency", func(c *Config) {
			c.Enabled = true
			c.Concurrency = 0
		}, strings.Repeat("a", 64), true},
		{"too high concurrency", func(c *Config) {
			c.Enabled = true
			c.Concurrency = 17
		}, strings.Repeat("a", 64), true},
		{"zero timeout", func(c *Config) {
			c.Enabled = true
			c.TimeoutSeconds = 0
		}, strings.Repeat("a", 64), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("WEBDB_SCAN_MASTER_KEY", tc.key)
			c := DefaultConfig()
			tc.mutate(c)
			err := c.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
