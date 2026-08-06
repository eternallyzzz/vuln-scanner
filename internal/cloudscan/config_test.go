package cloudscan

import (
	"strings"
	"testing"
	"time"
)

func TestConfigValidateMatrix(t *testing.T) {
	t.Setenv("CLOUD_SCAN_MASTER_KEY", strings.Repeat("a", 64))
	base := func() *Config {
		c := DefaultConfig()
		c.Enabled = true
		return c
	}
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"valid", func(c *Config) {}, ""},
		{"disabled valid", func(c *Config) { c.Enabled = false }, ""},
		{"nil valid", func(c *Config) {}, ""},
		{"missing key env", func(c *Config) { c.MasterKeyEnv = "" }, "master_key_env"},
		{"empty key", func(c *Config) { c.MasterKeyEnv = "CLOUD_UNSET_KEY" }, "not set"},
		{"bad key", func(c *Config) { c.MasterKeyEnv = "CLOUD_BAD_KEY" }, "master key"},
		{"bad concurrency", func(c *Config) { c.Concurrency = 99 }, "concurrency"},
		{"bad interval", func(c *Config) { c.DefaultRefreshIntervalMinutes = 0 }, "refresh_interval_minutes"},
		{"bad timeout", func(c *Config) { c.TimeoutSeconds = 0 }, "timeout_seconds"},
	}
	t.Setenv("CLOUD_BAD_KEY", "short")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c *Config
			if tc.name != "nil valid" {
				c = base()
				tc.mut(c)
			}
			err := c.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestConfigDefaultsAndTimeout(t *testing.T) {
	c := DefaultConfig()
	if c.MasterKeyEnv != "CLOUD_SCAN_MASTER_KEY" || c.Concurrency != 2 ||
		c.DefaultRefreshIntervalMinutes != 60 || c.TimeoutSeconds != 30 {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if c.Timeout() != 30*time.Second {
		t.Fatalf("Timeout() = %v", c.Timeout())
	}
	n := (&Config{}).Normalized()
	if n.Concurrency != 2 || n.DefaultRefreshIntervalMinutes != 60 || n.TimeoutSeconds != 30 {
		t.Fatalf("normalized defaults not applied: %+v", n)
	}
}
