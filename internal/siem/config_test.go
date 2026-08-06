package siem

import (
	"strings"
	"testing"
	"time"
)

func TestConfigValidateMatrix(t *testing.T) {
	t.Setenv("SIEM_SPLUNK_HEC_TOKEN", "hec-token")
	t.Setenv("SIEM_WEBHOOK_SECRET", "wh-secret")
	base := func() *Config {
		c := DefaultConfig()
		c.Enabled = true
		c.SplunkHEC.URL = "https://splunk.example.com:8088/services/collector/event"
		return c
	}
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"valid hec", func(c *Config) {}, ""},
		{"valid webhook", func(c *Config) {
			c.SplunkHEC.URL = ""
			c.Webhook.URL = "https://soar.example.com/hook"
		}, ""},
		{"valid both", func(c *Config) {
			c.Webhook.URL = "https://soar.example.com/hook"
		}, ""},
		{"disabled valid", func(c *Config) { c.Enabled = false }, ""},
		{"nil valid", func(c *Config) {}, ""},
		{"no target", func(c *Config) { c.SplunkHEC.URL = "" }, "at least one target"},
		{"bad hec scheme", func(c *Config) { c.SplunkHEC.URL = "ftp://splunk" }, "http"},
		{"missing hec token env", func(c *Config) { c.SplunkHEC.TokenEnv = "" }, "token_env"},
		{"empty hec token", func(c *Config) { c.SplunkHEC.TokenEnv = "SIEM_UNSET_TOKEN" }, "token is empty"},
		{"bad webhook scheme", func(c *Config) {
			c.SplunkHEC.URL = ""
			c.Webhook.URL = "ftp://hook"
		}, "http"},
		{"empty webhook secret", func(c *Config) {
			c.SplunkHEC.URL = ""
			c.Webhook.URL = "https://hook.example.com"
			c.Webhook.SecretEnv = "SIEM_UNSET_SECRET"
		}, "secret is empty"},
		{"zero interval", func(c *Config) { c.DeliveryIntervalSeconds = 0 }, "delivery_interval_seconds"},
		{"bad batch size", func(c *Config) { c.BatchSize = 501 }, "batch_size"},
		{"zero attempts", func(c *Config) { c.MaxAttempts = 0 }, "max_attempts"},
		{"zero timeout", func(c *Config) { c.TimeoutSeconds = 0 }, "timeout_seconds"},
	}
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

func TestConfigDefaultsAndCredentials(t *testing.T) {
	t.Setenv("SIEM_SPLUNK_HEC_TOKEN", "tok")
	t.Setenv("SIEM_WEBHOOK_SECRET", "sec")
	c := DefaultConfig()
	if got := c.HECToken(); got != "tok" {
		t.Fatalf("HECToken() = %q", got)
	}
	c.Webhook.SecretEnv = "SIEM_WEBHOOK_SECRET"
	if got := c.WebhookSecret(); got != "sec" {
		t.Fatalf("WebhookSecret() = %q", got)
	}
	if got := c.Timeout(); got != 10*time.Second {
		t.Fatalf("Timeout() = %v", got)
	}
	n := (&Config{SplunkHEC: &HECConfig{URL: "https://s.example.com/"}}).Normalized()
	if n.SplunkHEC.URL != "https://s.example.com" || n.SplunkHEC.Index != "main" ||
		n.SplunkHEC.SourceType != "vulnscan:events" || n.DeliveryIntervalSeconds != 10 ||
		n.BatchSize != 50 || n.MaxAttempts != 3 {
		t.Fatalf("normalized defaults not applied: %+v", n)
	}
}

func TestConfigNilHelpers(t *testing.T) {
	var c *Config
	if c.Validate() != nil {
		t.Fatal("nil config must validate")
	}
	if c.HECToken() != "" || c.WebhookSecret() != "" {
		t.Fatal("nil credentials must be empty")
	}
	if c.Timeout() != 10*time.Second {
		t.Fatal("nil timeout must default to 10s")
	}
}
