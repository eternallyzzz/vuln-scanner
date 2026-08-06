package siem

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// HECConfig configures the Splunk HTTP Event Collector target.
type HECConfig struct {
	URL        string `mapstructure:"url"`
	TokenEnv   string `mapstructure:"token_env"`
	Index      string `mapstructure:"index"`
	SourceType string `mapstructure:"sourcetype"`
}

// WebhookConfig configures the generic JSON webhook target.
type WebhookConfig struct {
	URL       string `mapstructure:"url"`
	SecretEnv string `mapstructure:"secret_env"`
}

// Config controls the optional SIEM/SOAR event stream. Credentials are
// never stored in server.yaml: TokenEnv/SecretEnv name environment
// variables that contain them.
type Config struct {
	Enabled                 bool           `mapstructure:"enabled"`
	SplunkHEC               *HECConfig     `mapstructure:"splunk_hec"`
	Webhook                 *WebhookConfig `mapstructure:"webhook"`
	DeliveryIntervalSeconds int            `mapstructure:"delivery_interval_seconds"`
	BatchSize               int            `mapstructure:"batch_size"`
	MaxAttempts             int            `mapstructure:"max_attempts"`
	TimeoutSeconds          int            `mapstructure:"timeout_seconds"`
	TLSSkipVerify           bool           `mapstructure:"tls_skip_verify"`
}

// DefaultConfig returns the defaults used when the siem section is absent.
// The feature is off unless explicitly enabled.
func DefaultConfig() *Config {
	return &Config{
		SplunkHEC: &HECConfig{
			TokenEnv:   "SIEM_SPLUNK_HEC_TOKEN",
			Index:      "main",
			SourceType: "vulnscan:events",
		},
		Webhook:                 &WebhookConfig{},
		DeliveryIntervalSeconds: 10,
		BatchSize:               50,
		MaxAttempts:             3,
		TimeoutSeconds:          10,
	}
}

// Normalized returns a copy with safe defaults filled in.
func (c *Config) Normalized() *Config {
	if c == nil {
		return DefaultConfig()
	}
	out := *c
	if out.SplunkHEC == nil {
		out.SplunkHEC = &HECConfig{}
	}
	hec := *out.SplunkHEC
	hec.URL = strings.TrimRight(strings.TrimSpace(hec.URL), "/")
	hec.TokenEnv = strings.TrimSpace(hec.TokenEnv)
	if hec.TokenEnv == "" {
		hec.TokenEnv = "SIEM_SPLUNK_HEC_TOKEN"
	}
	if hec.Index == "" {
		hec.Index = "main"
	}
	if hec.SourceType == "" {
		hec.SourceType = "vulnscan:events"
	}
	out.SplunkHEC = &hec

	if out.Webhook == nil {
		out.Webhook = &WebhookConfig{}
	}
	wh := *out.Webhook
	wh.URL = strings.TrimRight(strings.TrimSpace(wh.URL), "/")
	wh.SecretEnv = strings.TrimSpace(wh.SecretEnv)
	out.Webhook = &wh

	if out.DeliveryIntervalSeconds <= 0 {
		out.DeliveryIntervalSeconds = 10
	}
	if out.BatchSize <= 0 {
		out.BatchSize = 50
	}
	if out.MaxAttempts < 1 {
		out.MaxAttempts = 3
	}
	if out.TimeoutSeconds <= 0 {
		out.TimeoutSeconds = 10
	}
	return &out
}

// HECToken resolves the Splunk HEC token from the environment.
func (c *Config) HECToken() string {
	if c == nil || c.SplunkHEC == nil || c.SplunkHEC.TokenEnv == "" {
		return ""
	}
	return os.Getenv(c.SplunkHEC.TokenEnv)
}

// WebhookSecret resolves the webhook signing secret from the environment.
func (c *Config) WebhookSecret() string {
	if c == nil || c.Webhook == nil || c.Webhook.SecretEnv == "" {
		return ""
	}
	return os.Getenv(c.Webhook.SecretEnv)
}

// Timeout returns the HTTP client timeout, defaulting to 10 seconds.
func (c *Config) Timeout() time.Duration {
	if c == nil || c.TimeoutSeconds <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// Validate checks the enabled SIEM configuration. A disabled or nil config
// is always valid.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	hec := c.SplunkHEC
	wh := c.Webhook
	if (hec == nil || hec.URL == "") && (wh == nil || wh.URL == "") {
		return errors.New("siem.enabled requires at least one target (splunk_hec.url or webhook.url)")
	}
	if hec != nil && hec.URL != "" {
		if !strings.HasPrefix(hec.URL, "https://") && !strings.HasPrefix(hec.URL, "http://") {
			return errors.New("siem.splunk_hec.url must start with http:// or https://")
		}
		if strings.TrimSpace(hec.TokenEnv) == "" {
			return errors.New("siem.splunk_hec.token_env is required when splunk_hec.url is set")
		}
		if c.HECToken() == "" {
			return fmt.Errorf("siem splunk HEC token is empty; set the environment variable named by siem.splunk_hec.token_env")
		}
	}
	if wh != nil && wh.URL != "" {
		if !strings.HasPrefix(wh.URL, "https://") && !strings.HasPrefix(wh.URL, "http://") {
			return errors.New("siem.webhook.url must start with http:// or https://")
		}
		if wh.SecretEnv != "" && c.WebhookSecret() == "" {
			return fmt.Errorf("siem webhook secret is empty; set the environment variable named by siem.webhook.secret_env")
		}
	}
	if c.DeliveryIntervalSeconds <= 0 {
		return errors.New("siem.delivery_interval_seconds must be positive")
	}
	if c.BatchSize < 1 || c.BatchSize > 500 {
		return errors.New("siem.batch_size must be in 1-500")
	}
	if c.MaxAttempts < 1 {
		return errors.New("siem.max_attempts must be >= 1")
	}
	if c.TimeoutSeconds <= 0 {
		return errors.New("siem.timeout_seconds must be positive")
	}
	return nil
}
