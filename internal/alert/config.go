package alert

import (
	"fmt"
	"strings"
)

type SMTPConfig struct {
	Host               string   `mapstructure:"host"`
	Port               int      `mapstructure:"port"`
	User               string   `mapstructure:"user"`
	PasswordEnv        string   `mapstructure:"password_env"`
	From               string   `mapstructure:"from"`
	To                 []string `mapstructure:"to"`
	InsecureSkipVerify bool     `mapstructure:"insecure_skip_verify"`
}

type Config struct {
	Enabled                 bool        `mapstructure:"enabled"`
	WebhookURL              string      `mapstructure:"webhook_url"`
	WebhookSecret           string      `mapstructure:"webhook_secret"`
	SMTP                    *SMTPConfig `mapstructure:"smtp"`
	DeliveryIntervalSeconds int         `mapstructure:"delivery_interval_seconds"`
	MaxAttempts             int         `mapstructure:"max_attempts"`
	SLACheckIntervalMinutes int         `mapstructure:"sla_check_interval_minutes"`
}

func (c *Config) ChannelNames() []string {
	var names []string
	if c.WebhookURL != "" {
		names = append(names, "webhook")
	}
	if c.SMTP != nil && c.SMTP.Host != "" {
		names = append(names, "smtp")
	}
	return names
}

func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if len(c.ChannelNames()) == 0 {
		return fmt.Errorf("alerting enabled but no channel configured (webhook_url or smtp)")
	}
	if c.MaxAttempts < 1 {
		return fmt.Errorf("alerting.max_attempts must be >= 1")
	}
	if c.SLACheckIntervalMinutes < 0 {
		return fmt.Errorf("alerting.sla_check_interval_minutes must be >= 0")
	}
	if c.SMTP != nil && c.SMTP.Host != "" {
		if c.SMTP.Port <= 0 {
			return fmt.Errorf("alerting.smtp.port must be > 0")
		}
		if c.SMTP.From == "" {
			return fmt.Errorf("alerting.smtp.from is required")
		}
		if len(c.SMTP.To) == 0 {
			return fmt.Errorf("alerting.smtp.to is required")
		}
		for _, addr := range c.SMTP.To {
			if !strings.Contains(addr, "@") {
				return fmt.Errorf("alerting.smtp.to contains invalid address %q", addr)
			}
		}
	}
	if c.WebhookURL != "" && !strings.HasPrefix(c.WebhookURL, "https://") &&
		!strings.HasPrefix(c.WebhookURL, "http://") {
		return fmt.Errorf("alerting.webhook_url must start with http:// or https://")
	}
	return nil
}
