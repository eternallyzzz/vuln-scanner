package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

// Config controls the scheduled panorama report. SMTP server/auth settings
// are intentionally reused from alerting.smtp; only recipients are owned by
// the reporting section.
type Config struct {
	Enabled  bool     `mapstructure:"enabled"`
	Schedule string   `mapstructure:"schedule"`
	Timezone string   `mapstructure:"timezone"`
	To       []string `mapstructure:"to"`
}

func DefaultConfig() *Config {
	return &Config{
		Schedule: "0 8 * * *",
		Timezone: "Local",
	}
}

// Validate normalizes the schedule/timezone/recipients and requires the
// shared SMTP connection settings when reporting is enabled.
func (c *Config) Validate(smtpHost, smtpFrom string) error {
	if c == nil || !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.Schedule) == "" {
		c.Schedule = DefaultConfig().Schedule
	}
	if _, err := cron.ParseStandard(c.Schedule); err != nil {
		return fmt.Errorf("reporting.schedule: %w", err)
	}
	if strings.TrimSpace(c.Timezone) == "" {
		c.Timezone = DefaultConfig().Timezone
	}
	if _, err := time.LoadLocation(c.Timezone); err != nil {
		return fmt.Errorf("reporting.timezone: %w", err)
	}
	clean := make([]string, 0, len(c.To))
	for _, addr := range c.To {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if !strings.Contains(addr, "@") {
			return fmt.Errorf("reporting.to contains invalid address %q", addr)
		}
		clean = append(clean, addr)
	}
	if len(clean) == 0 {
		return fmt.Errorf("reporting.to must contain at least one recipient")
	}
	c.To = clean
	if strings.TrimSpace(smtpHost) == "" {
		return fmt.Errorf("reporting enabled requires alerting.smtp.host")
	}
	if strings.TrimSpace(smtpFrom) == "" {
		return fmt.Errorf("reporting enabled requires alerting.smtp.from")
	}
	return nil
}

// Location returns the configured cron timezone, defaulting to server local.
func (c *Config) Location() (*time.Location, error) {
	if c == nil || strings.TrimSpace(c.Timezone) == "" {
		return time.Local, nil
	}
	return time.LoadLocation(c.Timezone)
}

// ScheduleSpec returns the normalized cron expression.
func (c *Config) ScheduleSpec() string {
	if c == nil || strings.TrimSpace(c.Schedule) == "" {
		return DefaultConfig().Schedule
	}
	return strings.TrimSpace(c.Schedule)
}
