package ticket

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config controls the optional Jira/ServiceNow ticket integration. The
// credential is never stored in server.yaml: PasswordEnv names the
// environment variable that contains it.
type Config struct {
	Enabled                  bool   `mapstructure:"enabled"`
	Provider                 string `mapstructure:"provider"`
	BaseURL                  string `mapstructure:"base_url"`
	Username                 string `mapstructure:"username"`
	PasswordEnv              string `mapstructure:"password_env"`
	TimeoutSeconds           int    `mapstructure:"timeout_seconds"`
	TLSSkipVerify            bool   `mapstructure:"tls_skip_verify"`
	Project                  string `mapstructure:"project"`
	IssueType                string `mapstructure:"issue_type"`
	JiraAckTransitionID      string `mapstructure:"jira_ack_transition_id"`
	JiraResolvedTransitionID string `mapstructure:"jira_resolved_transition_id"`
	ServiceNowTable          string `mapstructure:"servicenow_table"`
	ServiceNowAckState       int    `mapstructure:"servicenow_ack_state"`
	ServiceNowResolvedState  int    `mapstructure:"servicenow_resolved_state"`
}

// DefaultConfig returns the defaults used when the ticketing section is
// absent. The feature is off unless explicitly enabled.
func DefaultConfig() *Config {
	return &Config{
		PasswordEnv:             "TICKET_PASSWORD",
		TimeoutSeconds:          15,
		IssueType:               "Task",
		ServiceNowTable:         "incident",
		ServiceNowAckState:      2,
		ServiceNowResolvedState: 6,
	}
}

// Normalized returns a copy with safe defaults filled in.
func (c *Config) Normalized() *Config {
	if c == nil {
		return DefaultConfig()
	}
	out := *c
	out.BaseURL = strings.TrimRight(strings.TrimSpace(out.BaseURL), "/")
	out.Provider = strings.ToLower(strings.TrimSpace(out.Provider))
	if strings.TrimSpace(out.PasswordEnv) == "" {
		out.PasswordEnv = "TICKET_PASSWORD"
	}
	if out.TimeoutSeconds <= 0 {
		out.TimeoutSeconds = 15
	}
	if strings.TrimSpace(out.IssueType) == "" {
		out.IssueType = "Task"
	}
	if strings.TrimSpace(out.ServiceNowTable) == "" {
		out.ServiceNowTable = "incident"
	}
	if out.ServiceNowAckState <= 0 {
		out.ServiceNowAckState = 2
	}
	if out.ServiceNowResolvedState <= 0 {
		out.ServiceNowResolvedState = 6
	}
	return &out
}

// Password resolves the credential from the environment variable named by
// PasswordEnv.
func (c *Config) Password() string {
	if c == nil || c.PasswordEnv == "" {
		return ""
	}
	return os.Getenv(c.PasswordEnv)
}

// Timeout returns the HTTP client timeout, defaulting to 15 seconds.
func (c *Config) Timeout() time.Duration {
	if c == nil || c.TimeoutSeconds <= 0 {
		return 15 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// Validate checks the enabled ticketing configuration. A disabled or nil
// config is always valid.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	if c.Provider != "jira" && c.Provider != "servicenow" {
		return errors.New("ticketing.provider must be jira or servicenow when ticketing is enabled")
	}
	if strings.TrimSpace(c.BaseURL) == "" {
		return errors.New("ticketing.base_url is required when ticketing is enabled")
	}
	if !strings.HasPrefix(c.BaseURL, "https://") && !strings.HasPrefix(c.BaseURL, "http://") {
		return errors.New("ticketing.base_url must start with http:// or https://")
	}
	if strings.TrimSpace(c.Username) == "" {
		return errors.New("ticketing.username is required when ticketing is enabled")
	}
	if strings.TrimSpace(c.PasswordEnv) == "" {
		return errors.New("ticketing.password_env is required when ticketing is enabled")
	}
	if c.Password() == "" {
		return fmt.Errorf("ticketing password is empty; set the environment variable named by ticketing.password_env")
	}
	if c.TimeoutSeconds <= 0 {
		return errors.New("ticketing.timeout_seconds must be positive")
	}
	switch c.Provider {
	case "jira":
		if strings.TrimSpace(c.Project) == "" {
			return errors.New("ticketing.project is required for jira")
		}
		if strings.TrimSpace(c.IssueType) == "" {
			return errors.New("ticketing.issue_type is required for jira")
		}
	case "servicenow":
		if strings.TrimSpace(c.ServiceNowTable) == "" {
			return errors.New("ticketing.servicenow_table is required for servicenow")
		}
		if c.ServiceNowAckState < 1 || c.ServiceNowAckState > 7 ||
			c.ServiceNowResolvedState < 1 || c.ServiceNowResolvedState > 7 {
			return errors.New("ticketing.servicenow_ack_state and servicenow_resolved_state must be in 1-7")
		}
	}
	return nil
}
