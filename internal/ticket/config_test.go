package ticket

import (
	"strings"
	"testing"
	"time"
)

func TestConfigValidateMatrix(t *testing.T) {
	t.Setenv("TICKET_PASSWORD", "s3cret")
	base := func() *Config {
		c := DefaultConfig()
		c.Enabled = true
		c.Provider = "jira"
		c.BaseURL = "https://jira.example.com"
		c.Username = "svc"
		c.Project = "SEC"
		return c
	}
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"valid jira", func(c *Config) {}, ""},
		{"valid servicenow", func(c *Config) {
			c.Provider = "servicenow"
			c.Project = ""
			c.IssueType = ""
		}, ""},
		{"disabled always valid", func(c *Config) { c.Enabled = false }, ""},
		{"nil valid", func(c *Config) {}, ""},
		{"bad provider", func(c *Config) { c.Provider = "linear" }, "provider"},
		{"missing base url", func(c *Config) { c.BaseURL = "" }, "base_url"},
		{"bad base url scheme", func(c *Config) { c.BaseURL = "ftp://jira" }, "http"},
		{"missing username", func(c *Config) { c.Username = "" }, "username"},
		{"missing password env", func(c *Config) { c.PasswordEnv = "" }, "password_env"},
		{"empty password", func(c *Config) { c.PasswordEnv = "TICKET_PASSWORD_UNSET" }, "password is empty"},
		{"zero timeout", func(c *Config) { c.TimeoutSeconds = 0 }, "timeout_seconds"},
		{"jira missing project", func(c *Config) { c.Project = "" }, "project"},
		{"jira missing issue type", func(c *Config) { c.IssueType = "" }, "issue_type"},
		{"servicenow missing table", func(c *Config) {
			c.Provider = "servicenow"
			c.Project = ""
			c.IssueType = ""
			c.ServiceNowTable = ""
		}, "servicenow_table"},
		{"servicenow bad states", func(c *Config) {
			c.Provider = "servicenow"
			c.Project = ""
			c.IssueType = ""
			c.ServiceNowResolvedState = 9
		}, "1-7"},
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

func TestConfigDefaultsAndPassword(t *testing.T) {
	t.Setenv("TICKET_PASSWORD", "pw")
	c := DefaultConfig()
	if got := c.Password(); got != "pw" {
		t.Fatalf("Password() = %q, want env value", got)
	}
	if got := c.Timeout(); got != 15*time.Second {
		t.Fatalf("Timeout() = %v, want 15s", got)
	}
	n := (&Config{Provider: " Jira ", BaseURL: "https://jira.example.com/", PasswordEnv: "TICKET_PASSWORD"}).Normalized()
	if n.Provider != "jira" || n.BaseURL != "https://jira.example.com" ||
		n.IssueType != "Task" || n.ServiceNowTable != "incident" {
		t.Fatalf("normalized defaults not applied: %+v", n)
	}
}

func TestConfigNilHelpers(t *testing.T) {
	var c *Config
	if c.Validate() != nil {
		t.Fatal("nil config must validate")
	}
	if c.Password() != "" {
		t.Fatal("nil password must be empty")
	}
	if c.Timeout() != 15*time.Second {
		t.Fatal("nil timeout must default to 15s")
	}
}
