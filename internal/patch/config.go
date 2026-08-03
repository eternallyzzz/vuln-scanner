package patch

import (
	"fmt"
	"regexp"
	"strings"
)

var tokenRe = regexp.MustCompile(`^[A-Za-z0-9._/+-]+$`)

type Config struct {
	Enabled                 bool                   `mapstructure:"enabled"`
	DefaultApprovalRequired bool                   `mapstructure:"default_approval_required"`
	AgentTimeoutSeconds     int                    `mapstructure:"agent_timeout_seconds"`
	AptCommand              string                 `mapstructure:"apt_command"`
	DnfCommand              string                 `mapstructure:"dnf_command"`
	YumCommand              string                 `mapstructure:"yum_command"`
	ApkCommand              string                 `mapstructure:"apk_command"`
	DryRun                  bool                   `mapstructure:"dry_run"`
	AutoRemediation         *AutoRemediationConfig `mapstructure:"auto_remediation"`
}

type AutoRemediationConfig struct {
	Enabled             bool   `mapstructure:"enabled"`
	ApprovalRequired    *bool  `mapstructure:"approval_required"`
	MinSeverity         string `mapstructure:"min_severity"`
	MaxCampaignsPerHour int    `mapstructure:"max_campaigns_per_hour"`
}

func (a *AutoRemediationConfig) ApprovalRequiredResolved() bool {
	if a != nil && a.ApprovalRequired != nil {
		return *a.ApprovalRequired
	}
	return true
}

func (a *AutoRemediationConfig) MinSeverityResolved() string {
	if a == nil || strings.TrimSpace(a.MinSeverity) == "" {
		return "HIGH"
	}
	return strings.ToUpper(strings.TrimSpace(a.MinSeverity))
}

func (a *AutoRemediationConfig) MaxCampaignsPerHourResolved() int {
	if a == nil || a.MaxCampaignsPerHour < 1 {
		return 50
	}
	return a.MaxCampaignsPerHour
}

func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.AgentTimeoutSeconds < 30 {
		return fmt.Errorf("patch.agent_timeout_seconds must be >= 30")
	}
	if c.AptCommand == "" {
		c.AptCommand = "apt-get install -y --only-upgrade"
	}
	if c.DnfCommand == "" {
		c.DnfCommand = "dnf -y update"
	}
	if c.YumCommand == "" {
		c.YumCommand = "yum -y update"
	}
	if c.ApkCommand == "" {
		c.ApkCommand = "apk upgrade"
	}
	if c.AutoRemediation != nil && c.AutoRemediation.Enabled {
		switch c.AutoRemediation.MinSeverityResolved() {
		case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		default:
			return fmt.Errorf("patch.auto_remediation.min_severity must be LOW/MEDIUM/HIGH/CRITICAL")
		}
	}
	for _, field := range []struct {
		name, value string
	}{
		{"patch.apt_command", c.AptCommand},
		{"patch.dnf_command", c.DnfCommand},
		{"patch.yum_command", c.YumCommand},
		{"patch.apk_command", c.ApkCommand},
	} {
		for _, tok := range strings.Fields(field.value) {
			if !tokenRe.MatchString(tok) {
				return fmt.Errorf("%s contains unsafe token %q", field.name, tok)
			}
		}
	}
	return nil
}

func (c *Config) AptArgv() []string {
	return strings.Fields(c.AptCommand)
}

func (c *Config) DnfArgv() []string {
	return strings.Fields(c.DnfCommand)
}

func (c *Config) YumArgv() []string {
	return strings.Fields(c.YumCommand)
}

func (c *Config) ApkArgv() []string {
	return strings.Fields(c.ApkCommand)
}
