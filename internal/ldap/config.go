package ldap

import (
	"errors"
	"os"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// Config holds the optional LDAP directory integration settings. The bind
// password is never stored in configuration files: BindPasswordEnv names
// the environment variable that contains it.
type Config struct {
	Enabled         bool       `mapstructure:"enabled" json:"enabled,omitempty"`
	URL             string     `mapstructure:"url" json:"url,omitempty"`
	TLSSkipVerify   bool       `mapstructure:"tls_skip_verify" json:"tls_skip_verify,omitempty"`
	BindDN          string     `mapstructure:"bind_dn" json:"bind_dn,omitempty"`
	BindPasswordEnv string     `mapstructure:"bind_password_env" json:"bind_password_env,omitempty"`
	UserBaseDN      string     `mapstructure:"user_base_dn" json:"user_base_dn,omitempty"`
	UserFilter      string     `mapstructure:"user_filter" json:"user_filter,omitempty"`
	GroupBaseDN     string     `mapstructure:"group_base_dn" json:"group_base_dn,omitempty"`
	GroupFilter     string     `mapstructure:"group_filter" json:"group_filter,omitempty"`
	RoleGroups      RoleGroups `mapstructure:"role_groups" json:"role_groups,omitempty"`
	AutoProvision   bool       `mapstructure:"auto_provision" json:"auto_provision,omitempty"`
	TimeoutSeconds  int        `mapstructure:"timeout_seconds" json:"timeout_seconds,omitempty"`
}

// RoleGroups maps directory groups onto the three local roles. Entries may
// be full DNs or CNs; matching is case-insensitive and follows a fixed
// admin > operator > viewer priority.
type RoleGroups struct {
	Admin    []string `mapstructure:"admin" json:"admin,omitempty"`
	Operator []string `mapstructure:"operator" json:"operator,omitempty"`
	Viewer   []string `mapstructure:"viewer" json:"viewer,omitempty"`
}

// Password resolves the bind password from the environment variable named
// by BindPasswordEnv.
func (c *Config) Password() string {
	if c == nil || c.BindPasswordEnv == "" {
		return ""
	}
	return os.Getenv(c.BindPasswordEnv)
}

// Timeout returns the connection/request timeout, defaulting to 10 seconds
// when unset or invalid.
func (c *Config) Timeout() time.Duration {
	if c == nil || c.TimeoutSeconds <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// Validate checks the required LDAP settings. A disabled or nil config is
// always valid.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.URL) == "" {
		return errors.New("ldap.url is required when ldap is enabled")
	}
	if strings.TrimSpace(c.BindDN) == "" {
		return errors.New("ldap.bind_dn is required when ldap is enabled")
	}
	if strings.TrimSpace(c.BindPasswordEnv) == "" {
		return errors.New("ldap.bind_password_env is required when ldap is enabled")
	}
	if c.Password() == "" {
		return errors.New("ldap bind password is empty; set the environment variable named by ldap.bind_password_env")
	}
	if strings.TrimSpace(c.UserBaseDN) == "" {
		return errors.New("ldap.user_base_dn is required when ldap is enabled")
	}
	if strings.TrimSpace(c.UserFilter) == "" {
		return errors.New("ldap.user_filter is required when ldap is enabled")
	}
	if c.GroupFilter != "" && strings.TrimSpace(c.GroupBaseDN) == "" {
		return errors.New("ldap.group_base_dn is required when ldap.group_filter is set")
	}
	if len(c.RoleGroups.Admin)+len(c.RoleGroups.Operator)+len(c.RoleGroups.Viewer) == 0 {
		return errors.New("ldap.role_groups must contain at least one group for admin/operator/viewer")
	}
	return nil
}

// MapRole returns the highest-priority local role for the given directory
// groups, or "" when no configured group matches. Matching is
// case-insensitive and accepts full DNs as well as CNs.
func MapRole(groups []string, roleGroups RoleGroups) string {
	matched := func(configured []string) bool {
		for _, g := range groups {
			g = strings.TrimSpace(g)
			if g == "" {
				continue
			}
			for _, want := range configured {
				if strings.EqualFold(g, strings.TrimSpace(want)) {
					return true
				}
			}
		}
		return false
	}
	if matched(roleGroups.Admin) {
		return "admin"
	}
	if matched(roleGroups.Operator) {
		return "operator"
	}
	if matched(roleGroups.Viewer) {
		return "viewer"
	}
	return ""
}

// replacePlaceholders substitutes {username} and {dn} in an LDAP filter,
// escaping both values so they are treated as literal filter values.
func replacePlaceholders(filter, username, dn string) string {
	if strings.Contains(filter, "{username}") {
		filter = strings.ReplaceAll(filter, "{username}", goldap.EscapeFilter(username))
	}
	if strings.Contains(filter, "{dn}") {
		filter = strings.ReplaceAll(filter, "{dn}", goldap.EscapeFilter(dn))
	}
	return filter
}
