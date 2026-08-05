package ldap

import (
	"strings"
	"testing"
)

func TestConfigValidateMatrix(t *testing.T) {
	base := Config{
		Enabled:         true,
		URL:             "ldap://localhost:389",
		BindDN:          "cn=admin,dc=example,dc=org",
		BindPasswordEnv: "LDAP_TEST_BIND_PASSWORD",
		UserBaseDN:      "ou=users,dc=example,dc=org",
		UserFilter:      "(uid={username})",
		GroupBaseDN:     "ou=groups,dc=example,dc=org",
		GroupFilter:     "(member={dn})",
		RoleGroups: RoleGroups{
			Admin: []string{"cn=admins,ou=groups,dc=example,dc=org"},
		},
	}
	t.Setenv("LDAP_TEST_BIND_PASSWORD", "secret")

	cases := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"valid", func(c *Config) {}, ""},
		{"disabled ignores missing fields", func(c *Config) { c.Enabled = false; c.URL = "" }, ""},
		{"nil is valid", func(c *Config) {}, ""},
		{"missing url", func(c *Config) { c.URL = "" }, "ldap.url"},
		{"missing bind dn", func(c *Config) { c.BindDN = "" }, "ldap.bind_dn"},
		{"missing password env", func(c *Config) { c.BindPasswordEnv = "" }, "ldap.bind_password_env"},
		{"missing password value", func(c *Config) { c.BindPasswordEnv = "LDAP_TEST_MISSING" }, "bind password is empty"},
		{"missing user base dn", func(c *Config) { c.UserBaseDN = "" }, "ldap.user_base_dn"},
		{"missing user filter", func(c *Config) { c.UserFilter = "" }, "ldap.user_filter"},
		{"group filter without group base", func(c *Config) { c.GroupBaseDN = "" }, "ldap.group_base_dn"},
		{"missing role groups", func(c *Config) { c.RoleGroups = RoleGroups{} }, "ldap.role_groups"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			if tc.name != "nil is valid" {
				tc.edit(&c)
			}
			var cfg *Config
			if tc.name != "nil is valid" {
				cfg = &c
			}
			err := cfg.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestConfigPasswordFromEnv(t *testing.T) {
	t.Setenv("LDAP_TEST_BIND_PASSWORD", "s3cret")
	c := &Config{BindPasswordEnv: "LDAP_TEST_BIND_PASSWORD"}
	if got := c.Password(); got != "s3cret" {
		t.Fatalf("Password() = %q, want env value", got)
	}
	if c.Timeout() == 0 {
		t.Fatal("Timeout() must default to a positive duration")
	}
	c.TimeoutSeconds = 3
	if c.Timeout().Seconds() != 3 {
		t.Fatalf("Timeout() = %v, want 3s", c.Timeout())
	}
}

func TestMapRole(t *testing.T) {
	rg := RoleGroups{
		Admin:    []string{"CN=Admins,OU=Groups,DC=example,DC=org"},
		Operator: []string{"cn=ops,ou=groups,dc=example,dc=org", "ops"},
		Viewer:   []string{"viewers", "cn=readers,ou=groups,dc=example,dc=org"},
	}
	cases := []struct {
		name   string
		groups []string
		want   string
	}{
		{"no match", []string{"cn=none,ou=groups,dc=example,dc=org"}, ""},
		{"empty", nil, ""},
		{"admin by DN case-insensitive", []string{"cn=admins,ou=groups,dc=example,dc=org"}, "admin"},
		{"operator by CN", []string{"ops"}, "operator"},
		{"viewer by CN", []string{"viewers"}, "viewer"},
		{"viewer by DN", []string{"CN=Readers,OU=Groups,DC=example,DC=org"}, "viewer"},
		{"admin wins over viewer", []string{"viewers", "CN=ADMINS,OU=GROUPS,DC=EXAMPLE,DC=ORG"}, "admin"},
		{"operator wins over viewer", []string{"readers", "ops"}, "operator"},
		{"whitespace tolerated", []string{"  ops  "}, "operator"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MapRole(tc.groups, rg); got != tc.want {
				t.Fatalf("MapRole(%v) = %q, want %q", tc.groups, got, tc.want)
			}
		})
	}
}

func TestReplacePlaceholders(t *testing.T) {
	filter := "(&(uid={username})(memberOf={dn}))"
	got := replacePlaceholders(filter, "a(b)*", "cn=u\\1,dc=example")
	want := "(&(uid=a\\28b\\29\\2a)(memberOf=cn=u\\5c1,dc=example))"
	if got != want {
		t.Fatalf("replacePlaceholders() = %q, want %q", got, want)
	}
}
