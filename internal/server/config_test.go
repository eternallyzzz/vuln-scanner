package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigEnvWithoutFile(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/vulnscan?sslmode=disable")
	t.Setenv("JWT_SECRET", "env-jwt")
	t.Setenv("API_KEY", "env-api")
	t.Setenv("SERVER_URL", "https://vuln.example.com")
	t.Setenv("NVD_API_KEY", "env-nvd")

	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseURL != "postgres://u:p@db:5432/vulnscan?sslmode=disable" {
		t.Fatalf("database_url = %q, want env value", cfg.DatabaseURL)
	}
	if cfg.JWTSecret != "env-jwt" {
		t.Fatalf("jwt_secret = %q, want env value", cfg.JWTSecret)
	}
	if cfg.APIKey != "env-api" {
		t.Fatalf("api_key = %q, want env value", cfg.APIKey)
	}
	if cfg.ServerURL != "https://vuln.example.com" {
		t.Fatalf("server_url = %q, want env value", cfg.ServerURL)
	}
	if cfg.CVE.NVDAPIKey != "env-nvd" {
		t.Fatalf("cve.nvd_api_key = %q, want env value", cfg.CVE.NVDAPIKey)
	}
}

func TestLoadConfigEnvExpansionAndPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	content := []byte(`
jwt_secret: "${JWT_SECRET}"
api_key: "sk-file"
database_url: "postgres://file:file@localhost:5432/file?sslmode=disable"
server_url: "https://file.example.com/"
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("JWT_SECRET", "expanded-jwt")
	t.Setenv("API_KEY", "env-api")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.JWTSecret != "expanded-jwt" {
		t.Fatalf("jwt_secret = %q, want ${ENV} expansion", cfg.JWTSecret)
	}
	if cfg.APIKey != "env-api" {
		t.Fatalf("api_key = %q, want env precedence over file", cfg.APIKey)
	}
	if cfg.DatabaseURL != "postgres://file:file@localhost:5432/file?sslmode=disable" {
		t.Fatalf("database_url = %q, want file value", cfg.DatabaseURL)
	}
	if cfg.ServerURL != "https://file.example.com/" {
		t.Fatalf("server_url = %q, want file value", cfg.ServerURL)
	}
}

func TestServerURLFallbackAndTrim(t *testing.T) {
	cfg := DefaultConfig()
	if got := serverURL(cfg); got != "http://localhost:8080" {
		t.Fatalf("serverURL() = %q, want localhost fallback", got)
	}
	cfg.ServerURL = "https://vuln.example.com/"
	if got := serverURL(cfg); got != "https://vuln.example.com" {
		t.Fatalf("serverURL() = %q, want trailing slash trimmed", got)
	}
}

func TestCVEScanConfigFeedConfig(t *testing.T) {
	c := &CVEScanConfig{
		MSRCRefreshMinutes: 120,
		NVDTTLHours:        1,
	}
	cfg := c.FeedConfig()
	if cfg.MSRCRefresh != 2*time.Hour {
		t.Fatalf("MSRC refresh = %v, want 2h", cfg.MSRCRefresh)
	}
	if cfg.NVDTTL < cfg.NVDRefresh {
		t.Fatalf("NVD TTL %v must be >= refresh %v", cfg.NVDTTL, cfg.NVDRefresh)
	}
}

func TestNilCVEScanConfigFeedConfig(t *testing.T) {
	var c *CVEScanConfig
	if got := c.FeedConfig(); got == nil {
		t.Fatal("nil config must return defaults")
	}
}

func TestLoadConfigReportingEnv(t *testing.T) {
	t.Setenv("REPORTING_ENABLED", "true")
	t.Setenv("REPORTING_SCHEDULE", "0 9 * * *")
	t.Setenv("REPORTING_TIMEZONE", "UTC")
	t.Setenv("REPORTING_TO", "a@example.com,b@example.com")

	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Reporting == nil || !cfg.Reporting.Enabled {
		t.Fatal("REPORTING_ENABLED must enable reporting")
	}
	if cfg.Reporting.Schedule != "0 9 * * *" || cfg.Reporting.Timezone != "UTC" {
		t.Fatalf("reporting env not applied: %+v", cfg.Reporting)
	}
	if len(cfg.Reporting.To) != 2 ||
		!strings.Contains(cfg.Reporting.To[0], "a@example.com") ||
		!strings.Contains(cfg.Reporting.To[1], "b@example.com") {
		t.Fatalf("REPORTING_TO not split: %#v", cfg.Reporting.To)
	}
}

func TestLoadConfigRemoteScanEnv(t *testing.T) {
	t.Setenv("REMOTE_SCAN_ENABLED", "true")
	t.Setenv("REMOTE_SCAN_MASTER_KEY", strings.Repeat("a", 64))
	t.Setenv("REMOTE_SCAN_TIMEOUT_SECONDS", "45")
	t.Setenv("REMOTE_SCAN_CONCURRENCY", "4")

	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RemoteScan == nil || !cfg.RemoteScan.Enabled {
		t.Fatal("REMOTE_SCAN_ENABLED must enable remote scan")
	}
	if cfg.RemoteScan.TimeoutSeconds != 45 || cfg.RemoteScan.Concurrency != 4 {
		t.Fatalf("remote scan env not applied: %+v", cfg.RemoteScan)
	}
	if cfg.RemoteScan.MasterKeyEnv != "REMOTE_SCAN_MASTER_KEY" {
		t.Fatalf("master key env = %q", cfg.RemoteScan.MasterKeyEnv)
	}
}

func TestLoadConfigRemoteScanRequiresMasterKey(t *testing.T) {
	t.Setenv("REMOTE_SCAN_ENABLED", "true")
	t.Setenv("REMOTE_SCAN_MASTER_KEY", "")
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("enabled remote scan without master key must fail")
	}

	t.Setenv("REMOTE_SCAN_ENABLED", "false")
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml")); err != nil {
		t.Fatalf("disabled remote scan without master key must pass: %v", err)
	}
}

func TestLoadConfigReportingFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	content := []byte(`
reporting:
  enabled: true
  schedule: "0 9 * * *"
  timezone: "UTC"
  to:
    - reports@example.com
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Reporting.Enabled || cfg.Reporting.Schedule != "0 9 * * *" ||
		cfg.Reporting.Timezone != "UTC" || len(cfg.Reporting.To) != 1 ||
		cfg.Reporting.To[0] != "reports@example.com" {
		t.Fatalf("reporting file config not applied: %+v", cfg.Reporting)
	}
}

func TestLoadConfigLDAPFromFileAndEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	content := []byte(`
ldap:
  enabled: true
  url: "ldap://ldap.example.com:389"
  tls_skip_verify: false
  bind_dn: "cn=admin,dc=example,dc=org"
  bind_password_env: "LDAP_BIND_PASSWORD"
  user_base_dn: "ou=users,dc=example,dc=org"
  user_filter: "(uid={username})"
  group_base_dn: "ou=groups,dc=example,dc=org"
  group_filter: "(member={dn})"
  role_groups:
    admin: ["cn=admins,ou=groups,dc=example,dc=org"]
    viewer: ["viewers"]
  auto_provision: true
  timeout_seconds: 5
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LDAP_BIND_PASSWORD", "s3cret")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LDAP == nil || !cfg.LDAP.Enabled || cfg.LDAP.URL != "ldap://ldap.example.com:389" {
		t.Fatalf("ldap file config not applied: %+v", cfg.LDAP)
	}
	if cfg.LDAP.BindDN != "cn=admin,dc=example,dc=org" ||
		cfg.LDAP.UserFilter != "(uid={username})" ||
		cfg.LDAP.GroupFilter != "(member={dn})" {
		t.Fatalf("ldap fields not applied: %+v", cfg.LDAP)
	}
	if len(cfg.LDAP.RoleGroups.Admin) != 1 ||
		cfg.LDAP.RoleGroups.Admin[0] != "cn=admins,ou=groups,dc=example,dc=org" ||
		len(cfg.LDAP.RoleGroups.Viewer) != 1 || cfg.LDAP.RoleGroups.Viewer[0] != "viewers" {
		t.Fatalf("ldap role_groups not applied: %+v", cfg.LDAP.RoleGroups)
	}
	if !cfg.LDAP.AutoProvision || cfg.LDAP.Timeout().Seconds() != 5 {
		t.Fatalf("ldap auto_provision/timeout not applied: %+v", cfg.LDAP)
	}
	if got := cfg.LDAP.Password(); got != "s3cret" {
		t.Fatalf("ldap bind password = %q, want env value", got)
	}
}

func TestLoadConfigLDAPEnvOnly(t *testing.T) {
	t.Setenv("LDAP_ENABLED", "true")
	t.Setenv("LDAP_URL", "ldaps://ldap.example.com:636")
	t.Setenv("LDAP_TLS_SKIP_VERIFY", "true")
	t.Setenv("LDAP_BIND_DN", "cn=admin,dc=example,dc=org")
	t.Setenv("LDAP_BIND_PASSWORD", "env-secret")
	t.Setenv("LDAP_USER_BASE_DN", "ou=users,dc=example,dc=org")
	t.Setenv("LDAP_USER_FILTER", "(sAMAccountName={username})")
	t.Setenv("LDAP_GROUP_BASE_DN", "ou=groups,dc=example,dc=org")
	t.Setenv("LDAP_GROUP_FILTER", "(member={dn})")
	t.Setenv("LDAP_ROLE_GROUPS", `{"admin":["cn=admins,ou=groups,dc=example,dc=org"],"operator":["cn=ops,ou=groups,dc=example,dc=org"]}`)
	t.Setenv("LDAP_AUTO_PROVISION", "true")
	t.Setenv("LDAP_TIMEOUT_SECONDS", "7")

	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LDAP == nil || !cfg.LDAP.Enabled || !cfg.LDAP.TLSSkipVerify ||
		cfg.LDAP.URL != "ldaps://ldap.example.com:636" ||
		cfg.LDAP.BindDN != "cn=admin,dc=example,dc=org" ||
		cfg.LDAP.UserFilter != "(sAMAccountName={username})" ||
		!cfg.LDAP.AutoProvision || cfg.LDAP.Timeout().Seconds() != 7 {
		t.Fatalf("ldap env-only config not applied: %+v", cfg.LDAP)
	}
	if cfg.LDAP.BindPasswordEnv != "LDAP_BIND_PASSWORD" {
		t.Fatalf("bind_password_env = %q, want default LDAP_BIND_PASSWORD", cfg.LDAP.BindPasswordEnv)
	}
	if got := cfg.LDAP.Password(); got != "env-secret" {
		t.Fatalf("ldap bind password = %q, want env value", got)
	}
	if len(cfg.LDAP.RoleGroups.Admin) != 1 || cfg.LDAP.RoleGroups.Admin[0] != "cn=admins,ou=groups,dc=example,dc=org" ||
		len(cfg.LDAP.RoleGroups.Operator) != 1 || cfg.LDAP.RoleGroups.Operator[0] != "cn=ops,ou=groups,dc=example,dc=org" {
		t.Fatalf("LDAP_ROLE_GROUPS JSON not applied: %+v", cfg.LDAP.RoleGroups)
	}
}

func TestLoadConfigLDAPEnvPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	content := []byte(`
ldap:
  enabled: true
  url: "ldap://file.example.com:389"
  bind_dn: "cn=admin,dc=file,dc=org"
  bind_password_env: "LDAP_BIND_PASSWORD"
  user_base_dn: "ou=users,dc=file,dc=org"
  user_filter: "(uid={username})"
  role_groups:
    viewer: ["viewers"]
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LDAP_BIND_PASSWORD", "pw")
	t.Setenv("LDAP_ENABLED", "false")
	t.Setenv("LDAP_URL", "ldap://env.example.com:389")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LDAP.Enabled {
		t.Fatal("LDAP_ENABLED=false must override file value")
	}
	if cfg.LDAP.URL != "ldap://env.example.com:389" {
		t.Fatalf("LDAP_URL = %q, want env value", cfg.LDAP.URL)
	}
}

func TestLoadConfigLDAPInvalidEnv(t *testing.T) {
	t.Setenv("LDAP_TIMEOUT_SECONDS", "abc")
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("invalid LDAP_TIMEOUT_SECONDS must fail config load")
	}

	t.Setenv("LDAP_TIMEOUT_SECONDS", "")
	t.Setenv("LDAP_ROLE_GROUPS", "{not-json")
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("invalid LDAP_ROLE_GROUPS JSON must fail config load")
	}

	t.Setenv("LDAP_ROLE_GROUPS", "")
	t.Setenv("LDAP_ENABLED", "maybe")
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("invalid LDAP_ENABLED must fail config load")
	}
}
