package server

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"

	"vuln-scanner/internal/alert"
	"vuln-scanner/internal/container"
	"vuln-scanner/internal/cve"
	"vuln-scanner/internal/ldap"
	"vuln-scanner/internal/patch"
	"vuln-scanner/internal/remotescan"
	"vuln-scanner/internal/report"
)

type LLMConfig struct {
	Provider    string   `mapstructure:"provider"`
	APIKey      string   `mapstructure:"api_key"`
	Model       string   `mapstructure:"model"`
	BaseURL     string   `mapstructure:"base_url"`
	AutoAnalyze []string `mapstructure:"auto_analyze"`
}

type CVEScanConfig struct {
	NVDAPIKey          string `mapstructure:"nvd_api_key"`
	MSRCRefreshMinutes int    `mapstructure:"msrc_refresh_minutes"`
	NVDRefreshHours    int    `mapstructure:"nvd_refresh_hours"`
	OSVRefreshHours    int    `mapstructure:"osv_refresh_hours"`
	DebianRefreshHours int    `mapstructure:"debian_refresh_hours"`
	RedHatRefreshHours int    `mapstructure:"redhat_refresh_hours"`
	MSRCTTLHours       int    `mapstructure:"msrc_ttl_hours"`
	NVDTTLHours        int    `mapstructure:"nvd_ttl_hours"`
	OSVTTLHours        int    `mapstructure:"osv_ttl_hours"`
	DebianTTLHours     int    `mapstructure:"debian_ttl_hours"`
	RedHatTTLHours     int    `mapstructure:"redhat_ttl_hours"`
}

type Config struct {
	GRPCAddr      string            `mapstructure:"grpc_addr"`
	HTTPAddr      string            `mapstructure:"http_addr"`
	DatabaseURL   string            `mapstructure:"database_url"`
	JWTSecret     string            `mapstructure:"jwt_secret"`
	APIKey        string            `mapstructure:"api_key"`
	ServerURL     string            `mapstructure:"server_url"`
	CVE           *CVEScanConfig    `mapstructure:"cve"`
	LLM           *LLMConfig        `mapstructure:"llm"`
	Alerting      *alert.Config     `mapstructure:"alerting"`
	Patch         *patch.Config     `mapstructure:"patch"`
	ContainerScan *container.Config `mapstructure:"container_scan"`
	Reporting     *report.Config    `mapstructure:"reporting"`
	LDAP          *ldap.Config      `mapstructure:"ldap"`
	RemoteScan    *remotescan.Config `mapstructure:"remote_scan"`
}

func DefaultConfig() *Config {
	return &Config{
		GRPCAddr:    ":9090",
		HTTPAddr:    ":8080",
		DatabaseURL: "postgres://vulnscan:vulnscan@localhost:5432/vulnscan?sslmode=disable",
		JWTSecret:   "change-me-in-production",
		APIKey:      "sk-change-me",
		Reporting:   report.DefaultConfig(),
		RemoteScan:  remotescan.DefaultConfig(),
	}
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	v := viper.New()
	v.SetConfigType("yaml")
	v.AutomaticEnv()
	bindCoreEnv(v)

	loaded := false
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read config %s: %w", path, err)
		}
	} else {
		loaded = true
	}
	if !loaded {
		v.SetConfigFile("server.yaml")
		if err := v.ReadInConfig(); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("read config server.yaml: %w", err)
		}
	}

	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}

	cfg.JWTSecret = os.ExpandEnv(cfg.JWTSecret)
	cfg.APIKey = os.ExpandEnv(cfg.APIKey)
	cfg.DatabaseURL = os.ExpandEnv(cfg.DatabaseURL)
	cfg.ServerURL = os.ExpandEnv(cfg.ServerURL)
	if cfg.Reporting == nil {
		cfg.Reporting = report.DefaultConfig()
	}
	if raw := os.Getenv("REPORTING_ENABLED"); raw != "" {
		cfg.Reporting.Enabled = strings.EqualFold(strings.TrimSpace(raw), "true") ||
			strings.TrimSpace(raw) == "1"
	}
	if raw := os.Getenv("REPORTING_SCHEDULE"); raw != "" {
		cfg.Reporting.Schedule = strings.TrimSpace(raw)
	}
	if raw := os.Getenv("REPORTING_TIMEZONE"); raw != "" {
		cfg.Reporting.Timezone = strings.TrimSpace(raw)
	}
	if raw := os.Getenv("REPORTING_TO"); raw != "" {
		cfg.Reporting.To = splitCommaList(raw)
	}
	if cfg.CVE == nil {
		cfg.CVE = &CVEScanConfig{}
	}
	cfg.CVE.NVDAPIKey = os.ExpandEnv(cfg.CVE.NVDAPIKey)
	if cfg.LLM != nil {
		cfg.LLM.APIKey = os.ExpandEnv(cfg.LLM.APIKey)
		cfg.LLM.BaseURL = os.ExpandEnv(cfg.LLM.BaseURL)
	}
	if cfg.LDAP == nil {
		cfg.LDAP = &ldap.Config{}
	}
	if err := applyLDAPEnv(cfg.LDAP); err != nil {
		return nil, fmt.Errorf("apply ldap env: %w", err)
	}
	if cfg.RemoteScan == nil {
		cfg.RemoteScan = remotescan.DefaultConfig()
	}
	if err := applyRemoteScanEnv(cfg.RemoteScan); err != nil {
		return nil, fmt.Errorf("apply remote scan env: %w", err)
	}
	if err := cfg.RemoteScan.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// applyRemoteScanEnv applies REMOTE_SCAN_* environment overrides on top of
// any server.yaml remote_scan section. The master key itself is read from
// the environment variable named by master_key_env (default
// REMOTE_SCAN_MASTER_KEY) and is never written to server.yaml.
func applyRemoteScanEnv(c *remotescan.Config) error {
	setString := func(envName string, dst *string) {
		if raw := os.Getenv(envName); raw != "" {
			*dst = os.ExpandEnv(raw)
		}
	}
	setBool := func(envName string, dst *bool) error {
		raw := os.Getenv(envName)
		if raw == "" {
			return nil
		}
		v, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("%s must be true or false: %w", envName, err)
		}
		*dst = v
		return nil
	}
	setInt := func(envName string, dst *int) error {
		raw := os.Getenv(envName)
		if raw == "" {
			return nil
		}
		v, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("%s must be an integer: %w", envName, err)
		}
		*dst = v
		return nil
	}

	setString("REMOTE_SCAN_MASTER_KEY_ENV", &c.MasterKeyEnv)
	if err := setBool("REMOTE_SCAN_ENABLED", &c.Enabled); err != nil {
		return err
	}
	if err := setInt("REMOTE_SCAN_TIMEOUT_SECONDS", &c.TimeoutSeconds); err != nil {
		return err
	}
	if err := setInt("REMOTE_SCAN_CONCURRENCY", &c.Concurrency); err != nil {
		return err
	}
	return nil
}

// applyLDAPEnv applies LDAP_* environment overrides on top of any
// server.yaml ldap section. LDAP_ROLE_GROUPS is a JSON object such as
// {"admin":["cn=admins,..."],"operator":["cn=ops,..."]}; the bind password
// itself is read from the environment variable named by bind_password_env.
func applyLDAPEnv(c *ldap.Config) error {
	c.URL = os.ExpandEnv(c.URL)
	c.BindDN = os.ExpandEnv(c.BindDN)
	c.BindPasswordEnv = os.ExpandEnv(c.BindPasswordEnv)
	c.UserBaseDN = os.ExpandEnv(c.UserBaseDN)
	c.UserFilter = os.ExpandEnv(c.UserFilter)
	c.GroupBaseDN = os.ExpandEnv(c.GroupBaseDN)
	c.GroupFilter = os.ExpandEnv(c.GroupFilter)

	setString := func(envName string, dst *string) {
		if raw := os.Getenv(envName); raw != "" {
			*dst = os.ExpandEnv(raw)
		}
	}
	setBool := func(envName string, dst *bool) error {
		raw := os.Getenv(envName)
		if raw == "" {
			return nil
		}
		v, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("%s must be true or false: %w", envName, err)
		}
		*dst = v
		return nil
	}

	setString("LDAP_URL", &c.URL)
	setString("LDAP_BIND_DN", &c.BindDN)
	setString("LDAP_BIND_PASSWORD_ENV", &c.BindPasswordEnv)
	setString("LDAP_USER_BASE_DN", &c.UserBaseDN)
	setString("LDAP_USER_FILTER", &c.UserFilter)
	setString("LDAP_GROUP_BASE_DN", &c.GroupBaseDN)
	setString("LDAP_GROUP_FILTER", &c.GroupFilter)
	if err := setBool("LDAP_ENABLED", &c.Enabled); err != nil {
		return err
	}
	if err := setBool("LDAP_TLS_SKIP_VERIFY", &c.TLSSkipVerify); err != nil {
		return err
	}
	if err := setBool("LDAP_AUTO_PROVISION", &c.AutoProvision); err != nil {
		return err
	}
	if raw := os.Getenv("LDAP_TIMEOUT_SECONDS"); raw != "" {
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || n <= 0 {
			return fmt.Errorf("LDAP_TIMEOUT_SECONDS must be a positive integer")
		}
		c.TimeoutSeconds = n
	}
	if raw := os.Getenv("LDAP_ROLE_GROUPS"); raw != "" {
		var rg ldap.RoleGroups
		if err := json.Unmarshal([]byte(raw), &rg); err != nil {
			return fmt.Errorf("LDAP_ROLE_GROUPS must be valid JSON: %w", err)
		}
		c.RoleGroups = rg
	}
	// Convenience for env-only deployments: when bind_password_env is not
	// set but LDAP_BIND_PASSWORD is, use it directly.
	if c.BindPasswordEnv == "" && os.Getenv("LDAP_BIND_PASSWORD") != "" {
		c.BindPasswordEnv = "LDAP_BIND_PASSWORD"
	}
	return nil
}

// bindCoreEnv registers the environment variables that must work even when
// the server runs without a config file (e.g. the container image). Viper
// only exposes environment values for keys it knows about, so without these
// bindings an env-only deployment would silently fall back to defaults.
func bindCoreEnv(v *viper.Viper) {
	for _, key := range []string{
		"grpc_addr",
		"http_addr",
		"database_url",
		"jwt_secret",
		"api_key",
		"server_url",
		"reporting.enabled",
		"reporting.schedule",
		"reporting.timezone",
		"reporting.to",
	} {
		_ = v.BindEnv(key)
	}
	// Nested keys cannot use the automatic mapping: viper would turn
	// "cve.nvd_api_key" into "CVE.NVD_API_KEY", which is not a valid
	// environment variable name. Bind the real variable explicitly.
	_ = v.BindEnv("cve.nvd_api_key", "NVD_API_KEY")
}

func splitCommaList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func (c *Config) LLMEnabled() bool {
	return c.LLM != nil && c.LLM.APIKey != "" && c.LLM.Provider != ""
}

// FeedConfig maps the optional cve.* settings onto cve.Config, keeping
// DefaultConfig values whenever a field is unset.
func (c *CVEScanConfig) FeedConfig() *cve.Config {
	cfg := cve.DefaultConfig()
	if c == nil {
		return cfg
	}
	if c.MSRCRefreshMinutes > 0 {
		cfg.MSRCRefresh = time.Duration(c.MSRCRefreshMinutes) * time.Minute
	}
	if c.NVDRefreshHours > 0 {
		cfg.NVDRefresh = time.Duration(c.NVDRefreshHours) * time.Hour
	}
	if c.OSVRefreshHours > 0 {
		cfg.OSVRefresh = time.Duration(c.OSVRefreshHours) * time.Hour
	}
	if c.DebianRefreshHours > 0 {
		cfg.DebianRefresh = time.Duration(c.DebianRefreshHours) * time.Hour
	}
	if c.RedHatRefreshHours > 0 {
		cfg.RedHatRefresh = time.Duration(c.RedHatRefreshHours) * time.Hour
	}
	if c.MSRCTTLHours > 0 {
		cfg.MSRCTTL = time.Duration(c.MSRCTTLHours) * time.Hour
	}
	if c.NVDTTLHours > 0 {
		cfg.NVDTTL = time.Duration(c.NVDTTLHours) * time.Hour
	}
	if c.OSVTTLHours > 0 {
		cfg.OSVTTL = time.Duration(c.OSVTTLHours) * time.Hour
	}
	if c.DebianTTLHours > 0 {
		cfg.DebianTTL = time.Duration(c.DebianTTLHours) * time.Hour
	}
	if c.RedHatTTLHours > 0 {
		cfg.RedHatTTL = time.Duration(c.RedHatTTLHours) * time.Hour
	}
	return cfg.Normalized()
}
