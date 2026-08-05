package server

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"

	"vuln-scanner/internal/alert"
	"vuln-scanner/internal/container"
	"vuln-scanner/internal/cve"
	"vuln-scanner/internal/patch"
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
}

func DefaultConfig() *Config {
	return &Config{
		GRPCAddr:    ":9090",
		HTTPAddr:    ":8080",
		DatabaseURL: "postgres://vulnscan:vulnscan@localhost:5432/vulnscan?sslmode=disable",
		JWTSecret:   "change-me-in-production",
		APIKey:      "sk-change-me",
		Reporting:   report.DefaultConfig(),
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

	return cfg, nil
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
