package server

import (
	"os"
	"time"

	"github.com/spf13/viper"

	"vuln-scanner/internal/alert"
	"vuln-scanner/internal/container"
	"vuln-scanner/internal/cve"
	"vuln-scanner/internal/patch"
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
	CVE           *CVEScanConfig    `mapstructure:"cve"`
	LLM           *LLMConfig        `mapstructure:"llm"`
	Alerting      *alert.Config     `mapstructure:"alerting"`
	Patch         *patch.Config     `mapstructure:"patch"`
	ContainerScan *container.Config `mapstructure:"container_scan"`
}

func DefaultConfig() *Config {
	return &Config{
		GRPCAddr:    ":9090",
		HTTPAddr:    ":8080",
		DatabaseURL: "postgres://vulnscan:vulnscan@localhost:5432/vulnscan?sslmode=disable",
		JWTSecret:   "change-me-in-production",
		APIKey:      "sk-change-me",
	}
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		v.SetConfigFile("server.yaml")
		if err2 := v.ReadInConfig(); err2 != nil {
			return cfg, nil
		}
	}

	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}

	cfg.JWTSecret = os.ExpandEnv(cfg.JWTSecret)
	cfg.APIKey = os.ExpandEnv(cfg.APIKey)
	cfg.DatabaseURL = os.ExpandEnv(cfg.DatabaseURL)
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
