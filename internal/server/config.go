package server

import (
	"os"

	"github.com/spf13/viper"

	"vuln-scanner/internal/alert"
	"vuln-scanner/internal/container"
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
	NVDAPIKey string `mapstructure:"nvd_api_key"`
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
