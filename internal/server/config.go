package server

import (
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

type Config struct {
	GRPCAddr      string            `mapstructure:"grpc_addr"`
	HTTPAddr      string            `mapstructure:"http_addr"`
	DatabaseURL   string            `mapstructure:"database_url"`
	JWTSecret     string            `mapstructure:"jwt_secret"`
	APIKey        string            `mapstructure:"api_key"`
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

	return cfg, nil
}

func (c *Config) LLMEnabled() bool {
	return c.LLM != nil && c.LLM.APIKey != "" && c.LLM.Provider != ""
}
