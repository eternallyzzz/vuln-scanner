package container

import (
	"fmt"
	"regexp"
	"time"
)

type Config struct {
	Enabled             bool     `mapstructure:"enabled"`
	DockerHost          string   `mapstructure:"docker_host"`
	Images              []string `mapstructure:"images"`
	ImageFilter         string   `mapstructure:"image_filter"`
	Exclude             []string `mapstructure:"exclude"`
	TrivyImage          string   `mapstructure:"trivy_image"`
	TrivyCacheVolume    string   `mapstructure:"trivy_cache_volume"`
	AgentID             string   `mapstructure:"agent_id"`
	AgentHostname       string   `mapstructure:"agent_hostname"`
	TenantID            int64    `mapstructure:"tenant_id"`
	ScanIntervalMinutes int      `mapstructure:"scan_interval_minutes"`
	TimeoutMinutes      int      `mapstructure:"timeout_minutes"`
	MaxImages           int      `mapstructure:"max_images"`
}

// Validate fills defaults and rejects invalid values when scanning is enabled.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	if c.DockerHost == "" {
		c.DockerHost = "unix:///var/run/docker.sock"
	}
	if c.TrivyImage == "" {
		c.TrivyImage = "aquasec/trivy:latest"
	}
	if c.TrivyCacheVolume == "" {
		c.TrivyCacheVolume = "vulnscan-trivy-cache"
	}
	if c.AgentID == "" {
		c.AgentID = "agent-container-docker"
	}
	if c.AgentHostname == "" {
		c.AgentHostname = "docker-host"
	}
	if c.TenantID <= 0 {
		c.TenantID = 1
	}
	if c.ScanIntervalMinutes == 0 {
		c.ScanIntervalMinutes = 360
	}
	if c.ScanIntervalMinutes < 15 {
		return fmt.Errorf("container_scan.scan_interval_minutes must be >= 15")
	}
	if c.TimeoutMinutes == 0 {
		c.TimeoutMinutes = 20
	}
	if c.TimeoutMinutes < 1 {
		return fmt.Errorf("container_scan.timeout_minutes must be >= 1")
	}
	if c.MaxImages == 0 {
		c.MaxImages = 100
	}
	if c.MaxImages < 1 {
		return fmt.Errorf("container_scan.max_images must be >= 1")
	}
	if c.ImageFilter != "" {
		if _, err := regexp.Compile(c.ImageFilter); err != nil {
			return fmt.Errorf("container_scan.image_filter is not a valid regexp: %w", err)
		}
	}
	return nil
}

func (c *Config) ResolvedTimeout() time.Duration {
	return time.Duration(c.TimeoutMinutes) * time.Minute
}
