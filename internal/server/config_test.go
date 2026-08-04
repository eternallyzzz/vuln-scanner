package server

import (
	"testing"
	"time"
)

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
