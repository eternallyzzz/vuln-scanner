package cve

import (
	"testing"
	"time"
)

func TestDefaultConfigNormalized(t *testing.T) {
	cfg := DefaultConfig().Normalized()
	if cfg.MSRCRefresh != time.Hour {
		t.Fatalf("MSRC refresh = %v, want 1h", cfg.MSRCRefresh)
	}
	if cfg.NVDRefresh != 3*time.Hour {
		t.Fatalf("NVD refresh = %v, want 3h", cfg.NVDRefresh)
	}
	if cfg.OSVTTL != 12*time.Hour {
		t.Fatalf("OSV TTL = %v, want 12h", cfg.OSVTTL)
	}
	if cfg.RedHatRefresh != 24*time.Hour {
		t.Fatalf("Red Hat refresh = %v, want 24h", cfg.RedHatRefresh)
	}
}

func TestNormalizedClamps(t *testing.T) {
	cfg := (&Config{
		MSRCRefresh: time.Minute,
		NVDTTL:      time.Second,
		OSVTTL:      -time.Hour,
	}).Normalized()
	if cfg.MSRCRefresh != 30*time.Minute {
		t.Fatalf("MSRC refresh = %v, want min 30m", cfg.MSRCRefresh)
	}
	if cfg.NVDTTL < cfg.NVDRefresh {
		t.Fatalf("NVD TTL %v must be >= refresh %v", cfg.NVDTTL, cfg.NVDRefresh)
	}
	if cfg.OSVTTL < cfg.OSVRefresh {
		t.Fatalf("OSV TTL %v must be >= refresh %v", cfg.OSVTTL, cfg.OSVRefresh)
	}
}

func TestNilConfigNormalized(t *testing.T) {
	var cfg *Config
	if got := cfg.Normalized(); got == nil {
		t.Fatal("nil Normalized must fall back to defaults")
	}
}
