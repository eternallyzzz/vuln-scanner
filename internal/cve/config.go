package cve

import (
	"fmt"
	"time"
)

// Config controls refresh cadence and cache TTLs for the external CVE feeds.
type Config struct {
	MSRCRefresh   time.Duration
	NVDRefresh    time.Duration
	OSVRefresh    time.Duration
	DebianRefresh time.Duration
	RedHatRefresh time.Duration
	UbuntuRefresh time.Duration
	AlpineRefresh time.Duration

	MSRCTTL   time.Duration
	NVDTTL    time.Duration
	OSVTTL    time.Duration
	DebianTTL time.Duration
	RedHatTTL time.Duration
	UbuntuTTL time.Duration
	AlpineTTL time.Duration
}

// DefaultConfig returns the production defaults matching the previous
// hard-coded worker schedule and feed TTLs.
func DefaultConfig() *Config {
	return &Config{
		MSRCRefresh:   time.Hour,
		NVDRefresh:    3 * time.Hour,
		OSVRefresh:    6 * time.Hour,
		DebianRefresh: 6 * time.Hour,
		RedHatRefresh: 24 * time.Hour,
		UbuntuRefresh: 6 * time.Hour,
		AlpineRefresh: 6 * time.Hour,

		MSRCTTL:   30 * 24 * time.Hour,
		NVDTTL:    7 * 24 * time.Hour,
		OSVTTL:    12 * time.Hour,
		DebianTTL: 7 * 24 * time.Hour,
		RedHatTTL: 24 * time.Hour,
		UbuntuTTL: 12 * time.Hour,
		AlpineTTL: 12 * time.Hour,
	}
}

// Normalized returns a copy with safe minimums applied. A nil receiver falls
// back to DefaultConfig.
func (c *Config) Normalized() *Config {
	if c == nil {
		return DefaultConfig()
	}
	out := *c
	minRefresh := time.Hour
	if out.MSRCRefresh < 30*time.Minute {
		out.MSRCRefresh = 30 * time.Minute
	}
	if out.NVDRefresh < minRefresh {
		out.NVDRefresh = minRefresh
	}
	if out.OSVRefresh < minRefresh {
		out.OSVRefresh = minRefresh
	}
	if out.DebianRefresh < minRefresh {
		out.DebianRefresh = minRefresh
	}
	if out.RedHatRefresh < minRefresh {
		out.RedHatRefresh = minRefresh
	}
	if out.UbuntuRefresh < minRefresh {
		out.UbuntuRefresh = minRefresh
	}
	if out.AlpineRefresh < minRefresh {
		out.AlpineRefresh = minRefresh
	}
	if out.MSRCTTL <= 0 || out.MSRCTTL < out.MSRCRefresh {
		out.MSRCTTL = out.MSRCRefresh
	}
	if out.NVDTTL <= 0 || out.NVDTTL < out.NVDRefresh {
		out.NVDTTL = out.NVDRefresh
	}
	if out.OSVTTL <= 0 || out.OSVTTL < out.OSVRefresh {
		out.OSVTTL = out.OSVRefresh
	}
	if out.DebianTTL <= 0 || out.DebianTTL < out.DebianRefresh {
		out.DebianTTL = out.DebianRefresh
	}
	if out.RedHatTTL <= 0 || out.RedHatTTL < out.RedHatRefresh {
		out.RedHatTTL = out.RedHatRefresh
	}
	if out.UbuntuTTL <= 0 || out.UbuntuTTL < out.UbuntuRefresh {
		out.UbuntuTTL = out.UbuntuRefresh
	}
	if out.AlpineTTL <= 0 || out.AlpineTTL < out.AlpineRefresh {
		out.AlpineTTL = out.AlpineRefresh
	}
	return &out
}

func (c *Config) String() string {
	if c == nil {
		c = DefaultConfig()
	}
	return fmt.Sprintf("msrc=%s/%s nvd=%s/%s osv=%s/%s debian=%s/%s redhat=%s/%s ubuntu=%s/%s alpine=%s/%s",
		c.MSRCRefresh, c.MSRCTTL,
		c.NVDRefresh, c.NVDTTL,
		c.OSVRefresh, c.OSVTTL,
		c.DebianRefresh, c.DebianTTL,
		c.RedHatRefresh, c.RedHatTTL,
		c.UbuntuRefresh, c.UbuntuTTL,
		c.AlpineRefresh, c.AlpineTTL)
}
