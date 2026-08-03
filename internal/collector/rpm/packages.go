//go:build linux || darwin

// Package rpm collects installed RPM packages for rpm-based distributions.
package rpm

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"vuln-scanner/internal/collector"
	"vuln-scanner/internal/collector/linuxinfo"
)

// Collector implements collector.Collector for rpm-based systems.
type Collector struct{}

// New returns a new rpm collector.
func New() *Collector {
	return &Collector{}
}

// CollectPackages lists installed packages via `rpm -qa`. The query format
// emits one record per package separated by the unit separator byte.
func (c *Collector) CollectPackages(ctx context.Context) ([]collector.Asset, error) {
	cmd := exec.CommandContext(ctx, "rpm", "-qa", "--qf",
		"%{NAME}\x1f%{EPOCHNUM}\x1f%{VERSION}\x1f%{RELEASE}\x1f%{ARCH}\x1f%{INSTALLTIME}\x1f%{VENDOR}\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("rpm -qa: %w", err)
	}
	return parseRPMQuery(string(out)), nil
}

// CollectHotfixes is not applicable to rpm systems (updates are full package
// version changes).
func (c *Collector) CollectHotfixes(ctx context.Context) ([]collector.Asset, error) {
	return nil, nil
}

// SystemInfo reports the shared Linux profile plus os-release fields.
func (c *Collector) SystemInfo(ctx context.Context) (collector.SystemInfo, error) {
	return linuxinfo.SystemInfo()
}

// parseRPMQuery parses `rpm -qa --qf` output into assets. Each line is
// name\x1fepoch\x1fversion\x1frelease\x1farch\x1finstalltime\x1fvendor.
func parseRPMQuery(output string) []collector.Asset {
	var assets []collector.Asset
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\x1f")
		if len(fields) < 5 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		epoch := strings.TrimSpace(fields[1])
		version := strings.TrimSpace(fields[2])
		release := strings.TrimSpace(fields[3])
		arch := strings.TrimSpace(fields[4])
		if name == "" || version == "" || release == "" {
			continue
		}
		installDate := ""
		if len(fields) > 5 {
			installDate = formatInstallTime(strings.TrimSpace(fields[5]))
		}
		vendor := ""
		if len(fields) > 6 {
			vendor = strings.TrimSpace(fields[6])
		}
		assets = append(assets, collector.Asset{
			Name:        name,
			Version:     evrString(epoch, version, release),
			Arch:        arch,
			Format:      "rpm",
			Vendor:      vendor,
			InstallDate: installDate,
			Type:        "PACKAGE",
		})
	}
	return assets
}

// evrString builds `[epoch:]version-release`, omitting the epoch when it is
// missing or zero.
func evrString(epoch, version, release string) string {
	base := version + "-" + release
	if epoch == "" || epoch == "(none)" || epoch == "0" {
		return base
	}
	return epoch + ":" + base
}

func formatInstallTime(raw string) string {
	if raw == "" || raw == "(none)" {
		return ""
	}
	secs, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || secs <= 0 {
		return raw
	}
	return time.Unix(secs, 0).UTC().Format("2006-01-02T15:04:05Z")
}
