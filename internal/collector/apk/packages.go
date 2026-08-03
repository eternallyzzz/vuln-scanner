//go:build linux || darwin

// Package apk collects installed packages for Alpine Linux from the apk
// installed database.
package apk

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"vuln-scanner/internal/collector"
	"vuln-scanner/internal/collector/linuxinfo"
)

const installedDB = "/lib/apk/db/installed"

// Collector implements collector.Collector for Alpine Linux.
type Collector struct{}

// New returns a new apk collector.
func New() *Collector {
	return &Collector{}
}

// CollectPackages parses the apk installed database. Package records are
// blocks of "X:value" lines separated by blank lines.
func (c *Collector) CollectPackages(ctx context.Context) ([]collector.Asset, error) {
	f, err := os.Open(installedDB)
	if err != nil {
		return nil, fmt.Errorf("apk db: %w", err)
	}
	defer f.Close()
	return parseInstalledDB(f), nil
}

// CollectHotfixes is not applicable to Alpine (updates are full package
// version changes).
func (c *Collector) CollectHotfixes(ctx context.Context) ([]collector.Asset, error) {
	return nil, nil
}

// SystemInfo reports the shared Linux profile; os-release supplies the OS name
// and version (e.g. "alpine linux" / "3.23.3").
func (c *Collector) SystemInfo(ctx context.Context) (collector.SystemInfo, error) {
	return linuxinfo.SystemInfo()
}

type apkPackage struct {
	name    string
	version string
	arch    string
	vendor  string
}

func parseInstalledDB(r io.Reader) []collector.Asset {
	var assets []collector.Asset
	var pkg *apkPackage

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if pkg != nil && pkg.name != "" && pkg.version != "" {
				assets = append(assets, pkg.toAsset())
			}
			pkg = nil
			continue
		}
		if pkg == nil {
			pkg = &apkPackage{}
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		value := strings.TrimSpace(line[2:])
		switch line[0] {
		case 'P':
			pkg.name = value
		case 'V':
			pkg.version = value
		case 'A':
			pkg.arch = value
		case 'm':
			pkg.vendor = value
		}
	}
	if pkg != nil && pkg.name != "" && pkg.version != "" {
		assets = append(assets, pkg.toAsset())
	}
	return assets
}

func (p *apkPackage) toAsset() collector.Asset {
	return collector.Asset{
		Name:    p.name,
		Version: p.version,
		Arch:    p.arch,
		Format:  "apk",
		Vendor:  p.vendor,
		Type:    "PACKAGE",
	}
}
