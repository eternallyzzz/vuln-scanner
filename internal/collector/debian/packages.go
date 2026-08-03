//go:build linux || darwin

package debian

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"vuln-scanner/internal/collector"
	"vuln-scanner/internal/collector/linuxinfo"
)

type Collector struct{}

func New() *Collector {
	return &Collector{}
}

func (c *Collector) CollectPackages(ctx context.Context) ([]collector.Asset, error) {
	var assets []collector.Asset

	dpkgPkgs, err := c.collectDpkgPackages(ctx)
	if err != nil {
		return nil, fmt.Errorf("dpkg: %w", err)
	}
	assets = append(assets, dpkgPkgs...)

	snapPkgs, err := c.collectSnapPackages(ctx)
	if err == nil {
		assets = append(assets, snapPkgs...)
	}

	return assets, nil
}

func (c *Collector) collectDpkgPackages(ctx context.Context) ([]collector.Asset, error) {
	const statusFile = "/var/lib/dpkg/status"
	f, err := os.Open(statusFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var assets []collector.Asset
	var pkg *dpkgPackage

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			if pkg != nil && pkg.installed {
				assets = append(assets, pkg.toAsset())
			}
			pkg = nil
			continue
		}

		if pkg == nil {
			pkg = &dpkgPackage{}
		}

		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])

		switch key {
		case "Package":
			pkg.name = value
		case "Version":
			pkg.version = value
		case "Architecture":
			pkg.arch = value
		case "Maintainer":
			pkg.vendor = value
		case "Installed-Size":
			pkg.size = value
		case "Section":
			pkg.section = value
		case "Priority":
			pkg.priority = value
		case "Multi-Arch":
			pkg.multiarch = value
		case "Source":
			pkg.source = value
		case "Description":
			pkg.description = value
		case "Status":
			pkg.installed = strings.Contains(value, "installed")
		}
	}

	if pkg != nil && pkg.installed {
		assets = append(assets, pkg.toAsset())
	}

	return assets, nil
}

func (c *Collector) collectSnapPackages(ctx context.Context) ([]collector.Asset, error) {
	cmd := exec.CommandContext(ctx, "snap", "list")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var assets []collector.Asset
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			assets = append(assets, collector.Asset{
				Name:    fields[0],
				Version: fields[1],
				Format:  "snap",
				Vendor:  "SnapCraft",
				Type:    "PACKAGE",
			})
		}
	}
	return assets, nil
}

func (c *Collector) CollectHotfixes(ctx context.Context) ([]collector.Asset, error) {
	return nil, nil
}

func (c *Collector) SystemInfo(ctx context.Context) (collector.SystemInfo, error) {
	return linuxinfo.SystemInfo()
}

type dpkgPackage struct {
	name        string
	version     string
	arch        string
	vendor      string
	size        string
	section     string
	priority    string
	multiarch   string
	source      string
	description string
	installed   bool
}

func (p *dpkgPackage) toAsset() collector.Asset {
	return collector.Asset{
		Name:    p.name,
		Version: p.version,
		Arch:    p.arch,
		Format:  "deb",
		Vendor:  p.vendor,
		Type:    "PACKAGE",
	}
}

func (c *Collector) DpkgLogPatches(ctx context.Context) ([]collector.Asset, error) {
	const logFile = "/var/log/dpkg.log"
	f, err := os.Open(logFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var assets []collector.Asset
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, " installed ") || strings.Contains(line, " upgrade ") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				date := parts[0] + "T" + parts[1]
				pkg := parts[3]
				for i := 4; i < len(parts); i++ {
					if strings.Contains(parts[i], ":") {
						break
					}
					pkg = parts[i]
				}
				assets = append(assets, collector.Asset{
					Name:        pkg,
					InstallDate: date,
					Format:      "deb",
					Type:        "HOTFIX",
				})
			}
		}
	}
	return assets, nil
}
