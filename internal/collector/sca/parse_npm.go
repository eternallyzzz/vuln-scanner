package sca

import (
	"encoding/json"
	"os"
	"strings"

	"vuln-scanner/internal/collector"
)

func parseNPM(path string) []collector.Asset {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var pkg struct {
		Name         string            `json:"name"`
		Version      string            `json:"version"`
		Dependencies map[string]string `json:"dependencies"`
		DevDeps      map[string]string `json:"devDependencies"`
	}
	if err := json.NewDecoder(f).Decode(&pkg); err != nil {
		return nil
	}

	var assets []collector.Asset
	if pkg.Name != "" {
		assets = append(assets, collector.Asset{
			Name:    pkg.Name,
			Version: dedupeVersion(pkg.Version),
			Format:  "npm",
			Vendor:  "npm",
		})
	}

	for name, ver := range pkg.Dependencies {
		assets = append(assets, collector.Asset{
			Name:    strings.TrimSpace(name),
			Version: dedupeVersion(ver),
			Format:  "npm",
			Vendor:  "npm",
		})
	}
	for name, ver := range pkg.DevDeps {
		assets = append(assets, collector.Asset{
			Name:    strings.TrimSpace(name),
			Version: dedupeVersion(ver),
			Format:  "npm",
			Vendor:  "npm",
		})
	}
	return assets
}
