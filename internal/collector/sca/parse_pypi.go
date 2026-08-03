package sca

import (
	"bufio"
	"os"
	"strings"

	"vuln-scanner/internal/collector"
)

func parsePyPI(path string) []collector.Asset {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var assets []collector.Asset
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		var name, ver string
		for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">", "<", "~"} {
			if idx := strings.Index(line, sep); idx > 0 {
				name = strings.TrimSpace(line[:idx])
				ver = strings.TrimSpace(line[idx+len(sep):])
				break
			}
		}
		if name == "" {
			name = line
		}
		name = strings.TrimRight(name, ";\\ ")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		assets = append(assets, collector.Asset{
			Name:    name,
			Version: dedupeVersion(ver),
			Format:  "pypi",
			Vendor:  "PyPI",
		})
	}
	return assets
}
