package sca

import (
	"os"

	"vuln-scanner/internal/collector"

	"golang.org/x/mod/modfile"
)

func parseGoMod(path string) []collector.Asset {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	mf, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return nil
	}

	var assets []collector.Asset
	if mf.Module != nil && mf.Module.Mod.Path != "" {
		assets = append(assets, collector.Asset{
			Name:    mf.Module.Mod.Path,
			Version: mf.Module.Mod.Version,
			Format:  "go-mod",
			Vendor:  "go",
		})
	}
	for _, req := range mf.Require {
		if req.Indirect {
			continue
		}
		assets = append(assets, collector.Asset{
			Name:    req.Mod.Path,
			Version: req.Mod.Version,
			Format:  "go-mod",
			Vendor:  "go",
		})
	}
	return assets
}
