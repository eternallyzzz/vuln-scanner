package sca

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"vuln-scanner/internal/collector"
)

type Decorator struct {
	Inner    collector.Collector
	scanDirs []string
}

func NewDecorator(inner collector.Collector, scanDirs []string) *Decorator {
	if len(scanDirs) == 0 {
		scanDirs = []string{"/", "C:\\"}
	}
	return &Decorator{Inner: inner, scanDirs: scanDirs}
}

func (d *Decorator) CollectPackages(ctx context.Context) ([]collector.Asset, error) {
	base, err := d.Inner.CollectPackages(ctx)
	sca := d.scan(ctx)
	return append(base, sca...), err
}

func (d *Decorator) CollectHotfixes(ctx context.Context) ([]collector.Asset, error) {
	return d.Inner.CollectHotfixes(ctx)
}

func (d *Decorator) SystemInfo(ctx context.Context) (collector.SystemInfo, error) {
	return d.Inner.SystemInfo(ctx)
}

type fileParser func(path string) []collector.Asset

var parsers = map[string]fileParser{
	"go.mod":           parseGoMod,
	"package.json":     parseNPM,
	"requirements.txt": parsePyPI,
	"pom.xml":          parseMaven,
}

func (d *Decorator) scan(ctx context.Context) []collector.Asset {
	var all []collector.Asset
	for _, root := range d.scanDirs {
		walkDepth(root, 0, 5, func(path string, info os.DirEntry) {
			name := info.Name()
			if parser, ok := parsers[name]; ok {
				assets := parser(path)
				for i := range assets {
					assets[i].Location = path
					assets[i].Type = "PACKAGE"
				}
				all = append(all, assets...)
			}
		})
	}
	return all
}

func walkDepth(dir string, depth, maxDepth int, fn func(string, os.DirEntry)) {
	if depth > maxDepth {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			if shallowSkip(path) {
				continue
			}
			walkDepth(path, depth+1, maxDepth, fn)
		} else {
			fn(path, entry)
		}
	}
}

func shallowSkip(path string) bool {
	base := filepath.Base(path)
	skip := map[string]bool{
		"node_modules": true,
		"vendor":       true,
		".git":         true,
		"target":       true,
		"__pycache__":  true,
		"venv":         true,
		".venv":        true,
		"env":          true,
	}
	return skip[base]
}

func dedupeVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	v = strings.TrimPrefix(v, "=")
	v = strings.TrimPrefix(v, "^")
	v = strings.TrimPrefix(v, "~")
	v = strings.TrimPrefix(v, ">")
	v = strings.TrimPrefix(v, "<")
	v = strings.TrimPrefix(v, "!")
	v = strings.TrimSpace(v)
	return v
}
