//go:build windows

package main

import (
	"os"

	"vuln-scanner/internal/collector"
	"vuln-scanner/internal/collector/sca"
	colWindows "vuln-scanner/internal/collector/windows"
)

func platformCollector() collector.Collector {
	inner := colWindows.New()
	scanDirs := []string{}
	if home, err := os.UserHomeDir(); err == nil {
		scanDirs = append(scanDirs, home)
	}
	return sca.NewDecorator(inner, scanDirs)
}
