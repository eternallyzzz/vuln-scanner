//go:build windows

package main

import (
	"os"

	"vuln-scanner/internal/collector"
	"vuln-scanner/internal/collector/sca"
	colWindows "vuln-scanner/internal/collector/windows"
)

func platformCollector(wuaEnabled bool, wuaTimeoutSeconds int) collector.Collector {
	inner := colWindows.New()
	inner.SetWUAEnabled(wuaEnabled)
	inner.SetWUATimeout(wuaTimeoutSeconds)
	scanDirs := []string{}
	if home, err := os.UserHomeDir(); err == nil {
		scanDirs = append(scanDirs, home)
	}
	return sca.NewDecorator(inner, scanDirs)
}
