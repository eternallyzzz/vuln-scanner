//go:build !windows

package main

import (
	"os"
	"strings"

	"vuln-scanner/internal/collector"
	colAPK "vuln-scanner/internal/collector/apk"
	colDebian "vuln-scanner/internal/collector/debian"
	"vuln-scanner/internal/collector/linuxinfo"

colRPM "vuln-scanner/internal/collector/rpm"

	colRPM "vuln-scanner/internal/collector/rpm"
)

func platformCollector() collector.Collector {
	var inner collector.Collector
	rel := linuxinfo.ReadOSRelease()
	switch strings.ToLower(rel.ID) {
	case "alpine":
		inner = colAPK.New()
	default:
		if isRPMDistro() {
			inner = colRPM.New()
		} else {
			inner = colDebian.New()
		}
	}
	scanDirs := []string{}
	if home, err := os.UserHomeDir(); err == nil {
		scanDirs = append(scanDirs, home)
	}
	return sca.NewDecorator(inner, scanDirs)
}

// isRPMDistro detects rpm-based distributions from /etc/os-release and falls
// back to filesystem markers when os-release is unavailable.
func isRPMDistro() bool {
	rel := linuxinfo.ReadOSRelease()
	id := strings.ToLower(rel.ID)
	idLike := strings.ToLower(rel.IDLike)
	tokens := strings.Fields(id + " " + idLike)
	rpmIDs := map[string]bool{
		"rhel": true, "centos": true, "rocky": true, "almalinux": true,
		"fedora": true, "ol": true, "amzn": true, "sles": true,
		"suse": true, "opensuse": true,
	}
	for _, tok := range tokens {
		if rpmIDs[tok] {
			return true
		}
	}
	// Fallback: an rpmdb without a dpkg database means rpm-based.
	if _, err := os.Stat("/var/lib/rpm"); err == nil {
		if _, err := os.Stat("/var/lib/dpkg/status"); os.IsNotExist(err) {
			return true
		}
	}
	return false
}
