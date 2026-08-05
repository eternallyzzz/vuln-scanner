//go:build linux || darwin

package compliance

import (
	"context"
	"os"
	"strconv"
	"strings"

	"vuln-scanner/internal/collector"
)

// CollectFacts gathers Linux facts from the latest SystemInfo plus a few
// direct file reads and one best-effort ufw query. Every gatherer is
// fail-safe: unreadable paths leave nil/empty fields that map to na.
func CollectFacts(_ context.Context, sys collector.SystemInfo) Facts {
	return Facts{
		Platform:       "linux",
		FirewallRules:  sys.FirewallRules,
		Services:       sys.Services,
		DiskEncryption: sys.DiskEncryption,
		SELinux:        sys.SELinux,
		AppArmor:       sys.AppArmor,
		SSHDConfig:     readFile("/etc/ssh/sshd_config"),
		RandomizeVA:    readIntFile("/proc/sys/kernel/randomize_va_space"),
		IPForward:      readIntFile("/proc/sys/net/ipv4/ip_forward"),
		ShadowText:     readFile("/etc/shadow"),
		UFWActive:      ufwActive(),
	}
}

func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func readIntFile(path string) *int {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return nil
	}
	return &n
}

func ufwActive() bool {
	out, err := collector.RunTimeout("ufw", "status")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "status: active")
}
