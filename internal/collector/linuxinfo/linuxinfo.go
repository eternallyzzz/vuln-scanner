//go:build linux || darwin

// Package linuxinfo provides Linux system information helpers shared by
// platform collectors (deb/rpm).
package linuxinfo

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"vuln-scanner/internal/collector"
)

// OSRelease holds the parsed fields of /etc/os-release that collectors need.
type OSRelease struct {
	Name    string
	Version string
	ID      string
	IDLike  string
}

// ReadOSRelease parses /etc/os-release. Missing fields fall back to empty
// strings and Name falls back to "linux".
func ReadOSRelease() OSRelease {
	var r OSRelease
	r.Name = "linux"
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return r
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch key {
		case "NAME":
			r.Name = value
		case "VERSION_ID":
			r.Version = value
		case "ID":
			r.ID = value
		case "ID_LIKE":
			r.IDLike = value
		}
	}
	return r
}

// SystemInfo collects the shared parts of a Linux system profile.
func SystemInfo() (collector.SystemInfo, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	rel := ReadOSRelease()
	return collector.SystemInfo{
		Hostname:        hostname,
		OS:              strings.ToLower(rel.Name),
		Version:         rel.Version,
		Arch:            runtime.GOARCH,
		MachineID:       ReadMachineID(),
		CPU:             CPU(),
		GPU:             GPU(),
		MemoryMB:        Memory(),
		NetInterfaces:   NetInterfaces(),
		OpenPorts:       OpenPorts(),
		RunningServices: Services(),
	}, nil
}

// ReadMachineID reads the machine id from the standard locations.
func ReadMachineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := os.ReadFile(p)
		if err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

// CPU parses /proc/cpuinfo into CPUSpec entries.
func CPU() []collector.CPUSpec {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return nil
	}
	var result []collector.CPUSpec
	seen := make(map[string]bool)
	var currentName string
	var cores int
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentName = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "processor") {
			cores++
		}
		if line == "" && currentName != "" && !seen[currentName] {
			seen[currentName] = true
			result = append(result, collector.CPUSpec{Name: currentName, Cores: cores})
			cores = 0
		}
	}
	return result
}

// GPU parses lspci output for display devices.
func GPU() []collector.GPUSpec {
	out, _ := exec.Command("lspci").Output()
	if out == nil {
		return nil
	}
	var result []collector.GPUSpec
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "VGA") || strings.Contains(line, "3D") || strings.Contains(line, "Display") {
			result = append(result, collector.GPUSpec{Name: strings.TrimSpace(line)})
		}
	}
	return result
}

// Memory returns total memory in MB.
func Memory() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				return kb / 1024
			}
		}
	}
	return 0
}

// NetInterfaces parses `ip addr show`.
func NetInterfaces() []collector.NetInterfaceSpec {
	out, _ := exec.Command("ip", "addr", "show").Output()
	if out == nil {
		return nil
	}
	var result []collector.NetInterfaceSpec
	var current *collector.NetInterfaceSpec
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			if current != nil {
				result = append(result, *current)
				current = nil
			}
			continue
		}
		if !strings.HasPrefix(line, " ") {
			if current != nil {
				result = append(result, *current)
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				current = &collector.NetInterfaceSpec{Name: strings.TrimRight(fields[1], ":")}
			}
			continue
		}
		if current != nil && strings.Contains(line, "link/ether") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				current.MAC = fields[1]
			}
		}
		if current != nil && strings.Contains(line, "inet ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				current.Addresses = append(current.Addresses, fields[1])
			}
		}
	}
	if current != nil {
		result = append(result, *current)
	}
	return result
}

// OpenPorts lists listening TCP/UDP sockets via `ss`.
func OpenPorts() []string {
	out, _ := exec.Command("ss", "-tlnp").Output()
	if out == nil {
		return nil
	}
	var result []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "State") || strings.HasPrefix(line, "Netid") {
			continue
		}
		result = append(result, line)
	}
	return result
}

// Services lists unique running process names.
func Services() []string {
	out, _ := exec.Command("ps", "-eo", "comm", "--no-headers").Output()
	if out == nil {
		return nil
	}
	seen := make(map[string]bool)
	var result []string
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		if name != "" && !seen[name] {
			seen[name] = true
			result = append(result, name)
		}
	}
	return result
}
