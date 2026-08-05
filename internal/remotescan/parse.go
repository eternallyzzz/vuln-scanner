package remotescan

import (
	"encoding/json"
	"strings"

	"vuln-scanner/internal/collector"
)

// ParseOSRelease extracts NAME and VERSION_ID from /etc/os-release text.
// Missing fields fall back to "linux" / empty.
func ParseOSRelease(text string) (name, version string) {
	name = "linux"
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch key {
		case "NAME":
			name = value
		case "VERSION_ID":
			version = value
		}
	}
	if name == "" {
		name = "linux"
	}
	return name, version
}

// ParseDPKGQuery parses `dpkg-query -W -f='${Package}\t${Version}\n'` output.
func ParseDPKGQuery(text string) []collector.Asset {
	var assets []collector.Asset
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, version, ok := strings.Cut(line, "\t")
		name = strings.TrimSpace(name)
		version = strings.TrimSpace(version)
		if !ok || name == "" || version == "" {
			continue
		}
		assets = append(assets, collector.Asset{
			Name:    name,
			Version: version,
			Format:  "deb",
			Type:    "PACKAGE",
		})
	}
	return assets
}

// ParseRPMQuery parses `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'`
// output. The version keeps the `version-release` convention used by the
// rpm collector so the matcher compares consistently.
func ParseRPMQuery(text string) []collector.Asset {
	var assets []collector.Asset
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, version, ok := strings.Cut(line, "\t")
		name = strings.TrimSpace(name)
		version = strings.TrimSpace(version)
		if !ok || name == "" || version == "" {
			continue
		}
		assets = append(assets, collector.Asset{
			Name:    name,
			Version: version,
			Format:  "rpm",
			Type:    "PACKAGE",
		})
	}
	return assets
}

// ParseSwVers extracts the product name and version from `sw_vers` output.
func ParseSwVers(text string) (name, version string) {
	name = "macos"
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "ProductName":
			if strings.Contains(value, "macOS") || strings.Contains(value, "Mac OS X") {
				name = "macos"
			} else if value != "" {
				name = value
			}
		case "ProductVersion":
			version = value
		}
	}
	return strings.ToLower(name), version
}

// ParseBrewList parses `brew list --versions` lines ("name version").
func ParseBrewList(text string) []collector.Asset {
	var assets []collector.Asset
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		assets = append(assets, collector.Asset{
			Name:    fields[0],
			Version: fields[1],
			Format:  "brew",
			Type:    "PACKAGE",
		})
	}
	return assets
}

// ParseWindowsOSJSON parses the PowerShell Win32_OperatingSystem JSON.
func ParseWindowsOSJSON(text string) (caption, version, arch string) {
	items := unmarshalAny[map[string]interface{}](text)
	for _, it := range items {
		if v, _ := it["Caption"].(string); v != "" && caption == "" {
			caption = v
		}
		if v, _ := it["Version"].(string); v != "" && version == "" {
			version = v
		}
		if v, _ := it["OSArchitecture"].(string); v != "" && arch == "" {
			arch = v
		}
	}
	return caption, version, arch
}

// ParseHotfixJSON parses the PowerShell Get-HotFix JSON.
func ParseHotfixJSON(text string) []collector.Asset {
	var assets []collector.Asset
	for _, f := range unmarshalAny[map[string]interface{}](text) {
		id, _ := f["HotFixID"].(string)
		if id == "" {
			continue
		}
		installed, _ := f["InstalledOn"].(string)
		assets = append(assets, collector.Asset{
			Name:    id,
			Version: installed,
			Format:  "hotfix",
			Type:    "HOTFIX",
		})
	}
	return assets
}

// ParseWindowsAppsJSON parses the PowerShell Uninstall registry JSON.
func ParseWindowsAppsJSON(text string) []collector.Asset {
	var assets []collector.Asset
	for _, a := range unmarshalAny[map[string]interface{}](text) {
		name, _ := a["DisplayName"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		version, _ := a["DisplayVersion"].(string)
		vendor, _ := a["Publisher"].(string)
		assets = append(assets, collector.Asset{
			Name:    name,
			Version: strings.TrimSpace(version),
			Vendor:  strings.TrimSpace(vendor),
			Format:  "win",
			Type:    "PACKAGE",
		})
	}
	return assets
}

// unmarshalAny accepts a JSON array or a single object.
func unmarshalAny[T any](text string) []T {
	var list []T
	if err := json.Unmarshal([]byte(text), &list); err == nil {
		return list
	}
	var one T
	if err := json.Unmarshal([]byte(text), &one); err == nil {
		return []T{one}
	}
	return nil
}

// NormalizeArch maps common uname -m values to the agent arch convention.
func NormalizeArch(arch string) string {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "x86_64", "amd64", "x64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "i386", "i686", "x86", "386":
		return "386"
	case "":
		return ""
	default:
		return strings.ToLower(strings.TrimSpace(arch))
	}
}

// NormalizeWindowsArch maps Win32_OperatingSystem.OSArchitecture.
func NormalizeWindowsArch(arch string) string {
	a := strings.ToLower(strings.TrimSpace(arch))
	switch {
	case strings.Contains(a, "arm"):
		return "arm64"
	case strings.Contains(a, "64"):
		return "amd64"
	case strings.Contains(a, "32"):
		return "386"
	default:
		return a
	}
}
