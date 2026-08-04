package patch

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var assetNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

var kbHostAllowlist = map[string]bool{
	"download.microsoft.com":               true,
	"catalog.s.download.microsoft.com":     true,
	"catalog.s.download.windowsupdate.com": true,
	"aka.ms":                               true,
	"go.microsoft.com":                     true,
}

type Command struct {
	Display    string     `json:"display"`
	ArgvLists  [][]string `json:"argv_lists"`
	Deployable bool       `json:"deployable"`
}

type pkgManager string

const (
	managerApt pkgManager = "apt"
	managerDnf pkgManager = "dnf"
	managerYum pkgManager = "yum"
	managerApk pkgManager = "apk"
)

// BuildCommand builds the remediation command for apt-based agents (the
// default for all non-RPM platforms).
func BuildCommand(cfg *Config, fixType, fixValue, assetName, patchURL string) (Command, error) {
	return buildCommand(cfg, managerApt, fixType, fixValue, assetName, patchURL, "")
}

// BuildCommandForAgent builds the remediation command using the package
// manager implied by the agent OS (yum for RHEL 7, dnf for RHEL 8+ and
// derivatives, apt otherwise). patchSHA256 optionally pins the KB .msu
// download before installation.
func BuildCommandForAgent(cfg *Config, fixType, fixValue, assetName, patchURL, patchSHA256, agentOS, agentVersion string) (Command, error) {
	return buildCommand(cfg, packageManagerForAgent(agentOS, agentVersion),
		fixType, fixValue, assetName, patchURL, patchSHA256)
}

func buildCommand(cfg *Config, manager pkgManager, fixType, fixValue, assetName, patchURL, patchSHA256 string) (Command, error) {
	var c Command
	switch fixType {
	case "", "none":
		c.Display = "no automated remediation"
		return c, nil
	case "rebuild":
		// Container findings are advisory-only: the fix is rebuilding the
		// image with an updated base. Never generate a package-manager argv.
		c.Display = "manual: rebuild container image with updated base"
		return c, nil
	case "version":
		if !assetNameRe.MatchString(assetName) {
			return c, fmt.Errorf("unsafe asset name %q", assetName)
		}
		switch manager {
		case managerDnf:
			withPkg := append(append([]string{}, dnfArgv(cfg)...), assetName)
			c.ArgvLists = [][]string{withPkg}
			c.Display = strings.Join(withPkg, " ")
		case managerYum:
			withPkg := append(append([]string{}, yumArgv(cfg)...), assetName)
			c.ArgvLists = [][]string{withPkg}
			c.Display = strings.Join(withPkg, " ")
		case managerApk:
			withPkg := append(append([]string{}, apkArgv(cfg)...), assetName)
			c.ArgvLists = [][]string{withPkg}
			c.Display = strings.Join(withPkg, " ")
		default:
			argv := aptArgv(cfg)
			c.ArgvLists = [][]string{
				{"apt-get", "update"},
				append(append([]string{}, argv...), assetName),
			}
			c.Display = "apt-get update && " + strings.Join(append([]string{}, argv...), " ") + " " + assetName
		}
		c.Deployable = true
	case "kb":
		u, err := url.Parse(patchURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			c.Display = "manual download required: " + patchURL
			return c, nil
		}
		if !kbHostAllowlist[strings.ToLower(u.Host)] {
			c.Display = "manual download required (host not allowed): " + patchURL
			return c, nil
		}
		// The KB script interpolates the URL and hash into single-quoted
		// PowerShell strings; strip quotes from both to keep the argv safe.
		cleanURL := strings.ReplaceAll(u.String(), "'", "")
		cleanSHA := strings.ReplaceAll(patchSHA256, "'", "")
		script := fmt.Sprintf(`$p="$env:TEMP\vulnscan-kb.msu"; Invoke-WebRequest -Uri '%s' -OutFile $p; if ('%s' -ne '') { $h=(Get-FileHash -Algorithm SHA256 $p).Hash; if ($h -ne '%s') { Remove-Item $p -Force; exit 2 } }; $proc=Start-Process wusa.exe -ArgumentList @($p,'/quiet','/norestart') -Wait -PassThru; Remove-Item $p -Force; exit $proc.ExitCode`, cleanURL, cleanSHA, cleanSHA)
		c.ArgvLists = [][]string{{"powershell", "-NoProfile", "-Command", script}}
		c.Display = "powershell: download " + u.String() + " and install via wusa /quiet /norestart"
		if patchSHA256 != "" {
			c.Display += " (sha256 verified)"
		}
		c.Deployable = true
	default:
		return c, fmt.Errorf("unknown fix_type %q", fixType)
	}
	return c, nil
}

func aptArgv(cfg *Config) []string {
	if cfg != nil && cfg.AptCommand != "" {
		return cfg.AptArgv()
	}
	return []string{"apt-get", "install", "-y", "--only-upgrade"}
}

func dnfArgv(cfg *Config) []string {
	if cfg != nil && cfg.DnfCommand != "" {
		return cfg.DnfArgv()
	}
	return []string{"dnf", "-y", "update"}
}

func yumArgv(cfg *Config) []string {
	if cfg != nil && cfg.YumCommand != "" {
		return cfg.YumArgv()
	}
	return []string{"yum", "-y", "update"}
}

func apkArgv(cfg *Config) []string {
	if cfg != nil && cfg.ApkCommand != "" {
		return cfg.ApkArgv()
	}
	return []string{"apk", "upgrade"}
}

func packageManagerForAgent(agentOS, agentVersion string) pkgManager {
	lower := strings.ToLower(agentOS)
	if strings.Contains(lower, "alpine") {
		return managerApk
	}
	if strings.Contains(lower, "red hat") || strings.Contains(lower, "centos") ||
		strings.Contains(lower, "rocky") || strings.Contains(lower, "alma") {
		major, _, _ := strings.Cut(strings.TrimSpace(agentVersion), ".")
		if major == "7" {
			return managerYum
		}
		return managerDnf
	}
	return managerApt
}

func RiskFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
