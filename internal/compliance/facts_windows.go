//go:build windows

package compliance

import (
	"context"
	"encoding/json"
	"strings"

	"golang.org/x/sys/windows/registry"

	"vuln-scanner/internal/collector"
)

// CollectFacts gathers Windows facts from the latest SystemInfo plus a few
// registry reads and one PowerShell firewall query. Failures degrade to nil
// fields so the corresponding checks report na instead of blocking the sync.
func CollectFacts(_ context.Context, sys collector.SystemInfo) Facts {
	f := Facts{
		Platform:        "windows",
		Accounts:        sys.Accounts,
		FirewallRules:   sys.FirewallRules,
		TPMEnabled:      sys.TPMEnabled,
		DiskEncryption:  sys.DiskEncryption,
		Antivirus:       sys.Antivirus,
		UpdateFactCount: len(sys.UpdateFacts),
	}
	if sys.UpdateSourceStatus != nil {
		reachable := sys.UpdateSourceStatus.SourceReachable
		f.UpdateReachable = &reachable
	}
	f.FirewallProfiles = windowsFirewallProfiles()
	f.EnableLUA = registryDWORD(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA")
	f.FDenyTSConnections = registryDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections")
	f.RDPUserAuth = registryDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "UserAuthentication")
	f.SMB1 = registryDWORD(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "SMB1")
	f.AutoAdminLogon = registryString(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "AutoAdminLogon")
	return f
}

func registryDWORD(root registry.Key, path, name string) *int {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return nil
	}
	n := int(v)
	return &n
}

func registryString(root registry.Key, path, name string) *string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return nil
	}
	return &v
}

type firewallProfileRaw struct {
	Name    string `json:"Name"`
	Enabled bool   `json:"Enabled"`
}

func windowsFirewallProfiles() map[string]bool {
	out, err := collector.RunTimeout("powershell", "-NoProfile", "-Command",
		"Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress")
	if err != nil {
		return nil
	}
	var single firewallProfileRaw
	if err := json.Unmarshal(out, &single); err == nil && single.Name != "" {
		return map[string]bool{strings.ToLower(single.Name): single.Enabled}
	}
	var many []firewallProfileRaw
	if err := json.Unmarshal(out, &many); err == nil {
		m := make(map[string]bool, len(many))
		for _, p := range many {
			m[strings.ToLower(p.Name)] = p.Enabled
		}
		return m
	}
	return nil
}
