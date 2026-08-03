//go:build windows

package windows

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"vuln-scanner/internal/collector"

	"golang.org/x/sys/windows/registry"
)

type Collector struct{}

func New() *Collector {
	return &Collector{}
}

func (c *Collector) CollectPackages(ctx context.Context) ([]collector.Asset, error) {
	var assets []collector.Asset

	msiPkgs, err := c.collectMSIPackages(ctx)
	if err == nil {
		assets = append(assets, msiPkgs...)
	}

	appxPkgs, err := c.collectAppXPackages()
	if err == nil {
		assets = append(assets, appxPkgs...)
	}

	return deduplicate(assets), nil
}

func (c *Collector) collectMSIPackages(ctx context.Context) ([]collector.Asset, error) {
	var assets []collector.Asset

	uninstallPaths := []struct {
		key  registry.Key
		path string
		arch string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "x86_64"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "i686"},
	}

	for _, up := range uninstallPaths {
		k, err := registry.OpenKey(up.key, up.path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		subKeys, err := k.ReadSubKeyNames(0)
		k.Close()
		if err != nil {
			continue
		}

		for _, subKey := range subKeys {
			sk, err := registry.OpenKey(up.key, up.path+"\\"+subKey, registry.QUERY_VALUE)
			if err != nil {
				continue
			}

			name := getStr(sk, "DisplayName")
			version := getStr(sk, "DisplayVersion")
			vendor := getStr(sk, "Publisher")
			installDate := getStr(sk, "InstallDate")
			location := getStr(sk, "InstallLocation")

			sk.Close()

			if name == "" {
				continue
			}

			assets = append(assets, collector.Asset{
				Name:        name,
				Version:     version,
				Arch:        up.arch,
				Format:      "win",
				Vendor:      vendor,
				Location:    location,
				InstallDate: installDate,
				Type:        "PACKAGE",
			})
		}
	}

	return assets, nil
}

func (c *Collector) collectAppXPackages() ([]collector.Asset, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-AppxPackage | Select-Object Name,Version,Architecture,Publisher | ConvertTo-Json -Compress",
	).Output()
	if err != nil {
		return nil, err
	}

	var pkgs []struct {
		Name         string `json:"Name"`
		Version      string `json:"Version"`
		Architecture string `json:"Architecture"`
		Publisher    string `json:"Publisher"`
	}
	if err := json.Unmarshal(out, &pkgs); err != nil {
		return nil, err
	}

	var assets []collector.Asset
	for _, p := range pkgs {
		if p.Name == "" {
			continue
		}
		assets = append(assets, collector.Asset{
			Name:    p.Name,
			Version: p.Version,
			Arch:    p.Architecture,
			Format:  "appx",
			Vendor:  p.Publisher,
			Type:    "PACKAGE",
		})
	}
	return assets, nil
}

func (c *Collector) CollectHotfixes(ctx context.Context) ([]collector.Asset, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-HotFix | ForEach-Object { [PSCustomObject]@{HotFixID=$_.HotFixID; InstalledOn=$_.InstalledOn.ToString('yyyy-MM-dd')} } | ConvertTo-Json -Compress",
	).Output()
	if err != nil {
		return nil, nil
	}

	type fixRaw struct {
		HotFixID    string `json:"HotFixID"`
		InstalledOn string `json:"InstalledOn"`
	}
	fixes := unmarshalArray[fixRaw](out)
	var assets []collector.Asset
	for _, f := range fixes {
		if f.HotFixID == "" {
			continue
		}
		assets = append(assets, collector.Asset{
			Name:    f.HotFixID,
			Version: f.InstalledOn,
			Format:  "hotfix",
			Type:    "HOTFIX",
		})
	}

	cbsFixes, _ := c.collectCBSHotfixes(ctx)
	assets = append(assets, cbsFixes...)

	wuaFixes := c.collectWUAHotfixes(ctx)
	assets = append(assets, wuaFixes...)

	return dedupHotfixes(assets), nil
}

var kbPattern = regexp.MustCompile(`KB\d+`)

func (c *Collector) collectCBSHotfixes(ctx context.Context) ([]collector.Asset, error) {
	const cbsPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, cbsPath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	subKeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	var assets []collector.Asset
	seen := make(map[string]bool)
	for _, subKey := range subKeys {
		if !strings.HasPrefix(subKey, "Package_for_") {
			continue
		}
		match := kbPattern.FindString(subKey)
		if match == "" || seen[match] {
			continue
		}
		seen[match] = true
		assets = append(assets, collector.Asset{
			Name:   match,
			Format: "hotfix",
			Type:   "HOTFIX",
		})
	}
	return assets, nil
}

func (c *Collector) collectWUAHotfixes(ctx context.Context) []collector.Asset {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`try { $session = New-Object -ComObject Microsoft.Update.Session; $searcher = $session.CreateUpdateSearcher(); $total = $searcher.GetTotalHistoryCount(); if ($total -gt 0) { $searcher.QueryHistory(0, $total) | ForEach-Object { $_.Title } | ConvertTo-Json -Compress } else { '[]' } } catch { '[]' }`,
	).Output()
	if err != nil || len(out) == 0 {
		return nil
	}

	var titles []string
	json.Unmarshal(out, &titles)

	var assets []collector.Asset
	seen := make(map[string]bool)
	for _, title := range titles {
		match := kbPattern.FindString(title)
		if match == "" || seen[match] {
			continue
		}
		seen[match] = true
		assets = append(assets, collector.Asset{
			Name:   match,
			Format: "hotfix",
			Type:   "HOTFIX",
		})
	}
	return assets
}

func dedupHotfixes(assets []collector.Asset) []collector.Asset {
	seen := make(map[string]bool)
	var result []collector.Asset
	for _, a := range assets {
		if !seen[a.Name] {
			seen[a.Name] = true
			result = append(result, a)
		}
	}
	return result
}

func (c *Collector) SystemInfo(ctx context.Context) (collector.SystemInfo, error) {
	hostname, _ := os.Hostname()

	info := collector.SystemInfo{
		Hostname:        hostname,
		OS:              windowsProductName(),
		Version:         windowsVersion(),
		Arch:            runtime.GOARCH,
		MachineID:       registryMachineGUID(),
		CPU:             getCPU(),
		GPU:             getGPU(),
		Motherboard:     getMotherboard(),
		MemoryMB:        getMemory(),
		NetInterfaces:   getNetInterfaces(),
		OpenPorts:       getOpenPorts(),
		RunningServices: getRunningServices(),
	}

	return info, nil
}

func getCPU() []collector.CPUSpec {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores | ConvertTo-Json -Compress",
	).Output()
	if err != nil {
		return nil
	}

	type cpuRaw struct {
		Name          string `json:"Name"`
		NumberOfCores uint32 `json:"NumberOfCores"`
	}
	cpus := unmarshalArray[cpuRaw](out)
	var result []collector.CPUSpec
	for _, c := range cpus {
		result = append(result, collector.CPUSpec{
			Name:  strings.TrimSpace(c.Name),
			Cores: int(c.NumberOfCores),
		})
	}
	return result
}

func getGPU() []collector.GPUSpec {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_VideoController | Where-Object { $_.Name -notmatch 'Virtual' } | Select-Object Name,DriverVersion | ConvertTo-Json -Compress",
	).Output()
	if err != nil {
		return nil
	}

	type gpuRaw struct {
		Name          string `json:"Name"`
		DriverVersion string `json:"DriverVersion"`
	}
	gpus := unmarshalArray[gpuRaw](out)
	var result []collector.GPUSpec
	for _, g := range gpus {
		result = append(result, collector.GPUSpec{
			Name:   strings.TrimSpace(g.Name),
			Driver: g.DriverVersion,
		})
	}
	return result
}

func getMotherboard() *collector.MotherboardSpec {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product | ConvertTo-Json -Compress",
	).Output()
	if err != nil {
		return nil
	}

	type mbRaw struct {
		Manufacturer string `json:"Manufacturer"`
		Product      string `json:"Product"`
	}
	boards := unmarshalArray[mbRaw](out)
	if len(boards) == 0 {
		return nil
	}
	return &collector.MotherboardSpec{
		Manufacturer: strings.TrimSpace(boards[0].Manufacturer),
		Product:      strings.TrimSpace(boards[0].Product),
	}
}

func getMemory() int64 {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
	).Output()
	if err != nil {
		return 0
	}
	mb, _ := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	return mb / (1024 * 1024)
}

func getNetInterfaces() []collector.NetInterfaceSpec {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object Name,MacAddress,InterfaceIndex | ConvertTo-Json -Compress",
	).Output()
	if err != nil {
		return nil
	}

	type netRaw struct {
		Name           string `json:"Name"`
		MAC            string `json:"MacAddress"`
		InterfaceIndex int    `json:"InterfaceIndex"`
	}
	adapters := unmarshalArray[netRaw](out)
	var result []collector.NetInterfaceSpec
	for _, a := range adapters {
		if a.Name == "" {
			continue
		}
		ips := getAdapterIPs(a.InterfaceIndex)
		result = append(result, collector.NetInterfaceSpec{
			Name:      strings.TrimSpace(a.Name),
			MAC:       a.MAC,
			Addresses: ips,
		})
	}
	return result
}

func getAdapterIPs(index int) []string {
	cmd := fmt.Sprintf("Get-NetIPAddress -InterfaceIndex %d -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress", index)
	out, err := exec.Command("powershell", "-NoProfile", "-Command", cmd).Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\r\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func getOpenPorts() []string {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-NetTCPConnection -State Listen | ForEach-Object { \"$($_.LocalAddress):$($_.LocalPort)\" } | Sort-Object -Unique",
	).Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func getRunningServices() []string {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-Process | Where-Object { $_.Id -ne 0 } | Select-Object -First 200 -ExpandProperty ProcessName | Sort-Object -Unique",
	).Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func registryMachineGUID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	id, _, _ := k.GetStringValue("MachineGuid")
	return id
}

func windowsVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()

	current, _, _ := k.GetStringValue("CurrentVersion")
	build, _, _ := k.GetStringValue("CurrentBuildNumber")
	ubr, _, _ := k.GetStringValue("UBR")

	if current != "" && build != "" && ubr != "" {
		return current + "." + build + "." + ubr
	}
	if current != "" && build != "" {
		return current + "." + build
	}
	return current
}

func windowsProductName() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "windows"
	}
	defer k.Close()

	build, _, _ := k.GetStringValue("CurrentBuildNumber")
	buildNum, _ := strconv.Atoi(build)

	displayVer, _, _ := k.GetStringValue("DisplayVersion")

	productName, _, _ := k.GetStringValue("ProductName")
	if productName == "" {
		productName = "windows"
	}

	if buildNum >= 22000 {
		if strings.Contains(productName, "10") {
			productName = strings.Replace(productName, "Windows 10", "Windows 11", 1)
		}
	}

	if displayVer != "" {
		productName = productName + " " + displayVer
	}

	return strings.TrimSpace(productName)
}

func getStr(k registry.Key, name string) string {
	s, _, _ := k.GetStringValue(name)
	return s
}

func unmarshalArray[T any](raw []byte) []T {
	var items []T
	if len(raw) == 0 {
		return nil
	}
	if raw[0] == '[' {
		json.Unmarshal(raw, &items)
	} else {
		var item T
		if json.Unmarshal(raw, &item) == nil {
			items = append(items, item)
		}
	}
	return items

}

func deduplicate(assets []collector.Asset) []collector.Asset {
	seen := make(map[string]bool)
	var result []collector.Asset
	for _, a := range assets {
		key := a.Name + "\x00" + a.Version + "\x00" + a.Format
		if !seen[key] {
			seen[key] = true
			result = append(result, a)
		}
	}
	return result
}
