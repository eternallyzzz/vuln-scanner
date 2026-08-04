//go:build windows

package windows

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

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
	manufacturer, model, serial := getSystemIdentity()
	biosVersion, biosDate := getBIOS()
	uptime, bootTime := getUptimeAndBoot()

	info := collector.SystemInfo{
		Hostname:           hostname,
		OS:                 windowsProductName(),
		Version:            windowsVersion(),
		Arch:               runtime.GOARCH,
		MachineID:          registryMachineGUID(),
		SystemManufacturer: manufacturer,
		SystemModel:        model,
		SystemSerial:       serial,
		BIOSVersion:        biosVersion,
		BIOSDate:           biosDate,
		KernelVersion:      getKernelVersion(),
		UptimeSeconds:      uptime,
		BootTime:           bootTime,
		Timezone:           getTimezone(),
		OSDomain:           getOSDomain(),
		CPU:                getCPU(),
		GPU:                getGPU(),
		Motherboard:        getMotherboard(),
		MemoryMB:           getMemory(),
		MemoryModules:      getMemoryModules(),
		NetInterfaces:      getNetInterfaces(),
		OpenPorts:          getOpenPorts(),
		Processes:          getProcesses(),
		Storage:            getStorage(),
		Services:           getServices(),
		StartupItems:       getStartupItems(),
		ScheduledTasks:     getScheduledTasks(),
		Routes:             getRoutes(),
		FirewallRules:      getFirewallRules(),
		Neighbors:          getNeighbors(),
		Certificates:       getCertificates(),
		Accounts:           getAccounts(),
		SSHKeys:            getSSHKeys(),
		Runtimes:           getRuntimes(),
		TPMEnabled:         getTPM(),
		DiskEncryption:     getDiskEncryption(),
		Antivirus:          getAntivirus(),
	}
	applyWindowsCaps(&info)

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
		"Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object Name,MacAddress,InterfaceIndex,LinkSpeed,DriverDescription | ConvertTo-Json -Compress",
	).Output()
	if err != nil {
		return nil
	}

	type netRaw struct {
		Name              string `json:"Name"`
		MAC               string `json:"MacAddress"`
		InterfaceIndex    int    `json:"InterfaceIndex"`
		LinkSpeed         string `json:"LinkSpeed"`
		DriverDescription string `json:"DriverDescription"`
	}
	adapters := unmarshalArray[netRaw](out)
	config := getNetConfig()
	var result []collector.NetInterfaceSpec
	for _, a := range adapters {
		if a.Name == "" {
			continue
		}
		ips := getAdapterIPs(a.InterfaceIndex)
		spec := collector.NetInterfaceSpec{
			Name:      strings.TrimSpace(a.Name),
			MAC:       a.MAC,
			Addresses: ips,
			LinkSpeed: strings.TrimSpace(a.LinkSpeed),
			Driver:    strings.TrimSpace(a.DriverDescription),
		}
		if cfg, ok := config[a.InterfaceIndex]; ok {
			spec.Gateways = cfg.Gateways
			spec.DNS = cfg.DNS
		}
		result = append(result, spec)
	}
	return result
}

type netConfig struct {
	Gateways []string
	DNS      []string
}

func getNetConfig() map[int]netConfig {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' } | ForEach-Object { [PSCustomObject]@{ IfIndex=$_.InterfaceIndex; Gateway=($_.IPv4DefaultGateway.ServerAddresses -join ','); DNS=($_.DNSServer.ServerAddresses -join ',') } } | ConvertTo-Json -Compress",
	).Output()
	if err != nil {
		return nil
	}
	type raw struct {
		IfIndex int    `json:"IfIndex"`
		Gateway string `json:"Gateway"`
		DNS     string `json:"DNS"`
	}
	result := map[int]netConfig{}
	for _, r := range unmarshalArray[raw](out) {
		cfg := netConfig{}
		if r.Gateway != "" {
			cfg.Gateways = splitCSVish(r.Gateway)
		}
		if r.DNS != "" {
			cfg.DNS = splitCSVish(r.DNS)
		}
		result[r.IfIndex] = cfg
	}
	return result
}

func splitCSVish(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
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

func getOpenPorts() []collector.PortInfo {
	procNames := getProcessNameMap()
	var ports []collector.PortInfo
	seen := map[string]bool{}

	tcpOut, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress",
	).Output()
	if err == nil {
		type raw struct {
			LocalAddress string `json:"LocalAddress"`
			LocalPort    int    `json:"LocalPort"`
			OwningPID    int    `json:"OwningProcess"`
		}
		for _, r := range unmarshalArray[raw](tcpOut) {
			key := fmt.Sprintf("tcp:%s:%d", r.LocalAddress, r.LocalPort)
			if seen[key] {
				continue
			}
			seen[key] = true
			ports = append(ports, collector.PortInfo{
				Protocol: "tcp",
				Address:  r.LocalAddress,
				Port:     r.LocalPort,
				Process:  procNames[r.OwningPID],
			})
		}
	}

	udpOut, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress",
	).Output()
	if err == nil {
		type raw struct {
			LocalAddress string `json:"LocalAddress"`
			LocalPort    int    `json:"LocalPort"`
			OwningPID    int    `json:"OwningProcess"`
		}
		for _, r := range unmarshalArray[raw](udpOut) {
			key := fmt.Sprintf("udp:%s:%d", r.LocalAddress, r.LocalPort)
			if seen[key] {
				continue
			}
			seen[key] = true
			ports = append(ports, collector.PortInfo{
				Protocol: "udp",
				Address:  r.LocalAddress,
				Port:     r.LocalPort,
				Process:  procNames[r.OwningPID],
			})
		}
	}
	return ports
}

func getProcessNameMap() map[int]string {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-Process | Where-Object { $_.Id -ne 0 } | Select-Object Id,ProcessName | ConvertTo-Json -Compress",
	).Output()
	if err != nil {
		return nil
	}
	type raw struct {
		ID          int    `json:"Id"`
		ProcessName string `json:"ProcessName"`
	}
	result := map[int]string{}
	for _, r := range unmarshalArray[raw](out) {
		result[r.ID] = r.ProcessName
	}
	return result
}

func getProcesses() []collector.ProcessInfo {
	out, err := exec.Command("tasklist", "/v", "/fo", "csv", "/nh").Output()
	if err != nil {
		return nil
	}
	procs, err := collector.ParseTasklistCSV(out)
	if err != nil {
		return nil
	}
	if len(procs) > 300 {
		procs = procs[:300]
	}
	return procs
}

func getStorage() []collector.StorageSpec {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_DiskDrive | Select-Object Model,Size,SerialNumber,FirmwareRevision | ConvertTo-Json -Compress",
	).Output()
	if err != nil {
		return nil
	}
	type raw struct {
		Model            string `json:"Model"`
		Size             int64  `json:"Size"`
		SerialNumber     string `json:"SerialNumber"`
		FirmwareRevision string `json:"FirmwareRevision"`
	}
	var result []collector.StorageSpec
	for _, r := range unmarshalArray[raw](out) {
		if r.Size <= 0 {
			continue
		}
		result = append(result, collector.StorageSpec{
			Name:      strings.TrimSpace(r.Model),
			SizeBytes: r.Size,
			Serial:    strings.TrimSpace(r.SerialNumber),
			Model:     strings.TrimSpace(r.Model),
			Firmware:  strings.TrimSpace(r.FirmwareRevision),
		})
	}
	if lout, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,Size,FreeSpace,FileSystem | ConvertTo-Json -Compress",
	).Output(); err == nil {
		if volumes, verr := collector.ParseLogicalDiskJSON(lout); verr == nil {
			result = append(result, volumes...)
		}
	}
	return result
}

func getSystemIdentity() (manufacturer, model, serial string) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model | ConvertTo-Json -Compress",
	).Output()
	if err == nil {
		type raw struct {
			Manufacturer string `json:"Manufacturer"`
			Model        string `json:"Model"`
		}
		items := unmarshalArray[raw](out)
		if len(items) > 0 {
			manufacturer = strings.TrimSpace(items[0].Manufacturer)
			model = strings.TrimSpace(items[0].Model)
		}
	}
	out, err = exec.Command("powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_BIOS | Select-Object -ExpandProperty SerialNumber",
	).Output()
	if err == nil {
		serial = strings.TrimSpace(string(out))
	}
	return manufacturer, model, serial
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

func ps(script string) ([]byte, error) {
	return collector.RunTimeout("powershell", "-NoProfile", "-Command", script)
}

func getBIOS() (version, date string) {
	out, err := ps("$b=Get-CimInstance Win32_BIOS; $d=''; try { $d=[Management.ManagementDateTimeConverter]::ToDateTime($b.ReleaseDate).ToString('yyyy-MM-dd') } catch { $d=$b.ReleaseDate.ToString('yyyy-MM-dd') }; [PSCustomObject]@{Version=$b.SMBIOSBIOSVersion; Date=$d} | ConvertTo-Json -Compress")
	if err != nil {
		return "", ""
	}
	type raw struct {
		Version string `json:"Version"`
		Date    string `json:"Date"`
	}
	items := unmarshalArray[raw](out)
	if len(items) == 0 {
		return "", ""
	}
	return strings.TrimSpace(items[0].Version), strings.TrimSpace(items[0].Date)
}

func getKernelVersion() string {
	out, err := ps("(Get-CimInstance Win32_OperatingSystem).Version")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func getUptimeAndBoot() (int64, string) {
	out, err := ps("$os=Get-CimInstance Win32_OperatingSystem; $boot=$os.LastBootUpTime; [PSCustomObject]@{Uptime=[math]::Round(((Get-Date)-$boot).TotalSeconds); Boot=$boot.ToString('yyyy-MM-ddTHH:mm:sszzz')} | ConvertTo-Json -Compress")
	if err != nil {
		return 0, ""
	}
	var raw struct {
		Uptime float64 `json:"Uptime"`
		Boot   string  `json:"Boot"`
	}
	if json.Unmarshal(out, &raw) != nil {
		return 0, ""
	}
	return int64(raw.Uptime), raw.Boot
}

func getTimezone() string {
	out, err := ps("(Get-TimeZone).Id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func getOSDomain() string {
	out, err := ps("(Get-CimInstance Win32_ComputerSystem).Domain")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func getServices() []collector.ServiceInfo {
	out, err := ps("Get-Service | ForEach-Object { [PSCustomObject]@{Name=$_.Name; DisplayName=$_.DisplayName; Status=$_.Status.ToString(); StartType=$_.StartType.ToString()} } | ConvertTo-Json -Compress")
	if err != nil {
		return nil
	}
	type svcRaw struct {
		Name      string `json:"Name"`
		Status    string `json:"Status"`
		StartType string `json:"StartType"`
	}
	runAs := map[string]string{}
	if aout, err := ps("Get-CimInstance Win32_Service | Select-Object Name,StartName | ConvertTo-Json -Compress"); err == nil {
		type acctRaw struct {
			Name      string `json:"Name"`
			StartName string `json:"StartName"`
		}
		for _, a := range unmarshalArray[acctRaw](aout) {
			runAs[a.Name] = a.StartName
		}
	}
	var services []collector.ServiceInfo
	for _, r := range unmarshalArray[svcRaw](out) {
		services = append(services, collector.ServiceInfo{
			Name:      r.Name,
			State:     r.Status,
			StartType: r.StartType,
			RunAs:     runAs[r.Name],
		})
	}
	return services
}

func getStartupItems() []collector.StartupItem {
	out, err := ps("Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location | ConvertTo-Json -Compress")
	if err != nil {
		return nil
	}
	type raw struct {
		Name     string `json:"Name"`
		Command  string `json:"Command"`
		Location string `json:"Location"`
	}
	var items []collector.StartupItem
	for _, r := range unmarshalArray[raw](out) {
		items = append(items, collector.StartupItem{
			Name: r.Name, Command: r.Command, Location: r.Location,
		})
	}
	return items
}

func getScheduledTasks() []collector.ScheduledTask {
	out, err := collector.RunTimeoutWith(30*time.Second, "schtasks", "/query", "/fo", "csv", "/v")
	if err != nil {
		return nil
	}
	tasks, err := collector.ParseSchTasksCSV(out)
	if err != nil {
		return nil
	}
	return tasks
}

func getRoutes() []collector.RouteInfo {
	out, err := ps("Get-NetRoute | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | ConvertTo-Json -Compress")
	if err != nil {
		return nil
	}
	type raw struct {
		Destination string `json:"DestinationPrefix"`
		NextHop     string `json:"NextHop"`
		Interface   string `json:"InterfaceAlias"`
		Metric      int64  `json:"RouteMetric"`
	}
	var routes []collector.RouteInfo
	for _, r := range unmarshalArray[raw](out) {
		routes = append(routes, collector.RouteInfo{
			Destination: r.Destination,
			Gateway:     r.NextHop,
			Interface:   r.Interface,
			Metric:      strconv.FormatInt(r.Metric, 10),
		})
	}
	return routes
}

func getFirewallRules() []collector.FirewallRule {
	out, err := collector.RunTimeout("netsh", "advfirewall", "firewall", "show", "rule", "name=all")
	if err != nil {
		return nil
	}
	return collector.ParseNetShFirewall(string(out))
}

func getNeighbors() []collector.NeighborInfo {
	out, err := ps("Get-NetNeighbor | Select-Object InterfaceAlias,IPAddress,LinkLayerAddress,State | ConvertTo-Json -Compress")
	if err != nil {
		return nil
	}
	type raw struct {
		Interface string `json:"InterfaceAlias"`
		IP        string `json:"IPAddress"`
		MAC       string `json:"LinkLayerAddress"`
		State     string `json:"State"`
	}
	var neighbors []collector.NeighborInfo
	for _, r := range unmarshalArray[raw](out) {
		neighbors = append(neighbors, collector.NeighborInfo{
			Interface: r.Interface, IP: r.IP, MAC: r.MAC, State: r.State,
		})
	}
	return neighbors
}

func getCertificates() []collector.CertificateInfo {
	out, err := ps("$certs = foreach($s in 'My','Root','CA'){ Get-ChildItem \"Cert:\\LocalMachine\\$s\" -ErrorAction SilentlyContinue | ForEach-Object { [PSCustomObject]@{Subject=$_.Subject; Issuer=$_.Issuer; SerialNumber=$_.SerialNumber; NotBefore=$_.NotBefore.ToString('yyyy-MM-dd'); NotAfter=$_.NotAfter.ToString('yyyy-MM-dd'); Store=$s} } }; $certs | ConvertTo-Json -Compress")
	if err != nil {
		return nil
	}
	type raw struct {
		Subject   string `json:"Subject"`
		Issuer    string `json:"Issuer"`
		Serial    string `json:"SerialNumber"`
		NotBefore string `json:"NotBefore"`
		NotAfter  string `json:"NotAfter"`
		Store     string `json:"Store"`
	}
	var certs []collector.CertificateInfo
	for _, r := range unmarshalArray[raw](out) {
		certs = append(certs, collector.CertificateInfo{
			Subject: r.Subject, Issuer: r.Issuer, Serial: r.Serial,
			NotBefore: r.NotBefore, NotAfter: r.NotAfter, Store: r.Store,
		})
	}
	return certs
}

func getAccounts() []collector.AccountInfo {
	out, err := ps("$admins=@(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }); Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object { $n=$_.Name; [PSCustomObject]@{Name=$n; Enabled=$_.Enabled; Domain=$env:COMPUTERNAME; Admin=[bool](($admins -contains $n) -or ($admins -contains ($env:COMPUTERNAME+'\\'+$n)))} } | ConvertTo-Json -Compress")
	if err != nil {
		return nil
	}
	type raw struct {
		Name    string `json:"Name"`
		Enabled bool   `json:"Enabled"`
		Domain  string `json:"Domain"`
		Admin   bool   `json:"Admin"`
	}
	var accounts []collector.AccountInfo
	for _, r := range unmarshalArray[raw](out) {
		accounts = append(accounts, collector.AccountInfo{
			Name: r.Name, Domain: r.Domain, Admin: r.Admin, Disabled: !r.Enabled,
		})
	}
	return accounts
}

func getSSHKeys() []collector.SSHKeyInfo {
	var paths []string
	if matches, err := filepath.Glob(`C:\Users\*\.ssh\authorized_keys`); err == nil {
		paths = append(paths, matches...)
	}
	if _, err := os.Stat(`C:\ProgramData\ssh\administrators_authorized_keys`); err == nil {
		paths = append(paths, `C:\ProgramData\ssh\administrators_authorized_keys`)
	}
	keygen := `C:\Windows\System32\OpenSSH\ssh-keygen.exe`
	hasKeygen := false
	if _, err := os.Stat(keygen); err == nil {
		hasKeygen = true
	}
	var keys []collector.SSHKeyInfo
	for _, path := range paths {
		if len(keys) >= 200 {
			break
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		line := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		info := collector.SSHKeyInfo{Path: path}
		if len(fields) >= 2 {
			info.Type = fields[0]
		}
		if hasKeygen {
			if fp, err := collector.RunTimeout(keygen, "-lf", path); err == nil {
				fpFields := strings.Fields(string(fp))
				if len(fpFields) >= 2 {
					info.Fingerprint = fpFields[1]
				}
			}
		}
		keys = append(keys, info)
	}
	return keys
}

func getMemoryModules() []collector.MemoryModule {
	out, err := ps("Get-CimInstance Win32_PhysicalMemory | Select-Object DeviceLocator,Capacity,Speed,ConfiguredClockSpeed,PartNumber,SerialNumber,SMBIOSMemoryType | ConvertTo-Json -Compress")
	if err != nil {
		return nil
	}
	mods, err := collector.ParsePhysicalMemoryJSON(out)
	if err != nil {
		return nil
	}
	return mods
}

func getRuntimes() []collector.RuntimeInfo {
	out, err := collector.RunTimeout("wsl", "-l", "-q")
	if err != nil {
		return nil
	}
	return collector.ParseWSLList(collector.DecodeCommandOutput(out))
}

func getTPM() bool {
	out, err := ps("(Get-Tpm -ErrorAction SilentlyContinue).TpmPresent")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "True"
}

func getDiskEncryption() string {
	out, err := ps("Get-BitLockerVolume -ErrorAction SilentlyContinue | ForEach-Object { $_.MountPoint + ':' + $_.ProtectionStatus }")
	if err != nil {
		return ""
	}
	lines := strings.Fields(string(out))
	if len(lines) == 0 {
		return ""
	}
	return "BitLocker " + strings.Join(lines, ", ")
}

func getAntivirus() string {
	out, err := ps("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object -ExpandProperty displayName")
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\r\n")
	var names []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			names = append(names, l)
		}
	}
	return strings.Join(names, ", ")
}

func applyWindowsCaps(info *collector.SystemInfo) {
	capWindows(&info.Services, 500, "services", info)
	capWindows(&info.StartupItems, 200, "startup_items", info)
	capWindows(&info.ScheduledTasks, 300, "scheduled_tasks", info)
	capWindows(&info.Routes, 200, "routes", info)
	capWindows(&info.FirewallRules, 500, "firewall_rules", info)
	capWindows(&info.Neighbors, 200, "neighbors", info)
	capWindows(&info.Certificates, 200, "certificates", info)
	capWindows(&info.Accounts, 500, "accounts", info)
	capWindows(&info.SSHKeys, 200, "ssh_keys", info)
	capWindows(&info.MemoryModules, 32, "memory_modules", info)
	capWindows(&info.Runtimes, 200, "runtimes", info)
}

func capWindows[T any](list *[]T, limit int, name string, info *collector.SystemInfo) {
	if len(*list) > limit {
		*list = (*list)[:limit]
		info.Truncated = append(info.Truncated, name)
	}
}
