//go:build linux || darwin

// Package linuxinfo provides Linux system information helpers shared by
// platform collectors (deb/rpm).
package linuxinfo

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

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
	manufacturer, model, serial := Hardware()
	biosVersion, biosDate := HardwareBIOS()
	var mb *collector.MotherboardSpec
	if manufacturer != "" || model != "" {
		mb = &collector.MotherboardSpec{Manufacturer: manufacturer, Product: model}
	}
	uptime := Uptime()
	info := collector.SystemInfo{
		Hostname:           hostname,
		OS:                 strings.ToLower(rel.Name),
		Version:            rel.Version,
		Arch:               runtime.GOARCH,
		MachineID:          ReadMachineID(),
		SystemManufacturer: manufacturer,
		SystemModel:        model,
		SystemSerial:       serial,
		BIOSVersion:        biosVersion,
		BIOSDate:           biosDate,
		KernelVersion:      KernelVersion(),
		UptimeSeconds:      uptime,
		BootTime:           time.Now().Add(-time.Duration(uptime) * time.Second).Format(time.RFC3339),
		Timezone:           Timezone(),
		OSDomain:           OSDomain(),
		CPU:                CPU(),
		GPU:                GPU(),
		Motherboard:        mb,
		MemoryMB:           Memory(),
		MemoryModules:      MemoryModules(),
		NetInterfaces:      NetInterfaces(),
		OpenPorts:          OpenPorts(),
		Processes:          Processes(),
		Storage:            Disks(),
		Services:           Services(),
		StartupItems:       StartupItems(),
		ScheduledTasks:     ScheduledTasks(),
		Routes:             Routes(),
		FirewallRules:      FirewallRules(),
		Neighbors:          Neighbors(),
		Certificates:       Certificates(),
		Accounts:           Accounts(),
		SSHKeys:            SSHKeys(),
		Runtimes:           Runtimes(),
		TPMEnabled:         TPMEnabled(),
		DiskEncryption:     DiskEncryption(),
		SELinux:            SELinuxStatus(),
		AppArmor:           AppArmorStatus(),
	}
	applyCaps(&info)
	return info, nil
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
		if current != nil && strings.Contains(line, "inet6 ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				current.Addresses = append(current.Addresses, fields[1])
			}
		}
	}
	if current != nil {
		result = append(result, *current)
	}
	for i := range result {
		result[i].Driver = nicDriver(result[i].Name)
		result[i].LinkSpeed = nicSpeed(result[i].Name)
	}
	return enrichNetConfig(result)
}

func nicDriver(name string) string {
	target, err := filepath.EvalSymlinks("/sys/class/net/" + name + "/device/driver")
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

func nicSpeed(name string) string {
	data, err := os.ReadFile("/sys/class/net/" + name + "/speed")
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(data))
	if v == "" || v == "-1" {
		return ""
	}
	return v + "Mb/s"
}

// enrichNetConfig attaches default-route gateways and DNS servers per NIC.
func enrichNetConfig(ifaces []collector.NetInterfaceSpec) []collector.NetInterfaceSpec {
	gateways := map[string]string{}
	if out, err := exec.Command("ip", "route", "show", "default").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			gw, dev := "", ""
			for i, tok := range fields {
				if tok == "via" && i+1 < len(fields) {
					gw = fields[i+1]
				}
				if tok == "dev" && i+1 < len(fields) {
					dev = fields[i+1]
				}
			}
			if gw != "" && dev != "" {
				gateways[dev] = gw
			}
		}
	}
	dns := readDNSServers()
	for i := range ifaces {
		if gw := gateways[ifaces[i].Name]; gw != "" {
			ifaces[i].Gateways = []string{gw}
		}
		if len(dns) > 0 {
			ifaces[i].DNS = dns
		}
	}
	return ifaces
}

func readDNSServers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			servers = append(servers, fields[1])
		}
	}
	return servers
}

// OpenPorts lists listening TCP/UDP sockets via `ss`.
func OpenPorts() []collector.PortInfo {
	out, err := exec.Command("ss", "-tulnp").Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	return collector.ParseSSPorts(string(out))
}

// Processes lists running processes sorted by memory, capped at 300.
func Processes() []collector.ProcessInfo {
	out, err := exec.Command("ps", "-eo", "pid,user,comm,rss", "--no-headers").Output()
	if err != nil {
		return nil
	}
	var procs []collector.ProcessInfo
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, _ := strconv.Atoi(fields[0])
		rssKB, _ := strconv.ParseInt(fields[3], 10, 64)
		procs = append(procs, collector.ProcessInfo{
			PID:      pid,
			Name:     fields[2],
			User:     fields[1],
			MemoryMB: rssKB / 1024,
		})
	}
	sort.SliceStable(procs, func(i, j int) bool {
		return procs[i].MemoryMB > procs[j].MemoryMB
	})
	if len(procs) > 300 {
		procs = procs[:300]
	}
	return procs
}

// Disks returns block devices with sizes via lsblk.
func Disks() []collector.StorageSpec {
	out, err := exec.Command("lsblk", "-bno", "NAME,SIZE,MOUNTPOINT,SERIAL,MODEL").Output()
	if err != nil {
		return nil
	}
	disks := collector.ParseLSBLK(string(out))
	if df, err := exec.Command("df", "-Pk").Output(); err == nil {
		usage := collector.ParseDF(string(df))
		for i := range disks {
			if pct, ok := usage[disks[i].Mount]; ok {
				disks[i].UsagePercent = pct
			}
		}
	}
	return disks
}

// Hardware reads DMI system identity fields.
func Hardware() (manufacturer, model, serial string) {
	return readDMI("sys_vendor"), readDMI("product_name"), readDMI("product_serial")
}

// HardwareBIOS reads DMI BIOS identity fields.
func HardwareBIOS() (version, date string) {
	return readDMI("bios_version"), readDMI("bios_date")
}

func readDMI(name string) string {
	data, err := os.ReadFile("/sys/class/dmi/id/" + name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// Services lists systemd or OpenRC services with state and start type.
func Services() []collector.ServiceInfo {
	if out, err := collector.RunTimeout("systemctl", "list-units", "--type=service", "--all", "--no-legend"); err == nil {
		units := collector.ParseSystemctlUnits(string(out))
		files := map[string]string{}
		if fout, err := collector.RunTimeout("systemctl", "list-unit-files", "--type=service", "--no-legend"); err == nil {
			files = collector.ParseSystemctlUnitFiles(string(fout))
		}
		var result []collector.ServiceInfo
		for _, u := range units {
			if strings.Contains(u.State, "not-found") {
				continue
			}
			u.StartType = files[u.Name]
			result = append(result, u)
		}
		return result
	}
	return openrcServices()
}

func openrcServices() []collector.ServiceInfo {
	out, err := collector.RunTimeout("rc-status", "--all")
	if err != nil {
		return nil
	}
	var result []collector.ServiceInfo
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Runlevel:") {
			continue
		}
		if idx := strings.Index(line, " ["); idx >= 0 && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(line[:idx])
			state := strings.Trim(strings.TrimSpace(line[idx+2:]), "]")
			result = append(result, collector.ServiceInfo{Name: name, State: state})
		}
	}
	return result
}

// StartupItems lists enabled systemd units, OpenRC services and rc.local.
func StartupItems() []collector.StartupItem {
	var items []collector.StartupItem
	if out, err := collector.RunTimeout("systemctl", "list-unit-files", "--type=service", "--no-legend"); err == nil {
		for unit, state := range collector.ParseSystemctlUnitFiles(string(out)) {
			if state == "enabled" {
				items = append(items, collector.StartupItem{Name: unit, Command: unit, Location: "systemd"})
			}
		}
	} else if out, err := collector.RunTimeout("rc-update", "show"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "|" {
				items = append(items, collector.StartupItem{Name: fields[0], Command: fields[0], Location: "openrc"})
			}
		}
	}
	if _, err := os.Stat("/etc/rc.local"); err == nil {
		items = append(items, collector.StartupItem{Name: "rc.local", Location: "/etc/rc.local"})
	}
	return items
}

// ScheduledTasks lists systemd timers and crontab entries.
func ScheduledTasks() []collector.ScheduledTask {
	var tasks []collector.ScheduledTask
	if out, err := collector.RunTimeout("systemctl", "list-timers", "--all", "--no-legend"); err == nil {
		tasks = append(tasks, collector.ParseSystemctlTimers(string(out))...)
	}
	for _, path := range cronFiles() {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		tasks = append(tasks, collector.ParseCrontab(string(data), path)...)
	}
	return tasks
}

func cronFiles() []string {
	paths := []string{"/etc/crontab"}
	if entries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				paths = append(paths, "/etc/cron.d/"+e.Name())
			}
		}
	}
	if _, err := os.Stat("/var/spool/cron/crontabs/root"); err == nil {
		paths = append(paths, "/var/spool/cron/crontabs/root")
	}
	return paths
}

// Routes lists the full IP routing table.
func Routes() []collector.RouteInfo {
	out, err := collector.RunTimeout("ip", "route", "show")
	if err != nil {
		return nil
	}
	return collector.ParseIPRoute(string(out))
}

// FirewallRules lists nftables or iptables rules.
func FirewallRules() []collector.FirewallRule {
	if out, err := collector.RunTimeout("nft", "list", "ruleset"); err == nil {
		if rules := collector.ParseNFTListRuleset(string(out)); len(rules) > 0 {
			return rules
		}
	}
	out, err := collector.RunTimeout("iptables-save")
	if err != nil {
		return nil
	}
	return collector.ParseIPTablesSave(string(out))
}

// Neighbors lists the ARP/NDP neighbor table.
func Neighbors() []collector.NeighborInfo {
	out, err := collector.RunTimeout("ip", "neigh", "show")
	if err != nil {
		return nil
	}
	return collector.ParseIPNeigh(string(out))
}

// Certificates parses CA certificates from the common system stores.
func Certificates() []collector.CertificateInfo {
	if _, err := exec.LookPath("openssl"); err != nil {
		return nil
	}
	var files []string
	seen := map[string]bool{}
	for _, dir := range []string{"/etc/ssl/certs", "/etc/pki/tls/certs", "/usr/local/share/ca-certificates"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if (strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".pem")) && !seen[name] {
				seen[name] = true
				files = append(files, dir+"/"+name)
			}
		}
	}
	var certs []collector.CertificateInfo
	for _, f := range files {
		if len(certs) >= 200 {
			break
		}
		out, err := collector.RunTimeout("openssl", "x509", "-in", f, "-noout",
			"-subject", "-issuer", "-serial", "-dates")
		if err != nil {
			continue
		}
		if cert, ok := collector.ParseOpenSSLCert(string(out), filepath.Dir(f)); ok {
			certs = append(certs, cert)
		}
	}
	return certs
}

// Accounts lists local users and whether they are administrative.
func Accounts() []collector.AccountInfo {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}
	accounts := collector.ParsePasswd(string(data))
	admins := adminUsers()
	for i := range accounts {
		accounts[i].Admin = admins[accounts[i].Name] || accounts[i].Name == "root"
	}
	return accounts
}

func adminUsers() map[string]bool {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		switch fields[0] {
		case "sudo", "wheel", "root", "admin":
			for _, m := range strings.Split(fields[3], ",") {
				m = strings.TrimSpace(m)
				if m != "" {
					out[m] = true
				}
			}
		}
	}
	return out
}

// SSHKeys lists authorized_keys fingerprints (public keys only).
func SSHKeys() []collector.SSHKeyInfo {
	hasKeygen := false
	if _, err := exec.LookPath("ssh-keygen"); err == nil {
		hasKeygen = true
	}
	var keys []collector.SSHKeyInfo
	for user, home := range userHomes() {
		if len(keys) >= 200 {
			break
		}
		path := filepath.Join(home, ".ssh", "authorized_keys")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		line := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		info := collector.SSHKeyInfo{User: user, Path: path}
		if len(fields) >= 2 {
			info.Type = fields[0]
		}
		if hasKeygen {
			if fp, err := collector.RunTimeout("ssh-keygen", "-lf", path); err == nil {
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

func userHomes() map[string]string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 6 && fields[5] != "" {
			out[fields[0]] = fields[5]
		}
	}
	return out
}

// MemoryModules reads DIMM details when dmidecode is available.
func MemoryModules() []collector.MemoryModule {
	if _, err := exec.LookPath("dmidecode"); err != nil {
		return nil
	}
	out, err := collector.RunTimeout("dmidecode", "-t", "memory")
	if err != nil {
		return nil
	}
	return collector.ParseDMIdecodeMemory(string(out))
}

// Runtimes lists containers via docker/podman when available.
func Runtimes() []collector.RuntimeInfo {
	if out, err := collector.RunTimeout("docker", "ps", "-a", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"); err == nil {
		return collector.ParseDockerPS(string(out))
	}
	if out, err := collector.RunTimeout("podman", "ps", "-a", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"); err == nil {
		return collector.ParseDockerPS(string(out))
	}
	return nil
}

// KernelVersion returns `uname -r` output.
func KernelVersion() string {
	out, err := collector.RunTimeout("uname", "-r")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Uptime returns system uptime in seconds from /proc/uptime.
func Uptime() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	seconds, _ := strconv.ParseFloat(fields[0], 64)
	return int64(seconds)
}

// Timezone reads /etc/timezone or the /etc/localtime symlink.
func Timezone() string {
	if data, err := os.ReadFile("/etc/timezone"); err == nil {
		if v := strings.TrimSpace(string(data)); v != "" {
			return v
		}
	}
	target, err := filepath.EvalSymlinks("/etc/localtime")
	if err != nil {
		return ""
	}
	parts := strings.Split(target, "/")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], "/")
	}
	return ""
}

// OSDomain returns the DNS domain of the host.
func OSDomain() string {
	out, err := collector.RunTimeout("hostname", "-d")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// TPMEnabled detects a TPM device.
func TPMEnabled() bool {
	if _, err := os.Stat("/sys/class/tpm"); err == nil {
		return true
	}
	_, err := os.Stat("/dev/tpm0")
	return err == nil
}

// DiskEncryption reports LUKS encryption presence.
func DiskEncryption() string {
	out, err := collector.RunTimeout("lsblk", "-no", "FSTYPE")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "crypto_LUKS") {
			return "LUKS"
		}
	}
	return ""
}

// SELinuxStatus reports enforcing/permissive state.
func SELinuxStatus() string {
	data, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil {
		return ""
	}
	if strings.TrimSpace(string(data)) == "1" {
		return "enforcing"
	}
	return "permissive"
}

// AppArmorStatus reports AppArmor presence.
func AppArmorStatus() string {
	if _, err := os.Stat("/sys/kernel/security/apparmor"); err == nil {
		return "enabled"
	}
	return ""
}

func applyCaps(info *collector.SystemInfo) {
	capList(&info.Services, 500, "services", info)
	capList(&info.StartupItems, 200, "startup_items", info)
	capList(&info.ScheduledTasks, 300, "scheduled_tasks", info)
	capList(&info.Routes, 200, "routes", info)
	capList(&info.FirewallRules, 500, "firewall_rules", info)
	capList(&info.Neighbors, 200, "neighbors", info)
	capList(&info.Certificates, 200, "certificates", info)
	capList(&info.Accounts, 500, "accounts", info)
	capList(&info.SSHKeys, 200, "ssh_keys", info)
	capList(&info.MemoryModules, 32, "memory_modules", info)
	capList(&info.Runtimes, 200, "runtimes", info)
}

func capList[T any](list *[]T, limit int, name string, info *collector.SystemInfo) {
	if len(*list) > limit {
		*list = (*list)[:limit]
		info.Truncated = append(info.Truncated, name)
	}
}
