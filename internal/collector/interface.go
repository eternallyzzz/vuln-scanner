package collector

import (
	"context"
	"time"
)

type Asset struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Arch        string `json:"arch"`
	Format      string `json:"format"`
	Vendor      string `json:"vendor,omitempty"`
	Location    string `json:"location,omitempty"`
	InstallDate string `json:"install_date,omitempty"`
	Status      string `json:"status,omitempty"`
	Type        string `json:"type"`
}

type CPUSpec struct {
	Name  string `json:"name"`
	Cores int    `json:"cores"`
}

type GPUSpec struct {
	Name   string `json:"name"`
	Driver string `json:"driver,omitempty"`
}

type MotherboardSpec struct {
	Manufacturer string `json:"manufacturer"`
	Product      string `json:"product"`
}

type NetInterfaceSpec struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	Addresses []string `json:"addresses,omitempty"`
	Gateways  []string `json:"gateways,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	LinkSpeed string   `json:"link_speed,omitempty"`
	Driver    string   `json:"driver,omitempty"`
}

type PortInfo struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Process  string `json:"process,omitempty"`
}

type ProcessInfo struct {
	PID      int    `json:"pid"`
	Name     string `json:"name"`
	User     string `json:"user,omitempty"`
	MemoryMB int64  `json:"memory_mb"`
}

type StorageSpec struct {
	Name         string  `json:"name"`
	SizeBytes    int64   `json:"size_bytes"`
	Mount        string  `json:"mount,omitempty"`
	Serial       string  `json:"serial,omitempty"`
	Model        string  `json:"model,omitempty"`
	Firmware     string  `json:"firmware,omitempty"`
	UsagePercent float64 `json:"usage_percent,omitempty"`
}

type ServiceInfo struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	StartType string `json:"start_type,omitempty"`
	RunAs     string `json:"run_as,omitempty"`
}

type StartupItem struct {
	Name     string `json:"name"`
	Command  string `json:"command,omitempty"`
	Location string `json:"location,omitempty"`
}

type ScheduledTask struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	NextRun string `json:"next_run,omitempty"`
	Command string `json:"command,omitempty"`
}

type RouteInfo struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Metric      string `json:"metric,omitempty"`
}

type FirewallRule struct {
	Name      string `json:"name"`
	Enabled   string `json:"enabled,omitempty"`
	Direction string `json:"direction,omitempty"`
	Action    string `json:"action,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	LocalPort string `json:"local_port,omitempty"`
	RemoteIP  string `json:"remote_ip,omitempty"`
}

type NeighborInfo struct {
	Interface string `json:"interface,omitempty"`
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	State     string `json:"state,omitempty"`
}

type CertificateInfo struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	Serial    string `json:"serial"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Store     string `json:"store"`
}

type AccountInfo struct {
	Name     string `json:"name"`
	Domain   string `json:"domain,omitempty"`
	Group    string `json:"group,omitempty"`
	Admin    bool   `json:"admin"`
	Disabled bool   `json:"disabled"`
}

type SSHKeyInfo struct {
	User        string `json:"user"`
	Path        string `json:"path"`
	Type        string `json:"type,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type MemoryModule struct {
	Slot       string `json:"slot"`
	CapacityMB int64  `json:"capacity_mb"`
	Type       string `json:"type,omitempty"`
	Speed      string `json:"speed,omitempty"`
	Serial     string `json:"serial,omitempty"`
}

type RuntimeInfo struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	State string `json:"state,omitempty"`
}

// UpdateFact is one Windows update observed through WUA/WSUS: either an
// applicable-but-not-installed (pending) update or an installed update.
type UpdateFact struct {
	KB             string    `json:"kb"`
	Title          string    `json:"title,omitempty"`
	State          string    `json:"state"` // installed | pending
	Severity       string    `json:"severity,omitempty"`
	RebootRequired bool      `json:"reboot_required,omitempty"`
	Source         string    `json:"source"` // wua | wsus | mu
	CollectedAt    time.Time `json:"collected_at,omitempty"`
}

// UpdateSourceStatus reports whether the WUA update source was reachable
// during the last collection and, if not, why.
type UpdateSourceStatus struct {
	SourceReachable bool      `json:"source_reachable"`
	LastCheckedAt   time.Time `json:"last_checked_at,omitempty"`
	Error           string    `json:"error,omitempty"`
}

type SystemInfo struct {
	Hostname           string              `json:"hostname"`
	OS                 string              `json:"os"`
	Version            string              `json:"version"`
	Arch               string              `json:"arch"`
	MachineID          string              `json:"machine_id"`
	SystemManufacturer string              `json:"system_manufacturer,omitempty"`
	SystemModel        string              `json:"system_model,omitempty"`
	SystemSerial       string              `json:"system_serial,omitempty"`
	BIOSVersion        string              `json:"bios_version,omitempty"`
	BIOSDate           string              `json:"bios_date,omitempty"`
	KernelVersion      string              `json:"kernel_version,omitempty"`
	UptimeSeconds      int64               `json:"uptime_seconds,omitempty"`
	BootTime           string              `json:"boot_time,omitempty"`
	Timezone           string              `json:"timezone,omitempty"`
	OSDomain           string              `json:"os_domain,omitempty"`
	CPU                []CPUSpec           `json:"cpu,omitempty"`
	GPU                []GPUSpec           `json:"gpu,omitempty"`
	Motherboard        *MotherboardSpec    `json:"motherboard,omitempty"`
	MemoryMB           int64               `json:"memory_mb,omitempty"`
	MemoryModules      []MemoryModule      `json:"memory_modules,omitempty"`
	NetInterfaces      []NetInterfaceSpec  `json:"net_interfaces,omitempty"`
	OpenPorts          []PortInfo          `json:"open_ports,omitempty"`
	Processes          []ProcessInfo       `json:"processes,omitempty"`
	Storage            []StorageSpec       `json:"storage,omitempty"`
	Services           []ServiceInfo       `json:"services,omitempty"`
	StartupItems       []StartupItem       `json:"startup_items,omitempty"`
	ScheduledTasks     []ScheduledTask     `json:"scheduled_tasks,omitempty"`
	Routes             []RouteInfo         `json:"routes,omitempty"`
	FirewallRules      []FirewallRule      `json:"firewall_rules,omitempty"`
	Neighbors          []NeighborInfo      `json:"neighbors,omitempty"`
	Certificates       []CertificateInfo   `json:"certificates,omitempty"`
	Accounts           []AccountInfo       `json:"accounts,omitempty"`
	SSHKeys            []SSHKeyInfo        `json:"ssh_keys,omitempty"`
	Runtimes           []RuntimeInfo       `json:"runtimes,omitempty"`
	TPMEnabled         bool                `json:"tpm_enabled,omitempty"`
	DiskEncryption     string              `json:"disk_encryption,omitempty"`
	Antivirus          string              `json:"antivirus,omitempty"`
	SELinux            string              `json:"selinux,omitempty"`
	AppArmor           string              `json:"apparmor,omitempty"`
	Truncated          []string            `json:"truncated,omitempty"`
	UpdateFacts        []UpdateFact        `json:"update_facts,omitempty"`
	UpdateSourceStatus *UpdateSourceStatus `json:"update_source_status,omitempty"`
}

type Collector interface {
	CollectPackages(ctx context.Context) ([]Asset, error)
	CollectHotfixes(ctx context.Context) ([]Asset, error)
	SystemInfo(ctx context.Context) (SystemInfo, error)
}

func All(ctx context.Context, c Collector) ([]Asset, SystemInfo, error) {
	sys, err := c.SystemInfo(ctx)
	if err != nil {
		return nil, SystemInfo{}, err
	}

	var assets []Asset

	pkgs, err := c.CollectPackages(ctx)
	if err != nil {
		return nil, sys, err
	}
	assets = append(assets, pkgs...)

	hotfixes, _ := c.CollectHotfixes(ctx)
	assets = append(assets, hotfixes...)

	if sys.OS != "" {
		assets = append(assets, Asset{
			Name:    sys.OS,
			Version: sys.Version,
			Format:  "os",
			Type:    "OS",
		})
	}

	return assets, sys, nil
}
