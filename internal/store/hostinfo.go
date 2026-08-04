package store

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"vuln-scanner/internal/collector"
)

// HostSystemInfo is the latest host-level telemetry reported by an agent:
// OS, hardware, network, open ports and processes.
type HostSystemInfo struct {
	AgentID            string                       `json:"agent_id"`
	Hostname           string                       `json:"hostname"`
	OS                 string                       `json:"os"`
	OSVersion          string                       `json:"os_version"`
	Arch               string                       `json:"arch"`
	MachineID          string                       `json:"machine_id"`
	SystemManufacturer string                       `json:"system_manufacturer,omitempty"`
	SystemModel        string                       `json:"system_model,omitempty"`
	SystemSerial       string                       `json:"system_serial,omitempty"`
	BIOSVersion        string                       `json:"bios_version,omitempty"`
	BIOSDate           string                       `json:"bios_date,omitempty"`
	KernelVersion      string                       `json:"kernel_version,omitempty"`
	UptimeSeconds      int64                        `json:"uptime_seconds,omitempty"`
	BootTime           string                       `json:"boot_time,omitempty"`
	Timezone           string                       `json:"timezone,omitempty"`
	OSDomain           string                       `json:"os_domain,omitempty"`
	MemoryMB           int64                        `json:"memory_mb"`
	CPU                []collector.CPUSpec          `json:"cpu,omitempty"`
	GPU                []collector.GPUSpec          `json:"gpu,omitempty"`
	Motherboard        *collector.MotherboardSpec   `json:"motherboard,omitempty"`
	MemoryModules      []collector.MemoryModule     `json:"memory_modules,omitempty"`
	NetInterfaces      []collector.NetInterfaceSpec `json:"net_interfaces,omitempty"`
	OpenPorts          []collector.PortInfo         `json:"open_ports,omitempty"`
	Processes          []collector.ProcessInfo      `json:"processes,omitempty"`
	Storage            []collector.StorageSpec      `json:"storage,omitempty"`
	Services           []collector.ServiceInfo      `json:"services,omitempty"`
	StartupItems       []collector.StartupItem      `json:"startup_items,omitempty"`
	ScheduledTasks     []collector.ScheduledTask    `json:"scheduled_tasks,omitempty"`
	Routes             []collector.RouteInfo        `json:"routes,omitempty"`
	FirewallRules      []collector.FirewallRule     `json:"firewall_rules,omitempty"`
	Neighbors          []collector.NeighborInfo     `json:"neighbors,omitempty"`
	Certificates       []collector.CertificateInfo  `json:"certificates,omitempty"`
	Accounts           []collector.AccountInfo      `json:"accounts,omitempty"`
	SSHKeys            []collector.SSHKeyInfo       `json:"ssh_keys,omitempty"`
	Runtimes           []collector.RuntimeInfo      `json:"runtimes,omitempty"`
	TPMEnabled         bool                         `json:"tpm_enabled,omitempty"`
	DiskEncryption     string                       `json:"disk_encryption,omitempty"`
	Antivirus          string                       `json:"antivirus,omitempty"`
	SELinux            string                       `json:"selinux,omitempty"`
	AppArmor           string                       `json:"apparmor,omitempty"`
	Truncated          []string                     `json:"truncated,omitempty"`
	CollectedAt        time.Time                    `json:"collected_at"`
}

// SaveHostSystemInfo upserts the latest host telemetry and refreshes the
// agent record plus the CMDB host asset in one transaction.
func (s *Store) SaveHostSystemInfo(ctx context.Context, info *HostSystemInfo) error {
	cpu, _ := json.Marshal(info.CPU)
	gpu, _ := json.Marshal(info.GPU)
	mb, _ := json.Marshal(info.Motherboard)
	nics, _ := json.Marshal(info.NetInterfaces)
	ports, _ := json.Marshal(info.OpenPorts)
	procs, _ := json.Marshal(info.Processes)
	storage, _ := json.Marshal(info.Storage)
	memoryModules, _ := json.Marshal(info.MemoryModules)
	services, _ := json.Marshal(info.Services)
	startupItems, _ := json.Marshal(info.StartupItems)
	scheduledTasks, _ := json.Marshal(info.ScheduledTasks)
	routes, _ := json.Marshal(info.Routes)
	firewallRules, _ := json.Marshal(info.FirewallRules)
	neighbors, _ := json.Marshal(info.Neighbors)
	certificates, _ := json.Marshal(info.Certificates)
	accounts, _ := json.Marshal(info.Accounts)
	sshKeys, _ := json.Marshal(info.SSHKeys)
	runtimes, _ := json.Marshal(info.Runtimes)
	if info.Truncated == nil {
		info.Truncated = []string{}
	}
	ip := primaryIPv4(info.NetInterfaces)
	now := time.Now()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		INSERT INTO host_system_info (
			agent_id, hostname, os, os_version, arch, machine_id,
			system_manufacturer, system_model, system_serial, memory_mb,
			bios_version, bios_date, kernel_version, uptime_seconds, boot_time, timezone, os_domain,
			cpu, gpu, motherboard, memory_modules, net_interfaces, open_ports, processes, storage,
			services, startup_items, scheduled_tasks, routes, firewall_rules, neighbors,
			certificates, accounts, ssh_keys, runtimes,
			tpm_enabled, disk_encryption, antivirus, selinux, apparmor, truncated, collected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
			$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,
			$36,$37,$38,$39,$40,$41,$42)
		ON CONFLICT (agent_id) DO UPDATE SET
			hostname=$2, os=$3, os_version=$4, arch=$5, machine_id=$6,
			system_manufacturer=$7, system_model=$8, system_serial=$9, memory_mb=$10,
			bios_version=$11, bios_date=$12, kernel_version=$13, uptime_seconds=$14,
			boot_time=$15, timezone=$16, os_domain=$17,
			cpu=$18, gpu=$19, motherboard=$20, memory_modules=$21, net_interfaces=$22,
			open_ports=$23, processes=$24, storage=$25, services=$26, startup_items=$27,
			scheduled_tasks=$28, routes=$29, firewall_rules=$30, neighbors=$31,
			certificates=$32, accounts=$33, ssh_keys=$34, runtimes=$35,
			tpm_enabled=$36, disk_encryption=$37, antivirus=$38, selinux=$39, apparmor=$40,
			truncated=$41, collected_at=$42
	`, info.AgentID, info.Hostname, info.OS, info.OSVersion, info.Arch, info.MachineID,
		info.SystemManufacturer, info.SystemModel, info.SystemSerial, info.MemoryMB,
		info.BIOSVersion, info.BIOSDate, info.KernelVersion, info.UptimeSeconds,
		info.BootTime, info.Timezone, info.OSDomain,
		cpu, gpu, mb, memoryModules, nics, ports, procs, storage,
		services, startupItems, scheduledTasks, routes, firewallRules, neighbors,
		certificates, accounts, sshKeys, runtimes,
		info.TPMEnabled, info.DiskEncryption, info.Antivirus, info.SELinux, info.AppArmor,
		info.Truncated, now); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `
		UPDATE agents SET os_type=$1, os_version=$2, arch=$3, ip=$4, updated_at=$5
		WHERE id=$6
	`, info.OS, info.OSVersion, info.Arch, ip, now, info.AgentID); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `
		UPDATE assets SET version=$1, os_version=$2, os_type=$3, ip=$4,
			last_seen=$5, updated_at=$5
		WHERE asset_key=$6
	`, info.OSVersion, info.OSVersion, info.OS, ip, now, "host:"+info.AgentID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// GetHostSystemInfo returns the latest telemetry for an agent.
func (s *Store) GetHostSystemInfo(ctx context.Context, agentID string) (*HostSystemInfo, error) {
	var info HostSystemInfo
	var cpu, gpu, mb, memoryModules, nics, ports, procs, storage []byte
	var services, startupItems, scheduledTasks, routes, firewallRules, neighbors []byte
	var certificates, accounts, sshKeys, runtimes []byte
	err := s.pool.QueryRow(ctx, `
		SELECT agent_id, hostname, os, os_version, arch, machine_id,
			system_manufacturer, system_model, system_serial, memory_mb,
			bios_version, bios_date, kernel_version, uptime_seconds, boot_time, timezone, os_domain,
			cpu, gpu, motherboard, memory_modules, net_interfaces, open_ports, processes, storage,
			services, startup_items, scheduled_tasks, routes, firewall_rules, neighbors,
			certificates, accounts, ssh_keys, runtimes,
			tpm_enabled, disk_encryption, antivirus, selinux, apparmor, truncated, collected_at
		FROM host_system_info WHERE agent_id=$1
	`, agentID).Scan(&info.AgentID, &info.Hostname, &info.OS, &info.OSVersion, &info.Arch,
		&info.MachineID, &info.SystemManufacturer, &info.SystemModel, &info.SystemSerial,
		&info.MemoryMB, &info.BIOSVersion, &info.BIOSDate, &info.KernelVersion,
		&info.UptimeSeconds, &info.BootTime, &info.Timezone, &info.OSDomain,
		&cpu, &gpu, &mb, &memoryModules, &nics, &ports, &procs, &storage,
		&services, &startupItems, &scheduledTasks, &routes, &firewallRules, &neighbors,
		&certificates, &accounts, &sshKeys, &runtimes,
		&info.TPMEnabled, &info.DiskEncryption, &info.Antivirus, &info.SELinux, &info.AppArmor,
		&info.Truncated, &info.CollectedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(cpu, &info.CPU)
	_ = json.Unmarshal(gpu, &info.GPU)
	_ = json.Unmarshal(mb, &info.Motherboard)
	_ = json.Unmarshal(memoryModules, &info.MemoryModules)
	_ = json.Unmarshal(nics, &info.NetInterfaces)
	_ = json.Unmarshal(ports, &info.OpenPorts)
	_ = json.Unmarshal(procs, &info.Processes)
	_ = json.Unmarshal(storage, &info.Storage)
	_ = json.Unmarshal(services, &info.Services)
	_ = json.Unmarshal(startupItems, &info.StartupItems)
	_ = json.Unmarshal(scheduledTasks, &info.ScheduledTasks)
	_ = json.Unmarshal(routes, &info.Routes)
	_ = json.Unmarshal(firewallRules, &info.FirewallRules)
	_ = json.Unmarshal(neighbors, &info.Neighbors)
	_ = json.Unmarshal(certificates, &info.Certificates)
	_ = json.Unmarshal(accounts, &info.Accounts)
	_ = json.Unmarshal(sshKeys, &info.SSHKeys)
	_ = json.Unmarshal(runtimes, &info.Runtimes)
	return &info, nil
}

// IsHostSystemInfoNotFound reports whether the error is a missing row.
func IsHostSystemInfoNotFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}

func primaryIPv4(ifaces []collector.NetInterfaceSpec) string {
	for _, n := range ifaces {
		for _, a := range n.Addresses {
			ipStr := strings.SplitN(a, "/", 2)[0]
			ip := net.ParseIP(ipStr)
			if ip == nil || !strings.Contains(ipStr, ".") || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			return ipStr
		}
	}
	return ""
}
