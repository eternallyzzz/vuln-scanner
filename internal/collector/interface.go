package collector

import "context"

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
}

type SystemInfo struct {
	Hostname        string             `json:"hostname"`
	OS              string             `json:"os"`
	Version         string             `json:"version"`
	Arch            string             `json:"arch"`
	MachineID       string             `json:"machine_id"`
	CPU             []CPUSpec          `json:"cpu,omitempty"`
	GPU             []GPUSpec          `json:"gpu,omitempty"`
	Motherboard     *MotherboardSpec   `json:"motherboard,omitempty"`
	MemoryMB        int64              `json:"memory_mb,omitempty"`
	NetInterfaces   []NetInterfaceSpec `json:"net_interfaces,omitempty"`
	OpenPorts       []string           `json:"open_ports,omitempty"`
	RunningServices []string           `json:"running_services,omitempty"`
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
