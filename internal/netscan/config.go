package netscan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultPorts is the v1 discovery port table. Ports are TCP-only.
func DefaultPorts() []int {
	return []int{21, 22, 25, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443}
}

// Config controls one network discovery pass.
type Config struct {
	Targets     []string      `json:"targets,omitempty" yaml:"targets,omitempty"`
	Ports       []int         `json:"ports,omitempty" yaml:"ports,omitempty"`
	Exclude     []string      `json:"exclude,omitempty" yaml:"exclude,omitempty"`
	Timeout     time.Duration `json:"-" yaml:"-"`
	Concurrency int           `json:"concurrency,omitempty" yaml:"concurrency,omitempty"`
	MaxHosts    int           `json:"max_hosts,omitempty" yaml:"max_hosts,omitempty"`
}

// Normalized applies defaults and validates the config.
func (c Config) Normalized() (Config, error) {
	if len(c.Targets) == 0 {
		return c, fmt.Errorf("network scan targets required")
	}
	if len(c.Ports) == 0 {
		c.Ports = DefaultPorts()
	}
	if c.Timeout <= 0 {
		c.Timeout = 2 * time.Second
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 32
	}
	if c.MaxHosts <= 0 {
		c.MaxHosts = 1024
	}
	return c, nil
}

// ExpandTargets expands CIDRs and single IPs into a sorted, de-duplicated
// IPv4 list. IPv6 targets are rejected in v1 to avoid accidental huge scans.
func ExpandTargets(targets []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range targets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if ip := net.ParseIP(raw); ip != nil {
			if ip.To4() == nil {
				return nil, fmt.Errorf("IPv6 target not supported in v1: %s", raw)
			}
			if !seen[raw] {
				seen[raw] = true
				out = append(out, raw)
			}
			continue
		}
		ip, ipnet, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid target %q: %w", raw, err)
		}
		if ip.To4() == nil {
			return nil, fmt.Errorf("IPv6 target not supported in v1: %s", raw)
		}
		base := ip.To4()
		for ip4 := cloneIPv4(base); ipnet.Contains(ip4); incIPv4(ip4) {
			s := ip4.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// LocalNonLoopbackIPs lists the host's own interface addresses (loopback
// excluded) so scheduled scans can skip the machine they run on.
func LocalNonLoopbackIPs() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip := net.ParseIP(strings.SplitN(a.String(), "/", 2)[0])
			if ip != nil && ip.To4() != nil {
				out = append(out, ip.String())
			}
		}
	}
	return out
}

func cloneIPv4(ip net.IP) net.IP {
	out := make(net.IP, 4)
	copy(out, ip.To4())
	return out
}

func incIPv4(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

// Scan runs one discovery pass over the configured targets.
func Scan(ctx context.Context, cfg Config) ([]Host, error) {
	cfg, err := cfg.Normalized()
	if err != nil {
		return nil, err
	}
	ips, err := ExpandTargets(cfg.Targets)
	if err != nil {
		return nil, err
	}
	exclude := map[string]bool{}
	for _, e := range cfg.Exclude {
		exclude[strings.TrimSpace(e)] = true
	}
	skipLocal := map[string]bool{}
	for _, ip := range LocalNonLoopbackIPs() {
		skipLocal[ip] = true
	}
	hosts := make([]Host, 0, len(ips))
	for _, ip := range ips {
		if exclude[ip] || skipLocal[ip] {
			continue
		}
		if len(hosts) >= cfg.MaxHosts {
			break
		}
		host, err := scanHost(ctx, ip, cfg)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		hosts = append(hosts, host)
	}
	return hosts, nil
}

func scanHost(ctx context.Context, ip string, cfg Config) (Host, error) {
	sem := make(chan struct{}, cfg.Concurrency)
	type probe struct {
		port int
		open bool
	}
	results := make([]probe, len(cfg.Ports))
	var wg sync.WaitGroup
	for i, port := range cfg.Ports {
		wg.Add(1)
		go func(i, port int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), cfg.Timeout)
			if err == nil {
				conn.Close()
				results[i] = probe{port: port, open: true}
			}
		}(i, port)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return Host{}, ctx.Err()
	}

	var open []int
	for _, p := range results {
		if p.open {
			open = append(open, p.port)
		}
	}
	if len(open) == 0 {
		return Host{}, fmt.Errorf("no open ports")
	}

	host := Host{
		IP:          ip,
		OSTypeGuess: GuessOS(open),
		Hostname:    reverseLookup(ip),
	}
	for _, port := range open {
		svc := Service{Port: port, Protocol: "tcp", Service: ServiceName(port)}
		if bannerPort(port) {
			banner := grabBanner(ip, port, cfg.Timeout)
			if banner != "" {
				svc.Banner = truncate(banner, 256)
				if product, version := ParseBanner(port, banner); product != "" {
					svc.Service = product
					svc.Version = version
				}
			}
		}
		host.Services = append(host.Services, svc)
	}
	return host, nil
}

func reverseLookup(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func bannerPort(port int) bool {
	switch port {
	case 21, 22, 25, 80, 110, 143, 443, 8080, 8443:
		return true
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
