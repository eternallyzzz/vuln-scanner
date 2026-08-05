package agent

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	pb "vuln-scanner/api/gen/vulnscan/v1"
	"vuln-scanner/internal/collector"
	"vuln-scanner/internal/compliance"
	"vuln-scanner/internal/netscan"

	"github.com/golang-jwt/jwt/v5"
)

// complianceSyncInterval bounds how often the agent re-evaluates the CIS
// baseline. The first evaluation runs right after startup; afterwards the
// baseline is refreshed daily without a full asset inventory sync.
const complianceSyncInterval = 24 * time.Hour

type Scheduler struct {
	cfg        *Config
	client     *Client
	collect    collector.Collector
	ticker     *time.Ticker
	done       chan struct{}
	lastAssets map[string]string
}

func NewScheduler(cfg *Config, client *Client, col collector.Collector) *Scheduler {
	return &Scheduler{
		cfg:     cfg,
		client:  client,
		collect: col,
		done:    make(chan struct{}),
	}
}

func (s *Scheduler) Start(ctx context.Context) error {
	interval := time.Duration(s.cfg.Agent.CollectionInterval) * time.Second
	if interval < 60*time.Second {
		interval = 60 * time.Second
	}
	heartbeatInterval := 30 * time.Second
	patchInterval := 60 * time.Second
	netScanInterval := time.Duration(s.cfg.NetworkScan.IntervalMinutes) * time.Minute
	if netScanInterval < 15*time.Minute {
		netScanInterval = 15 * time.Minute
	}
	complianceTicker := time.NewTicker(complianceSyncInterval)
	netScanTicker := time.NewTicker(netScanInterval)
	defer complianceTicker.Stop()
	defer netScanTicker.Stop()

	s.ticker = time.NewTicker(interval)
	hbTicker := time.NewTicker(heartbeatInterval)
	patchTicker := time.NewTicker(patchInterval)
	defer patchTicker.Stop()

	_, sys := s.doFullSync(ctx)
	s.syncCompliance(ctx, sys)
	if s.cfg.NetworkScan.Enabled && len(s.cfg.NetworkScan.Targets) > 0 {
		s.runNetworkScan(ctx, "", nil, 0, "scheduled")
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.done:
			return nil
		case <-hbTicker.C:
			if err := s.client.Heartbeat(ctx, 0); err != nil {
				slog.Warn("heartbeat failed", "error", err)
			}
		case <-s.ticker.C:
			if s.tokenExpiringSoon() {
				if err := s.client.RefreshToken(ctx); err != nil {
					slog.Warn("token refresh failed", "error", err)
				}
			}
			s.doIncrementalSync(ctx)
		case <-complianceTicker.C:
			sys, err := s.collect.SystemInfo(ctx)
			if err != nil {
				slog.Warn("compliance system info collection failed", "error", err)
				continue
			}
			s.syncCompliance(ctx, sys)
		case <-patchTicker.C:
			if s.cfg.Agent.PatchEnabled {
				s.doPatchLoop(ctx)
			}
			s.doNetworkTaskLoop(ctx)
		case <-netScanTicker.C:
			if s.cfg.NetworkScan.Enabled && len(s.cfg.NetworkScan.Targets) > 0 {
				s.runNetworkScan(ctx, "", nil, 0, "scheduled")
			}
		}
	}
}

// doNetworkTaskLoop claims server-dispatched network scan tasks. Any agent
// can execute a task because the target and ports travel with the task.
func (s *Scheduler) doNetworkTaskLoop(ctx context.Context) {
	tasks, err := s.client.FetchNetworkScanTasks(ctx)
	if err != nil {
		slog.Warn("fetch network scan tasks failed", "error", err)
		return
	}
	for _, task := range tasks {
		ports := make([]int, 0, len(task.GetPorts()))
		for _, p := range task.GetPorts() {
			ports = append(ports, int(p))
		}
		s.runNetworkScan(ctx, task.GetTarget(), ports, task.GetId(), "manual")
	}
}

// runNetworkScan runs one discovery pass and reports the result. A server
// task that fails to scan is still reported so it can be marked failed.
func (s *Scheduler) runNetworkScan(ctx context.Context, target string, ports []int, taskID int64, mode string) {
	cfg := netscan.Config{
		Targets:     s.cfg.NetworkScan.Targets,
		Ports:       ports,
		Exclude:     s.cfg.NetworkScan.Exclude,
		Timeout:     time.Duration(s.cfg.NetworkScan.TimeoutSeconds) * time.Second,
		Concurrency: s.cfg.NetworkScan.Concurrency,
		MaxHosts:    s.cfg.NetworkScan.MaxHosts,
	}
	if target != "" {
		cfg.Targets = []string{target}
	}
	if len(ports) == 0 {
		cfg.Ports = s.cfg.NetworkScan.Ports
	}
	hosts, err := netscan.Scan(ctx, cfg)
	scanErr := ""
	if err != nil {
		scanErr = err.Error()
		hosts = nil
	}
	if err := s.client.SyncNetworkScan(ctx, taskID, mode, toPBHosts(hosts), scanErr); err != nil {
		slog.Warn("sync network scan failed", "task_id", taskID, "error", err)
		return
	}
	slog.Info("network scan reported", "task_id", taskID, "mode", mode,
		"hosts", len(hosts), "error", scanErr)
}

func toPBHosts(hosts []netscan.Host) []*pb.NetworkHost {
	out := make([]*pb.NetworkHost, 0, len(hosts))
	for _, h := range hosts {
		services := make([]*pb.NetworkService, 0, len(h.Services))
		for _, svc := range h.Services {
			services = append(services, &pb.NetworkService{
				Port:     int32(svc.Port),
				Protocol: svc.Protocol,
				Service:  svc.Service,
				Version:  svc.Version,
				Banner:   svc.Banner,
			})
		}
		out = append(out, &pb.NetworkHost{
			Ip:       h.IP,
			Hostname: h.Hostname,
			OsType:   h.OSTypeGuess,
			Services: services,
		})
	}
	return out
}

func (s *Scheduler) doPatchLoop(ctx context.Context) {
	tasks, err := s.client.FetchPatchTasks(ctx)
	if err != nil {
		slog.Warn("fetch patch tasks failed", "error", err)
		return
	}
	for _, task := range tasks {
		timeout := time.Duration(s.cfg.Agent.PatchTimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = 600 * time.Second
		}
		if task.GetDryRun() {
			slog.Info("patch task dry-run", "task_id", task.GetId(),
				"asset", task.GetAssetName(), "command", task.GetCommand())
			if err := s.client.ReportPatchTask(ctx, task.GetId(), "success", 0,
				"dry-run: execution skipped"); err != nil {
				slog.Warn("report patch task failed", "task_id", task.GetId(), "error", err)
			}
			continue
		}

		slog.Info("patch task executing", "task_id", task.GetId(),
			"asset", task.GetAssetName(), "command", task.GetCommand())
		var argvLists [][]string
		for _, c := range task.GetCommands() {
			if c != nil {
				argvLists = append(argvLists, c.GetArgv())
			}
		}
		exitCode, output, err := executeCommands(ctx, argvLists, timeout)
		status := "success"
		if err != nil {
			status = "failed"
			slog.Error("patch task failed", "task_id", task.GetId(),
				"exit_code", exitCode, "error", err)
		}
		if err := s.client.ReportPatchTask(ctx, task.GetId(), status, exitCode, output); err != nil {
			slog.Warn("report patch task failed", "task_id", task.GetId(), "error", err)
		}
	}
}

func (s *Scheduler) Stop() {
	close(s.done)
	if s.ticker != nil {
		s.ticker.Stop()
	}
}

func (s *Scheduler) RunOnce(ctx context.Context) ([]collector.Asset, collector.SystemInfo) {
	assets, sys := s.doFullSync(ctx)
	s.syncCompliance(ctx, sys)
	return assets, sys
}

// syncCompliance evaluates the baseline from the given SystemInfo snapshot
// and uploads the report. Failures only log; they never block the inventory
// loop.
func (s *Scheduler) syncCompliance(ctx context.Context, sys collector.SystemInfo) {
	facts := compliance.CollectFacts(ctx, sys)
	rep := compliance.Evaluate(facts, time.Now())
	if len(rep.Checks) == 0 {
		slog.Warn("compliance sync skipped", "reason", "unsupported platform or no checks")
		return
	}
	if err := s.client.SyncCompliance(ctx, complianceReportToPb(rep)); err != nil {
		slog.Warn("compliance sync failed", "error", err)
		return
	}
	slog.Info("compliance synced", "benchmark", rep.Benchmark,
		"score", rep.Score, "passed", rep.Passed, "failed", rep.Failed, "na", rep.NA)
}

func (s *Scheduler) doFullSync(ctx context.Context) ([]collector.Asset, collector.SystemInfo) {
	slog.Info("starting full inventory sync")
	assets, sys, err := collector.All(ctx, s.collect)
	if err != nil {
		slog.Error("full sync collection failed", "error", err)
		return nil, collector.SystemInfo{}
	}
	assets = dedupeAssets(assets)

	var pbAssets []*pb.Asset
	for _, a := range assets {
		pbAssets = append(pbAssets, assetToPb(a))
	}

	if err := s.client.SyncInventory(ctx, pbAssets, pb.SyncMode_FULL, systemInfoToPb(sys)); err != nil {
		slog.Error("full sync rpc failed", "error", err)
		return assets, sys
	}

	s.lastAssets = make(map[string]string, len(assets))
	for _, a := range assets {
		s.lastAssets[assetSyncKey(a)] = a.Version
	}

	slog.Info("full sync completed", "assets", len(pbAssets), "os", sys.OS, "version", sys.Version)
	return assets, sys
}

func (s *Scheduler) doIncrementalSync(ctx context.Context) {
	slog.Info("starting incremental inventory sync")
	assets, _, err := collector.All(ctx, s.collect)
	if err != nil {
		slog.Error("incremental sync collection failed", "error", err)
		return
	}
	assets = dedupeAssets(assets)

	current := make(map[string]string, len(assets))
	for _, a := range assets {
		current[assetSyncKey(a)] = a.Version
	}

	var changed []*pb.Asset
	for _, a := range assets {
		prev, existed := s.lastAssets[assetSyncKey(a)]
		if !existed || prev != a.Version {
			changed = append(changed, assetToPb(a))
		}
	}

	if len(changed) == 0 {
		slog.Info("incremental sync: no changes")
		s.lastAssets = current
		return
	}

	if err := s.client.SyncInventory(ctx, changed, pb.SyncMode_INCREMENTAL, nil); err != nil {
		slog.Warn("incremental sync rpc failed", "error", err)
		return
	}

	s.lastAssets = current
	names := make([]string, 0, len(changed))
	for _, a := range changed {
		names = append(names, a.GetName()+"@"+a.GetVersion())
	}
	slog.Info("incremental sync completed", "changed", len(changed), "total", len(assets), "assets", strings.Join(names, ", "))
}

func (s *Scheduler) tokenExpiringSoon() bool {
	if s.cfg.Agent.Token == "" {
		return false
	}
	parser := jwt.Parser{}
	token, _, err := parser.ParseUnverified(s.cfg.Agent.Token, jwt.MapClaims{})
	if err != nil {
		return false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return false
	}
	remaining := time.Until(time.Unix(int64(exp), 0))
	return remaining < 1*time.Hour
}

func assetToPb(a collector.Asset) *pb.Asset {
	assetType := pb.AssetType_PACKAGE
	switch a.Type {
	case "HOTFIX":
		assetType = pb.AssetType_HOTFIX
	case "OS":
		assetType = pb.AssetType_OS
	}
	return &pb.Asset{
		Name:        a.Name,
		Version:     a.Version,
		Arch:        a.Arch,
		Format:      a.Format,
		Vendor:      a.Vendor,
		Location:    a.Location,
		InstallDate: a.InstallDate,
		Status:      a.Status,
		Type:        assetType,
	}
}

func systemInfoToPb(s collector.SystemInfo) *pb.SystemInfo {
	if s.Hostname == "" && s.OS == "" && s.Arch == "" {
		return nil
	}
	out := &pb.SystemInfo{
		Hostname:           s.Hostname,
		Os:                 s.OS,
		Version:            s.Version,
		Arch:               s.Arch,
		MachineId:          s.MachineID,
		SystemManufacturer: s.SystemManufacturer,
		SystemModel:        s.SystemModel,
		SystemSerial:       s.SystemSerial,
		MemoryMb:           s.MemoryMB,
		BiosVersion:        s.BIOSVersion,
		BiosDate:           s.BIOSDate,
		KernelVersion:      s.KernelVersion,
		UptimeSeconds:      s.UptimeSeconds,
		BootTime:           s.BootTime,
		Timezone:           s.Timezone,
		OsDomain:           s.OSDomain,
		TpmEnabled:         s.TPMEnabled,
		DiskEncryption:     s.DiskEncryption,
		Antivirus:          s.Antivirus,
		Selinux:            s.SELinux,
		Apparmor:           s.AppArmor,
		Truncated:          s.Truncated,
	}
	for _, c := range s.CPU {
		out.Cpu = append(out.Cpu, &pb.CPUSpec{Name: c.Name, Cores: int32(c.Cores)})
	}
	for _, g := range s.GPU {
		out.Gpu = append(out.Gpu, &pb.GPUSpec{Name: g.Name, Driver: g.Driver})
	}
	if s.Motherboard != nil {
		out.Motherboard = &pb.MotherboardSpec{
			Manufacturer: s.Motherboard.Manufacturer,
			Product:      s.Motherboard.Product,
		}
	}
	for _, n := range s.NetInterfaces {
		out.NetInterfaces = append(out.NetInterfaces, &pb.NetInterfaceSpec{
			Name: n.Name, Mac: n.MAC,
			Addresses: n.Addresses, Gateways: n.Gateways, Dns: n.DNS,
			LinkSpeed: n.LinkSpeed, Driver: n.Driver,
		})
	}
	for _, p := range s.OpenPorts {
		out.OpenPorts = append(out.OpenPorts, &pb.PortInfo{
			Protocol: p.Protocol, Address: p.Address,
			Port: int32(p.Port), Process: p.Process,
		})
	}
	for _, p := range s.Processes {
		out.Processes = append(out.Processes, &pb.ProcessInfo{
			Pid: int32(p.PID), Name: p.Name, User: p.User, MemoryMb: p.MemoryMB,
		})
	}
	for _, d := range s.Storage {
		out.Storage = append(out.Storage, &pb.StorageSpec{
			Name: d.Name, SizeBytes: d.SizeBytes, Mount: d.Mount,
			Serial: d.Serial, Model: d.Model, Firmware: d.Firmware,
			UsagePercent: d.UsagePercent,
		})
	}
	for _, m := range s.MemoryModules {
		out.MemoryModules = append(out.MemoryModules, &pb.MemoryModule{
			Slot: m.Slot, CapacityMb: m.CapacityMB, Type: m.Type,
			Speed: m.Speed, Serial: m.Serial,
		})
	}
	for _, v := range s.Services {
		out.Services = append(out.Services, &pb.ServiceInfo{
			Name: v.Name, State: v.State, StartType: v.StartType, RunAs: v.RunAs,
		})
	}
	for _, v := range s.StartupItems {
		out.StartupItems = append(out.StartupItems, &pb.StartupItem{
			Name: v.Name, Command: v.Command, Location: v.Location,
		})
	}
	for _, v := range s.ScheduledTasks {
		out.ScheduledTasks = append(out.ScheduledTasks, &pb.ScheduledTask{
			Name: v.Name, Status: v.Status, NextRun: v.NextRun, Command: v.Command,
		})
	}
	for _, v := range s.Routes {
		out.Routes = append(out.Routes, &pb.RouteInfo{
			Destination: v.Destination, Gateway: v.Gateway,
			Interface: v.Interface, Metric: v.Metric,
		})
	}
	for _, v := range s.FirewallRules {
		out.FirewallRules = append(out.FirewallRules, &pb.FirewallRule{
			Name: v.Name, Enabled: v.Enabled, Direction: v.Direction,
			Action: v.Action, Protocol: v.Protocol,
			LocalPort: v.LocalPort, RemoteIp: v.RemoteIP,
		})
	}
	for _, v := range s.Neighbors {
		out.Neighbors = append(out.Neighbors, &pb.NeighborInfo{
			Interface: v.Interface, Ip: v.IP, Mac: v.MAC, State: v.State,
		})
	}
	for _, v := range s.Certificates {
		out.Certificates = append(out.Certificates, &pb.CertificateInfo{
			Subject: v.Subject, Issuer: v.Issuer, Serial: v.Serial,
			NotBefore: v.NotBefore, NotAfter: v.NotAfter, Store: v.Store,
		})
	}
	for _, v := range s.Accounts {
		out.Accounts = append(out.Accounts, &pb.AccountInfo{
			Name: v.Name, Domain: v.Domain, Group: v.Group,
			Admin: v.Admin, Disabled: v.Disabled,
		})
	}
	for _, v := range s.SSHKeys {
		out.SshKeys = append(out.SshKeys, &pb.SSHKeyInfo{
			User: v.User, Path: v.Path, Type: v.Type, Fingerprint: v.Fingerprint,
		})
	}
	for _, v := range s.Runtimes {
		out.Runtimes = append(out.Runtimes, &pb.RuntimeInfo{
			Name: v.Name, Type: v.Type, State: v.State,
		})
	}
	for _, f := range s.UpdateFacts {
		out.UpdateFacts = append(out.UpdateFacts, &pb.UpdateFact{
			Kb:             f.KB,
			Title:          f.Title,
			State:          f.State,
			Severity:       f.Severity,
			RebootRequired: f.RebootRequired,
			Source:         f.Source,
			CollectedAt:    formatTimeOrEmpty(f.CollectedAt),
		})
	}
	if s.UpdateSourceStatus != nil {
		out.UpdateSourceStatus = &pb.UpdateSourceStatus{
			SourceReachable: s.UpdateSourceStatus.SourceReachable,
			LastCheckedAt:   formatTimeOrEmpty(s.UpdateSourceStatus.LastCheckedAt),
			Error:           s.UpdateSourceStatus.Error,
		}
	}
	return out
}

func complianceReportToPb(r compliance.Report) *pb.ComplianceReport {
	out := &pb.ComplianceReport{
		Benchmark: r.Benchmark,
		Score:     r.Score,
		Total:     int32(r.Total),
		Passed:    int32(r.Passed),
		Failed:    int32(r.Failed),
		Na:        int32(r.NA),
		CheckedAt: r.CheckedAt.UTC().Format(time.RFC3339),
	}
	for _, c := range r.Checks {
		out.Checks = append(out.Checks, &pb.ComplianceCheck{
			Id:       c.ID,
			Title:    c.Title,
			Group:    c.Group,
			Status:   c.Status,
			Evidence: c.Evidence,
		})
	}
	return out
}

func formatTimeOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// assetSyncKey identifies an inventory entry across sync cycles. Name alone is
// not enough: the same name can appear multiple times with different formats
// or locations (e.g. a dpkg "git" and an npm extension "git").
func assetSyncKey(a collector.Asset) string {
	return a.Name + "\x00" + a.Format + "\x00" + a.Location + "\x00" + a.Arch
}

// dedupeAssets collapses entries that share the same sync identity, keeping
// the entry with the highest version. Without this, registry/AppX collectors
// can emit the same package several times with different variants or stale
// versions, which would make every incremental cycle report spurious changes.
func dedupeAssets(assets []collector.Asset) []collector.Asset {
	best := make(map[string]int, len(assets))
	out := make([]collector.Asset, 0, len(assets))
	for _, a := range assets {
		key := assetSyncKey(a)
		if idx, ok := best[key]; ok {
			if versionNewer(a.Version, out[idx].Version) {
				out[idx] = a
			}
			continue
		}
		best[key] = len(out)
		out = append(out, a)
	}
	return out
}

func versionNewer(a, b string) bool {
	if a == b {
		return false
	}
	if a == "" {
		return false
	}
	if b == "" {
		return true
	}
	aSegs := strings.Split(a, ".")
	bSegs := strings.Split(b, ".")
	for i := 0; i < len(aSegs) || i < len(bSegs); i++ {
		var aNum, bNum int64
		if i < len(aSegs) {
			aNum, _ = strconv.ParseInt(aSegs[i], 10, 64)
		}
		if i < len(bSegs) {
			bNum, _ = strconv.ParseInt(bSegs[i], 10, 64)
		}
		if aNum != bNum {
			return aNum > bNum
		}
	}
	return false
}
