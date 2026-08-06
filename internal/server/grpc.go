package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"strings"
	"time"

	pb "vuln-scanner/api/gen/vulnscan/v1"
	"vuln-scanner/internal/collector"
	"vuln-scanner/internal/patch"
	"vuln-scanner/internal/store"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type snapshotAsset struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Arch        string `json:"arch"`
	Format      string `json:"format"`
	Vendor      string `json:"vendor"`
	Location    string `json:"location"`
	InstallDate string `json:"install_date"`
	Status      string `json:"status"`
	Type        string `json:"type"`
}

type snapshotAssetKey struct {
	Name     string
	Format   string
	Location string
	Arch     string
}

func toSnapshotAsset(a *pb.Asset) snapshotAsset {
	return snapshotAsset{
		Name:        a.Name,
		Version:     a.Version,
		Arch:        a.Arch,
		Format:      a.Format,
		Vendor:      a.Vendor,
		Location:    a.Location,
		InstallDate: a.InstallDate,
		Status:      a.Status,
		Type:        a.Type.String(),
	}
}

func marshalAssets(assets []*pb.Asset) []byte {
	out := make([]snapshotAsset, 0, len(assets))
	for _, a := range assets {
		out = append(out, toSnapshotAsset(a))
	}
	data, _ := json.Marshal(map[string]interface{}{"assets": out})
	return data
}

type AgentGRPCServer struct {
	pb.UnimplementedAgentServiceServer
	auth     *AgentAuth
	store    *store.Store
	worker   *Worker
	patchCfg *patch.Config
}

func NewAgentGRPCServer(auth *AgentAuth, s *store.Store, w *Worker, patchCfg *patch.Config) *AgentGRPCServer {
	return &AgentGRPCServer{
		auth:     auth,
		store:    s,
		worker:   w,
		patchCfg: patchCfg,
	}
}

func (s *AgentGRPCServer) Auth(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	agentID := req.GetAgentId()
	fingerprint := req.GetFingerprint()

	storedFP, err := s.store.GetAgentByFingerprint(ctx, agentID)
	if err != nil {
		slog.Warn("auth agent not found", "agent_id", agentID, "error", err)
		return nil, status.Error(codes.NotFound, "agent not found")
	}

	if storedFP != "" && HashFingerprint(fingerprint) != storedFP {
		s.store.UpdateAgentStatus(ctx, agentID, "challenged")
		return &pb.AuthResponse{
			Status:  "challenged",
			Message: "fingerprint mismatch, agent challenged",
		}, nil
	}

	agent, err := s.store.GetAgent(ctx, agentID)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to get agent")
	}

	token, expires, err := s.auth.IssueToken(agentID)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to issue token")
	}

	agent.TokenHash = token
	if err := s.store.UpsertAgentToken(ctx, agentID, token); err != nil {
		slog.Warn("failed to persist token hash", "agent_id", agentID, "error", err)
	}

	s.store.UpdateAgentHeartbeat(ctx, agentID)

	slog.Info("agent authenticated", "agent_id", agentID, "hostname", agent.Hostname)
	return &pb.AuthResponse{
		Token:     token,
		ExpiresIn: int64(expires.Sub(time.Now()).Seconds()),
	}, nil
}

func (s *AgentGRPCServer) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	agentID, err := s.auth.ValidateToken(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if agentID != req.GetAgentId() {
		return nil, status.Error(codes.PermissionDenied, "agent_id mismatch")
	}

	fingerprint := req.GetFingerprint()
	storedFP, _ := s.store.GetAgentByFingerprint(ctx, agentID)
	if storedFP != "" && HashFingerprint(fingerprint) != storedFP {
		return nil, status.Error(codes.PermissionDenied, "fingerprint mismatch")
	}

	token, expires, err := s.auth.IssueToken(agentID)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to issue token")
	}

	if err := s.store.UpsertAgentToken(ctx, agentID, token); err != nil {
		slog.Warn("failed to persist token hash", "agent_id", agentID, "error", err)
	}

	return &pb.RefreshTokenResponse{
		Token:     token,
		ExpiresIn: int64(expires.Sub(time.Now()).Seconds()),
	}, nil
}

func (s *AgentGRPCServer) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	agentID, err := s.auth.ValidateToken(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if agentID != req.GetAgentId() {
		return nil, status.Error(codes.PermissionDenied, "agent_id mismatch")
	}

	if err := s.store.UpdateAgentHeartbeat(ctx, agentID); err != nil {
		slog.Warn("heartbeat update failed", "agent_id", agentID, "error", err)
		return nil, status.Error(codes.Internal, "failed to update heartbeat")
	}

	return &pb.HeartbeatResponse{Ok: true}, nil
}

func (s *AgentGRPCServer) SyncInventory(ctx context.Context, req *pb.SyncInventoryRequest) (*pb.SyncInventoryResponse, error) {
	agentID, err := s.auth.ValidateToken(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if agentID != req.GetAgentId() {
		return nil, status.Error(codes.PermissionDenied, "agent_id mismatch")
	}

	mode := "INCREMENTAL"
	if req.GetMode() == pb.SyncMode_FULL {
		mode = "FULL"
	}

	assetsJSON := marshalAssets(req.GetAssets())
	if mode == "INCREMENTAL" {
		assetsJSON = s.mergeIncremental(ctx, agentID, req.GetAssets())
	}

	snap := &store.AssetSnapshot{
		AgentID:   agentID,
		Mode:      mode,
		Assets:    assetsJSON,
		CreatedAt: time.Now(),
	}

	if err := s.store.UpsertAssetSnapshot(ctx, snap); err != nil {
		slog.Error("failed to store asset snapshot", "agent_id", agentID, "error", err)
		return nil, status.Error(codes.Internal, "failed to store snapshot")
	}
	if _, err := s.store.SyncCMDBFromSnapshot(ctx, agentID, snap.Assets, mode == "FULL"); err != nil {
		slog.Warn("cmdb sync failed", "agent_id", agentID, "mode", mode, "error", err)
	}

	if mode == "FULL" && req.GetSystemInfo() != nil {
		info := hostSystemInfoFromPB(req.GetSystemInfo())
		info.AgentID = agentID
		if err := s.store.SaveHostSystemInfo(ctx, info); err != nil {
			slog.Warn("host system info save failed", "agent_id", agentID, "error", err)
		}
		if len(req.GetSystemInfo().GetEdrFindings()) > 0 {
			if err := s.ingestEDRFindings(ctx, agentID, req.GetSystemInfo().GetEdrFindings()); err != nil {
				slog.Warn("edr findings ingest failed", "agent_id", agentID, "error", err)
			}
		}
		updateFacts := updateFactsFromPB(req.GetSystemInfo().GetUpdateFacts())
		updateStatus := updateSourceStatusFromPB(req.GetSystemInfo().GetUpdateSourceStatus())
		slog.Info("agent update facts received",
			"agent_id", agentID,
			"facts", len(updateFacts),
			"status_reported", updateStatus != nil)
		if err := s.store.ReplaceAgentUpdateFacts(ctx, agentID, updateFacts); err != nil {
			slog.Warn("agent update facts save failed", "agent_id", agentID, "error", err)
		}
		if updateStatus != nil {
			if err := s.store.UpsertAgentUpdateStatus(ctx, agentID, *updateStatus); err != nil {
				slog.Warn("agent update status save failed", "agent_id", agentID, "error", err)
			}
		}
	}

	for _, a := range req.GetAssets() {
		if a.GetType() == pb.AssetType_OS && a.GetName() != "" {
			s.store.UpdateAgentOSInfo(ctx, agentID,
				strings.ToLower(a.GetName()), a.GetVersion())
			break
		}
	}

	slog.Info("inventory synced",
		"agent_id", agentID,
		"mode", mode,
		"count", len(req.GetAssets()))

	go s.worker.TriggerMatch(agentID)

	return &pb.SyncInventoryResponse{
		Ok:            true,
		ReceivedCount: int64(len(req.GetAssets())),
	}, nil
}

// SyncCompliance stores the latest agent-side CIS baseline report. It is a
// dedicated RPC so the daily compliance refresh never triggers an inventory
// snapshot, CMDB sync or match cycle.
func (s *AgentGRPCServer) SyncCompliance(ctx context.Context, req *pb.SyncComplianceRequest) (*pb.SyncComplianceResponse, error) {
	agentID, err := s.auth.ValidateToken(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if agentID != req.GetAgentId() {
		return nil, status.Error(codes.PermissionDenied, "agent_id mismatch")
	}
	if req.GetCompliance() == nil {
		return nil, status.Error(codes.InvalidArgument, "compliance report required")
	}
	rep := complianceReportFromPB(req.GetCompliance())
	rep.AgentID = agentID
	if err := s.store.UpsertComplianceReport(ctx, rep); err != nil {
		slog.Error("compliance report save failed", "agent_id", agentID, "error", err)
		return nil, status.Error(codes.Internal, "failed to store compliance report")
	}
	slog.Info("compliance report received", "agent_id", agentID,
		"benchmark", rep.Benchmark, "score", rep.Score, "failed", rep.Failed)
	return &pb.SyncComplianceResponse{Ok: true}, nil
}

func complianceReportFromPB(in *pb.ComplianceReport) *store.ComplianceReport {
	out := &store.ComplianceReport{
		Benchmark: in.GetBenchmark(),
		Score:     in.GetScore(),
		Total:     int(in.GetTotal()),
		Passed:    int(in.GetPassed()),
		Failed:    int(in.GetFailed()),
		NA:        int(in.GetNa()),
	}
	if t, err := time.Parse(time.RFC3339, in.GetCheckedAt()); err == nil {
		out.CheckedAt = t
	} else {
		out.CheckedAt = time.Now()
	}
	for _, c := range in.GetChecks() {
		if c == nil {
			continue
		}
		out.Checks = append(out.Checks, store.ComplianceCheck{
			ID:       c.GetId(),
			Title:    c.GetTitle(),
			Group:    c.GetGroup(),
			Status:   c.GetStatus(),
			Evidence: c.GetEvidence(),
		})
	}
	return out
}

func hostSystemInfoFromPB(in *pb.SystemInfo) *store.HostSystemInfo {
	info := &store.HostSystemInfo{
		Hostname:           in.GetHostname(),
		OS:                 in.GetOs(),
		OSVersion:          in.GetVersion(),
		Arch:               in.GetArch(),
		MachineID:          in.GetMachineId(),
		SystemManufacturer: in.GetSystemManufacturer(),
		SystemModel:        in.GetSystemModel(),
		SystemSerial:       in.GetSystemSerial(),
		BIOSVersion:        in.GetBiosVersion(),
		BIOSDate:           in.GetBiosDate(),
		KernelVersion:      in.GetKernelVersion(),
		UptimeSeconds:      in.GetUptimeSeconds(),
		BootTime:           in.GetBootTime(),
		Timezone:           in.GetTimezone(),
		OSDomain:           in.GetOsDomain(),
		MemoryMB:           in.GetMemoryMb(),
		TPMEnabled:         in.GetTpmEnabled(),
		DiskEncryption:     in.GetDiskEncryption(),
		Antivirus:          in.GetAntivirus(),
		SELinux:            in.GetSelinux(),
		AppArmor:           in.GetApparmor(),
		Truncated:          in.GetTruncated(),
	}
	for _, c := range in.GetCpu() {
		info.CPU = append(info.CPU, collector.CPUSpec{Name: c.GetName(), Cores: int(c.GetCores())})
	}
	for _, g := range in.GetGpu() {
		info.GPU = append(info.GPU, collector.GPUSpec{Name: g.GetName(), Driver: g.GetDriver()})
	}
	if mb := in.GetMotherboard(); mb != nil {
		info.Motherboard = &collector.MotherboardSpec{
			Manufacturer: mb.GetManufacturer(),
			Product:      mb.GetProduct(),
		}
	}
	for _, n := range in.GetNetInterfaces() {
		info.NetInterfaces = append(info.NetInterfaces, collector.NetInterfaceSpec{
			Name: n.GetName(), MAC: n.GetMac(),
			Addresses: n.GetAddresses(), Gateways: n.GetGateways(), DNS: n.GetDns(),
			LinkSpeed: n.GetLinkSpeed(), Driver: n.GetDriver(),
		})
	}
	for _, p := range in.GetOpenPorts() {
		info.OpenPorts = append(info.OpenPorts, collector.PortInfo{
			Protocol: p.GetProtocol(), Address: p.GetAddress(),
			Port: int(p.GetPort()), Process: p.GetProcess(),
		})
	}
	for _, p := range in.GetProcesses() {
		info.Processes = append(info.Processes, collector.ProcessInfo{
			PID: int(p.GetPid()), Name: p.GetName(), User: p.GetUser(), MemoryMB: p.GetMemoryMb(),
		})
	}
	for _, d := range in.GetStorage() {
		info.Storage = append(info.Storage, collector.StorageSpec{
			Name: d.GetName(), SizeBytes: d.GetSizeBytes(), Mount: d.GetMount(),
			Serial: d.GetSerial(), Model: d.GetModel(), Firmware: d.GetFirmware(),
			UsagePercent: d.GetUsagePercent(),
		})
	}
	for _, m := range in.GetMemoryModules() {
		info.MemoryModules = append(info.MemoryModules, collector.MemoryModule{
			Slot: m.GetSlot(), CapacityMB: m.GetCapacityMb(), Type: m.GetType(),
			Speed: m.GetSpeed(), Serial: m.GetSerial(),
		})
	}
	for _, v := range in.GetServices() {
		info.Services = append(info.Services, collector.ServiceInfo{
			Name: v.GetName(), State: v.GetState(),
			StartType: v.GetStartType(), RunAs: v.GetRunAs(),
		})
	}
	for _, v := range in.GetStartupItems() {
		info.StartupItems = append(info.StartupItems, collector.StartupItem{
			Name: v.GetName(), Command: v.GetCommand(), Location: v.GetLocation(),
		})
	}
	for _, v := range in.GetScheduledTasks() {
		info.ScheduledTasks = append(info.ScheduledTasks, collector.ScheduledTask{
			Name: v.GetName(), Status: v.GetStatus(),
			NextRun: v.GetNextRun(), Command: v.GetCommand(),
		})
	}
	for _, v := range in.GetRoutes() {
		info.Routes = append(info.Routes, collector.RouteInfo{
			Destination: v.GetDestination(), Gateway: v.GetGateway(),
			Interface: v.GetInterface(), Metric: v.GetMetric(),
		})
	}
	for _, v := range in.GetFirewallRules() {
		info.FirewallRules = append(info.FirewallRules, collector.FirewallRule{
			Name: v.GetName(), Enabled: v.GetEnabled(), Direction: v.GetDirection(),
			Action: v.GetAction(), Protocol: v.GetProtocol(),
			LocalPort: v.GetLocalPort(), RemoteIP: v.GetRemoteIp(),
		})
	}
	for _, v := range in.GetNeighbors() {
		info.Neighbors = append(info.Neighbors, collector.NeighborInfo{
			Interface: v.GetInterface(), IP: v.GetIp(), MAC: v.GetMac(), State: v.GetState(),
		})
	}
	for _, v := range in.GetCertificates() {
		info.Certificates = append(info.Certificates, collector.CertificateInfo{
			Subject: v.GetSubject(), Issuer: v.GetIssuer(), Serial: v.GetSerial(),
			NotBefore: v.GetNotBefore(), NotAfter: v.GetNotAfter(), Store: v.GetStore(),
		})
	}
	for _, v := range in.GetAccounts() {
		info.Accounts = append(info.Accounts, collector.AccountInfo{
			Name: v.GetName(), Domain: v.GetDomain(), Group: v.GetGroup(),
			Admin: v.GetAdmin(), Disabled: v.GetDisabled(),
		})
	}
	for _, v := range in.GetSshKeys() {
		info.SSHKeys = append(info.SSHKeys, collector.SSHKeyInfo{
			User: v.GetUser(), Path: v.GetPath(), Type: v.GetType(), Fingerprint: v.GetFingerprint(),
		})
	}
	for _, v := range in.GetRuntimes() {
		info.Runtimes = append(info.Runtimes, collector.RuntimeInfo{
			Name: v.GetName(), Type: v.GetType(), State: v.GetState(),
		})
	}
	return info
}

func updateFactsFromPB(items []*pb.UpdateFact) []collector.UpdateFact {
	var out []collector.UpdateFact
	for _, f := range items {
		if f == nil || f.GetKb() == "" {
			continue
		}
		out = append(out, collector.UpdateFact{
			KB:             f.GetKb(),
			Title:          f.GetTitle(),
			State:          f.GetState(),
			Severity:       f.GetSeverity(),
			RebootRequired: f.GetRebootRequired(),
			Source:         f.GetSource(),
			CollectedAt:    parseRFC3339(f.GetCollectedAt()),
		})
	}
	return out
}

func updateSourceStatusFromPB(in *pb.UpdateSourceStatus) *collector.UpdateSourceStatus {
	if in == nil {
		return nil
	}
	return &collector.UpdateSourceStatus{
		SourceReachable: in.GetSourceReachable(),
		LastCheckedAt:   parseRFC3339(in.GetLastCheckedAt()),
		Error:           in.GetError(),
	}
}

func parseRFC3339(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// mergeIncremental merges a set of changed assets into the agent's stored
// snapshot so an incremental sync does not replace the full inventory.
func (s *AgentGRPCServer) mergeIncremental(ctx context.Context, agentID string, incoming []*pb.Asset) []byte {
	assets := make(map[snapshotAssetKey]snapshotAsset)

	existing, err := s.store.GetAssetSnapshot(ctx, agentID)
	if err == nil && existing != nil {
		var cur struct {
			Assets []snapshotAsset `json:"assets"`
		}
		if json.Unmarshal(existing.Assets, &cur) == nil {
			for _, a := range cur.Assets {
				assets[snapshotAssetKey{Name: a.Name, Format: a.Format, Location: a.Location, Arch: a.Arch}] = a
			}
		} else {
			slog.Warn("incremental sync: existing snapshot unparsable, replacing", "agent_id", agentID, "error", err)
		}
	} else if err != nil {
		slog.Warn("incremental sync: no existing snapshot, starting fresh", "agent_id", agentID, "error", err)
	}

	for _, a := range incoming {
		key := snapshotAssetKey{Name: a.GetName(), Format: a.GetFormat(), Location: a.GetLocation(), Arch: a.GetArch()}
		prev, existed := assets[key]
		assets[key] = toSnapshotAsset(a)

		if !existed {
			slog.Info("incremental sync: asset added", "agent_id", agentID, "asset", a.GetName(), "version", a.GetVersion())
			if err := s.store.RecordAssetChange(ctx, agentID, "added", a.GetName(), "", a.GetVersion(), a.GetFormat()); err != nil {
				slog.Warn("record asset change failed", "agent_id", agentID, "asset", a.GetName(), "error", err)
			}
			continue
		}
		if prev.Version != a.GetVersion() {
			slog.Info("incremental sync: asset updated", "agent_id", agentID, "asset", a.GetName(), "old", prev.Version, "new", a.GetVersion())
			if err := s.store.RecordAssetChange(ctx, agentID, "updated", a.GetName(), prev.Version, a.GetVersion(), a.GetFormat()); err != nil {
				slog.Warn("record asset change failed", "agent_id", agentID, "asset", a.GetName(), "error", err)
			}
		}
	}

	out := make([]snapshotAsset, 0, len(assets))
	for _, a := range assets {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		if out[i].Format != out[j].Format {
			return out[i].Format < out[j].Format
		}
		if out[i].Location != out[j].Location {
			return out[i].Location < out[j].Location
		}
		return out[i].Arch < out[j].Arch
	})
	data, _ := json.Marshal(map[string]interface{}{"assets": out})
	return data
}
