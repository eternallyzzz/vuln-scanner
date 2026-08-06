package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"time"

	pb "vuln-scanner/api/gen/vulnscan/v1"
	"vuln-scanner/internal/netscan"
	"vuln-scanner/internal/store"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FetchNetworkScanTasks atomically claims pending discovery tasks for the
// calling agent. The task carries its own target and ports so any agent can
// execute it, even without a local network_scan config.
func (s *AgentGRPCServer) FetchNetworkScanTasks(ctx context.Context, req *pb.FetchNetworkScanTasksRequest) (*pb.FetchNetworkScanTasksResponse, error) {
	agentID, err := s.auth.ValidateToken(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if agentID != req.GetAgentId() {
		return nil, status.Error(codes.PermissionDenied, "agent_id mismatch")
	}
	tasks, err := s.store.ClaimNetworkScanTasks(ctx, agentID, 5)
	if err != nil {
		slog.Error("claim network scan tasks failed", "agent_id", agentID, "error", err)
		return nil, status.Error(codes.Internal, "claim tasks failed")
	}
	infos := make([]*pb.NetworkScanTaskInfo, 0, len(tasks))
	for _, t := range tasks {
		infos = append(infos, &pb.NetworkScanTaskInfo{
			Id:     t.ID,
			Target: t.Target,
			Ports:  t.Ports,
		})
	}
	return &pb.FetchNetworkScanTasksResponse{Tasks: infos}, nil
}

// SyncNetworkScan stores discovered hosts, materializes one synthetic agent
// per host, and triggers the existing match/risk/alert pipeline. A server
// task is completed (done/failed) from the same report.
func (s *AgentGRPCServer) SyncNetworkScan(ctx context.Context, req *pb.SyncNetworkScanRequest) (*pb.SyncNetworkScanResponse, error) {
	agentID, err := s.auth.ValidateToken(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if agentID != req.GetAgentId() {
		return nil, status.Error(codes.PermissionDenied, "agent_id mismatch")
	}

	tenantID := int64(1)
	if req.GetTaskId() > 0 {
		task, err := s.store.GetNetworkScanTask(ctx, req.GetTaskId())
		if err == nil && task != nil && task.TenantID > 0 {
			tenantID = task.TenantID
		} else {
			slog.Warn("network scan task tenant lookup failed", "task_id", req.GetTaskId(), "error", err)
		}
	} else if agent, err := s.store.GetAgent(ctx, agentID); err == nil && agent != nil && agent.TenantID > 0 {
		tenantID = agent.TenantID
	}

	complete := func(scanErr string, summary map[string]interface{}) {
		if req.GetTaskId() <= 0 {
			return
		}
		data, _ := json.Marshal(summary)
		if err := s.store.CompleteNetworkScanTask(ctx, req.GetTaskId(), scanErr, data); err != nil {
			slog.Error("complete network scan task failed", "task_id", req.GetTaskId(), "error", err)
		}
	}

	if req.GetError() != "" {
		slog.Warn("network scan reported failure", "agent_id", agentID,
			"task_id", req.GetTaskId(), "error", req.GetError())
		complete(req.GetError(), nil)
		return &pb.SyncNetworkScanResponse{Ok: true}, nil
	}

	hosts := req.GetHosts()
	storeHosts := make([]store.NetworkHost, 0, len(hosts))
	serviceCount := 0
	for _, h := range hosts {
		services := make([]netscan.Service, 0, len(h.GetServices()))
		for _, svc := range h.GetServices() {
			services = append(services, netscan.Service{
				Port:     int(svc.GetPort()),
				Protocol: svc.GetProtocol(),
				Service:  svc.GetService(),
				Version:  svc.GetVersion(),
				Banner:   svc.GetBanner(),
			})
		}
		serviceCount += len(services)
		storeHosts = append(storeHosts, store.NetworkHost{
			IP:       h.GetIp(),
			Hostname: h.GetHostname(),
			OSType:   h.GetOsType(),
			Services: services,
		})
	}
	agentIDs, err := s.store.UpsertNetworkHosts(ctx, storeHosts, agentID)
	if err != nil {
		slog.Error("upsert network hosts failed", "agent_id", agentID, "error", err)
		complete("upsert hosts failed", nil)
		return nil, status.Error(codes.Internal, "upsert hosts failed")
	}

	for i, h := range hosts {
		netAgentID := agentIDs[i]
		if err := s.store.UpsertNetworkAgent(ctx, netAgentID, h.GetHostname(), h.GetIp(), h.GetOsType(), tenantID); err != nil {
			slog.Error("upsert network agent failed", "agent_id", netAgentID, "error", err)
			continue
		}
		snap := &store.AssetSnapshot{
			AgentID:   netAgentID,
			Mode:      "FULL",
			Assets:    networkAssetsJSON(h),
			CreatedAt: time.Now(),
		}
		if err := s.store.UpsertAssetSnapshot(ctx, snap); err != nil {
			slog.Error("upsert network snapshot failed", "agent_id", netAgentID, "error", err)
			continue
		}
		go s.worker.TriggerMatch(netAgentID)
	}

	complete("", map[string]interface{}{"hosts": len(hosts), "services": serviceCount})
	slog.Info("network scan synced", "agent_id", agentID,
		"hosts", len(hosts), "services", serviceCount)
	return &pb.SyncNetworkScanResponse{Ok: true, ReceivedCount: int64(len(hosts))}, nil
}

// networkAssetsJSON maps discovered services to matcher assets. The OS is
// intentionally omitted: without a version it would not produce OS-level
// findings, and service products are the v1 signal.
func networkAssetsJSON(h *pb.NetworkHost) []byte {
	assets := make([]map[string]interface{}, 0, len(h.GetServices()))
	for _, svc := range h.GetServices() {
		assets = append(assets, map[string]interface{}{
			"name":     svc.GetService(),
			"version":  svc.GetVersion(),
			"format":   "network",
			"vendor":   "",
			"location": ipPort(h.GetIp(), svc.GetPort()),
			"type":     "PACKAGE",
		})
	}
	data, _ := json.Marshal(map[string]interface{}{"assets": assets})
	return data
}

func ipPort(ip string, port int32) string {
	if port <= 0 {
		return ip
	}
	return ip + ":" + strconv.Itoa(int(port))
}
