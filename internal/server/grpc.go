package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"strings"
	"time"

	pb "vuln-scanner/api/gen/vulnscan/v1"
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
	if err := s.store.SyncCMDBFromSnapshot(ctx, agentID, snap.Assets, mode == "FULL"); err != nil {
		slog.Warn("cmdb sync failed", "agent_id", agentID, "mode", mode, "error", err)
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
