package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "vuln-scanner/api/gen/vulnscan/v1"
	"vuln-scanner/internal/collector"
	"vuln-scanner/internal/edr"
	"vuln-scanner/internal/monitor"
	"vuln-scanner/internal/store"
)

// SyncTelemetry ingests the periodic file-integrity and behavior facts from
// an agent, replaces the server-side baselines, and turns any drift into
// findings (with alerts for HIGH/CRITICAL).
func (s *AgentGRPCServer) SyncTelemetry(ctx context.Context, req *pb.SyncTelemetryRequest) (*pb.SyncTelemetryResponse, error) {
	agentID, err := s.auth.ValidateToken(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if agentID != req.GetAgentId() {
		return nil, status.Error(codes.PermissionDenied, "agent_id mismatch")
	}

	var fileFacts []monitor.FileFact
	for _, f := range req.GetFileFacts() {
		if f.GetPath() == "" {
			continue
		}
		fileFacts = append(fileFacts, monitor.FileFact{
			Path:       f.GetPath(),
			SHA256:     f.GetSha256(),
			SizeBytes:  f.GetSizeBytes(),
			Mode:       f.GetMode(),
			ModifiedAt: f.GetModifiedAt(),
		})
	}

	var drifts []monitor.Drift
	if len(fileFacts) > 0 {
		fileDrifts, err := s.store.ReplaceFileBaselines(ctx, agentID, fileFacts)
		if err != nil {
			slog.Warn("telemetry file baseline failed", "agent_id", agentID, "error", err)
			return nil, status.Error(codes.Internal, "file baseline failed")
		}
		drifts = append(drifts, fileDrifts...)
	}
	if req.GetSystemInfo() != nil {
		info := hostSystemInfoFromPB(req.GetSystemInfo())
		facts := telemetryBehaviorFacts(info)
		if len(facts) > 0 {
			behaviorDrifts, err := s.store.ReplaceBehaviorBaselines(ctx, agentID, facts)
			if err != nil {
				slog.Warn("telemetry behavior baseline failed", "agent_id", agentID, "error", err)
				return nil, status.Error(codes.Internal, "behavior baseline failed")
			}
			drifts = append(drifts, behaviorDrifts...)
		}
	}
	if err := s.ingestTelemetryDrifts(ctx, agentID, drifts); err != nil {
		slog.Warn("telemetry drift ingest failed", "agent_id", agentID, "error", err)
	}
	slog.Info("telemetry synced", "agent_id", agentID,
		"files", len(fileFacts), "drifts", len(drifts))
	return &pb.SyncTelemetryResponse{Ok: true}, nil
}

// telemetryBehaviorFacts canonicalizes the relevant SystemInfo slices into
// per-category behavior items. Keys are stable identities: PID is excluded
// from process keys because it changes on every restart.
func telemetryBehaviorFacts(info *store.HostSystemInfo) map[string][]monitor.BehaviorItem {
	out := make(map[string][]monitor.BehaviorItem)
	out["processes"] = marshalBehavior(info.Processes, func(p collector.ProcessInfo) string {
		return p.Name + "|" + p.User
	})
	out["open_ports"] = marshalBehavior(info.OpenPorts, func(p collector.PortInfo) string {
		return fmt.Sprintf("%s|%s|%d|%s", p.Protocol, p.Address, p.Port, p.Process)
	})
	out["startup_items"] = marshalBehavior(info.StartupItems, func(s collector.StartupItem) string {
		return s.Name + "|" + s.Location + "|" + s.Command
	})
	out["scheduled_tasks"] = marshalBehavior(info.ScheduledTasks, func(s collector.ScheduledTask) string {
		return s.Name + "|" + s.Command
	})
	out["accounts"] = marshalBehavior(info.Accounts, func(a collector.AccountInfo) string {
		return a.Domain + "|" + a.Name
	})
	out["ssh_keys"] = marshalBehavior(info.SSHKeys, func(k collector.SSHKeyInfo) string {
		return k.User + "|" + k.Path + "|" + k.Type + "|" + k.Fingerprint
	})
	out["services"] = marshalBehavior(info.Services, func(s collector.ServiceInfo) string {
		return s.Name + "|" + s.State + "|" + s.StartType + "|" + s.RunAs
	})
	out["firewall_rules"] = marshalBehavior(info.FirewallRules, func(r collector.FirewallRule) string {
		return r.Name + "|" + r.Direction + "|" + r.Action + "|" + r.Protocol + "|" + r.LocalPort
	})
	for category, items := range out {
		if len(items) == 0 {
			delete(out, category)
		}
	}
	return out
}

func marshalBehavior[T any](items []T, key func(T) string) []monitor.BehaviorItem {
	byKey := make(map[string]json.RawMessage, len(items))
	for _, it := range items {
		k := key(it)
		if k == "" {
			continue
		}
		raw, _ := json.Marshal(it)
		byKey[k] = raw
	}
	out := make([]monitor.BehaviorItem, 0, len(byKey))
	for k, raw := range byKey {
		out = append(out, monitor.BehaviorItem{Key: k, Data: raw})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (s *AgentGRPCServer) ingestTelemetryDrifts(ctx context.Context, agentID string, drifts []monitor.Drift) error {
	if len(drifts) == 0 {
		return nil
	}
	agent, _ := s.store.GetAgent(ctx, agentID)
	hostname := ""
	tenantID := int64(1)
	if agent != nil {
		hostname = agent.Hostname
		if agent.TenantID > 0 {
			tenantID = agent.TenantID
		}
	}
	for _, d := range drifts {
		source := "file_integrity"
		findingType := "file_change"
		if d.Category != "file" {
			source = "behavior"
			findingType = "behavior_drift"
		}
		detail, _ := json.Marshal(map[string]interface{}{
			"kind": d.Kind, "category": d.Category, "old": d.Old, "new": d.New,
		})
		hash := ""
		if d.Category == "file" && d.Kind != "removed" {
			var f monitor.FileFact
			if json.Unmarshal(d.New, &f) == nil {
				hash = f.SHA256
			}
		}
		name := d.Key
		if len(name) > 500 {
			name = name[:500]
		}
		finding, created, err := s.store.UpsertEDRFinding(ctx, store.EDRFindingInput{
			AgentID:     agentID,
			Source:      source,
			FindingType: findingType,
			Name:        name,
			Severity:    d.Severity,
			Path:        d.Path,
			Hash:        hash,
			Detail:      string(detail),
		})
		if err != nil {
			slog.Warn("telemetry finding upsert failed", "agent_id", agentID, "error", err)
			continue
		}
		if created && edr.ShouldAlert(finding.Severity) {
			ruleName := "file-integrity"
			if source == "behavior" {
				ruleName = "behavior-drift"
			}
			rule, err := s.store.GetAlertRuleByName(ctx, tenantID, ruleName)
			if err != nil {
				slog.Warn("telemetry alert rule missing", "rule", ruleName, "error", err)
			} else if _, _, err := s.store.UpsertFindingAlert(ctx, rule.ID, agentID, hostname, finding.Severity, finding.ID, source); err != nil {
				slog.Warn("telemetry alert link failed", "finding_id", finding.ID, "error", err)
			}
		}
		if created {
			_ = s.store.AppendSiemEvent(ctx,
				fmt.Sprintf("finding.created:%d", finding.ID),
				"finding.created",
				map[string]interface{}{
					"finding_id": finding.ID, "agent_id": agentID,
					"source": finding.Source, "finding_type": finding.FindingType,
					"name": finding.Name, "severity": finding.Severity,
					"path": finding.Path, "detail": finding.Detail,
				})
		}
	}
	return nil
}

func (s *RESTServer) getTelemetryStatus(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if err := s.requireAgent(r, agentID); err != nil {
		writeScopeError(w, err)
		return
	}
	statusInfo, err := s.store.GetTelemetryStatus(r.Context(), agentID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"agent_id": agentID, "status": statusInfo,
	})
}

func (s *RESTServer) rebaselineTelemetry(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if err := s.requireAgent(r, agentID); err != nil {
		writeScopeError(w, err)
		return
	}
	if err := s.store.RebaselineTelemetry(r.Context(), agentID); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	_ = s.store.AppendSiemEvent(r.Context(),
		fmt.Sprintf("telemetry.rebaselined:%s", agentID),
		"telemetry.rebaselined",
		map[string]interface{}{"agent_id": agentID, "actor": actorFromRequest(r)})
	writeJSON(w, 200, map[string]interface{}{
		"agent_id": agentID, "rebaselined": true,
	})
}
