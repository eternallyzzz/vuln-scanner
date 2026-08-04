package server

import (
	"context"
	"errors"
	"log/slog"
	"time"

	pb "vuln-scanner/api/gen/vulnscan/v1"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *AgentGRPCServer) FetchPatchTasks(ctx context.Context, req *pb.FetchPatchTasksRequest) (*pb.FetchPatchTasksResponse, error) {
	agentID, err := s.auth.ValidateToken(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if agentID != req.GetAgentId() {
		return nil, status.Error(codes.PermissionDenied, "agent_id mismatch")
	}

	task, err := s.store.ClaimNextPatchTask(ctx, agentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &pb.FetchPatchTasksResponse{}, nil
		}
		slog.Warn("claim patch task failed", "agent_id", agentID, "error", err)
		return nil, status.Error(codes.Internal, "claim failed")
	}
	if task.ID == 0 {
		return &pb.FetchPatchTasksResponse{}, nil
	}

	dryRun := false
	if s.patchCfg != nil {
		dryRun = s.patchCfg.DryRun
	}
	info := &pb.PatchTaskInfo{
		Id:        task.ID,
		AssetName: task.AssetName,
		FixType:   task.FixType,
		FixValue:  task.FixValue,
		Command:   task.Command,
		DryRun:    dryRun,
	}
	for _, argv := range task.Commands {
		info.Commands = append(info.Commands, &pb.CommandArgv{Argv: argv})
	}
	slog.Info("patch task claimed", "task_id", task.ID, "agent_id", agentID,
		"asset", task.AssetName, "dry_run", dryRun)
	return &pb.FetchPatchTasksResponse{Tasks: []*pb.PatchTaskInfo{info}}, nil
}

func (s *AgentGRPCServer) ReportPatchTask(ctx context.Context, req *pb.ReportPatchTaskRequest) (*pb.ReportPatchTaskResponse, error) {
	agentID, err := s.auth.ValidateToken(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if agentID != req.GetAgentId() {
		return nil, status.Error(codes.PermissionDenied, "agent_id mismatch")
	}
	if req.GetStatus() != "success" && req.GetStatus() != "failed" {
		return nil, status.Error(codes.InvalidArgument, "status must be success or failed")
	}

	result := map[string]interface{}{
		"exit_code":   req.GetExitCode(),
		"output":      req.GetOutput(),
		"finished_at": time.Now(),
	}
	if err := s.store.CompletePatchTask(ctx, req.GetTaskId(), req.GetStatus(), result); err != nil {
		slog.Error("complete patch task failed", "task_id", req.GetTaskId(), "error", err)
		return nil, status.Error(codes.Internal, "complete failed")
	}
	slog.Info("patch task reported", "task_id", req.GetTaskId(),
		"agent_id", agentID, "status", req.GetStatus(), "exit_code", req.GetExitCode())
	if req.GetStatus() == "success" {
		// Close the loop: a successful patch invalidates the current CVE
		// snapshot, so re-match this agent immediately (risk recalc and
		// alert evaluation run inside the match pipeline).
		go s.worker.TriggerMatch(agentID)
	}
	return &pb.ReportPatchTaskResponse{Ok: true}, nil
}

// reapPatchLoop reverts tasks that have been running longer than the agent
// timeout so a crashed agent does not leave tasks stuck in running state.
func (w *Worker) reapPatchLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
			timeout := 600 * time.Second
			if w.patchCfg != nil && w.patchCfg.AgentTimeoutSeconds > 0 {
				timeout = time.Duration(w.patchCfg.AgentTimeoutSeconds) * time.Second
			}
			n, err := w.store.ReapStalePatchTasks(ctx, timeout)
			if err != nil {
				slog.Warn("reap stale patch tasks failed", "error", err)
			} else if n > 0 {
				slog.Info("reaped stale patch tasks", "count", n)
			}
		}
	}
}
