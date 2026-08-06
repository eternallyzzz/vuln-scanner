package server

import (
	"context"
	"errors"
	"log/slog"
	"time"

	pb "vuln-scanner/api/gen/vulnscan/v1"
	"vuln-scanner/internal/collector"
	"vuln-scanner/internal/patch"
	"vuln-scanner/internal/store"

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
		Id:              task.ID,
		AssetName:       task.AssetName,
		FixType:         task.FixType,
		FixValue:        task.FixValue,
		Command:         task.Command,
		DryRun:          dryRun,
		CancelRequested: task.CancelRequested,
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
	if req.GetStatus() != "success" && req.GetStatus() != "failed" && req.GetStatus() != "cancelled" {
		return nil, status.Error(codes.InvalidArgument, "status must be success, failed or cancelled")
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
		if s.worker != nil {
			go s.worker.TriggerMatch(agentID)
		}
	}
	return &pb.ReportPatchTaskResponse{Ok: true}, nil
}

// FetchRuntimeVerifyTasks returns the tasks whose patch succeeded and still
// await a runtime verification snapshot. The agent collects one SystemInfo
// snapshot and reports it back for every task in the list.
func (s *AgentGRPCServer) FetchRuntimeVerifyTasks(ctx context.Context, req *pb.FetchRuntimeVerifyTasksRequest) (*pb.FetchRuntimeVerifyTasksResponse, error) {
	agentID, err := s.auth.ValidateToken(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if agentID != req.GetAgentId() {
		return nil, status.Error(codes.PermissionDenied, "agent_id mismatch")
	}
	tasks, err := s.store.ListPendingRuntimeVerifyTasks(ctx, agentID)
	if err != nil {
		slog.Warn("list runtime verify tasks failed", "agent_id", agentID, "error", err)
		return nil, status.Error(codes.Internal, "list runtime verify tasks failed")
	}
	out := &pb.FetchRuntimeVerifyTasksResponse{}
	for _, t := range tasks {
		out.Tasks = append(out.Tasks, &pb.RuntimeVerifyTaskInfo{
			TaskId:    t.ID,
			AssetName: t.AssetName,
		})
	}
	return out, nil
}

// ReportRuntimeVerify evaluates one agent snapshot against the task baseline
// captured at claim time and writes the result plus a patch_task.verified
// outbox event.
func (s *AgentGRPCServer) ReportRuntimeVerify(ctx context.Context, req *pb.ReportRuntimeVerifyRequest) (*pb.ReportRuntimeVerifyResponse, error) {
	agentID, err := s.auth.ValidateToken(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if agentID != req.GetAgentId() {
		return nil, status.Error(codes.PermissionDenied, "agent_id mismatch")
	}
	if req.GetSystemInfo() == nil {
		return nil, status.Error(codes.InvalidArgument, "system_info required")
	}
	task, err := s.store.GetPatchTask(ctx, req.GetTaskId())
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "task not found")
		}
		slog.Warn("get patch task for runtime verify failed", "task_id", req.GetTaskId(), "error", err)
		return nil, status.Error(codes.Internal, "load task failed")
	}
	if task.AgentID != agentID {
		return nil, status.Error(codes.PermissionDenied, "task does not belong to this agent")
	}
	if task.Status != "success" || task.RuntimeVerifyStatus != "pending" {
		return nil, status.Error(codes.FailedPrecondition, "task is not awaiting runtime verification")
	}
	baseline, err := patch.ParseRuntimeBaseline(task.RuntimeVerifyBaseline)
	if err != nil {
		slog.Warn("parse runtime baseline failed", "task_id", task.ID, "error", err)
		return nil, status.Error(codes.Internal, "baseline unreadable")
	}
	snapshot := patch.RuntimeSnapshot{
		Services:  servicesFromPB(req.GetSystemInfo().GetServices()),
		Processes: processesFromPB(req.GetSystemInfo().GetProcesses()),
	}
	result := patch.EvaluateRuntimeVerification(baseline, snapshot, task.AssetName)
	if err := s.store.CompleteRuntimeVerification(ctx, task.ID, result.Status, result.Detail); err != nil {
		slog.Error("complete runtime verification failed", "task_id", task.ID, "error", err)
		return nil, status.Error(codes.Internal, "store verification failed")
	}
	slog.Info("runtime verification completed", "task_id", task.ID,
		"agent_id", agentID, "asset", task.AssetName,
		"status", result.Status, "detail", result.Detail)
	return &pb.ReportRuntimeVerifyResponse{Ok: true, Status: result.Status, Detail: result.Detail}, nil
}

func servicesFromPB(in []*pb.ServiceInfo) []collector.ServiceInfo {
	var out []collector.ServiceInfo
	for _, v := range in {
		if v == nil {
			continue
		}
		out = append(out, collector.ServiceInfo{
			Name: v.GetName(), State: v.GetState(),
			StartType: v.GetStartType(), RunAs: v.GetRunAs(),
		})
	}
	return out
}

func processesFromPB(in []*pb.ProcessInfo) []collector.ProcessInfo {
	var out []collector.ProcessInfo
	for _, p := range in {
		if p == nil {
			continue
		}
		out = append(out, collector.ProcessInfo{
			PID: int(p.GetPid()), Name: p.GetName(),
			User: p.GetUser(), MemoryMB: p.GetMemoryMb(),
		})
	}
	return out
}

// ReportPatchProgress stores one incremental stdout/stderr chunk and returns
// whether the operator has requested cancellation of the running task.
func (s *AgentGRPCServer) ReportPatchProgress(ctx context.Context, req *pb.ReportPatchProgressRequest) (*pb.ReportPatchProgressResponse, error) {
	agentID, err := s.auth.ValidateToken(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}
	if agentID != req.GetAgentId() {
		return nil, status.Error(codes.PermissionDenied, "agent_id mismatch")
	}
	if req.GetStream() != "stdout" && req.GetStream() != "stderr" && req.GetStream() != "heartbeat" {
		return nil, status.Error(codes.InvalidArgument, "stream must be stdout, stderr or heartbeat")
	}
	task, err := s.store.GetPatchTask(ctx, req.GetTaskId())
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "task not found")
		}
		slog.Warn("get patch task for progress failed", "task_id", req.GetTaskId(), "error", err)
		return nil, status.Error(codes.Internal, "load task failed")
	}
	if task.AgentID != agentID || task.Status != "running" {
		return nil, status.Error(codes.FailedPrecondition, "task is not running for this agent")
	}
	if req.GetData() != "" {
		events := []store.PatchTaskEvent{
			{Stream: req.GetStream(), Data: req.GetData()},
		}
		if err := s.store.AppendPatchTaskEvents(ctx, task.ID, events); err != nil {
			slog.Warn("append patch progress failed", "task_id", task.ID, "error", err)
			return nil, status.Error(codes.Internal, "append progress failed")
		}
	}
	cancelRequested, err := s.store.PatchTaskCancelRequested(ctx, task.ID)
	if err != nil {
		slog.Warn("load cancel flag failed", "task_id", task.ID, "error", err)
		return nil, status.Error(codes.Internal, "load cancel flag failed")
	}
	return &pb.ReportPatchProgressResponse{Ok: true, CancelRequested: cancelRequested}, nil
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
