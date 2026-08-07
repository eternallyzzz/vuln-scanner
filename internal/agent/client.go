package agent

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	pb "vuln-scanner/api/gen/vulnscan/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type Client struct {
	cfg       *Config
	grpcAddr  string
	conn      *grpc.ClientConn
	rawClient pb.AgentServiceClient
}

func NewClient(cfg *Config) (*Client, error) {
	return &Client{
		cfg:      cfg,
		grpcAddr: cfg.Server.Addr,
	}, nil
}

func (c *Client) Connect(ctx context.Context) error {
	conn, err := grpcDial(ctx, c.grpcAddr,
		grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			if c.cfg.Agent.Token != "" {
				md := metadata.Pairs("authorization", "Bearer "+c.cfg.Agent.Token)
				ctx = metadata.NewOutgoingContext(ctx, md)
			}
			return invoker(ctx, method, req, reply, cc, opts...)
		}),
	)
	if err != nil {
		return fmt.Errorf("grpc dial: %w", err)
	}
	c.conn = conn
	c.rawClient = pb.NewAgentServiceClient(conn)
	return nil
}

func (c *Client) Auth(ctx context.Context) error {
	fp := Fingerprint()
	resp, err := c.rawClient.Auth(ctx, &pb.AuthRequest{
		AgentId:     c.cfg.Agent.ID,
		Fingerprint: fp,
	})
	if err != nil {
		return fmt.Errorf("auth rpc: %w", err)
	}

	if resp.Status == "challenged" {
		return fmt.Errorf("agent challenged: %s", resp.Message)
	}

	c.cfg.Agent.Token = resp.Token
	if err := SaveConfig(c.cfg); err != nil {
		slog.Error("save token", "error", err)
	}

	slog.Info("auth success", "agent_id", c.cfg.Agent.ID)
	return nil
}

func (c *Client) RefreshToken(ctx context.Context) error {
	fp := Fingerprint()
	resp, err := c.rawClient.RefreshToken(ctx, &pb.RefreshTokenRequest{
		AgentId:     c.cfg.Agent.ID,
		Token:       c.cfg.Agent.Token,
		Fingerprint: fp,
	})
	if err != nil {
		return fmt.Errorf("refresh token rpc: %w", err)
	}

	c.cfg.Agent.Token = resp.Token
	if err := SaveConfig(c.cfg); err != nil {
		slog.Error("save token", "error", err)
	}

	return nil
}

func (c *Client) Heartbeat(ctx context.Context, collectorErrors int64) error {
	_, err := c.rawClient.Heartbeat(ctx, &pb.HeartbeatRequest{
		AgentId:         c.cfg.Agent.ID,
		Token:           c.cfg.Agent.Token,
		CollectorErrors: collectorErrors,
	})
	return err
}

func (c *Client) SyncInventory(ctx context.Context, assets []*pb.Asset, mode pb.SyncMode, sys *pb.SystemInfo) error {
	_, err := c.rawClient.SyncInventory(ctx, &pb.SyncInventoryRequest{
		AgentId:    c.cfg.Agent.ID,
		Token:      c.cfg.Agent.Token,
		Mode:       mode,
		Assets:     assets,
		SystemInfo: sys,
	})
	return err
}

// SyncCompliance uploads the latest agent-side compliance report.
func (c *Client) SyncCompliance(ctx context.Context, report *pb.ComplianceReport) error {
	_, err := c.rawClient.SyncCompliance(ctx, &pb.SyncComplianceRequest{
		AgentId:    c.cfg.Agent.ID,
		Token:      c.cfg.Agent.Token,
		Compliance: report,
	})
	return err
}

// SyncTelemetry uploads the periodic file-integrity and behavior facts.
func (c *Client) SyncTelemetry(ctx context.Context, files []*pb.FileFact, sys *pb.SystemInfo) error {
	_, err := c.rawClient.SyncTelemetry(ctx, &pb.SyncTelemetryRequest{
		AgentId:    c.cfg.Agent.ID,
		Token:      c.cfg.Agent.Token,
		FileFacts:  files,
		SystemInfo: sys,
	})
	return err
}

func (c *Client) FetchPatchTasks(ctx context.Context) ([]*pb.PatchTaskInfo, error) {
	resp, err := c.rawClient.FetchPatchTasks(ctx, &pb.FetchPatchTasksRequest{
		AgentId: c.cfg.Agent.ID,
		Token:   c.cfg.Agent.Token,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetTasks(), nil
}

func (c *Client) ReportPatchTask(ctx context.Context, taskID int64, status string, exitCode int32, output string) error {
	_, err := c.rawClient.ReportPatchTask(ctx, &pb.ReportPatchTaskRequest{
		TaskId:   taskID,
		AgentId:  c.cfg.Agent.ID,
		Token:    c.cfg.Agent.Token,
		Status:   status,
		ExitCode: exitCode,
		Output:   output,
	})
	return err
}

// ReportPatchProgress uploads one incremental execution chunk and returns
// whether the server has a pending cancel request for the task.
func (c *Client) ReportPatchProgress(ctx context.Context, taskID int64, stream, data string) (bool, error) {
	resp, err := c.rawClient.ReportPatchProgress(ctx, &pb.ReportPatchProgressRequest{
		TaskId:  taskID,
		AgentId: c.cfg.Agent.ID,
		Token:   c.cfg.Agent.Token,
		Stream:  stream,
		Data:    data,
	})
	if err != nil {
		return false, err
	}
	return resp.GetCancelRequested(), nil
}

// FetchRuntimeVerifyTasks returns succeeded patch tasks awaiting a runtime
// verification snapshot from this agent.
func (c *Client) FetchRuntimeVerifyTasks(ctx context.Context) ([]*pb.RuntimeVerifyTaskInfo, error) {
	resp, err := c.rawClient.FetchRuntimeVerifyTasks(ctx, &pb.FetchRuntimeVerifyTasksRequest{
		AgentId: c.cfg.Agent.ID,
		Token:   c.cfg.Agent.Token,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetTasks(), nil
}

// ReportRuntimeVerify uploads one SystemInfo snapshot for runtime
// verification and returns the evaluation result.
func (c *Client) ReportRuntimeVerify(ctx context.Context, taskID int64, sys *pb.SystemInfo) (string, string, error) {
	resp, err := c.rawClient.ReportRuntimeVerify(ctx, &pb.ReportRuntimeVerifyRequest{
		TaskId:     taskID,
		AgentId:    c.cfg.Agent.ID,
		Token:      c.cfg.Agent.Token,
		SystemInfo: sys,
	})
	if err != nil {
		return "", "", err
	}
	return resp.GetStatus(), resp.GetDetail(), nil
}

// FetchNetworkScanTasks claims pending server-dispatched network scan tasks
// for this agent.
func (c *Client) FetchNetworkScanTasks(ctx context.Context) ([]*pb.NetworkScanTaskInfo, error) {
	resp, err := c.rawClient.FetchNetworkScanTasks(ctx, &pb.FetchNetworkScanTasksRequest{
		AgentId: c.cfg.Agent.ID,
		Token:   c.cfg.Agent.Token,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetTasks(), nil
}

// SyncNetworkScan uploads one discovery result. taskID is 0 for scheduled
// scans; scanErr marks a server task as failed.
func (c *Client) SyncNetworkScan(ctx context.Context, taskID int64, scanMode string, hosts []*pb.NetworkHost, scanErr string) error {
	_, err := c.rawClient.SyncNetworkScan(ctx, &pb.SyncNetworkScanRequest{
		AgentId:   c.cfg.Agent.ID,
		Token:     c.cfg.Agent.Token,
		TaskId:    taskID,
		ScanMode:  scanMode,
		ScannedAt: time.Now().Format(time.RFC3339),
		Hosts:     hosts,
		Error:     scanErr,
	})
	return err
}
