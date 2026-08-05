package agent

import (
	"context"
	"fmt"
	"log/slog"

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
