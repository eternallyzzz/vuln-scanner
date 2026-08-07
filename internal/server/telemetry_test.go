package server

import (
	"context"
	"testing"

	pb "vuln-scanner/api/gen/vulnscan/v1"
	"vuln-scanner/internal/collector"
	"vuln-scanner/internal/monitor"
	"vuln-scanner/internal/store"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSyncTelemetryAuth(t *testing.T) {
	auth := NewAgentAuth("jwt-secret")
	grpcSrv := NewAgentGRPCServer(auth, nil, nil, nil)
	_, err := grpcSrv.SyncTelemetry(context.Background(), &pb.SyncTelemetryRequest{
		AgentId: "agent-1",
		Token:   "bad-token",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("invalid token = %v, want Unauthenticated", err)
	}
}

func TestTelemetryBehaviorFactsCanonicalKeys(t *testing.T) {
	info := &store.HostSystemInfo{
		Processes: []collector.ProcessInfo{
			{PID: 123, Name: "sshd", User: "root"},
			{PID: 456, Name: "sshd", User: "root"},
		},
		OpenPorts: []collector.PortInfo{
			{Protocol: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd"},
		},
		Accounts: []collector.AccountInfo{
			{Name: "alice", Domain: "example", Admin: true},
		},
		SSHKeys: []collector.SSHKeyInfo{
			{User: "root", Path: "/root/.ssh/authorized_keys", Type: "ssh-ed25519", Fingerprint: "abc"},
		},
	}
	facts := telemetryBehaviorFacts(info)
	if len(facts) != 4 {
		t.Fatalf("categories = %d, want 4 (processes, open_ports, accounts, ssh_keys)", len(facts))
	}
	procs := facts["processes"]
	if len(procs) != 1 {
		t.Fatalf("processes = %d, want 1 (PID must not be part of the key)", len(procs))
	}
	if procs[0].Key != "sshd|root" {
		t.Fatalf("process key = %q", procs[0].Key)
	}
	ports := facts["open_ports"]
	if ports[0].Key != "tcp|0.0.0.0|22|sshd" {
		t.Fatalf("port key = %q", ports[0].Key)
	}
	accounts := facts["accounts"]
	if accounts[0].Key != "example|alice" {
		t.Fatalf("account key = %q", accounts[0].Key)
	}
	keys := facts["ssh_keys"]
	if keys[0].Key != "root|/root/.ssh/authorized_keys|ssh-ed25519|abc" {
		t.Fatalf("ssh key = %q", keys[0].Key)
	}
	if monitor.CategorySeverity["accounts"] != "HIGH" {
		t.Fatalf("accounts severity = %q, want HIGH", monitor.CategorySeverity["accounts"])
	}
}
