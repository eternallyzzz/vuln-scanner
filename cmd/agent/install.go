package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"

	"vuln-scanner/internal/agent"
)

func registerAgent(ctx context.Context, serverURL, code string) (*agent.Config, error) {
	hostname, _ := osHostname()
	osType := runtime.GOOS
	arch := runtime.GOARCH

	req := map[string]string{
		"code":     code,
		"hostname": hostname,
		"os_type":  osType,
		"arch":     arch,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", serverURL+"/api/v1/register", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		AgentID  string `json:"agent_id"`
		GRPCAddr string `json:"grpc_addr"`
		Error    string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.AgentID == "" {
		return nil, fmt.Errorf("registration failed: %s", result.Error)
	}

	cfg := &agent.Config{}
	cfg.Server.Addr = result.GRPCAddr
	cfg.Agent.ID = result.AgentID
	cfg.Agent.Hostname = hostname

	return cfg, nil
}

func osHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	return hostname, nil
}
