package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestGRPCAddrForRequest(t *testing.T) {
	cases := []struct {
		host, grpcCfg, want string
	}{
		{"localhost:8080", ":9090", "localhost:9090"},
		{"172.28.95.139:8080", ":9090", "172.28.95.139:9090"},
		{"10.0.0.5:8080", "0.0.0.0:9090", "10.0.0.5:9090"},
		{"server.example.com", ":9090", "server.example.com:9090"},
		{"[::1]:8080", ":9090", "[::1]:9090"},
	}
	for _, c := range cases {
		req := &http.Request{Host: c.host}
		if got := grpcAddrForRequest(req, c.grpcCfg); got != c.want {
			t.Errorf("grpcAddrForRequest(%q, %q) = %q, want %q",
				c.host, c.grpcCfg, got, c.want)
		}
	}
}

func TestDownloadAgentRoute(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "agents"), 0755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "agents", "linux-amd64")
	if err := os.WriteFile(bin, []byte("agent-binary"), 0644); err != nil {
		t.Fatal(err)
	}

	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)

	cfg := DefaultConfig()
	cfg.HTTPAddr = ":8080"
	cfg.APIKey = "test-key"
	srv := NewRESTServer(nil, NewAgentAuth("jwt-secret"), cfg, nil, nil)

	req := httptest.NewRequest("GET", "/dl/agent/linux-amd64", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "agent-binary" {
		t.Fatalf("body = %q, want agent-binary", rr.Body.String())
	}
}
