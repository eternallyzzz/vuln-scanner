package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDemoPageServedWithoutAPIKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKey = "sk-demo-test"
	srv := NewRESTServer(nil, NewAgentAuth("jwt-secret"), cfg, nil, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/demo", nil)
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /demo = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "VulnScanner 成果展示") {
		t.Fatal("demo page missing title")
	}
	if !strings.Contains(body, "sk-demo-test") {
		t.Fatal("demo page missing injected API key")
	}
}

func TestDemoPageRequiresNoStore(t *testing.T) {
	cfg := DefaultConfig()
	srv := NewRESTServer(nil, NewAgentAuth("jwt-secret"), cfg, nil, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/demo", nil)
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /demo without store = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}
