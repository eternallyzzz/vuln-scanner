package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeRemoteTarget(t *testing.T) {
	cases := []struct {
		in      string
		port    int
		want    string
		wantErr bool
	}{
		{"10.0.0.1", 22, "10.0.0.1:22", false},
		{"10.0.0.1:2222", 22, "10.0.0.1:2222", false},
		{"host.example.com", 2222, "host.example.com:2222", false},
		{"[2001:db8::1]:22", 22, "[2001:db8::1]:22", false},
		{"", 22, "", true},
		{"10.0.0.1:70000", 22, "", true},
		{"10.0.0.1:abc", 22, "", true},
		{"a b", 22, "", true},
		{"a/b", 22, "", true},
		{"2001:db8::1", 22, "", true},
	}
	for _, c := range cases {
		got, err := normalizeRemoteTarget(c.in, c.port)
		if c.wantErr {
			if err == nil {
				t.Errorf("normalizeRemoteTarget(%q) should fail, got %q", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("normalizeRemoteTarget(%q) = (%q, %v), want %q", c.in, got, err, c.want)
		}
	}
}

func TestCreateRemoteScanValidation(t *testing.T) {
	s := NewRESTServer(nil, nil, DefaultConfig(), nil, nil)
	cases := []struct {
		body string
		want int
	}{
		{`{"credential_id":0,"targets":["10.0.0.1"]}`, http.StatusBadRequest},
		{`{"credential_id":1,"targets":[]}`, http.StatusBadRequest},
		{`{"credential_id":1,"targets":["10.0.0.1"],"port":70000}`, http.StatusBadRequest},
		{`{"credential_id":1,"targets":["bad host"]}`, http.StatusBadRequest},
		{`{bad json`, http.StatusBadRequest},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/remote/scan",
			strings.NewReader(c.body))
		req.Header.Set("X-API-Key", "sk-change-me")
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != c.want {
			t.Errorf("POST /remote/scan %s = %d, want %d", c.body, rr.Code, c.want)
		}
	}
}

func TestRemoteCredentialDisabled(t *testing.T) {
	s := NewRESTServer(nil, nil, DefaultConfig(), nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/remote/credentials",
		strings.NewReader(`{"name":"prod","username":"scan","auth_type":"password","password":"p"}`))
	req.Header.Set("X-API-Key", "sk-change-me")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST /remote/credentials disabled = %d, want 503", rr.Code)
	}
}

func TestRemoteCredentialValidationWhenEnabled(t *testing.T) {
	t.Setenv("REMOTE_SCAN_MASTER_KEY", strings.Repeat("a", 64))
	cfg := DefaultConfig()
	cfg.RemoteScan.Enabled = true
	s := NewRESTServer(nil, nil, cfg, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/remote/credentials",
		strings.NewReader(`{"name":"","username":"scan","auth_type":"password","password":"p"}`))
	req.Header.Set("X-API-Key", "sk-change-me")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("POST /remote/credentials missing name = %d, want 400", rr.Code)
	}
}
