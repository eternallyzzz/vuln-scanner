package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vuln-scanner/internal/ldap"
)

func TestLDAPLoginNotEnabled(t *testing.T) {
	s := NewRESTServer(nil, nil, DefaultConfig(), nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/ldap/login",
		strings.NewReader(`{"username":"alice","password":"secret"}`))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "not enabled") {
		t.Fatalf("body = %q, want ldap not enabled message", rr.Body.String())
	}
}

func TestLDAPLoginInvalidBody(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LDAP = &ldap.Config{Enabled: true}
	s := NewRESTServer(nil, nil, cfg, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/ldap/login",
		strings.NewReader(`{bad json`))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestLDAPLoginIsPublic(t *testing.T) {
	s := NewRESTServer(nil, nil, DefaultConfig(), nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/ldap/login",
		strings.NewReader(`{}`))
	req.Header.Del("X-API-Key")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	// Reaches the handler without an API key; disabled LDAP returns 400
	// rather than 401 from the API key middleware.
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (public endpoint)", rr.Code)
	}
}
