package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"vuln-scanner/internal/store"
)

func TestScopeRoles(t *testing.T) {
	s := NewRESTServer(nil, nil, DefaultConfig(), nil, nil)
	cases := []struct {
		name     string
		role     string
		tenantID int64
		wantID   int64
		restrict bool
	}{
		{"admin is global", "admin", 3, 0, false},
		{"operator tenant-bound", "operator", 3, 3, true},
		{"viewer tenant-bound", "viewer", 4, 4, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
			ctx := context.WithValue(req.Context(), userCtxKey, &requestUser{
				ID: 1, Username: "u", Role: tc.role, TenantID: tc.tenantID,
			})
			req = req.WithContext(ctx)
			id, restrict, err := s.scope(req)
			if err != nil {
				t.Fatal(err)
			}
			if id != tc.wantID || restrict != tc.restrict {
				t.Fatalf("scope = (%d,%v), want (%d,%v)", id, restrict, tc.wantID, tc.restrict)
			}
		})
	}
}

func TestScopeAPIKey(t *testing.T) {
	s := NewRESTServer(nil, nil, DefaultConfig(), nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	if id, restrict, err := s.scope(req); err != nil || id != 0 || restrict {
		t.Fatalf("API key without X-Tenant-ID must be global, got (%d,%v,%v)", id, restrict, err)
	}
	req.Header.Set("X-Tenant-ID", "abc")
	if _, _, err := s.scope(req); err != errInvalidTenant {
		t.Fatalf("non-numeric X-Tenant-ID = %v, want errInvalidTenant", err)
	}
}

func TestLegacyTokenDefaultsToTenantOne(t *testing.T) {
	auth := NewUserAuth("jwt-secret")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, UserClaims{
		UserID: 7, Username: "legacy", Role: "operator",
		RegisteredClaims: jwt.RegisteredClaims{Subject: "7"},
	})
	signed, err := token.SignedString([]byte("jwt-secret"))
	if err != nil {
		t.Fatal(err)
	}
	claims, err := auth.ValidateToken(signed)
	if err != nil {
		t.Fatal(err)
	}
	if claims.TenantID != 1 {
		t.Fatalf("legacy token tenant = %d, want 1", claims.TenantID)
	}
}

func TestUserCanTenantEndpoints(t *testing.T) {
	for _, path := range []string{
		"/api/v1/tenants",
		"/api/v1/tenants/1",
		"/api/v1/tenants/1/report",
		"/api/v1/tenants/1/report/send",
		"/api/v1/users/1/tenant",
		"/api/v1/agents/agent-1/tenant",
		"/api/v1/api-keys",
		"/api/v1/api-keys/1",
	} {
		if !userCan("admin", http.MethodGet, path) && !userCan("admin", http.MethodPost, path) &&
			!userCan("admin", http.MethodPut, path) && !userCan("admin", http.MethodDelete, path) {
			t.Fatalf("admin must access %s", path)
		}
		if userCan("operator", http.MethodGet, path) || userCan("viewer", http.MethodGet, path) ||
			userCan("operator", http.MethodPut, path) || userCan("operator", http.MethodDelete, path) {
			t.Fatalf("tenant endpoints must be admin-only: %s", path)
		}
	}
}

func TestScopeTenantBoundAPIKey(t *testing.T) {
	s := NewRESTServer(nil, nil, DefaultConfig(), nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	req = req.WithContext(context.WithValue(req.Context(), apiKeyTenantCtxKey, int64(7)))

	if id, restrict, err := s.scope(req); err != nil || id != 7 || !restrict {
		t.Fatalf("tenant-bound API key scope = (%d,%v,%v), want (7,true,nil)", id, restrict, err)
	}
	req.Header.Set("X-Tenant-ID", "7")
	if id, restrict, err := s.scope(req); err != nil || id != 7 || !restrict {
		t.Fatalf("matching X-Tenant-ID scope = (%d,%v,%v), want (7,true,nil)", id, restrict, err)
	}
	req.Header.Set("X-Tenant-ID", "8")
	if _, _, err := s.scope(req); err != errTenantForbidden {
		t.Fatalf("mismatched X-Tenant-ID = %v, want errTenantForbidden", err)
	}
}

func TestPublicUserIncludesTenant(t *testing.T) {
	u := publicUser(&store.User{TenantID: 9})
	if u["tenant_id"] != int64(9) {
		t.Fatalf("publicUser tenant_id = %v, want 9", u["tenant_id"])
	}
}

func TestTenantAPIKeyCan(t *testing.T) {
	allowed := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/agents"},
		{http.MethodPost, "/api/v1/alert-rules"},
		{http.MethodPut, "/api/v1/sla-policies/3"},
		{http.MethodGet, "/api/v1/remote/credentials"},
		{http.MethodPost, "/api/v1/remote/scan"},
		{http.MethodPost, "/api/v1/webdb/scan"},
		{http.MethodPost, "/api/v1/network/scan"},
		{http.MethodPost, "/api/v1/cloud/accounts"},
		{http.MethodGet, "/api/v1/edr/findings"},
		{http.MethodGet, "/api/v1/dashboard"},
		{http.MethodGet, "/api/v1/tenants/7/report"},
		{http.MethodPut, "/api/v1/tenants/7/report"},
		{http.MethodPost, "/api/v1/tenants/7/report/send"},
	}
	for _, tc := range allowed {
		if !tenantAPIKeyCan(tc.method, tc.path, 7) {
			t.Errorf("tenantAPIKeyCan(%s %s) = false, want true", tc.method, tc.path)
		}
	}

	forbidden := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/tenants"},
		{http.MethodPost, "/api/v1/tenants"},
		{http.MethodGet, "/api/v1/tenants/8/report"},
		{http.MethodPut, "/api/v1/tenants/8/report"},
		{http.MethodPost, "/api/v1/tenants/8/report/send"},
		{http.MethodGet, "/api/v1/users"},
		{http.MethodPost, "/api/v1/users"},
		{http.MethodGet, "/api/v1/api-keys"},
		{http.MethodPost, "/api/v1/api-keys"},
		{http.MethodGet, "/api/v1/audit-logs"},
		{http.MethodGet, "/api/v1/audit-logs/export.csv"},
		{http.MethodGet, "/api/v1/workers"},
		{http.MethodPost, "/api/v1/admin/report/send"},
		{http.MethodPut, "/api/v1/users/1/tenant"},
		{http.MethodPut, "/api/v1/agents/agent-1/tenant"},
	}
	for _, tc := range forbidden {
		if tenantAPIKeyCan(tc.method, tc.path, 7) {
			t.Errorf("tenantAPIKeyCan(%s %s) = true, want false", tc.method, tc.path)
		}
	}
}

func TestEnforceRBACTenantScopedKey(t *testing.T) {
	srv := NewRESTServer(nil, nil, DefaultConfig(), nil, nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := srv.enforceRBAC(next)

	allowed := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	allowed = allowed.WithContext(context.WithValue(allowed.Context(), apiKeyTenantCtxKey, int64(7)))
	allowed = allowed.WithContext(context.WithValue(allowed.Context(), apiKeyScopedCtxKey, true))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, allowed)
	if rr.Code != http.StatusOK {
		t.Fatalf("tenant-scoped allowed path status = %d, want 200", rr.Code)
	}

	denied := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	denied = denied.WithContext(context.WithValue(denied.Context(), apiKeyTenantCtxKey, int64(7)))
	denied = denied.WithContext(context.WithValue(denied.Context(), apiKeyScopedCtxKey, true))
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, denied)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("tenant-scoped denied path status = %d, want 403", rr.Code)
	}

	global := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, global)
	if rr.Code != http.StatusOK {
		t.Fatalf("unscoped API key status = %d, want 200", rr.Code)
	}
}
