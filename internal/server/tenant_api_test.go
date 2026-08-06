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
		"/api/v1/users/1/tenant",
		"/api/v1/agents/agent-1/tenant",
	} {
		if !userCan("admin", http.MethodGet, path) && !userCan("admin", http.MethodPost, path) &&
			!userCan("admin", http.MethodPut, path) {
			t.Fatalf("admin must access %s", path)
		}
		if userCan("operator", http.MethodGet, path) || userCan("viewer", http.MethodGet, path) ||
			userCan("operator", http.MethodPut, path) {
			t.Fatalf("tenant endpoints must be admin-only: %s", path)
		}
	}
}

func TestPublicUserIncludesTenant(t *testing.T) {
	u := publicUser(&store.User{TenantID: 9})
	if u["tenant_id"] != int64(9) {
		t.Fatalf("publicUser tenant_id = %v, want 9", u["tenant_id"])
	}
}
