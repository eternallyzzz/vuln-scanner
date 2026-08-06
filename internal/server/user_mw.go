package server

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"vuln-scanner/internal/store"
)

type userCtxKeyType int

const userCtxKey userCtxKeyType = iota + 1

// requestUser is the authenticated dashboard identity attached to a request
// context by userAuthMiddleware.
type requestUser struct {
	ID       int64
	Username string
	Role     string
	TenantID int64
}

func userFromContext(ctx context.Context) *requestUser {
	u, _ := ctx.Value(userCtxKey).(*requestUser)
	return u
}

// userAuthMiddleware parses an optional "Authorization: Bearer <token>"
// dashboard session token. A missing header leaves the request anonymous so
// the existing X-API-Key channel keeps working; a present-but-invalid token
// is rejected outright.
func (s *RESTServer) userAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if authz == "" {
			next.ServeHTTP(w, r)
			return
		}
		const prefix = "Bearer "
		if !strings.HasPrefix(authz, prefix) {
			writeError(w, http.StatusUnauthorized, "unsupported authorization scheme")
			return
		}
		claims, err := s.userAuth.ValidateToken(strings.TrimSpace(authz[len(prefix):]))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		ctx := context.WithValue(r.Context(), userCtxKey, &requestUser{
			ID:       claims.UserID,
			Username: claims.Username,
			Role:     claims.Role,
			TenantID: claims.TenantID,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// enforceRBAC applies the role permission matrix to authenticated dashboard
// requests. Anonymous (X-API-Key) requests pass through untouched.
func (s *RESTServer) enforceRBAC(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := userFromContext(r.Context())
		if u == nil {
			next.ServeHTTP(w, r)
			return
		}
		if !userCan(u.Role, r.Method, r.URL.Path) {
			writeError(w, http.StatusForbidden, "forbidden: insufficient role ("+u.Role+")")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// actorFromRequest returns the accountable actor for mutating operations:
// the dashboard username when a session is present, otherwise the legacy
// X-User header, otherwise "api".
func actorFromRequest(r *http.Request) string {
	if u := userFromContext(r.Context()); u != nil && u.Username != "" {
		return u.Username
	}
	if actor := strings.TrimSpace(r.Header.Get("X-User")); actor != "" {
		return actor
	}
	return "api"
}

// userCan is the RBAC permission matrix. admin can do everything; viewer is
// read-only; operator gets the daily operational mutations; self-service
// password change and /auth/me are available to every logged-in role.
func userCan(role, method, path string) bool {
	// Tenant management is a system-level surface: only admin may read or
	// mutate tenants and reassign users/agents between them.
	if strings.HasPrefix(path, "/api/v1/tenants") ||
		strings.HasSuffix(path, "/tenant") {
		return role == "admin"
	}
	// API key lifecycle is a system-level surface: only admins may manage
	// automation credentials.
	if strings.HasPrefix(path, "/api/v1/api-keys") {
		return role == "admin"
	}
	// The unified audit trail is a governance surface: only admins may read
	// or export it, regardless of the generic GET permissions below.
	if strings.HasPrefix(path, "/api/v1/audit-logs") {
		return role == "admin"
	}
	// Worker/lease topology is an infrastructure surface: only admins may
	// inspect which instances hold which loops.
	if strings.HasPrefix(path, "/api/v1/workers") {
		return role == "admin"
	}
	// Credential management exposes sensitive remote-login material: only
	// admins may read or mutate credentials.
	if strings.HasPrefix(path, "/api/v1/remote/credentials") {
		return role == "admin"
	}
	// Cloud account management exposes provider credentials: only admins may
	// read or mutate accounts; the manual refresh action stays operator-level.
	if strings.HasPrefix(path, "/api/v1/cloud/accounts") && !strings.HasSuffix(path, "/refresh") {
		return role == "admin"
	}
	// Web/database credentials expose login material: only admins may read
	// or mutate credentials.
	if strings.HasPrefix(path, "/api/v1/webdb/credentials") {
		return role == "admin"
	}
	switch role {
	case "admin":
		return true
	case "viewer":
		return method == http.MethodGet
	case "operator":
		if method == http.MethodGet {
			return true
		}
		if path == "/api/v1/auth/change-password" && method == http.MethodPost {
			return true
		}
		return operatorCan(method, strings.ToLower(path))
	default:
		return false
	}
}

type pathRule struct {
	method string
	prefix string
	suffix string
}

func operatorCan(method, path string) bool {
	rules := []pathRule{
		{http.MethodPost, "/api/v1/agents/", "/scan"},
		{http.MethodPost, "/api/v1/agents/", "/patch-tasks/generate"},
		{http.MethodPost, "/api/v1/patch-tasks/", ""},
		{http.MethodPost, "/api/v1/patch-campaigns", ""},
		{http.MethodPost, "/api/v1/patch-campaigns/", ""},
		{http.MethodPost, "/api/v1/alerts/", ""},
		{http.MethodPost, "/api/v1/exceptions", ""},
		{http.MethodPost, "/api/v1/exceptions/", ""},
		{http.MethodPost, "/api/v1/analyze", ""},
		{http.MethodPost, "/api/v1/trigger-match", ""},
		{http.MethodPut, "/api/v1/scan-policies/", ""},
		{http.MethodPost, "/api/v1/container/scan", ""},
		{http.MethodPost, "/api/v1/network/scan", ""},
		{http.MethodPost, "/api/v1/remote/scan", ""},
		{http.MethodPost, "/api/v1/webdb/scan", ""},
		{http.MethodPost, "/api/v1/cloud/accounts/", "/refresh"},
		{http.MethodPost, "/api/v1/assets/import", ""},
		{http.MethodPost, "/api/v1/assets/bulk-meta", ""},
		{http.MethodPut, "/api/v1/assets/", ""},
		{http.MethodPost, "/api/v1/alert-rules", ""},
		{http.MethodPut, "/api/v1/alert-rules/", ""},
		{http.MethodDelete, "/api/v1/alert-rules/", ""},
		{http.MethodPut, "/api/v1/sla-policies/", ""},
		{http.MethodPost, "/api/v1/edr/findings", ""},
	}
	for _, rule := range rules {
		if method != rule.method {
			continue
		}
		if rule.prefix != "" && !strings.HasPrefix(path, rule.prefix) {
			continue
		}
		if rule.suffix != "" && !strings.HasSuffix(path, rule.suffix) {
			continue
		}
		return true
	}
	return false
}

// userStore is the subset of *store.Store needed for admin bootstrap, kept
// small so the bootstrap logic is unit-testable without a database.
type userStore interface {
	CountUsers(ctx context.Context) (int64, error)
	CreateUser(ctx context.Context, username, passwordHash, displayName, role string, tenantID int64) (*store.User, error)
}

// BootstrapAdmin creates the first admin account on an empty users table when
// ADMIN_PASSWORD is supplied. Without a password the server logs a warning
// and dashboard login stays unavailable until an admin is bootstrapped.
func BootstrapAdmin(ctx context.Context, us userStore, username, password string) error {
	if password == "" {
		slog.Warn("ADMIN_PASSWORD not set; dashboard login disabled until admin bootstrap")
		return nil
	}
	n, err := us.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	if _, err := us.CreateUser(ctx, username, hash, "Administrator", "admin", 1); err != nil {
		return err
	}
	slog.Info("bootstrapped admin user", "username", username)
	return nil
}
