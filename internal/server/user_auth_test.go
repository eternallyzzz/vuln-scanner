package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"vuln-scanner/internal/store"
)

func TestHashAndCheckPassword(t *testing.T) {
	hash, err := hashPassword("s3cret-password")
	if err != nil {
		t.Fatal(err)
	}
	if hash == "s3cret-password" || !strings.HasPrefix(hash, "$2") {
		t.Fatalf("hash must be a bcrypt hash, got %q", hash)
	}
	if !checkPassword(hash, "s3cret-password") {
		t.Fatal("correct password must verify")
	}
	if checkPassword(hash, "wrong-password") {
		t.Fatal("wrong password must not verify")
	}
}

func TestUserTokenRoundtrip(t *testing.T) {
	ua := NewUserAuth("jwt-secret")
	u := &store.User{ID: 7, Username: "alice", Role: "operator"}
	token, expiresAt, err := ua.IssueToken(u)
	if err != nil {
		t.Fatal(err)
	}
	if !expiresAt.After(time.Now()) {
		t.Fatal("token must expire in the future")
	}
	claims, err := ua.ValidateToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != 7 || claims.Username != "alice" || claims.Role != "operator" {
		t.Fatalf("claims = %+v, want uid=7 alice/operator", claims)
	}
}

func TestUserTokenRejectsWrongSecret(t *testing.T) {
	ua := NewUserAuth("jwt-secret")
	other := NewUserAuth("other-secret")
	token, _, err := ua.IssueToken(&store.User{ID: 1, Username: "bob", Role: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.ValidateToken(token); err == nil {
		t.Fatal("token signed with another secret must be rejected")
	}
}

func TestUserTokenRejectsAgentToken(t *testing.T) {
	agentAuth := NewAgentAuth("jwt-secret")
	ua := NewUserAuth("jwt-secret")
	agentToken, _, err := agentAuth.IssueToken("agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ua.ValidateToken(agentToken); err == nil {
		t.Fatal("agent token must not validate as a user token")
	}
}

func TestUserTokenExpired(t *testing.T) {
	ua := newUserAuth("jwt-secret", -time.Minute)
	token, _, err := ua.IssueToken(&store.User{ID: 1, Username: "carol", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ua.ValidateToken(token); err == nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestUserCanMatrix(t *testing.T) {
	cases := []struct {
		role, method, path string
		want               bool
	}{
		{"admin", http.MethodGet, "/api/v1/audit-logs", true},
		{"admin", http.MethodGet, "/api/v1/audit-logs/export.csv", true},
		{"operator", http.MethodGet, "/api/v1/audit-logs", false},
		{"operator", http.MethodGet, "/api/v1/audit-logs/export.csv", false},
		{"viewer", http.MethodGet, "/api/v1/audit-logs", false},
		{"viewer", http.MethodGet, "/api/v1/audit-logs/export.csv", false},
		{"operator", http.MethodPost, "/api/v1/audit-logs", false},
		{"admin", http.MethodDelete, "/api/v1/admin/refresh-feeds", true},
		{"admin", http.MethodGet, "/api/v1/agents", true},
		{"viewer", http.MethodGet, "/api/v1/risk/summary", true},
		{"viewer", http.MethodPost, "/api/v1/patch-tasks/1/approve", false},
		{"viewer", http.MethodPost, "/api/v1/auth/change-password", false},
		{"operator", http.MethodGet, "/api/v1/alerts", true},
		{"operator", http.MethodPost, "/api/v1/patch-tasks/1/approve", true},
		{"operator", http.MethodPost, "/api/v1/patch-campaigns", true},
		{"operator", http.MethodPost, "/api/v1/patch-campaigns/5/reject", true},
		{"operator", http.MethodPost, "/api/v1/alerts/9/ack", true},
		{"operator", http.MethodPost, "/api/v1/exceptions", true},
		{"operator", http.MethodPost, "/api/v1/exceptions/3/revoke", true},
		{"operator", http.MethodPost, "/api/v1/agents/2/scan", true},
		{"operator", http.MethodPut, "/api/v1/scan-policies/2", true},
		{"operator", http.MethodPost, "/api/v1/container/scan", true},
		{"operator", http.MethodPut, "/api/v1/assets/3", true},
		{"operator", http.MethodPost, "/api/v1/auth/change-password", true},
		{"operator", http.MethodPost, "/api/v1/admin/refresh-feeds", false},
		{"admin", http.MethodPost, "/api/v1/admin/report/send", true},
		{"operator", http.MethodPost, "/api/v1/admin/report/send", false},
		{"operator", http.MethodPost, "/api/v1/users", false},
		{"operator", http.MethodDelete, "/api/v1/agents/2", false},
		{"operator", http.MethodPost, "/api/v1/agents", false},
		{"unknown", http.MethodGet, "/api/v1/agents", false},
	}
	for _, c := range cases {
		if got := userCan(c.role, c.method, c.path); got != c.want {
			t.Errorf("userCan(%q, %s, %s) = %v, want %v", c.role, c.method, c.path, got, c.want)
		}
	}
}

func TestActorFromRequest(t *testing.T) {
	req := &http.Request{}
	if got := actorFromRequest(req); got != "api" {
		t.Fatalf("no context/header actor = %q, want api", got)
	}
	req.Header = http.Header{}
	req.Header.Set("X-User", "legacy-user")
	if got := actorFromRequest(req); got != "legacy-user" {
		t.Fatalf("header actor = %q, want legacy-user", got)
	}
	ctx := context.WithValue(req.Context(), userCtxKey, &requestUser{ID: 1, Username: "alice", Role: "operator"})
	req = req.WithContext(ctx)
	if got := actorFromRequest(req); got != "alice" {
		t.Fatalf("session actor = %q, want alice", got)
	}
}

func TestUserInputValidation(t *testing.T) {
	if !usernamePattern.MatchString("alice.01-x") {
		t.Fatal("valid username rejected")
	}
	for _, bad := range []string{"", "ab", "a b", "名字", strings.Repeat("a", 65), "a/b"} {
		if usernamePattern.MatchString(bad) {
			t.Errorf("username %q must be rejected", bad)
		}
	}
	if validPassword("short") || !validPassword("long-enough") {
		t.Fatal("password length rule broken")
	}
	if !validRole("admin") || !validRole("operator") || !validRole("viewer") || validRole("root") {
		t.Fatal("role validation broken")
	}
}

type fakeUserStore struct {
	count   int64
	created int
}

func (f *fakeUserStore) CountUsers(context.Context) (int64, error) { return f.count, nil }
func (f *fakeUserStore) CreateUser(_ context.Context, username, passwordHash, displayName, role string) (*store.User, error) {
	f.created++
	return &store.User{ID: 1, Username: username, PasswordHash: passwordHash, DisplayName: displayName, Role: role}, nil
}

func TestBootstrapAdmin(t *testing.T) {
	existing := &fakeUserStore{count: 1}
	if err := BootstrapAdmin(context.Background(), existing, "admin", "pw"); err != nil {
		t.Fatal(err)
	}
	if existing.created != 0 {
		t.Fatalf("bootstrap must skip when users exist, created=%d", existing.created)
	}
	noPassword := &fakeUserStore{count: 0}
	if err := BootstrapAdmin(context.Background(), noPassword, "admin", ""); err != nil {
		t.Fatal(err)
	}
	if noPassword.created != 0 {
		t.Fatalf("bootstrap without password must not create a user, created=%d", noPassword.created)
	}
	empty := &fakeUserStore{count: 0}
	if err := BootstrapAdmin(context.Background(), empty, "admin", "pw"); err != nil {
		t.Fatal(err)
	}
	if empty.created != 1 {
		t.Fatalf("bootstrap must create one admin, created=%d", empty.created)
	}
}
