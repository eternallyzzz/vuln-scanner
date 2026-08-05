package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsAuditedMethod(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		if !isAuditedMethod(method) {
			t.Errorf("isAuditedMethod(%s) = false, want true", method)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if isAuditedMethod(method) {
			t.Errorf("isAuditedMethod(%s) = true, want false", method)
		}
	}
}

func TestStatusRecorderCapturesExplicitStatus(t *testing.T) {
	rr := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: rr}
	rec.WriteHeader(http.StatusForbidden)
	if rec.StatusCode() != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.StatusCode(), http.StatusForbidden)
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("underlying status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestStatusRecorderDefaultsTo200(t *testing.T) {
	rr := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: rr}
	_, _ = rec.Write([]byte("ok"))
	if rec.StatusCode() != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.StatusCode(), http.StatusOK)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("underlying status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestStatusRecorderKeepsFirstStatus(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	rec.WriteHeader(http.StatusCreated)
	rec.WriteHeader(http.StatusOK)
	if rec.StatusCode() != http.StatusCreated {
		t.Fatalf("status = %d, want first status %d", rec.StatusCode(), http.StatusCreated)
	}
}

func TestAuditActorFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	ctx := context.Background()
	if got := auditActorFor(ctx, req); got != "" {
		t.Fatalf("failed login actor = %q, want empty", got)
	}

	box := &auditActor{username: "alice"}
	ctx = context.WithValue(ctx, auditActorCtxKey, box)
	if got := auditActorFor(ctx, req); got != "alice" {
		t.Fatalf("successful login actor = %q, want alice", got)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", nil)
	if got := auditActorFor(ctx, req); got != "api" {
		t.Fatalf("anonymous actor = %q, want api", got)
	}
	req.Header.Set("X-User", "legacy")
	if got := auditActorFor(ctx, req); got != "legacy" {
		t.Fatalf("X-User actor = %q, want legacy", got)
	}
	req.Header.Del("X-User")
	userCtx := context.WithValue(req.Context(), userCtxKey, &requestUser{Username: "bob", Role: "operator"})
	req = req.WithContext(userCtx)
	if got := auditActorFor(req.Context(), req); got != "bob" {
		t.Fatalf("session actor = %q, want bob", got)
	}
}

func TestClientIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "10.0.0.5:4321"
	if got := clientIP(req); got != "10.0.0.5" {
		t.Fatalf("clientIP = %q, want 10.0.0.5", got)
	}
	req.RemoteAddr = "[2001:db8::1]:9090"
	if got := clientIP(req); got != "2001:db8::1" {
		t.Fatalf("clientIP = %q, want 2001:db8::1", got)
	}
	req.RemoteAddr = ""
	if got := clientIP(req); got != "" {
		t.Fatalf("clientIP with empty remote = %q, want empty", got)
	}
}
