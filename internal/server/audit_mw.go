package server

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vuln-scanner/internal/store"
)

type auditActorCtxKeyType int

const auditActorCtxKey auditActorCtxKeyType = iota + 1

// auditActor is a mutable annotation box placed into the request context by
// auditMiddleware. Login stores the successfully authenticated username here
// so the middleware can record it without changing authentication behavior.
type auditActor struct {
	username string
}

func setAuditActor(ctx context.Context, username string) {
	if a, ok := ctx.Value(auditActorCtxKey).(*auditActor); ok && username != "" {
		a.username = username
	}
}

// auditMiddleware records every mutating HTTP request that passed API-key
// auth into the unified audit_logs table. Reads are skipped by design; the
// audit endpoint itself is a GET and therefore not recorded.
func (s *RESTServer) auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAuditedMethod(r.Method) || s.store == nil {
			next.ServeHTTP(w, r)
			return
		}

		rec := &statusRecorder{ResponseWriter: w}
		box := &auditActor{}
		ctx := context.WithValue(r.Context(), auditActorCtxKey, box)
		start := time.Now()
		next.ServeHTTP(rec, r.WithContext(ctx))

		entry := store.AuditLog{
			Actor:      auditActorFor(ctx, r),
			Method:     r.Method,
			Path:       r.URL.Path,
			Status:     rec.StatusCode(),
			IP:         clientIP(r),
			DurationMS: time.Since(start).Milliseconds(),
			Detail:     []byte(`{}`),
			TenantID:   requestTenantID(r),
		}
		if err := s.store.AppendAuditLog(ctx, entry); err != nil {
			slog.Warn("failed to append audit log", "error", err,
				"method", entry.Method, "path", entry.Path)
		}
	})
}

// requestTenantID resolves the tenant recorded on audit entries: the session
// user's tenant, the X-Tenant-ID header for API-key automation, or the
// default tenant. Invalid headers fall back to 1 (best effort; validation
// happens in the scoped handlers).
func requestTenantID(r *http.Request) int64 {
	if u := userFromContext(r.Context()); u != nil {
		if u.Role == "admin" {
			if h := strings.TrimSpace(r.Header.Get("X-Tenant-ID")); h != "" {
				if id, err := strconv.ParseInt(h, 10, 64); err == nil && id > 0 {
					return id
				}
			}
		}
		if u.TenantID > 0 {
			return u.TenantID
		}
	}
	if bound := apiKeyTenantFromContext(r.Context()); bound > 0 {
		return bound
	}
	if h := strings.TrimSpace(r.Header.Get("X-Tenant-ID")); h != "" {
		if id, err := strconv.ParseInt(h, 10, 64); err == nil && id > 0 {
			return id
		}
	}
	return 1
}

func isAuditedMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	default:
		return false
	}
}

// auditActorFor resolves the accountable actor. Successful logins use the
// username annotated by the login handler; failed logins stay anonymous
// (empty string). Other anonymous automation is labelled "api" unless the
// legacy X-User header names the caller.
func auditActorFor(ctx context.Context, r *http.Request) string {
	if r.URL.Path == "/api/v1/auth/login" || r.URL.Path == "/api/v1/auth/ldap/login" {
		if a, ok := ctx.Value(auditActorCtxKey).(*auditActor); ok {
			return a.username
		}
		return ""
	}
	if u := userFromContext(ctx); u != nil && u.Username != "" {
		return u.Username
	}
	if actor := strings.TrimSpace(r.Header.Get("X-User")); actor != "" {
		return actor
	}
	return "api"
}

// clientIP returns the host part of RemoteAddr, matching how the audit trail
// identifies the source without trusting proxy headers.
func clientIP(r *http.Request) string {
	if r == nil || r.RemoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

// statusRecorder captures the response status code while delegating all
// writes to the underlying ResponseWriter.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.status = http.StatusOK
		r.wroteHeader = true
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) StatusCode() int {
	if !r.wroteHeader {
		return http.StatusOK
	}
	return r.status
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (r *statusRecorder) Push(target string, opts *http.PushOptions) error {
	if p, ok := r.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}
