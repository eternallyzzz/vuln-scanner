package server

import (
	"net/http"
	"strings"
	"testing"
)

func TestSanitizeHostname(t *testing.T) {
	for _, c := range []struct {
		in, want string
	}{
		{"", "unknown"},
		{"web-1", "web-1"},
		{"web node/1", "web-node-1"},
		{"A_B.C", "A_B-C"},
	} {
		if got := sanitizeHostname(c.in); got != c.want {
			t.Errorf("sanitizeHostname(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRandSuffix(t *testing.T) {
	const chars = "0123456789abcdefghijklmnopqrstuvwxyz"
	for _, n := range []int{1, 4, 8} {
		s := randSuffix(n)
		if len(s) != n {
			t.Fatalf("randSuffix(%d) length = %d", n, len(s))
		}
		for _, r := range s {
			if !strings.ContainsRune(chars, r) {
				t.Fatalf("randSuffix(%d) contains invalid char %q", n, r)
			}
		}
	}
}

func TestWorkersEndpointAdminOnly(t *testing.T) {
	if !userCan("admin", http.MethodGet, "/api/v1/workers") {
		t.Fatal("admin must access /api/v1/workers")
	}
	if userCan("operator", http.MethodGet, "/api/v1/workers") ||
		userCan("viewer", http.MethodGet, "/api/v1/workers") {
		t.Fatal("/api/v1/workers must be admin-only")
	}
}
