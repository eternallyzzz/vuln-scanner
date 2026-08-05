package store

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeAuditLimit(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{0, 200},
		{-1, 200},
		{200, 200},
		{1000, 1000},
		{2000, 1000},
	}
	for _, c := range cases {
		if got := normalizeAuditLimit(c.in); got != c.want {
			t.Errorf("normalizeAuditLimit(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestAuditLogWhere(t *testing.T) {
	now := time.Now()
	where, args := auditLogWhere(AuditLogFilter{
		Actor:  "alice",
		Method: "POST",
		Path:   "users",
		Since:  &now,
		Until:  &now,
	})
	for _, want := range []string{
		"actor = $1",
		"method = $2",
		"POSITION(LOWER($3) IN LOWER(path)) > 0",
		"created_at >= $4",
		"created_at <= $5",
	} {
		if !strings.Contains(where, want) {
			t.Errorf("where %q missing %q", where, want)
		}
	}
	if len(args) != 5 {
		t.Fatalf("args = %d, want 5: %#v", len(args), args)
	}

	where, args = auditLogWhere(AuditLogFilter{})
	if where != "" || len(args) != 0 {
		t.Fatalf("empty filter = (%q, %#v), want empty", where, args)
	}
}
