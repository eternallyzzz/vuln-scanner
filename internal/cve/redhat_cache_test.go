package cve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedHatFetchAllWithStateUsesCursorAnd304(t *testing.T) {
	oldURL := redhatFeedURL
	defer func() { redhatFeedURL = oldURL }()

	var after string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		after = r.URL.Query().Get("after")
		if r.Header.Get("If-None-Match") == `"r1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"r1"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	redhatFeedURL = srv.URL

	c := NewRedHatClient()
	c.http = srv.Client()
	st := FeedState{Cursor: "2026-01-01", ETag: `"r1"`}
	cves, next, notModified, err := c.FetchAllWithState(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	if after != "2026-01-01" {
		t.Fatalf("after = %q, want 2026-01-01", after)
	}
	if !notModified || cves != nil {
		t.Fatalf("notModified=%v cves=%v, want true/nil", notModified, cves)
	}
	if next.ETag != `"r1"` || next.Cursor != "2026-01-01" {
		t.Fatalf("state not preserved: %+v", next)
	}
}
