package cve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMSRCUpdatesWithState304(t *testing.T) {
	oldBase := msrcBaseURL
	defer func() { msrcBaseURL = oldBase }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[{"ID":"2026-Aug","DocumentTitle":"August 2026","CvrfUrl":"https://example/cvrf","InitialReleaseDate":"2026-08-01"}]}`))
	}))
	defer srv.Close()
	msrcBaseURL = srv.URL

	c := NewMSRCClient()
	c.http = srv.Client()
	st := FeedState{ETag: `"v1"`}
	updates, next, notModified, err := c.FetchUpdatesWithState(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	if !notModified || updates != nil {
		t.Fatalf("notModified=%v updates=%v, want true/nil", notModified, updates)
	}
	if next.ETag != `"v1"` {
		t.Fatalf("304 must preserve ETag, got %q", next.ETag)
	}
}
