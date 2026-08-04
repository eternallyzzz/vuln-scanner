package cve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDebianFetchAllWithState304(t *testing.T) {
	oldURL := debianTrackerURL
	defer func() { debianTrackerURL = oldURL }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"d1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"d1"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	debianTrackerURL = srv.URL

	c := NewDebianTrackerClient()
	c.http = srv.Client()
	data, next, notModified, err := c.FetchAllWithState(context.Background(), FeedState{ETag: `"d1"`})
	if err != nil {
		t.Fatal(err)
	}
	if !notModified || data != nil {
		t.Fatalf("notModified=%v data=%v, want true/nil", notModified, data)
	}
	if next.ETag != `"d1"` {
		t.Fatalf("ETag = %q, want preserved", next.ETag)
	}
}
