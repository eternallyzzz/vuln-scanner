package cve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConditionalGetSendsAndHonorsValidators(t *testing.T) {
	var sawETag, sawModified string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawETag = r.Header.Get("If-None-Match")
		sawModified = r.Header.Get("If-Modified-Since")
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	st := FeedState{ETag: `"v1"`, LastModified: "Mon, 02 Jan 2006 15:04:05 GMT"}
	body, status, next, err := conditionalGet(context.Background(), srv.Client(),
		http.MethodGet, srv.URL, nil, nil, st)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusNotModified {
		t.Fatalf("first status = %d, want 304", status)
	}
	if len(body) != 0 {
		t.Fatalf("304 body = %q, want empty", body)
	}
	if sawETag != `"v1"` || sawModified != "Mon, 02 Jan 2006 15:04:05 GMT" {
		t.Fatalf("validators not sent: etag=%q modified=%q", sawETag, sawModified)
	}

	st = FeedState{}
	body, status, next, err = conditionalGet(context.Background(), srv.Client(),
		http.MethodGet, srv.URL, nil, nil, st)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || string(body) != `{"ok":true}` {
		t.Fatalf("fresh request status=%d body=%q", status, body)
	}
	if next.ETag != `"v1"` || next.LastModified != "Mon, 02 Jan 2006 15:04:05 GMT" {
		t.Fatalf("validators not captured: %+v", next)
	}
}
