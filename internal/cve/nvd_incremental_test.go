package cve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestNVDIncrementalQueryParams(t *testing.T) {
	oldBase := nvdBaseURL
	defer func() { nvdBaseURL = oldBase }()

	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resultsPerPage":50,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()
	nvdBaseURL = srv.URL

	c := NewNVDClient()
	c.http = srv.Client()
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := c.SearchByKeywordSince(context.Background(), "openssl", since); err != nil {
		t.Fatal(err)
	}
	if got.Get("keywordSearch") != "openssl" {
		t.Fatalf("keywordSearch = %q, want openssl", got.Get("keywordSearch"))
	}
	if got.Get("lastModStartDate") != "2026-01-01T00:00:00Z" {
		t.Fatalf("lastModStartDate = %q", got.Get("lastModStartDate"))
	}
	if got.Get("lastModEndDate") == "" {
		t.Fatal("lastModEndDate must be set")
	}
}
