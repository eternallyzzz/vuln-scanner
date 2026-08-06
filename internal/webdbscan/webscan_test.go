package webdbscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScanWebFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/8.1.2")
		w.Write([]byte(`<html><head><title>Test App</title></head><body>hello</body></html>`))
	}))
	defer srv.Close()

	res, err := ScanWeb(context.Background(), srv.URL, nil, *DefaultConfig().Normalized())
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || res.Title != "Test App" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(res.Products) != 2 || res.Products[0].Name != "nginx" || res.Products[1].Name != "php" {
		t.Fatalf("unexpected products: %+v", res.Products)
	}

	res, err = ScanWeb(context.Background(), srv.URL+"/redirect", nil, *DefaultConfig().Normalized())
	if err != nil {
		t.Fatal(err)
	}
	if res.Redirects != 1 || res.URL != srv.URL+"/" {
		t.Fatalf("redirect handling failed: %+v", res)
	}
}

func TestScanWebBasicAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "scan" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte("<title>private</title>"))
	}))
	defer srv.Close()

	res, err := ScanWeb(context.Background(), srv.URL, &Credential{Username: "scan", Password: "secret"}, *DefaultConfig().Normalized())
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || res.Title != "private" {
		t.Fatalf("basic auth scan failed: %+v", res)
	}

	res, err = ScanWeb(context.Background(), srv.URL, nil, *DefaultConfig().Normalized())
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without credentials, got %d", res.StatusCode)
	}
}

func TestScanWebInvalidTarget(t *testing.T) {
	if _, err := ScanWeb(context.Background(), "bad target", nil, Config{}); err == nil {
		t.Fatal("expected error for invalid target")
	}
}
