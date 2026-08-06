package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateWebDBScanValidation(t *testing.T) {
	s := NewRESTServer(nil, nil, DefaultConfig(), nil, nil)
	cases := []struct {
		body string
		want int
	}{
		{`{}`, http.StatusBadRequest},
		{`{"web":[]}`, http.StatusBadRequest},
		{`{"db":[]}`, http.StatusBadRequest},
		{`{"web":["http://a"]}`, http.StatusServiceUnavailable},
		{`{"db":[{"target":"10.0.0.1:5432","db_type":"postgresql"}]}`, http.StatusServiceUnavailable},
		{`{bad json`, http.StatusBadRequest},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webdb/scan",
			strings.NewReader(c.body))
		req.Header.Set("X-API-Key", "sk-change-me")
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != c.want {
			t.Errorf("POST /webdb/scan %s = %d, want %d", c.body, rr.Code, c.want)
		}
	}
}

func TestCreateWebDBScanValidationWhenEnabled(t *testing.T) {
	t.Setenv("WEBDB_SCAN_MASTER_KEY", strings.Repeat("a", 64))
	cfg := DefaultConfig()
	cfg.WebDBScan.Enabled = true
	s := NewRESTServer(nil, nil, cfg, nil, nil)
	cases := []struct {
		body string
		want int
	}{
		{`{"web":["bad target"]}`, http.StatusBadRequest},
		{`{"web":["ftp://host"]}`, http.StatusBadRequest},
		{`{"db":[{"target":"10.0.0.1","db_type":"oracle"}]}`, http.StatusBadRequest},
		{`{"db":[{"target":"10.0.0.1:70000","db_type":"mysql"}]}`, http.StatusBadRequest},
		{`{"db":[{"target":"10.0.0.1","db_type":"mysql","credential_id":-1}]}`, http.StatusBadRequest},
		{`{"web":[` + strings.Repeat(`"http://a",`, 100) + `"http://z"],"db":[{"target":"10.0.0.1","db_type":"mysql"}]}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webdb/scan",
			strings.NewReader(c.body))
		req.Header.Set("X-API-Key", "sk-change-me")
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != c.want {
			t.Errorf("POST /webdb/scan %s = %d, want %d", c.body, rr.Code, c.want)
		}
	}
}

func TestWebDBCredentialDisabled(t *testing.T) {
	s := NewRESTServer(nil, nil, DefaultConfig(), nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webdb/credentials",
		strings.NewReader(`{"name":"db","username":"app","password":"p"}`))
	req.Header.Set("X-API-Key", "sk-change-me")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST /webdb/credentials disabled = %d, want 503", rr.Code)
	}
}

func TestWebDBCredentialValidationWhenEnabled(t *testing.T) {
	t.Setenv("WEBDB_SCAN_MASTER_KEY", strings.Repeat("a", 64))
	cfg := DefaultConfig()
	cfg.WebDBScan.Enabled = true
	s := NewRESTServer(nil, nil, cfg, nil, nil)
	cases := []struct {
		body string
		want int
	}{
		{`{"name":"","password":"p"}`, http.StatusBadRequest},
		{`{"name":"db","password":""}`, http.StatusBadRequest},
		{`{bad json`, http.StatusBadRequest},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webdb/credentials",
			strings.NewReader(c.body))
		req.Header.Set("X-API-Key", "sk-change-me")
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != c.want {
			t.Errorf("POST /webdb/credentials %s = %d, want %d", c.body, rr.Code, c.want)
		}
	}
}
