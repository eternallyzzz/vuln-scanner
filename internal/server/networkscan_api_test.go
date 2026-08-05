package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidNetworkTarget(t *testing.T) {
	valid := []string{"192.168.1.1", "10.0.0.0/24", "172.16.0.0/16"}
	for _, v := range valid {
		if !validNetworkTarget(v) {
			t.Errorf("validNetworkTarget(%q) = false, want true", v)
		}
	}
	invalid := []string{"", "not-an-ip", "2001:db8::1", "2001:db8::/32", "10.0.0.0/33"}
	for _, v := range invalid {
		if validNetworkTarget(v) {
			t.Errorf("validNetworkTarget(%q) = true, want false", v)
		}
	}
}

func TestCreateNetworkScanValidation(t *testing.T) {
	s := NewRESTServer(nil, nil, DefaultConfig(), nil, nil)
	cases := []struct {
		body string
		want int
	}{
		{`{"target":"not-an-ip"}`, http.StatusBadRequest},
		{`{"target":"2001:db8::1"}`, http.StatusBadRequest},
		{`{"target":"10.0.0.1","ports":[70000]}`, http.StatusBadRequest},
		{`{bad json`, http.StatusBadRequest},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/network/scan",
			strings.NewReader(c.body))
		req.Header.Set("X-API-Key", "sk-change-me")
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != c.want {
			t.Errorf("POST /network/scan %s = %d, want %d", c.body, rr.Code, c.want)
		}
	}
}
