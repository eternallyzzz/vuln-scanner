package server

import (
	"net/http"
	"testing"
)

func TestGRPCAddrForRequest(t *testing.T) {
	cases := []struct {
		host, grpcCfg, want string
	}{
		{"localhost:8080", ":9090", "localhost:9090"},
		{"172.28.95.139:8080", ":9090", "172.28.95.139:9090"},
		{"10.0.0.5:8080", "0.0.0.0:9090", "10.0.0.5:9090"},
		{"server.example.com", ":9090", "server.example.com:9090"},
		{"[::1]:8080", ":9090", "[::1]:9090"},
	}
	for _, c := range cases {
		req := &http.Request{Host: c.host}
		if got := grpcAddrForRequest(req, c.grpcCfg); got != c.want {
			t.Errorf("grpcAddrForRequest(%q, %q) = %q, want %q",
				c.host, c.grpcCfg, got, c.want)
		}
	}
}
