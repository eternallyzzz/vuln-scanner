package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "vuln-scanner/api/gen/vulnscan/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestEDRFindingsEndpointValidation(t *testing.T) {
	s := NewRESTServer(nil, nil, DefaultConfig(), nil, nil)
	cases := []struct {
		method, path string
		body         string
		want         int
	}{
		{http.MethodGet, "/api/v1/edr/findings/abc", "", http.StatusBadRequest},
		{http.MethodGet, "/api/v1/edr/findings/0", "", http.StatusBadRequest},
		{http.MethodPost, "/api/v1/edr/findings/abc/ack", "", http.StatusBadRequest},
		{http.MethodPost, "/api/v1/edr/findings/0/ignore", "", http.StatusBadRequest},
		{http.MethodPost, "/api/v1/edr/findings/abc/resolve", "", http.StatusBadRequest},
		{http.MethodPost, "/api/v1/edr/findings", `{"name":"Virus.A"}`, http.StatusBadRequest},
		{http.MethodPost, "/api/v1/edr/findings", `{"agent_id":"agent-1"}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		req.Header.Set("X-API-Key", "sk-change-me")
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != c.want {
			t.Errorf("%s %s (body %q) = %d, want %d", c.method, c.path, c.body, rr.Code, c.want)
		}
	}
}

func TestFetchRuntimeVerifyTasksAuth(t *testing.T) {
	auth := NewAgentAuth("jwt-secret")
	grpcSrv := NewAgentGRPCServer(auth, nil, nil, nil)
	_, err := grpcSrv.FetchRuntimeVerifyTasks(context.Background(), &pb.FetchRuntimeVerifyTasksRequest{
		AgentId: "agent-1",
		Token:   "bad-token",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("invalid token = %v, want Unauthenticated", err)
	}
}

func TestReportRuntimeVerifyAuth(t *testing.T) {
	auth := NewAgentAuth("jwt-secret")
	grpcSrv := NewAgentGRPCServer(auth, nil, nil, nil)
	_, err := grpcSrv.ReportRuntimeVerify(context.Background(), &pb.ReportRuntimeVerifyRequest{
		TaskId:  1,
		AgentId: "agent-1",
		Token:   "bad-token",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("invalid token = %v, want Unauthenticated", err)
	}
}
