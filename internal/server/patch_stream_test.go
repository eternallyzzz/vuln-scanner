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

func TestPatchTaskEventEndpointsValidation(t *testing.T) {
	s := NewRESTServer(nil, nil, DefaultConfig(), nil, nil)
	cases := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/api/v1/patch-tasks/abc/events", http.StatusBadRequest},
		{http.MethodGet, "/api/v1/patch-tasks/0/events", http.StatusBadRequest},
		{http.MethodPost, "/api/v1/patch-tasks/abc/stop", http.StatusBadRequest},
		{http.MethodPost, "/api/v1/patch-tasks/0/stop", http.StatusBadRequest},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(""))
		req.Header.Set("X-API-Key", "sk-change-me")
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != c.want {
			t.Errorf("%s %s = %d, want %d", c.method, c.path, rr.Code, c.want)
		}
	}
}

func TestReportPatchProgressAuth(t *testing.T) {
	auth := NewAgentAuth("jwt-secret")
	grpcSrv := NewAgentGRPCServer(auth, nil, nil, nil)
	_, err := grpcSrv.ReportPatchProgress(context.Background(), &pb.ReportPatchProgressRequest{
		TaskId:  1,
		AgentId: "agent-1",
		Token:   "bad-token",
		Stream:  "stdout",
		Data:    "x",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("invalid token = %v, want Unauthenticated", err)
	}
}

func TestReportPatchTaskRejectsUnknownStatus(t *testing.T) {
	auth := NewAgentAuth("jwt-secret")
	token, _, err := auth.IssueToken("agent-1")
	if err != nil {
		t.Fatal(err)
	}
	grpcSrv := NewAgentGRPCServer(auth, nil, nil, nil)
	_, err = grpcSrv.ReportPatchTask(context.Background(), &pb.ReportPatchTaskRequest{
		TaskId:  1,
		AgentId: "agent-1",
		Token:   token,
		Status:  "bogus",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unknown status = %v, want InvalidArgument", err)
	}
}
