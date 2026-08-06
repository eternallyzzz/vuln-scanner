package ticket

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestJiraCreateAndSync(t *testing.T) {
	t.Setenv("TICKET_PASSWORD", "token")
	var gotMethod, gotPath, gotAuth string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&gotBody)
		if r.URL.Path == "/rest/api/2/issue" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(201)
			w.Write([]byte(`{"key":"SEC-1","self":"https://jira.example.com/rest/api/2/issue/1001"}`))
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Provider = "jira"
	cfg.BaseURL = srv.URL
	cfg.Username = "svc@example.com"
	cfg.Project = "SEC"
	cfg.JiraAckTransitionID = ""
	cfg.JiraResolvedTransitionID = "31"

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := svc.Create(context.Background(), AlertInfo{
		AlertID: 7, RuleName: "high-nvd", AgentID: "agent-1",
		AgentHostname: "web01", CVEID: "CVE-2026-0001", AssetName: "openssl",
		Severity: "HIGH", CVSS: 8.1, Source: "nvd", DetectedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ref.Key != "SEC-1" || ref.Provider != "jira" {
		t.Fatalf("unexpected ref: %+v", ref)
	}
	if gotMethod != http.MethodPost || gotPath != "/rest/api/2/issue" {
		t.Fatalf("create = %s %s", gotMethod, gotPath)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("svc@example.com:token"))
	if gotAuth != wantAuth {
		t.Fatalf("auth = %q, want %q", gotAuth, wantAuth)
	}
	fields := gotBody["fields"].(map[string]interface{})
	if fields["summary"] != "[VulnScanner] HIGH CVE-2026-0001 on openssl" {
		t.Fatalf("summary = %v", fields["summary"])
	}
	desc := fields["description"].(string)
	for _, want := range []string{"Alert ID: 7", "CVE: CVE-2026-0001", "Asset: openssl"} {
		if !strings.Contains(desc, want) {
			t.Fatalf("description missing %q: %s", want, desc)
		}
	}
	if fields["priority"].(map[string]interface{})["name"] != "High" {
		t.Fatalf("priority = %v", fields["priority"])
	}

	if err := svc.Sync(context.Background(), ref, "ack"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/rest/api/2/issue/SEC-1/comment" {
		t.Fatalf("ack sync path = %s, want comment", gotPath)
	}
	comment := gotBody["body"].(string)
	if !strings.Contains(comment, "acknowledged") {
		t.Fatalf("comment = %q", comment)
	}

	if err := svc.Sync(context.Background(), ref, "resolved"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/rest/api/2/issue/SEC-1/transitions" {
		t.Fatalf("resolved sync path = %s, want transitions", gotPath)
	}
	tr := gotBody["transition"].(map[string]interface{})
	if tr["id"] != "31" {
		t.Fatalf("transition id = %v", tr["id"])
	}
}

func TestJiraCreateError(t *testing.T) {
	t.Setenv("TICKET_PASSWORD", "token")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"errorMessages":["bad request"]}`))
	}))
	defer srv.Close()
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Provider = "jira"
	cfg.BaseURL = srv.URL
	cfg.Username = "svc"
	cfg.Project = "SEC"
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(context.Background(), AlertInfo{CVEID: "CVE-1", AssetName: "x", Severity: "HIGH"}); err == nil ||
		!strings.Contains(err.Error(), "400") {
		t.Fatalf("Create() = %v, want 400 error", err)
	}
}
