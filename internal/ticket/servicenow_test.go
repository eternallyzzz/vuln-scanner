package ticket

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServiceNowCreateAndSync(t *testing.T) {
	t.Setenv("TICKET_PASSWORD", "pw")
	var gotMethod, gotPath string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(201)
			w.Write([]byte(`{"result":{"sys_id":"sys123","number":"INC0010001"}}`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Provider = "servicenow"
	cfg.BaseURL = srv.URL
	cfg.Username = "svc"
	cfg.ServiceNowTable = "incident"
	cfg.ServiceNowAckState = 2
	cfg.ServiceNowResolvedState = 6

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := svc.Create(context.Background(), AlertInfo{
		AlertID: 9, RuleName: "default-critical", CVEID: "CVE-2026-0002",
		AssetName: "db01", Severity: "CRITICAL", CVSS: 9.8, Source: "msrc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ref.Key != "INC0010001" || ref.Provider != "servicenow" ||
		!strings.Contains(ref.URL, "/api/now/table/incident/sys123") {
		t.Fatalf("unexpected ref: %+v", ref)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/now/table/incident" {
		t.Fatalf("create = %s %s", gotMethod, gotPath)
	}
	if gotBody["short_description"] != "[VulnScanner] CRITICAL CVE-2026-0002 on db01" ||
		gotBody["urgency"] != float64(1) || gotBody["impact"] != float64(1) {
		t.Fatalf("create body = %#v", gotBody)
	}

	if err := svc.Sync(context.Background(), ref, "ack"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPatch || gotPath != "/api/now/table/incident/INC0010001" {
		t.Fatalf("ack sync = %s %s", gotMethod, gotPath)
	}
	if gotBody["state"] != float64(2) || !strings.Contains(gotBody["work_notes"].(string), "acknowledged") {
		t.Fatalf("ack body = %#v", gotBody)
	}

	if err := svc.Sync(context.Background(), ref, "resolved"); err != nil {
		t.Fatal(err)
	}
	if gotBody["state"] != float64(6) || !strings.Contains(gotBody["work_notes"].(string), "resolved") {
		t.Fatalf("resolved body = %#v", gotBody)
	}
}

func TestServiceNowCreateError(t *testing.T) {
	t.Setenv("TICKET_PASSWORD", "pw")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"error":{"message":"forbidden"}}`))
	}))
	defer srv.Close()
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Provider = "servicenow"
	cfg.BaseURL = srv.URL
	cfg.Username = "svc"
	cfg.ServiceNowTable = "incident"
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(context.Background(), AlertInfo{CVEID: "CVE-1", AssetName: "x", Severity: "HIGH"}); err == nil ||
		!strings.Contains(err.Error(), "403") {
		t.Fatalf("Create() = %v, want 403 error", err)
	}
}
