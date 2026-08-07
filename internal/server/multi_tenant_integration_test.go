package server

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"vuln-scanner/internal/store"
)

// newMultiTenantIntegrationServer provisions an isolated PostgreSQL schema
// and runs every migration in it. The test is skipped unless
// VULNSCAN_TEST_DATABASE_URL is set (CI runs it against the postgres service).
func newMultiTenantIntegrationServer(t *testing.T) (*store.Store, *RESTServer) {
	t.Helper()
	baseURL := os.Getenv("VULNSCAN_TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("VULNSCAN_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	schema := fmt.Sprintf("vulnscan_it_%d_%d", os.Getpid(), time.Now().UnixNano())

	admin, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		t.Fatalf("connect integration database: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgQuoteIdent(schema)); err != nil {
		_ = admin.Close(context.Background())
		t.Fatalf("create integration schema: %v", err)
	}
	cleanup := func() {
		dropCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = admin.Exec(dropCtx, "DROP SCHEMA IF EXISTS "+pgQuoteIdent(schema)+" CASCADE")
		_ = admin.Close(context.Background())
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		cleanup()
		t.Fatalf("parse VULNSCAN_TEST_DATABASE_URL: %v", err)
	}
	q := u.Query()
	// Keep public in the search path so shared extensions (pg_trgm) and their
	// operator classes resolve inside the isolated test schema.
	q.Set("options", "-csearch_path="+schema+",public")
	u.RawQuery = q.Encode()

	st, err := store.New(ctx, u.String())
	if err != nil {
		cleanup()
		t.Fatalf("open integration store: %v", err)
	}
	if err := st.RunMigrations(ctx); err != nil {
		st.Close()
		cleanup()
		t.Fatalf("run migrations: %v", err)
	}
	t.Cleanup(func() {
		st.Close()
		cleanup()
	})

	cfg := DefaultConfig()
	cfg.APIKey = "legacy-global-api-key"
	srv := NewRESTServer(st, NewAgentAuth("jwt-secret"), cfg, nil, nil)
	return st, srv
}

func pgQuoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func integrationRequest(t *testing.T, srv *RESTServer, method, path, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	return rr
}

func integrationJSON(t *testing.T, rr *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode JSON response %q: %v", rr.Body.String(), err)
	}
	return out
}

func integrationListLen(v map[string]interface{}, key string) int {
	raw, ok := v[key].([]interface{})
	if !ok {
		return -1
	}
	return len(raw)
}

func TestMultiTenantIntegration(t *testing.T) {
	st, srv := newMultiTenantIntegrationServer(t)
	ctx := context.Background()

	// Tenant 1 template: one alert rule that new tenants must copy.
	if _, err := st.CreateAlertRule(ctx, store.AlertRule{
		TenantID:       1,
		Name:           "edr-malware",
		Enabled:        true,
		SeverityFilter: "HIGH",
		SourceFilter:   "edr",
		Channels:       []string{"webhook"},
	}); err != nil {
		t.Fatalf("seed tenant 1 alert rule: %v", err)
	}

	tenant2, err := st.CreateTenant(ctx, "Tenant Two", "tenant-two")
	if err != nil {
		t.Fatalf("create tenant 2: %v", err)
	}
	tenant3, err := st.CreateTenant(ctx, "Tenant Three", "tenant-three")
	if err != nil {
		t.Fatalf("create tenant 3: %v", err)
	}

	t.Run("tenant provisioning seeds rules/sla/report", func(t *testing.T) {
		rules, err := st.ListAlertRules(ctx, &tenant2.ID)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, rule := range rules {
			if rule.Name == "edr-malware" {
				found = true
			}
		}
		if !found {
			t.Fatalf("tenant 2 rules = %#v, want copied edr-malware", rules)
		}
		sla, err := st.ListSLAPolicies(ctx, &tenant2.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(sla) == 0 {
			t.Fatalf("tenant 2 SLA policies = %d, want seeded rows", len(sla))
		}
		tr, err := st.GetTenantReport(ctx, tenant2.ID)
		if err != nil {
			t.Fatalf("tenant 2 report row: %v", err)
		}
		if tr.TenantID != tenant2.ID {
			t.Fatalf("tenant report tenant_id = %d, want %d", tr.TenantID, tenant2.ID)
		}
	})

	_, tenant2Key, err := st.CreateAPIKey(ctx, "tenant2", &tenant2.ID, "integration")
	if err != nil {
		t.Fatalf("create tenant 2 key: %v", err)
	}
	_, tenant3Key, err := st.CreateAPIKey(ctx, "tenant3", &tenant3.ID, "integration")
	if err != nil {
		t.Fatalf("create tenant 3 key: %v", err)
	}
	_, globalDBKey, err := st.CreateAPIKey(ctx, "global-db", nil, "integration")
	if err != nil {
		t.Fatalf("create global DB key: %v", err)
	}

	now := time.Now().UTC()
	for _, a := range []*store.Agent{
		{ID: "agent-t2", Hostname: "host-t2", OSType: "linux", Arch: "amd64", Status: "online", TokenHash: "t2", LastSeen: now, CreatedAt: now, UpdatedAt: now},
		{ID: "agent-t3", Hostname: "host-t3", OSType: "linux", Arch: "amd64", Status: "online", TokenHash: "t3", LastSeen: now, CreatedAt: now, UpdatedAt: now},
	} {
		tenant := tenant2.ID
		if a.ID == "agent-t3" {
			tenant = tenant3.ID
		}
		if err := st.CreateAgent(ctx, a, tenant); err != nil {
			t.Fatalf("create agent %s: %v", a.ID, err)
		}
	}

	rc2, err := st.CreateRemoteCredential(ctx, tenant2.ID, "remote-2", "root", "password", "cipher", "", "", "integration")
	if err != nil {
		t.Fatalf("create remote credential 2: %v", err)
	}
	rc3, err := st.CreateRemoteCredential(ctx, tenant3.ID, "remote-3", "root", "password", "cipher", "", "", "integration")
	if err != nil {
		t.Fatalf("create remote credential 3: %v", err)
	}
	if _, err := st.CreateRemoteScanTasks(ctx, rc2.ID, []string{"10.0.0.2"}, "integration"); err != nil {
		t.Fatalf("create remote task 2: %v", err)
	}
	if _, err := st.CreateRemoteScanTasks(ctx, rc3.ID, []string{"10.0.0.3"}, "integration"); err != nil {
		t.Fatalf("create remote task 3: %v", err)
	}

	wc2, err := st.CreateWebDBCredential(ctx, tenant2.ID, "webdb-2", "app", "cipher", "integration")
	if err != nil {
		t.Fatalf("create webdb credential 2: %v", err)
	}
	wc3, err := st.CreateWebDBCredential(ctx, tenant3.ID, "webdb-3", "app", "cipher", "integration")
	if err != nil {
		t.Fatalf("create webdb credential 3: %v", err)
	}
	if _, err := st.CreateWebDBScanTasks(ctx, []store.WebDBTaskInput{
		{Kind: "web", Target: "https://t2.example", CredentialID: wc2.ID},
	}, "integration", tenant2.ID); err != nil {
		t.Fatalf("create webdb task 2: %v", err)
	}
	if _, err := st.CreateWebDBScanTasks(ctx, []store.WebDBTaskInput{
		{Kind: "web", Target: "https://t3.example", CredentialID: wc3.ID},
	}, "integration", tenant3.ID); err != nil {
		t.Fatalf("create webdb task 3: %v", err)
	}

	if _, err := st.CreateCloudAccount(ctx, tenant2.ID, "aws", "cloud-2", "acct-2", []string{"us-east-1"}, "cipher", 60, "integration"); err != nil {
		t.Fatalf("create cloud account 2: %v", err)
	}
	if _, err := st.CreateCloudAccount(ctx, tenant3.ID, "aws", "cloud-3", "acct-3", []string{"us-east-1"}, "cipher", 60, "integration"); err != nil {
		t.Fatalf("create cloud account 3: %v", err)
	}

	if _, err := st.CreateNetworkScanTask(ctx, "10.0.2.0/24", []int32{22}, "integration", tenant2.ID); err != nil {
		t.Fatalf("create network task 2: %v", err)
	}
	if _, err := st.CreateNetworkScanTask(ctx, "10.0.3.0/24", []int32{22}, "integration", tenant3.ID); err != nil {
		t.Fatalf("create network task 3: %v", err)
	}

	t.Run("tenant key allow/deny matrix", func(t *testing.T) {
		allowed := []struct{ method, path string }{
			{http.MethodGet, "/api/v1/agents"},
			{http.MethodGet, "/api/v1/remote/credentials"},
			{http.MethodGet, "/api/v1/remote/tasks"},
			{http.MethodGet, "/api/v1/webdb/credentials"},
			{http.MethodGet, "/api/v1/webdb/tasks"},
			{http.MethodGet, "/api/v1/cloud/accounts"},
			{http.MethodGet, "/api/v1/network/tasks"},
			{http.MethodGet, "/api/v1/alert-rules"},
			{http.MethodGet, "/api/v1/sla-policies"},
			{http.MethodGet, "/api/v1/tenants/2/report"},
		}
		for _, tc := range allowed {
			if rr := integrationRequest(t, srv, tc.method, tc.path, tenant2Key, ""); rr.Code != http.StatusOK {
				t.Errorf("%s %s = %d, want 200 (body %s)", tc.method, tc.path, rr.Code, rr.Body.String())
			}
		}
		forbidden := []struct{ method, path string }{
			{http.MethodGet, "/api/v1/tenants"},
			{http.MethodPost, "/api/v1/tenants"},
			{http.MethodGet, "/api/v1/users"},
			{http.MethodGet, "/api/v1/api-keys"},
			{http.MethodGet, "/api/v1/audit-logs"},
			{http.MethodGet, "/api/v1/audit-logs/export.csv"},
			{http.MethodGet, "/api/v1/workers"},
			{http.MethodPost, "/api/v1/admin/report/send"},
			{http.MethodGet, "/api/v1/tenants/3/report"},
			{http.MethodPut, "/api/v1/tenants/3/report"},
			{http.MethodPut, "/api/v1/agents/agent-t3/tenant"},
			{http.MethodPut, "/api/v1/users/1/tenant"},
		}
		for _, tc := range forbidden {
			if rr := integrationRequest(t, srv, tc.method, tc.path, tenant2Key, ""); rr.Code != http.StatusForbidden {
				t.Errorf("%s %s = %d, want 403 (body %s)", tc.method, tc.path, rr.Code, rr.Body.String())
			}
		}
	})

	t.Run("tenant scoped data lists", func(t *testing.T) {
		checks := []struct{ path, key string }{
			{"/api/v1/remote/credentials", "credentials"},
			{"/api/v1/remote/tasks", "tasks"},
			{"/api/v1/webdb/credentials", "credentials"},
			{"/api/v1/webdb/tasks", "tasks"},
			{"/api/v1/cloud/accounts", "accounts"},
			{"/api/v1/network/tasks", "tasks"},
			{"/api/v1/alert-rules", "rules"},
		}
		for _, tc := range checks {
			rr := integrationRequest(t, srv, http.MethodGet, tc.path, tenant2Key, "")
			if rr.Code != http.StatusOK {
				t.Fatalf("GET %s = %d (body %s)", tc.path, rr.Code, rr.Body.String())
			}
			body := integrationJSON(t, rr)
			if got := integrationListLen(body, tc.key); got != 1 {
				t.Errorf("GET %s %s count = %d, want 1", tc.path, tc.key, got)
			}
		}
	})

	t.Run("tenant report settings", func(t *testing.T) {
		rr := integrationRequest(t, srv, http.MethodPut, "/api/v1/tenants/2/report", tenant2Key,
			`{"enabled":true,"schedule":"0 9 * * *","timezone":"Local","to":["ops2@example.com"]}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("PUT tenant report = %d (body %s)", rr.Code, rr.Body.String())
		}
		body := integrationJSON(t, rr)
		if body["tenant_id"] != float64(tenant2.ID) || body["schedule"] != "0 9 * * *" {
			t.Fatalf("PUT tenant report response = %s", rr.Body.String())
		}
		rr = integrationRequest(t, srv, http.MethodGet, "/api/v1/tenants/2/report", tenant2Key, "")
		if rr.Code != http.StatusOK {
			t.Fatalf("GET tenant report = %d (body %s)", rr.Code, rr.Body.String())
		}
		body = integrationJSON(t, rr)
		if body["schedule"] != "0 9 * * *" {
			t.Fatalf("GET tenant report schedule = %v, want 0 9 * * *", body["schedule"])
		}
	})

	t.Run("edr high alert tenant isolation", func(t *testing.T) {
		rr := integrationRequest(t, srv, http.MethodPost, "/api/v1/edr/findings", tenant2Key,
			`{"agent_id":"agent-t2","source":"edr_api","finding_type":"malware","name":"eicar-t2","severity":"HIGH","path":"/tmp/eicar-t2","hash":"hash-t2","detail":"integration"}`)
		if rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
			t.Fatalf("report EDR t2 = %d (body %s)", rr.Code, rr.Body.String())
		}
		rr = integrationRequest(t, srv, http.MethodPost, "/api/v1/edr/findings", tenant3Key,
			`{"agent_id":"agent-t3","source":"edr_api","finding_type":"malware","name":"eicar-t3","severity":"HIGH","path":"/tmp/eicar-t3","hash":"hash-t3","detail":"integration"}`)
		if rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
			t.Fatalf("report EDR t3 = %d (body %s)", rr.Code, rr.Body.String())
		}

		var t2Alerts, t3Alerts int
		if err := st.Pool().QueryRow(ctx, `
			SELECT count(*) FROM alerts a JOIN agents ag ON ag.id = a.agent_id
			WHERE ag.tenant_id=$1`, tenant2.ID).Scan(&t2Alerts); err != nil {
			t.Fatal(err)
		}
		if err := st.Pool().QueryRow(ctx, `
			SELECT count(*) FROM alerts a JOIN agents ag ON ag.id = a.agent_id
			WHERE ag.tenant_id=$1`, tenant3.ID).Scan(&t3Alerts); err != nil {
			t.Fatal(err)
		}
		if t2Alerts != 1 || t3Alerts != 1 {
			t.Fatalf("alerts per tenant = %d/%d, want 1/1", t2Alerts, t3Alerts)
		}

		rr = integrationRequest(t, srv, http.MethodGet, "/api/v1/alerts", tenant2Key, "")
		if rr.Code != http.StatusOK {
			t.Fatalf("GET alerts t2 = %d (body %s)", rr.Code, rr.Body.String())
		}
		body := integrationJSON(t, rr)
		alerts, _ := body["alerts"].([]interface{})
		if len(alerts) != 1 {
			t.Fatalf("tenant 2 alert list count = %d, want 1 (body %s)", len(alerts), rr.Body.String())
		}
		first, ok := alerts[0].(map[string]interface{})
		if !ok || first["agent_id"] != "agent-t2" {
			t.Fatalf("tenant 2 alert agent_id = %v, want agent-t2", first["agent_id"])
		}
	})

	t.Run("audit export tenant filter", func(t *testing.T) {
		// Make sure tenant 3 has a write of its own before comparing exports.
		rr := integrationRequest(t, srv, http.MethodPut, "/api/v1/tenants/3/report", tenant3Key,
			`{"enabled":true,"schedule":"0 8 * * *","timezone":"Local","to":["ops3@example.com"]}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("PUT tenant 3 report = %d (body %s)", rr.Code, rr.Body.String())
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs/export.csv", nil)
		req.Header.Set("X-API-Key", "legacy-global-api-key")
		req.Header.Set("X-Tenant-ID", "2")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("export tenant 2 = %d (body %s)", rec.Code, rec.Body.String())
		}
		filtered, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if len(filtered) < 2 {
			t.Fatalf("filtered export rows = %d, want at least 1 data row", len(filtered))
		}
		for _, row := range filtered[1:] {
			if row[9] != "2" {
				t.Fatalf("filtered export row tenant_id = %q, want 2: %v", row[9], row)
			}
		}

		req = httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs/export.csv", nil)
		req.Header.Set("X-API-Key", "legacy-global-api-key")
		rec = httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("export all = %d (body %s)", rec.Code, rec.Body.String())
		}
		all, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if len(all) <= len(filtered) {
			t.Fatalf("full export rows = %d, filtered = %d; want full > filtered", len(all), len(filtered))
		}
	})

	t.Run("global keys unchanged and tenant key revocation", func(t *testing.T) {
		for _, key := range []string{globalDBKey, "legacy-global-api-key"} {
			for _, path := range []string{"/api/v1/tenants", "/api/v1/api-keys", "/api/v1/audit-logs"} {
				if rr := integrationRequest(t, srv, http.MethodGet, path, key, ""); rr.Code != http.StatusOK {
					t.Errorf("global key GET %s = %d, want 200 (body %s)", path, rr.Code, rr.Body.String())
				}
			}
			if rr := integrationRequest(t, srv, http.MethodGet, "/api/v1/tenants/3/report", key, ""); rr.Code != http.StatusOK {
				t.Errorf("global key other-tenant report = %d, want 200 (body %s)", rr.Code, rr.Body.String())
			}
		}

		ephemeral, plain, err := st.CreateAPIKey(ctx, "ephemeral-tenant2", &tenant2.ID, "integration")
		if err != nil {
			t.Fatal(err)
		}
		if err := st.RevokeAPIKey(ctx, ephemeral.ID); err != nil {
			t.Fatal(err)
		}
		if rr := integrationRequest(t, srv, http.MethodGet, "/api/v1/agents", plain, ""); rr.Code != http.StatusUnauthorized {
			t.Fatalf("revoked tenant key GET /agents = %d, want 401 (body %s)", rr.Code, rr.Body.String())
		}
	})
}
