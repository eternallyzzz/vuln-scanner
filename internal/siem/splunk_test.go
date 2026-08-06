package siem

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSplunkHECSenderBatch(t *testing.T) {
	t.Setenv("SIEM_SPLUNK_HEC_TOKEN", "hec-token")
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		raw := make([]byte, r.ContentLength)
		r.Body.Read(raw)
		gotBody = string(raw)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.SplunkHEC.URL = srv.URL
	cfg.SplunkHEC.Index = "vulnscan"
	cfg.SplunkHEC.SourceType = "vulnscan:events"
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	events := []Event{
		{ID: "alert.created:1:open", EventType: "alert.created",
			OccurredAt: time.Unix(1700000000, 0), Payload: json.RawMessage(`{"alert_id":1}`)},
		{ID: "patch_task.approved:2:approved", EventType: "patch_task.approved",
			OccurredAt: time.Unix(1700000001, 0), Payload: json.RawMessage(`{"task_id":2}`)},
	}
	if err := svc.SendBatch(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Splunk hec-token" {
		t.Fatalf("auth = %q", gotAuth)
	}
	scanner := bufio.NewScanner(strings.NewReader(gotBody))
	lines := 0
	for scanner.Scan() {
		lines++
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var line map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			t.Fatalf("bad NDJSON line: %v", err)
		}
		if line["index"] != "vulnscan" || line["sourcetype"] != "vulnscan:events" ||
			line["source"] != "vuln-scanner" {
			t.Fatalf("unexpected envelope: %#v", line)
		}
		event := line["event"].(map[string]interface{})
		if event["version"] != "1" || event["event_type"] == "" {
			t.Fatalf("unexpected event envelope: %#v", event)
		}
	}
	if lines != 2 {
		t.Fatalf("lines = %d, want 2", lines)
	}
}

func TestSplunkHECSenderError(t *testing.T) {
	t.Setenv("SIEM_SPLUNK_HEC_TOKEN", "hec-token")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"text":"invalid token"}`))
	}))
	defer srv.Close()
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.SplunkHEC.URL = srv.URL
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = svc.SendBatch(context.Background(), []Event{{ID: "e1", EventType: "alert.created", OccurredAt: time.Now(), Payload: json.RawMessage(`{}`)}})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("SendBatch() = %v, want 401 error", err)
	}
}
