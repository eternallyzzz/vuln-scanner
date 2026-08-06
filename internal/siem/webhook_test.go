package siem

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebhookSenderBatch(t *testing.T) {
	t.Setenv("SIEM_WEBHOOK_SECRET", "hush")
	var gotSig string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-VulnScanner-Signature")
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &gotBody)
		mac := hmac.New(sha256.New, []byte("hush"))
		mac.Write(raw)
		want := hex.EncodeToString(mac.Sum(nil))
		if gotSig != want {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.SplunkHEC.URL = ""
	cfg.Webhook.URL = srv.URL
	cfg.Webhook.SecretEnv = "SIEM_WEBHOOK_SECRET"
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = svc.SendBatch(context.Background(), []Event{
		{ID: "alert.created:1:open", EventType: "alert.created",
			OccurredAt: time.Unix(1700000000, 0), Payload: json.RawMessage(`{"alert_id":1}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	events := gotBody["events"].([]interface{})
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	ev := events[0].(map[string]interface{})
	if ev["event_id"] != "alert.created:1:open" || ev["event_type"] != "alert.created" ||
		ev["version"] != "1" {
		t.Fatalf("unexpected event: %#v", ev)
	}
}

func TestWebhookSenderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.SplunkHEC.URL = ""
	cfg.Webhook.URL = srv.URL
	cfg.Webhook.SecretEnv = ""
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = svc.SendBatch(context.Background(), []Event{{ID: "e1", EventType: "alert.created", OccurredAt: time.Now(), Payload: json.RawMessage(`{}`)}})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("SendBatch() = %v, want 500 error", err)
	}
}
