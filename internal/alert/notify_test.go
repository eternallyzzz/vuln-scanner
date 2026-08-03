package alert

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSignBody(t *testing.T) {
	body := []byte(`{"type":"test"}`)
	got := signBody("secret", body)
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Fatalf("signature mismatch: %s != %s", got, want)
	}
}

func TestWebhookNotifierValidatesURL(t *testing.T) {
	if _, err := NewWebhookNotifier("ftp://example.com/hook", ""); err == nil {
		t.Fatal("ftp scheme must be rejected")
	}
	if _, err := NewWebhookNotifier("https://example.com/hook", "s"); err != nil {
		t.Fatalf("https url must be accepted: %v", err)
	}
}

func TestWebhookNotifierSendsSignedPayload(t *testing.T) {
	var received map[string]interface{}
	var sig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig = r.Header.Get("X-VulnScanner-Signature")
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	n, err := NewWebhookNotifier(srv.URL, "hush")
	if err != nil {
		t.Fatal(err)
	}
	payload := Payload{
		Type:       "test",
		AlertID:    7,
		Severity:   "HIGH",
		DetectedAt: time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
	}
	if err := n.Send(httptest.NewRequest(http.MethodPost, "/", nil).Context(), payload); err != nil {
		t.Fatal(err)
	}
	if sig == "" {
		t.Fatal("signature header missing")
	}
	body, _ := json.Marshal(payload)
	if sig != signBody("hush", body) {
		t.Fatal("signature header mismatch")
	}
	if received["alert_id"] != float64(7) || received["severity"] != "HIGH" {
		t.Fatalf("unexpected payload: %v", received)
	}
}

func TestWebhookNotifierNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	n, _ := NewWebhookNotifier(srv.URL, "")
	if err := n.Send(httptest.NewRequest(http.MethodPost, "/", nil).Context(), Payload{}); err == nil {
		t.Fatal("5xx must be an error")
	}
}
