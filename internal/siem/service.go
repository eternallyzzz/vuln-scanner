package siem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Event is one outbound SIEM event. ID is the dedupe key assigned by the
// outbox so downstream consumers can discard retried duplicates.
type Event struct {
	ID         string          `json:"event_id"`
	EventType  string          `json:"event_type"`
	OccurredAt time.Time       `json:"occurred_at"`
	Payload    json.RawMessage `json:"payload"`
}

// Envelope returns the versioned event object sent to every target.
func (e Event) Envelope() map[string]interface{} {
	return map[string]interface{}{
		"event_id":    e.ID,
		"event_type":  e.EventType,
		"occurred_at": e.OccurredAt.UTC().Format(time.RFC3339),
		"version":     "1",
		"payload":     e.Payload,
	}
}

// Sender posts a batch of events to one external target.
type Sender interface {
	Name() string
	Send(ctx context.Context, events []Event) error
}

// Service fans a batch out to every configured target.
type Service struct {
	cfg     *Config
	client  *http.Client
	senders []Sender
}

// NewService validates the config and builds the target senders.
func NewService(cfg *Config) (*Service, error) {
	cfg = cfg.Normalized()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	s := &Service{cfg: cfg, client: newHTTPClient(cfg)}
	if cfg.SplunkHEC != nil && cfg.SplunkHEC.URL != "" {
		s.senders = append(s.senders, &splunkSender{
			cfg: cfg.SplunkHEC, token: cfg.HECToken(), client: s.client,
		})
	}
	if cfg.Webhook != nil && cfg.Webhook.URL != "" {
		s.senders = append(s.senders, &webhookSender{
			url: cfg.Webhook.URL, secret: cfg.WebhookSecret(), client: s.client,
		})
	}
	if len(s.senders) == 0 {
		return nil, fmt.Errorf("siem enabled but no target configured")
	}
	return s, nil
}

// Enabled reports whether the event stream is active.
func (s *Service) Enabled() bool {
	return s != nil && s.cfg != nil && s.cfg.Enabled
}

// Config exposes the normalized configuration for logging.
func (s *Service) Config() *Config {
	if s == nil {
		return nil
	}
	return s.cfg
}

// SendBatch sends the events to every configured target. A failure in any
// target fails the whole batch so the outbox can retry.
func (s *Service) SendBatch(ctx context.Context, events []Event) error {
	if !s.Enabled() || len(events) == 0 {
		return nil
	}
	for _, sender := range s.senders {
		if err := sender.Send(ctx, events); err != nil {
			return fmt.Errorf("%s: %w", sender.Name(), err)
		}
	}
	return nil
}

func newHTTPClient(cfg *Config) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify}
	return &http.Client{Timeout: cfg.Timeout(), Transport: transport}
}

func doPOST(ctx context.Context, client *http.Client, url, auth string, body []byte) error {
	return doPOSTHeaders(ctx, client, url, auth, "", body)
}

func doPOSTHeaders(ctx context.Context, client *http.Client, url, auth, signSecret string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vuln-scanner-siem/1.0")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if signSecret != "" {
		req.Header.Set("X-VulnScanner-Signature", signBody(signSecret, body))
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s returned %s: %s", url, resp.Status, string(snippet))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func signBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
