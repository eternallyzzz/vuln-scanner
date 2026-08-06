package ticket

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AlertInfo is the alert payload used to create a ticket.
type AlertInfo struct {
	AlertID       int64
	RuleName      string
	AgentID       string
	AgentHostname string
	CVEID         string
	AssetName     string
	Severity      string
	CVSS          float64
	Source        string
	DetectedAt    time.Time
}

// TicketRef identifies a created ticket in the external system.
type TicketRef struct {
	Provider string `json:"provider"`
	Key      string `json:"key"`
	URL      string `json:"url"`
}

// provider abstracts one external ticketing backend.
type provider interface {
	create(ctx context.Context, in AlertInfo) (TicketRef, error)
	syncStatus(ctx context.Context, ref TicketRef, status string) error
}

// Service creates and syncs tickets through the configured provider.
type Service struct {
	cfg      *Config
	client   *http.Client
	provider provider
}

// NewService validates the config and builds the provider client.
func NewService(cfg *Config) (*Service, error) {
	cfg = cfg.Normalized()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	s := &Service{cfg: cfg, client: newHTTPClient(cfg)}
	switch cfg.Provider {
	case "jira":
		s.provider = &jiraClient{cfg: cfg, client: s.client}
	case "servicenow":
		s.provider = &serviceNowClient{cfg: cfg, client: s.client}
	default:
		return nil, fmt.Errorf("unsupported ticket provider %q", cfg.Provider)
	}
	return s, nil
}

// Enabled reports whether ticket integration is active.
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

// Create creates a ticket for the alert and returns its external reference.
func (s *Service) Create(ctx context.Context, in AlertInfo) (TicketRef, error) {
	if !s.Enabled() {
		return TicketRef{}, fmt.Errorf("ticketing is disabled")
	}
	return s.provider.create(ctx, in)
}

// Sync updates an existing ticket to match the local alert status
// (ack or resolved).
func (s *Service) Sync(ctx context.Context, ref TicketRef, status string) error {
	if !s.Enabled() {
		return fmt.Errorf("ticketing is disabled")
	}
	return s.provider.syncStatus(ctx, ref, status)
}

func newHTTPClient(cfg *Config) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify}
	return &http.Client{Timeout: cfg.Timeout(), Transport: transport}
}

func basicAuthHeader(cfg *Config) string {
	token := base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password()))
	return "Basic " + token
}

func doJSON(ctx context.Context, client *http.Client, method, url, auth string, body, out interface{}) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vuln-scanner-ticket/1.0")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s returned %s: %s", method, url, resp.Status, string(snippet))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
