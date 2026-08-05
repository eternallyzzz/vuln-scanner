package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/smtp"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Payload struct {
	Type          string    `json:"type"`
	AlertID       int64     `json:"alert_id,omitempty"`
	RuleName      string    `json:"rule_name,omitempty"`
	AgentID       string    `json:"agent_id,omitempty"`
	AgentHostname string    `json:"agent_hostname,omitempty"`
	CVEID         string    `json:"cve_id,omitempty"`
	AssetName     string    `json:"asset_name,omitempty"`
	Severity      string    `json:"severity,omitempty"`
	CVSSScore     float64   `json:"cvss_score,omitempty"`
	Source        string    `json:"source,omitempty"`
	DetectedAt    time.Time `json:"detected_at,omitempty"`
}

type Notifier interface {
	Name() string
	Send(ctx context.Context, p Payload) error
}

// Attachment is one binary file attached to a report email.
type Attachment struct {
	Name        string
	ContentType string
	Data        []byte
}

func signBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

type WebhookNotifier struct {
	url    string
	secret string
	client *http.Client
}

func NewWebhookNotifier(rawURL, secret string) (*WebhookNotifier, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook url: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("webhook url scheme must be http(s)")
	}
	return &WebhookNotifier{
		url:    rawURL,
		secret: secret,
		client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (n *WebhookNotifier) Name() string { return "webhook" }

func (n *WebhookNotifier) Send(ctx context.Context, p Payload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vuln-scanner-alert/1.0")
	if n.secret != "" {
		req.Header.Set("X-VulnScanner-Signature", signBody(n.secret, body))
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

type SMTPNotifier struct {
	cfg *SMTPConfig
}

func NewSMTPNotifier(cfg *SMTPConfig) *SMTPNotifier {
	return &SMTPNotifier{cfg: cfg}
}

func (n *SMTPNotifier) Name() string { return "smtp" }

func (n *SMTPNotifier) Send(ctx context.Context, p Payload) error {
	subject := fmt.Sprintf("[VulnScanner] %s alert: %s on %s", p.Severity, p.CVEID, p.AssetName)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Severity: %s\n", p.Severity))
	b.WriteString(fmt.Sprintf("CVSS: %.1f\n", p.CVSSScore))
	b.WriteString(fmt.Sprintf("CVE: %s\n", p.CVEID))
	b.WriteString(fmt.Sprintf("Asset: %s\n", p.AssetName))
	b.WriteString(fmt.Sprintf("Agent: %s (%s)\n", p.AgentID, p.AgentHostname))
	b.WriteString(fmt.Sprintf("Source: %s\n", p.Source))
	b.WriteString(fmt.Sprintf("Detected: %s\n", p.DetectedAt.Format(time.RFC3339)))
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		n.cfg.From, strings.Join(n.cfg.To, ","), subject, b.String())
	return n.sendMessage(n.cfg.To, []byte(msg))
}

// SendMail delivers an HTML email with optional file attachments to a
// caller-supplied recipient list, reusing the notifier's SMTP connection
// settings.
func (n *SMTPNotifier) SendMail(ctx context.Context, subject, htmlBody string, to []string, attachments []Attachment) error {
	return n.sendMessage(to, buildMailMessage(n.cfg.From, subject, htmlBody, to, attachments))
}

func buildMailMessage(from, subject, htmlBody string, to []string, attachments []Attachment) []byte {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	htmlHdr := textproto.MIMEHeader{}
	htmlHdr.Set("Content-Type", "text/html; charset=UTF-8")
	htmlHdr.Set("Content-Transfer-Encoding", "base64")
	htmlPart, _ := writer.CreatePart(htmlHdr)
	_, _ = htmlPart.Write([]byte(encodeBase64Wrapped([]byte(htmlBody))))

	for _, a := range attachments {
		ct := a.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		hdr := textproto.MIMEHeader{}
		hdr.Set("Content-Type", ct)
		hdr.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, a.Name))
		hdr.Set("Content-Transfer-Encoding", "base64")
		part, _ := writer.CreatePart(hdr)
		_, _ = part.Write([]byte(encodeBase64Wrapped(a.Data)))
	}
	_ = writer.Close()

	return []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%s\r\n\r\n%s",
		from, strings.Join(to, ","), subject, writer.Boundary(), body.String()))
}

func encodeBase64Wrapped(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		if i > 0 {
			b.WriteString("\r\n")
		}
		b.WriteString(encoded[i:end])
	}
	return b.String()
}

func (n *SMTPNotifier) sendMessage(to []string, msg []byte) error {
	addr := net.JoinHostPort(n.cfg.Host, strconv.Itoa(n.cfg.Port))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	client, err := smtp.NewClient(conn, n.cfg.Host)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.StartTLS(&tls.Config{
		ServerName:         n.cfg.Host,
		InsecureSkipVerify: n.cfg.InsecureSkipVerify,
	}); err != nil {
		return fmt.Errorf("smtp starttls: %w", err)
	}

	if n.cfg.User != "" {
		password := os.Getenv(n.cfg.PasswordEnv)
		auth := smtp.PlainAuth("", n.cfg.User, password, n.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := client.Mail(n.cfg.From); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp rcpt %s: %w", rcpt, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close: %w", err)
	}
	return client.Quit()
}
