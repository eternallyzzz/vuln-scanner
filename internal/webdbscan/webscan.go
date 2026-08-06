package webdbscan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxWebBodyBytes = 1 << 20 // 1 MiB

// ScanWeb fingerprints one HTTP(S) application root URL. Optional
// credentials are used for Basic Auth. The response body is read up to a
// limit and never stored; only extracted signals and products are returned.
func ScanWeb(ctx context.Context, rawTarget string, cred *Credential, cfg Config) (WebResult, error) {
	target, err := NormalizeWebTarget(rawTarget)
	if err != nil {
		return WebResult{}, err
	}
	timeout := cfg.Timeout()
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	redirects := 0
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.TLSInsecureSkipVerify},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirects = len(via)
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return WebResult{}, err
	}
	req.Header.Set("User-Agent", "vuln-scanner-webdb/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	if cred != nil && (cred.Username != "" || cred.Password != "") {
		req.SetBasicAuth(cred.Username, cred.Password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return WebResult{}, fmt.Errorf("web request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxWebBodyBytes))
	if err != nil {
		return WebResult{}, fmt.Errorf("read web response: %w", err)
	}

	title := extractTitle(string(body))
	generator := extractMetaGenerator(string(body))
	if generator == "" {
		generator = strings.TrimSpace(resp.Header.Get("X-Generator"))
	}
	finalURL := target
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	result := WebResult{
		URL:        finalURL,
		StatusCode: resp.StatusCode,
		Title:      title,
		Server:     resp.Header.Get("Server"),
		XPoweredBy: resp.Header.Get("X-Powered-By"),
		Generator:  generator,
		Redirects:  redirects,
	}
	result.Products = FingerprintWeb(WebFingerprintInput{
		Server:        result.Server,
		XPoweredBy:    result.XPoweredBy,
		XGenerator:    resp.Header.Get("X-Generator"),
		Title:         title,
		MetaGenerator: generator,
		Body:          string(body),
	})
	return result, nil
}
