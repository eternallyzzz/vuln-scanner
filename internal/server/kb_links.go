package server

import (
	"context"
	"html"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"vuln-scanner/internal/store"
)

var kbLinkHTTP = &http.Client{
	Timeout: 20 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

var (
	titleRe        = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	notFoundMarker = regexp.MustCompile(`(?i)not found|could not be found|查无此项|doesn'?t exist|page cannot be found|error 404|此页不存在`)
)

// validateKBLinks verifies support.microsoft.com help pages with a content
// check (GET + KB number in title/body), not just an HTTP status. Active
// recommendation KBs are checked first, then the table is processed in
// bounded concurrent batches.
func validateKBLinks(ctx context.Context, st *store.Store) {
	// Pass 1: KBs referenced by active recommendations, so the links users
	// actually see get verified first.
	if kbs, err := st.ActiveKBArticles(ctx); err == nil && len(kbs) > 0 {
		meta, err := st.GetKBMetadataMap(ctx, kbs)
		if err == nil {
			var metas []store.KBMetadata
			for _, kb := range kbs {
				m := meta[kb]
				if m.SupportURL != "" && m.Status != "ok" {
					metas = append(metas, m)
				}
			}
			validateBatch(ctx, st, metas)
		}
	}

	// Pass 2: bounded background sweep of the whole table (50 rows per batch,
	// up to 1000 per call, 5 concurrent requests).
	const batchSize = 50
	const maxBatches = 20
	for b := 0; b < maxBatches; b++ {
		rows, err := st.ListKBMetadataForValidation(ctx, batchSize)
		if err != nil {
			slog.Warn("kb link validation: list failed", "error", err)
			return
		}
		if len(rows) == 0 {
			return
		}
		var metas []store.KBMetadata
		for _, m := range rows {
			if m.SupportURL == "" || m.Status == "ok" {
				continue
			}
			if m.Status == "broken" && m.VerifiedAt != nil &&
				time.Since(*m.VerifiedAt) < 7*24*time.Hour {
				continue
			}
			metas = append(metas, m)
		}
		if len(metas) == 0 {
			return
		}
		validateBatch(ctx, st, metas)
	}
}

// validateBatch content-checks a batch of support URLs concurrently and
// records ok/broken per KB.
func validateBatch(ctx context.Context, st *store.Store, metas []store.KBMetadata) {
	if len(metas) == 0 {
		return
	}
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make(map[string]string, len(metas))
	for _, m := range metas {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(m store.KBMetadata) {
			defer wg.Done()
			defer func() { <-sem }()
			status := "broken"
			if supportPageValid(ctx, m.SupportURL, kbNumber(m.KB)) {
				status = "ok"
			}
			mu.Lock()
			results[m.KB] = status
			mu.Unlock()
		}(m)
	}
	wg.Wait()
	for kb, status := range results {
		if err := st.UpdateKBMetadataStatus(ctx, kb, status); err != nil {
			slog.Warn("kb link validation: update failed", "kb", kb, "error", err)
		}
	}
	if len(results) > 0 {
		slog.Info("kb link validation completed", "checked", len(results))
	}
}

// supportPageValid fetches the support page and requires the KB number to
// appear in the page title or body. A 200 status alone is not trusted:
// support.microsoft.com serves an unrelated fallback article for unknown KBs.
func supportPageValid(ctx context.Context, url string, kbNum int) bool {
	if kbNum <= 0 {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", browserUA)
	resp, err := kbLinkHTTP.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return false
	}
	return supportPageHasKB(extractTitle(string(body)), string(body), kbNum)
}

// supportPageHasKB is the pure content rule: the KB number must appear in the
// page title (primary signal) or in the body, and a not-found title vetoes
// the result even if the number appears somewhere in the HTML noise.
func supportPageHasKB(title, body string, kbNum int) bool {
	if kbNum <= 0 {
		return false
	}
	title = html.UnescapeString(title)
	body = html.UnescapeString(body)
	re := regexp.MustCompile(`(?i)KB\s*` + strconv.Itoa(kbNum))
	if re.MatchString(title) {
		return true
	}
	if notFoundMarker.MatchString(title) {
		return false
	}
	return re.MatchString(body)
}

func extractTitle(raw string) string {
	m := titleRe.FindStringSubmatch(raw)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// kbNumber extracts the numeric part of a KB article identifier.
func kbNumber(kb string) int {
	n := 0
	for _, c := range kb {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}
