package patch

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	catalogSearchURL = "https://www.catalog.update.microsoft.com/Search.aspx?q="
	catalogDialogURL = "https://www.catalog.update.microsoft.com/DownloadDialog.aspx"
	catalogUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

var (
	catalogRowRe         = regexp.MustCompile(`(?is)<tr id="([0-9a-fA-F-]{36})_R0".*?</tr>`)
	catalogTitleRe       = regexp.MustCompile(`(?is)onclick='goToDetails\("[0-9a-fA-F-]{36}"\);'[^>]*>(.*?)</a>`)
	downloadURLLineRe    = regexp.MustCompile(`(?m)downloadInformation\[\d+\]\.files\[\d+\]\.url\s*=\s*'([^']+)'`)
	downloadDigestLineRe = regexp.MustCompile(`(?m)downloadInformation\[\d+\]\.files\[\d+\]\.digest\s*=\s*'([^']*)'`)
)

// DownloadInfo is a resolved direct .msu download for one KB article.
type DownloadInfo struct {
	Title  string
	URL    string
	SHA256 string
}

// CatalogEntry is one search result row of the Microsoft Update Catalog.
type CatalogEntry struct {
	GUID  string
	Title string
}

// CatalogResolver resolves KB articles to direct .msu download URLs through
// the Microsoft Update Catalog, with an in-memory 24h cache.
type CatalogResolver struct {
	http  *http.Client
	mu    sync.Mutex
	cache map[string]cachedDownload
}

type cachedDownload struct {
	info DownloadInfo
	at   time.Time
}

func NewCatalogResolver() *CatalogResolver {
	return &CatalogResolver{
		http: &http.Client{
			Timeout: 20 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		cache: make(map[string]cachedDownload),
	}
}

// Resolve returns the direct download for the KB, preferring an entry that
// matches the agent OS family and architecture (x64 default).
func (r *CatalogResolver) Resolve(ctx context.Context, kb, osType, arch string) (DownloadInfo, error) {
	if catalogKBNumber(kb) == 0 {
		return DownloadInfo{}, errors.New("invalid kb article")
	}
	r.mu.Lock()
	if c, ok := r.cache[kb]; ok && time.Since(c.at) < 24*time.Hour {
		r.mu.Unlock()
		return c.info, nil
	}
	r.mu.Unlock()

	info, err := r.resolve(ctx, kb, osType, arch)
	if err != nil {
		return DownloadInfo{}, err
	}
	r.mu.Lock()
	r.cache[kb] = cachedDownload{info: info, at: time.Now()}
	r.mu.Unlock()
	return info, nil
}

func (r *CatalogResolver) resolve(ctx context.Context, kb, osType, arch string) (DownloadInfo, error) {
	searchURL := catalogSearchURL + url.QueryEscape(kb)
	searchBody, err := r.getWithRetry(ctx, searchURL)
	if err != nil {
		return DownloadInfo{}, fmt.Errorf("catalog search: %w", err)
	}
	entries := parseCatalogSearchResults(searchBody)
	if len(entries) == 0 {
		return DownloadInfo{}, fmt.Errorf("catalog: no results for %s", kb)
	}
	entry := selectCatalogEntry(entries, osType, arch)
	if entry.GUID == "" {
		return DownloadInfo{}, fmt.Errorf("catalog: no %s/%s entry for %s", osType, arch, kb)
	}

	payload := `updateIDs=[{"size":0,"languages":"","uidInfo":"` + entry.GUID +
		`","updateID":"` + entry.GUID + `"}]`
	dialogBody, err := r.postWithRetry(ctx, catalogDialogURL, payload, searchURL)
	if err != nil {
		return DownloadInfo{}, fmt.Errorf("catalog download dialog: %w", err)
	}
	dlURL, digest := parseCatalogDownloadInfo(dialogBody)
	if dlURL == "" {
		return DownloadInfo{}, fmt.Errorf("catalog: no download link for %s", kb)
	}
	return DownloadInfo{Title: entry.Title, URL: dlURL, SHA256: digest}, nil
}

func (r *CatalogResolver) getWithRetry(ctx context.Context, target string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", catalogUserAgent)
		resp, err := r.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("http %d", resp.StatusCode)
			continue
		}
		return string(body), nil
	}
	return "", lastErr
}

func (r *CatalogResolver) postWithRetry(ctx context.Context, target, body, referer string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(body))
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", catalogUserAgent)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Referer", referer)
		resp, err := r.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("http %d", resp.StatusCode)
			continue
		}
		return string(data), nil
	}
	return "", lastErr
}

// parseCatalogSearchResults extracts update GUIDs and titles from the
// server-rendered search result table.
func parseCatalogSearchResults(page string) []CatalogEntry {
	var out []CatalogEntry
	for _, row := range catalogRowRe.FindAllStringSubmatch(page, -1) {
		guid := row[1]
		m := catalogTitleRe.FindStringSubmatch(row[0])
		if len(m) < 2 {
			continue
		}
		title := strings.TrimSpace(html.UnescapeString(m[1]))
		if title == "" {
			continue
		}
		out = append(out, CatalogEntry{GUID: guid, Title: title})
	}
	return out
}

// selectCatalogEntry picks the search result that matches the agent OS
// family and architecture. With unknown OS it accepts any Windows entry;
// x64 is the default architecture.
func selectCatalogEntry(entries []CatalogEntry, osType, arch string) CatalogEntry {
	family := ""
	lowerOS := strings.ToLower(osType)
	switch {
	case strings.Contains(lowerOS, "windows 11"):
		family = "windows 11"
	case strings.Contains(lowerOS, "windows 10"):
		family = "windows 10"
	case strings.Contains(lowerOS, "server"):
		family = "server"
	}
	archTok := "x64"
	if strings.Contains(strings.ToLower(arch), "arm") {
		archTok = "arm64"
	}

	best := CatalogEntry{}
	bestScore := -1
	for _, e := range entries {
		title := strings.ToLower(e.Title)
		score := 0
		if strings.Contains(title, "windows") {
			score++
		}
		if family != "" && strings.Contains(title, family) {
			score += 2
		}
		if strings.Contains(title, archTok) {
			score += 2
		}
		if score > bestScore {
			bestScore = score
			best = e
		}
	}
	return best
}

// parseCatalogDownloadInfo extracts the first direct .msu URL and its digest
// from the DownloadDialog response.
func parseCatalogDownloadInfo(page string) (downloadURL, digest string) {
	urls := downloadURLLineRe.FindAllStringSubmatch(page, -1)
	for _, m := range urls {
		u := strings.TrimSpace(m[1])
		if strings.HasSuffix(strings.ToLower(u), ".msu") {
			downloadURL = u
			break
		}
	}
	if d := downloadDigestLineRe.FindStringSubmatch(page); len(d) >= 2 {
		digest = strings.TrimSpace(d[1])
	}
	return downloadURL, digest
}

func catalogKBNumber(kb string) int {
	n := 0
	for _, c := range kb {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}
