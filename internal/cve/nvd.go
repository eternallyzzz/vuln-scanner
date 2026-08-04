package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
)

var nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type NVDClient struct {
	http    *http.Client
	apiKey  string
	rateMu  sync.Mutex
	lastReq time.Time
	minGap  time.Duration
}

func NewNVDClient(apiKey ...string) *NVDClient {
	key := ""
	if len(apiKey) > 0 {
		key = apiKey[0]
	}
	if key == "" {
		key = os.Getenv("NVD_API_KEY")
	}
	c := &NVDClient{
		http:   &http.Client{Timeout: 60 * time.Second},
		apiKey: key,
		minGap: 1200 * time.Millisecond,
	}
	if c.apiKey != "" {
		c.minGap = 600 * time.Millisecond
	}
	return c
}

func (c *NVDClient) waitRateLimit() {
	c.rateMu.Lock()
	defer c.rateMu.Unlock()
	elapsed := time.Since(c.lastReq)
	if elapsed < c.minGap {
		time.Sleep(c.minGap - elapsed)
	}
	c.lastReq = time.Now()
}

func (c *NVDClient) SearchByKeyword(ctx context.Context, keyword string) ([]FeedEntry, error) {
	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("resultsPerPage", "50")
	return c.fetchAllPages(ctx, params)
}

// SearchByKeywordSince returns only CVEs modified since the given time. It is
// used for incremental refreshes after the first full keyword load.
func (c *NVDClient) SearchByKeywordSince(ctx context.Context, keyword string, since time.Time) ([]FeedEntry, error) {
	if since.IsZero() {
		since = time.Now().Add(-24 * time.Hour)
	}
	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("resultsPerPage", "50")
	params.Set("lastModStartDate", since.UTC().Format(time.RFC3339))
	params.Set("lastModEndDate", time.Now().UTC().Format(time.RFC3339))
	return c.fetchAllPages(ctx, params)
}

func (c *NVDClient) fetchAllPages(ctx context.Context, params url.Values) ([]FeedEntry, error) {
	var all []FeedEntry
	startIndex := 0
	maxPages := 5

	for {
		if startIndex > 0 {
			params.Set("startIndex", fmt.Sprintf("%d", startIndex))
		}
		url := nvdBaseURL + "?" + params.Encode()
		entries, total, err := c.doRequest(ctx, url)
		if err != nil {
			return all, err
		}
		all = append(all, entries...)
		if len(all) >= total || total == 0 || len(entries) < 50 {
			break
		}
		startIndex += len(entries)
		maxPages--
		if maxPages <= 0 {
			break
		}
	}
	return all, nil
}

func (c *NVDClient) doRequest(ctx context.Context, reqURL string) ([]FeedEntry, int, error) {
	c.waitRateLimit()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("nvd query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 || resp.StatusCode == 403 {
		c.rateMu.Lock()
		c.minGap = c.minGap * 2
		c.rateMu.Unlock()
		slog.Warn("nvd rate limited", "status", resp.StatusCode, "gap", c.minGap)
		return nil, 0, fmt.Errorf("nvd rate limited: status %d", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		slog.Warn("nvd non-200", "status", resp.StatusCode, "url", reqURL[:min(len(reqURL), 120)])
		return nil, 0, fmt.Errorf("nvd status %d: %s", resp.StatusCode, reqURL[:min(len(reqURL), 120)])
	}

	var result NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, 0, fmt.Errorf("nvd decode: %w", err)
	}

	now := time.Now().UTC()
	var entries []FeedEntry
	for _, nvdVuln := range result.Vulnerabilities {
		entry := c.convertToFeedEntry(nvdVuln, now)
		if entry != nil {
			entries = append(entries, *entry)
		}
	}
	return entries, result.TotalResults, nil
}

func (c *NVDClient) convertToFeedEntry(vuln NVDVuln, now time.Time) *FeedEntry {
	cve := vuln.CVE
	if cve.ID == "" {
		return nil
	}

	description := ""
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			description = d.Value
			break
		}
	}

	score, severity := c.extractCVSS(cve.Metrics)
	affected := c.extractAffectedProducts(cve)
	if len(affected) == 0 {
		affected = []AffectedProduct{}
	}
	affectedJSON, _ := json.Marshal(affected)

	pubTime := now
	if cve.Published != "" {
		if t, err := time.Parse(time.RFC3339, cve.Published); err == nil {
			pubTime = t
		}
	}

	return &FeedEntry{
		Source:      "nvd",
		SourceKey:   cve.ID,
		CVEID:       cve.ID,
		CVEURL:      "https://nvd.nist.gov/vuln/detail/" + cve.ID,
		Affected:    affectedJSON,
		FixedVer:    firstFixedVersion(affected),
		Severity:    severity,
		CVSSScore:   score,
		Summary:     description,
		PublishedAt: pubTime,
		FetchedAt:   now,
		TTLSeconds:  7 * 24 * 3600,
	}
}

func (c *NVDClient) extractAffectedProducts(cve NVDCVE) []AffectedProduct {
	var products []AffectedProduct
	seen := make(map[string]bool)

	walkNodes(cve.Configurations, func(cpe NVDCPE) {
		if !cpe.Vulnerable {
			return
		}
		name, vendor := extractFromCPE(cpe.Criteria)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		ap := AffectedProduct{
			Name:   name,
			Vendor: vendor,
			CPE:    cpe.Criteria,
			CpeVer: extractCPEVerFromStr(cpe.Criteria),
		}
		if cpe.VersionStartIncluding != "" {
			ap.MinVer = cpe.VersionStartIncluding
		}
		if cpe.VersionStartExcluding != "" {
			ap.MinVer = cpe.VersionStartExcluding
			ap.MinExclusive = boolPtr(true)
		}
		if cpe.VersionEndIncluding != "" {
			ap.MaxVer = cpe.VersionEndIncluding
			ap.MaxInclusive = boolPtr(true)
		}
		if cpe.VersionEndExcluding != "" && cpe.VersionEndIncluding == "" {
			ap.MaxVer = cpe.VersionEndExcluding
		}
		products = append(products, ap)
	})
	return products
}

func boolPtr(v bool) *bool {
	return &v
}

func walkNodes(configs json.RawMessage, fn func(NVDCPE)) {
	if len(configs) == 0 || string(configs) == "null" {
		return
	}

	var configList []struct {
		Nodes []NVDNode `json:"nodes"`
	}
	if err := json.Unmarshal(configs, &configList); err == nil {
		for _, cfg := range configList {
			for _, node := range cfg.Nodes {
				for _, cpe := range node.CPEMatch {
					fn(cpe)
				}
			}
		}
	}
}

func extractFromCPE(criteria string) (string, string) {
	wfn, err := naming.UnbindURI(criteria)
	if err != nil {
		return "", ""
	}
	return wfnAttrStr(&wfn, common.AttributeProduct), wfnAttrStr(&wfn, common.AttributeVendor)
}

func extractCPEVerFromStr(criteria string) string {
	wfn, err := naming.UnbindURI(criteria)
	if err != nil {
		return ""
	}
	v := wfnAttrStr(&wfn, common.AttributeVersion)
	if v == "ANY" || v == "*" || v == "-" || v == "" {
		return ""
	}
	return v
}

func wfnAttrStr(wfn *common.WellFormedName, attr string) string {
	if wfn == nil {
		return ""
	}
	v, ok := (*wfn)[attr]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	if s == "ANY" {
		return "*"
	}
	return s
}

func (c *NVDClient) extractCVSS(metrics NVDMetrics) (float64, string) {
	scoreList := append(metrics.CVSSMetricV31, metrics.CVSSMetricV30...)
	scoreList = append(scoreList, metrics.CVSSMetricV2...)
	for _, m := range scoreList {
		if m.CVSSData.BaseScore > 0 {
			return m.CVSSData.BaseScore, SeverityFromCVSS(m.CVSSData.BaseScore)
		}
	}
	return 0, "MEDIUM"
}

func firstFixedVersion(products []AffectedProduct) string {
	for _, p := range products {
		if p.FixedIn != "" {
			return p.FixedIn
		}
		if p.MaxVer != "" {
			return p.MaxVer
		}
	}
	return ""
}

func (c *NVDClient) IsVersionAffected(entries []FeedEntry, version string) bool {
	if version == "" {
		return false
	}
	for _, e := range entries {
		var affected []AffectedProduct
		json.Unmarshal(e.Affected, &affected)
		for _, ap := range affected {
			if ap.MinVer == "" && ap.MaxVer == "" {
				continue
			}
			if isVersionAffected(version, ap) {
				return true
			}
		}
	}
	return false
}
