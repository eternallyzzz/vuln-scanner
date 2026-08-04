package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
)

var msrcBaseURL = "https://api.msrc.microsoft.com/cvrf/v3.0"

var kbRegex = regexp.MustCompile(`[Kk][Bb](\d+)`)

type MSRCClient struct {
	http   *http.Client
	cached map[string]*CVRFDocument
	mu     sync.RWMutex
}

func NewMSRCClient() *MSRCClient {
	return &MSRCClient{
		http:   &http.Client{Timeout: 180 * time.Second},
		cached: make(map[string]*CVRFDocument),
	}
}

func (c *MSRCClient) FetchUpdates(ctx context.Context) ([]MSRCUpdate, error) {
	updates, _, _, err := c.FetchUpdatesWithState(ctx, FeedState{})
	return updates, err
}

// FetchUpdatesWithState returns the MSRC update list. A 304 response leaves
// updates nil and reports notModified=true so the loader can skip rebuilding
// months that are already populated.
func (c *MSRCClient) FetchUpdatesWithState(ctx context.Context, st FeedState) ([]MSRCUpdate, FeedState, bool, error) {
	body, status, next, err := conditionalGet(ctx, c.http, http.MethodGet,
		msrcBaseURL+"/updates", nil, map[string]string{"Accept": "application/json"}, st)
	if err != nil {
		return nil, next, false, err
	}
	if status == http.StatusNotModified {
		return nil, next, true, nil
	}
	if status != http.StatusOK {
		return nil, next, false, fmt.Errorf("msrc updates: status %d", status)
	}

	var result MSRCUpdatesResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, next, false, fmt.Errorf("decode updates: %w", err)
	}
	var all []MSRCUpdate
	all = append(all, result.Value...)
	pageURL := result.NextLink
	for pageURL != "" && len(all) < 5000 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			return all, next, false, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return all, next, false, fmt.Errorf("fetch updates: %w", err)
		}
		var result MSRCUpdatesResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return all, next, false, fmt.Errorf("decode updates: %w", err)
		}
		resp.Body.Close()
		all = append(all, result.Value...)
		pageURL = result.NextLink
	}
	return all, next, false, nil
}

func (c *MSRCClient) FetchCVRF(ctx context.Context, cvrfURL string) (*CVRFDocument, error) {
	c.mu.RLock()
	if doc, ok := c.cached[cvrfURL]; ok {
		c.mu.RUnlock()
		return doc, nil
	}
	c.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, "GET", cvrfURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	var doc CVRFDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}

	c.mu.Lock()
	c.cached[cvrfURL] = &doc
	c.mu.Unlock()
	slog.Info("cached CVRF", "title", doc.DocumentTitle.Value)
	return &doc, nil
}

// FetchCVRFWithState fetches one CVRF document conditionally. A 304 returns
// notModified=true and a nil document.
func (c *MSRCClient) FetchCVRFWithState(ctx context.Context, cvrfURL string, st FeedState) (*CVRFDocument, FeedState, bool, error) {
	body, status, next, err := conditionalGet(ctx, c.http, http.MethodGet,
		cvrfURL, nil, map[string]string{"Accept": "application/json"}, st)
	if err != nil {
		return nil, next, false, err
	}
	if status == http.StatusNotModified {
		return nil, next, true, nil
	}
	if status != http.StatusOK {
		return nil, next, false, fmt.Errorf("msrc cvrf %s: status %d", cvrfURL, status)
	}
	var doc CVRFDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, next, false, fmt.Errorf("json decode: %w", err)
	}
	return &doc, next, false, nil
}

func (c *MSRCClient) ParseMonthLabel(label string) string {
	label = strings.TrimSpace(label)
	fields := strings.Fields(label)
	for i, f := range fields {
		l := strings.ToLower(f)
		if l == "january" || l == "february" || l == "march" || l == "april" ||
			l == "may" || l == "june" || l == "july" || l == "august" ||
			l == "september" || l == "october" || l == "november" || l == "december" {
			if i+1 < len(fields) {
				return fields[i+1] + "-" + f[:3]
			}
			return f
		}
	}
	return label
}

func (c *MSRCClient) BuildProductMap(doc *CVRFDocument) map[string]string {
	productMap := make(map[string]string)
	for _, branch := range doc.ProductTree.Branch {
		c.collectProducts(branch.Items, productMap)
	}
	return productMap
}

func (c *MSRCClient) collectProducts(items []CVRFItem, productMap map[string]string) {
	for _, item := range items {
		if item.ProductID != "" && item.Value != "" {
			productMap[item.ProductID] = item.Value
		}
		if len(item.Items) > 0 {
			c.collectProducts(item.Items, productMap)
		}
	}
}

func (c *MSRCClient) AffectedProductsForVuln(vuln CVRFVulnerability, productMap map[string]string, cpeMap map[string]CVRFFullProductName) []AffectedProduct {
	var products []AffectedProduct
	seen := make(map[string]bool)

	for _, status := range vuln.ProductStatuses {
		for _, pid := range status.ProductID {
			productName, ok := productMap[pid]
			if !ok || seen[productName] {
				continue
			}
			seen[productName] = true
			ap := AffectedProduct{
				Name:      productName,
				ProductID: pid,
			}
			if fpn, ok := cpeMap[pid]; ok && fpn.CPE != "" {
				ap.CPE = fpn.CPE
				ap.Vendor = extractVendorFromCPE(fpn.CPE)
				ap.CpeVer = extractCPEVersion(fpn.CPE)
			}
			products = append(products, ap)
		}
	}
	return products
}

func (c *MSRCClient) parseCVRFToFeedEntries(doc *CVRFDocument, sourceKey string) []*FeedEntry {
	productMap := c.BuildProductMap(doc)
	cpeMap := c.buildCPEMap(doc)
	now := time.Now().UTC()

	var entries []*FeedEntry
	for _, vuln := range doc.Vulnerability {
		if vuln.CVE == "" {
			continue
		}
		kbByProduct := c.buildKBByProduct(vuln.Remediations)
		affected := c.AffectedProductsForVuln(vuln, productMap, cpeMap)
		severity := c.extractMSRCSeverity(vuln.Threats)
		score := c.extractCVSSScore(vuln.CVSSScoreSets)
		summary := strings.TrimSpace(vuln.Title.Value)

		firstKB, firstKBURL := "", ""
		for i := range affected {
			ref, ok := kbByProduct[affected[i].ProductID]
			if !ok {
				// No per-product remediation: only a single remediation for the
				// whole CVE is unambiguous enough to apply to every product.
				// Multiple remediations without ProductID must not be smeared
				// across all products (that is how Mac/other-platform KBs
				// ended up attached to Windows products).
				kb, kbURL, fixedBuild := c.uniqueFallbackKB(vuln.Remediations)
				if kb != "" {
					ref = msrcKBRef{kb: kb, url: kbURL, fixedBuild: fixedBuild}
					ok = true
				}
			}
			if ok {
				affected[i].FixedIn = ref.kb
				affected[i].KBURL = ref.url
				if ref.fixedBuild != "" {
					affected[i].CpeVer = ref.fixedBuild
				}
				if firstKB == "" {
					firstKB, firstKBURL = ref.kb, ref.url
				}
			}
		}

		affectedJSON, _ := json.Marshal(affected)

		entries = append(entries, &FeedEntry{
			Source:      "msrc",
			SourceKey:   sourceKey,
			CVEID:       vuln.CVE,
			CVEURL:      firstKBURL,
			Affected:    affectedJSON,
			FixedKB:     firstKB,
			Severity:    severity,
			CVSSScore:   score,
			Summary:     summary,
			PublishedAt: now,
			FetchedAt:   now,
			TTLSeconds:  30 * 24 * 3600,
		})
	}
	return entries
}

type msrcKBRef struct {
	kb         string
	url        string
	fixedBuild string
}

// buildKBByProduct maps CVRF remediation ProductIDs to the KB article and URL
// declared for that product. Remediations without ProductID are ignored here
// and handled by uniqueFallbackKB.
func (c *MSRCClient) buildKBByProduct(remediations []CVRFRemediation) map[string]msrcKBRef {
	out := make(map[string]msrcKBRef)
	for _, r := range remediations {
		matched := kbRegex.FindStringSubmatch(r.URL)
		if len(matched) < 2 {
			continue
		}
		ref := msrcKBRef{
			kb:         "KB" + matched[1],
			url:        strings.TrimSpace(r.URL),
			fixedBuild: strings.TrimSpace(r.FixedBuild),
		}
		for _, pid := range r.ProductID {
			if pid != "" {
				out[pid] = ref
			}
		}
	}
	return out
}

// uniqueFallbackKB returns the KB of the only remediation when the CVE has
// exactly one remediation; with multiple remediations the mapping is
// ambiguous and no fallback is applied.
func (c *MSRCClient) uniqueFallbackKB(remediations []CVRFRemediation) (string, string, string) {
	if len(remediations) != 1 {
		return "", "", ""
	}
	return c.findKBInRemediations(remediations)
}

func (c *MSRCClient) findKBInRemediations(remediations []CVRFRemediation) (string, string, string) {
	for _, r := range remediations {
		matched := kbRegex.FindStringSubmatch(r.URL)
		if len(matched) >= 2 {
			return "KB" + matched[1], r.URL, strings.TrimSpace(r.FixedBuild)
		}
	}
	return "", "", ""
}

func (c *MSRCClient) extractMSRCSeverity(threats []CVRFThreat) string {
	for _, t := range threats {
		if t.Type == 3 {
			return SeverityFromMSRC(t.Description.Value)
		}
	}
	return "MEDIUM"
}

func (c *MSRCClient) extractCVSSScore(sets []CVRFScoreSet) float64 {
	for _, s := range sets {
		if s.BaseScore.Value != "" {
			score := 0.0
			fmt.Sscanf(s.BaseScore.Value, "%f", &score)
			return score
		}
	}
	return 0.0
}

func (c *MSRCClient) buildCPEMap(doc *CVRFDocument) map[string]CVRFFullProductName {
	cpeMap := make(map[string]CVRFFullProductName)
	for _, fpn := range doc.ProductTree.FullProductName {
		if fpn.ProductID != "" && fpn.CPE != "" {
			cpeMap[fpn.ProductID] = fpn
		}
	}
	return cpeMap
}

func extractVendorFromCPE(cpeStr string) string {
	wfn := parseCPE(cpeStr)
	if wfn == nil {
		return ""
	}
	return wfnAttr(wfn, common.AttributeVendor)
}

func extractCPEProduct(cpeStr string) string {
	wfn := parseCPE(cpeStr)
	if wfn == nil {
		return ""
	}
	return wfnAttr(wfn, common.AttributeProduct)
}

func extractCPEVersion(cpeStr string) string {
	wfn := parseCPE(cpeStr)
	if wfn == nil {
		return ""
	}
	v := wfnAttr(wfn, common.AttributeVersion)
	if v == "ANY" {
		return "*"
	}
	return v
}

func extractCPEArch(cpeStr string) string {
	wfn := parseCPE(cpeStr)
	if wfn == nil {
		return ""
	}
	return strings.ToLower(wfnAttr(wfn, common.AttributeTargetHw))
}

func extractCPETargetPlatform(cpeStr string) string {
	wfn := parseCPE(cpeStr)
	if wfn == nil {
		return ""
	}
	return strings.ToLower(wfnAttr(wfn, common.AttributeTargetSw))
}

func extractCPEPart(cpeStr string) string {
	wfn := parseCPE(cpeStr)
	if wfn == nil {
		return ""
	}
	return wfnAttr(wfn, common.AttributePart)
}

func parseCPE(cpeStr string) *common.WellFormedName {
	wfn, err := naming.UnbindURI(cpeStr)
	if err != nil {
		return nil
	}
	return &wfn
}

func wfnAttr(wfn *common.WellFormedName, attr string) string {
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
