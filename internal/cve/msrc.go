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

const msrcBaseURL = "https://api.msrc.microsoft.com/cvrf/v3.0"

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
	var all []MSRCUpdate
	nextURL := msrcBaseURL + "/updates"

	for nextURL != "" && len(all) < 5000 {
		req, err := http.NewRequestWithContext(ctx, "GET", nextURL, nil)
		if err != nil {
			return all, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return all, fmt.Errorf("fetch updates: %w", err)
		}
		var result MSRCUpdatesResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return all, fmt.Errorf("decode updates: %w", err)
		}
		resp.Body.Close()
		all = append(all, result.Value...)
		nextURL = result.NextLink
	}
	return all, nil
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
		kb, kbURL := c.findKBInRemediations(vuln.Remediations)
		affected := c.AffectedProductsForVuln(vuln, productMap, cpeMap)
		severity := c.extractMSRCSeverity(vuln.Threats)
		score := c.extractCVSSScore(vuln.CVSSScoreSets)
		summary := strings.TrimSpace(vuln.Title.Value)

		for i := range affected {
			if affected[i].FixedIn == "" && kb != "" {
				affected[i].FixedIn = kb
			}
		}

		affectedJSON, _ := json.Marshal(affected)

		entries = append(entries, &FeedEntry{
			Source:      "msrc",
			SourceKey:   sourceKey,
			CVEID:       vuln.CVE,
			CVEURL:      kbURL,
			Affected:    affectedJSON,
			FixedKB:     kb,
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

func (c *MSRCClient) findKBInRemediations(remediations []CVRFRemediation) (string, string) {
	for _, r := range remediations {
		matched := kbRegex.FindStringSubmatch(r.URL)
		if len(matched) >= 2 {
			return "KB" + matched[1], r.URL
		}
	}
	return "", ""
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
