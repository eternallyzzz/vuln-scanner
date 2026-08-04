package cve

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vuln-scanner/internal/store"
)

const (
	epssCSVURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
	epssAPIURL = "https://api.first.org/data/v1/epss"
	kevURL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

var intelHTTP = &http.Client{Timeout: 60 * time.Second}

// RefreshIntel loads EPSS + KEV intelligence and merges it into cve_intel.
// EPSS rows carry scores; KEV rows carry exploitation flags; a CVE present in
// both keeps both halves (merged before upsert so no field is zeroed).
func (l *Loader) RefreshIntel(ctx context.Context) error {
	merged := map[string]store.CVEIntel{}

	epss, err := fetchEPSS(ctx)
	if err != nil {
		slog.Error("intel: epss fetch failed", "error", err)
	} else {
		for _, e := range epss {
			merged[e.CVEID] = e
		}
		slog.Info("intel: epss fetched", "count", len(epss))
	}

	kev, err := fetchKEV(ctx)
	if err != nil {
		slog.Error("intel: kev fetch failed", "error", err)
	} else {
		for _, e := range kev {
			if existing, ok := merged[e.CVEID]; ok {
				existing.KEV = true
				existing.KEVAdded = e.KEVAdded
				existing.KnownRansomware = e.KnownRansomware
				merged[e.CVEID] = existing
			} else {
				merged[e.CVEID] = e
			}
		}
		slog.Info("intel: kev fetched", "count", len(kev))
	}

	if len(merged) == 0 {
		return fmt.Errorf("intel: no EPSS or KEV data fetched")
	}
	entries := make([]store.CVEIntel, 0, len(merged))
	for _, e := range merged {
		entries = append(entries, e)
	}
	if err := l.store.UpsertCVEIntelBatch(ctx, entries); err != nil {
		return fmt.Errorf("intel: store upsert: %w", err)
	}
	slog.Info("intel: refreshed", "total", len(entries))
	return nil
}

func fetchEPSS(ctx context.Context) ([]store.CVEIntel, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, epssCSVURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := intelHTTP.Do(req)
	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		gz, err := gzip.NewReader(resp.Body)
		if err == nil {
			defer gz.Close()
			return parseEPSSReader(gz)
		}
	}
	if resp != nil {
		resp.Body.Close()
	}
	slog.Warn("intel: epss csv unavailable, falling back to api paging")
	return fetchEPSSAPI(ctx)
}

func fetchEPSSAPI(ctx context.Context) ([]store.CVEIntel, error) {
	var all []store.CVEIntel
	total := -1
	for offset := 0; ; offset += 1000 {
		if offset > 0 && total >= 0 && offset >= total {
			break
		}
		if offset/1000 > 300 {
			break
		}
		url := fmt.Sprintf("%s?offset=%d&limit=1000", epssAPIURL, offset)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := intelHTTP.Do(req)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("epss api status %d", resp.StatusCode)
		}
		page, pageTotal, err := parseEPSSAPI(body)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		total = pageTotal
		if len(page) == 0 {
			break
		}
	}
	return all, nil
}

func fetchKEV(ctx context.Context) ([]store.CVEIntel, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := intelHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kev status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	return parseKEV(body)
}

// parseEPSSReader parses the official epss_scores CSV (gz-decompressed).
func parseEPSSReader(r io.Reader) ([]store.CVEIntel, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	records, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	var out []store.CVEIntel
	for i, rec := range records {
		if i == 0 || len(rec) < 3 {
			continue
		}
		cve := strings.TrimSpace(rec[0])
		if !strings.HasPrefix(cve, "CVE-") {
			continue
		}
		epss, _ := strconv.ParseFloat(strings.TrimSpace(rec[1]), 64)
		pct, _ := strconv.ParseFloat(strings.TrimSpace(rec[2]), 64)
		out = append(out, store.CVEIntel{
			CVEID: cve, EPSSScore: epss, EPSSPercentile: pct,
		})
	}
	return out, nil
}

// parseEPSSAPI parses one FIRST API page.
func parseEPSSAPI(data []byte) ([]store.CVEIntel, int, error) {
	var page struct {
		Data []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
		} `json:"data"`
		Meta struct {
			Total int `json:"total"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(data, &page); err != nil {
		return nil, 0, err
	}
	var out []store.CVEIntel
	for _, d := range page.Data {
		epss, _ := strconv.ParseFloat(d.EPSS, 64)
		pct, _ := strconv.ParseFloat(d.Percentile, 64)
		out = append(out, store.CVEIntel{CVEID: d.CVE, EPSSScore: epss, EPSSPercentile: pct})
	}
	return out, page.Meta.Total, nil
}

// parseKEV parses the CISA KEV catalog.
func parseKEV(data []byte) ([]store.CVEIntel, error) {
	var catalog struct {
		Vulnerabilities []struct {
			CVEID                      string `json:"cveID"`
			DateAdded                  string `json:"dateAdded"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, err
	}
	var out []store.CVEIntel
	for _, v := range catalog.Vulnerabilities {
		out = append(out, store.CVEIntel{
			CVEID:           v.CVEID,
			KEV:             true,
			KEVAdded:        v.DateAdded,
			KnownRansomware: strings.EqualFold(v.KnownRansomwareCampaignUse, "Known"),
		})
	}
	return out, nil
}
