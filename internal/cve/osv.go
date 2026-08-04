package cve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const osvAPIBase = "https://api.osv.dev/v1"

type OSVClient struct {
	http    *http.Client
	queried map[string]time.Time
	mu      sync.RWMutex
}

func NewOSVClient() *OSVClient {
	return &OSVClient{
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
		queried: make(map[string]time.Time),
	}
}

func (c *OSVClient) QueryBatch(ctx context.Context, assets []AssetToMatch) (map[string]*QueryResponse, error) {
	const batchSize = 100
	results := make(map[string]*QueryResponse)

	for i := 0; i < len(assets); i += batchSize {
		end := i + batchSize
		if end > len(assets) {
			end = len(assets)
		}

		batch := assets[i:end]
		var queries []QueryRequestV1
		for _, a := range batch {
			eco := a.Ecosystem
			if eco == "" {
				eco = EcosystemForFormat(a.Format)
			}
			queries = append(queries, QueryRequestV1{
				Version: a.Version,
				Package: PackageInfo{Name: a.Name, Ecosystem: eco},
			})
		}

		body, err := json.Marshal(QueryBatchRequest{Queries: queries})
		if err != nil {
			return nil, fmt.Errorf("marshal batch: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, "POST", osvAPIBase+"/querybatch", bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.http.Do(req)
		if err != nil {
			slog.Error("osv query failed", "error", err)
			continue
		}

		var batchResp struct {
			Results []QueryResponse `json:"results"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
			resp.Body.Close()
			slog.Error("osv decode failed", "error", err)
			continue
		}
		resp.Body.Close()

		for j, r := range batchResp.Results {
			key := batch[j].Name + "@" + batch[j].Version
			results[key] = &r
		}

		time.Sleep(500 * time.Millisecond)
	}

	return results, nil
}

// osvPackageKey identifies one package-level OSV query across ecosystems.
func osvPackageKey(a AssetToMatch) string {
	eco := a.Ecosystem
	if eco == "" {
		eco = EcosystemForFormat(a.Format)
	}
	return a.Name + "@" + eco
}

// QueryPackages queries OSV by package only (no version), returning all known
// vulnerabilities for each package. The response map is keyed by
// name@ecosystem.
func (c *OSVClient) QueryPackages(ctx context.Context, packages []AssetToMatch) (map[string]*QueryResponse, error) {
	const batchSize = 100
	results := make(map[string]*QueryResponse)

	for i := 0; i < len(packages); i += batchSize {
		end := i + batchSize
		if end > len(packages) {
			end = len(packages)
		}
		batch := packages[i:end]
		queries := make([]QueryRequestV1, 0, len(batch))
		for _, a := range batch {
			eco := a.Ecosystem
			if eco == "" {
				eco = EcosystemForFormat(a.Format)
			}
			queries = append(queries, QueryRequestV1{
				Package: PackageInfo{Name: a.Name, Ecosystem: eco},
			})
		}

		body, err := json.Marshal(QueryBatchRequest{Queries: queries})
		if err != nil {
			return nil, fmt.Errorf("marshal package batch: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvAPIBase+"/querybatch", bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("create package request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.http.Do(req)
		if err != nil {
			slog.Error("osv package query failed", "error", err)
			continue
		}
		var batchResp struct {
			Results []QueryResponse `json:"results"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
			resp.Body.Close()
			slog.Error("osv package decode failed", "error", err)
			continue
		}
		resp.Body.Close()

		for j, r := range batchResp.Results {
			if j >= len(batch) {
				break
			}
			key := osvPackageKey(batch[j])
			results[key] = &r
		}
		time.Sleep(500 * time.Millisecond)
	}
	return results, nil
}

func (c *OSVClient) QuerySingle(ctx context.Context, asset AssetToMatch) (*QueryResponse, error) {
	eco := asset.Ecosystem
	if eco == "" {
		eco = EcosystemForFormat(asset.Format)
	}
	body, err := json.Marshal(QueryRequestV1{
		Version: asset.Version,
		Package: PackageInfo{Name: asset.Name, Ecosystem: eco},
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", osvAPIBase+"/query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}
