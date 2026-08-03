package cve

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"

	"vuln-scanner/internal/store"
)

type Matcher struct {
	loader      *Loader
	feed        *FeedManager
	nvd         *NVDClient
	osv         *OSVClient
	store       *store.Store
	fetchingNVD sync.Map
}

func NewMatcher(s *store.Store, loader *Loader, feed *FeedManager) *Matcher {
	return &Matcher{
		loader: loader,
		feed:   feed,
		nvd:    NewNVDClient(),
		osv:    NewOSVClient(),
		store:  s,
	}
}

func (m *Matcher) Match(ctx context.Context, agentID string, assets []AssetToMatch, installedKBs map[string]bool) ([]MatchedCVE, error) {
	platform := m.store.AgentOSType(ctx, agentID)
	if strings.Contains(strings.ToLower(platform), "windows") {
		return m.matchWindows(ctx, agentID, assets, installedKBs)
	}
	return m.matchLinux(ctx, agentID, assets)
}

func (m *Matcher) matchWindows(ctx context.Context, agentID string, assets []AssetToMatch, installedKBs map[string]bool) ([]MatchedCVE, error) {
	rawNames, translatedNames := extractSoftwareNames(ctx, m.store, assets, "windows")

	searchNames := append(translatedNames, rawNames...)
	assetVersions := buildAssetVersions(ctx, assets, m.store, "windows")
	agentOS, agentVer := getAgentOSInfo(ctx, m.store, agentID)
	matched, err := m.feed.MatchAssets(ctx, searchNames, assetVersions, installedKBs, agentOS, agentVer)
	if err != nil {
		return nil, err
	}
	matched = m.enrichVersionStatus(matched, assets, installedKBs)
	return matched, nil
}

func (m *Matcher) prefetchNVD(ctx context.Context, names []string) {
	slog.Info("prefetch nvd starting", "names", len(names))
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	count := 0

	for _, name := range names {
		if name == "" {
			continue
		}
		if _, already := m.fetchingNVD.LoadOrStore(name, true); already {
			continue
		}

		has, _ := m.feed.HasFreshEntries(ctx, "nvd", name)
		if has {
			m.fetchingNVD.Delete(name)
			continue
		}

		count++
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := m.loader.LoadNVDForSoftware(ctx, n); err != nil {
				slog.Debug("prefetch nvd failed", "name", n, "error", err)
			}
			m.fetchingNVD.Delete(n)
		}(name)
	}
	wg.Wait()
	if count > 0 {
		slog.Info("prefetch nvd completed", "count", count)
	}
}

func (m *Matcher) matchLinux(ctx context.Context, agentID string, assets []AssetToMatch) ([]MatchedCVE, error) {
	rawNames, _ := extractSoftwareNames(ctx, m.store, assets, "linux")

	assetVersions := buildAssetVersions(ctx, assets, m.store, "linux")
	agentOS, agentVer := getAgentOSInfo(ctx, m.store, agentID)
	matched, err := m.feed.MatchAssets(ctx, rawNames, assetVersions, nil, agentOS, agentVer)
	if err != nil {
		return nil, err
	}
	return matched, nil
}

func (m *Matcher) enrichVersionStatus(results []MatchedCVE, assets []AssetToMatch, installedKBs map[string]bool) []MatchedCVE {
	assetMap := make(map[string]string)
	for _, a := range assets {
		if a.Name != "" {
			mergeAssetVersion(assetMap, strings.ToLower(a.Name), a.Version)
		}
	}

	for i := range results {
		if results[i].MatchStatus == "" {
			results[i].MatchStatus = "active"
		}
		if results[i].KBArticle != "" {
			if installedKBs[results[i].KBArticle] {
				results[i].MatchStatus = "fixed"
				results[i].FixedVersion = results[i].KBArticle
			}
		}
		if results[i].AssetVersion == "" {
			if v, ok := assetMap[strings.ToLower(results[i].AssetName)]; ok {
				results[i].AssetVersion = v
			}
		}
	}
	return results
}

func buildAssetVersions(ctx context.Context, assets []AssetToMatch, s *store.Store, platform string) map[string]string {
	m := make(map[string]string, len(assets))
	for _, a := range assets {
		if a.Name == "" || a.Version == "" {
			continue
		}
		key := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a.Name), " (x64)"))
		mergeAssetVersion(m, key, a.Version)

		cpe, err := s.TranslatePackage(ctx, a.Name, platform)
		if err == nil && cpe != "" {
			mergeAssetVersion(m, strings.ToLower(cpe), a.Version)
		}
	}
	return m
}

// mergeAssetVersion keeps the highest version for a name key. Asset lists can
// contain the same package several times (npm extension + system package,
// x86/x64/ARM64 variants), so a deterministic highest-wins rule prevents
// match results from flipping between cycles.
func mergeAssetVersion(m map[string]string, key, version string) {
	if key == "" || version == "" {
		return
	}
	if cur, ok := m[key]; !ok || compareVersions(version, cur) > 0 {
		m[key] = version
	}
}

func extractSoftwareNames(ctx context.Context, s *store.Store, assets []AssetToMatch, platform string) ([]string, []string) {
	seen := make(map[string]bool)
	var rawNames []string
	var translatedNames []string

	for _, a := range assets {
		if a.Format == "hotfix" || a.Version == "" {
			continue
		}
		name := trimAssetName(a.Name)
		if name == "" || isJunkName(name) || seen[name] {
			continue
		}
		seen[name] = true
		rawNames = append(rawNames, name)

		cpe, err := s.TranslatePackage(ctx, a.Name, platform)
		if err == nil && cpe != "" {
			if _, ok := seen[cpe]; !ok {
				seen[cpe] = true
				translatedNames = append(translatedNames, cpe)
			}
		}
	}
	return rawNames, translatedNames
}

func trimAssetName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, " (x64)")
	name = strings.TrimSuffix(name, " (x86)")
	name = strings.TrimSuffix(name, " (ARM64)")
	name = strings.TrimSpace(name)
	return name
}

func isJunkName(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "vs_") || strings.HasPrefix(lower, "kb") ||
		strings.HasPrefix(lower, "branding") || strings.HasPrefix(lower, "icecap_") ||
		strings.HasPrefix(lower, "diagnosticshub") || strings.HasPrefix(lower, "winappdeploy") ||
		strings.HasPrefix(lower, "vcpp_crt") {
		return true
	}
	return false
}

func AssetsFromJSON(raw []byte) []AssetToMatch {
	var wrapper struct {
		Assets []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Format  string `json:"format"`
			Type    string `json:"type"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil
	}

	var assets []AssetToMatch
	for _, a := range wrapper.Assets {
		assets = append(assets, AssetToMatch{
			Name:    a.Name,
			Version: a.Version,
			Format:  a.Format,
		})
	}
	return assets
}

func (m *Matcher) SaveResults(ctx context.Context, agentID string, results []MatchedCVE) error {
	if len(results) == 0 {
		return m.store.DeleteCVEResults(ctx, agentID)
	}
	entries := make([]*store.CVEResult, 0, len(results))
	for _, r := range results {
		status := r.MatchStatus
		if status == "" {
			status = "active"
		}
		entries = append(entries, &store.CVEResult{
			AgentID:      agentID,
			CVEID:        r.CVEID,
			AssetName:    r.AssetName,
			AssetVersion: r.AssetVersion,
			FixedVersion: r.FixedVersion,
			FixState:     r.FixState,
			KBArticle:    r.KBArticle,
			KBURL:        r.KBURL,
			Severity:     r.Severity,
			CVSSScore:    r.CVSSScore,
			Summary:      r.Summary,
			Source:       r.Source,
			Status:       status,
		})
	}
	return m.store.BulkUpsertCVEResults(ctx, entries)
}

func getAgentOSInfo(ctx context.Context, s *store.Store, agentID string) (string, string) {
	agent, err := s.GetAgent(ctx, agentID)
	if err != nil || agent == nil {
		return "", ""
	}
	return agent.OSType, agent.OSVersion
}
