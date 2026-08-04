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

func NewMatcher(s *store.Store, loader *Loader, feed *FeedManager, nvd ...*NVDClient) *Matcher {
	n := NewNVDClient()
	if len(nvd) > 0 && nvd[0] != nil {
		n = nvd[0]
	}
	return &Matcher{
		loader: loader,
		feed:   feed,
		nvd:    n,
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
	msrcNames, msrcVersions, osAssetName := msrcScopeAssets(assets)
	agentOS, agentVer, agentArch := getAgentOSInfo(ctx, m.store, agentID)
	if family := msrcFamilyToken(agentOS); family != "" {
		// MSRC OS products are named like "Windows 11 Version 22H2 for
		// x64-based Systems", which never contains the installed OS asset
		// name ("Windows 11 Pro 22H2"). The family token makes those rows
		// reach the Go-side version/architecture filter.
		msrcNames = append(msrcNames, family)
	}
	matched, err := m.feed.MatchAssets(ctx, searchNames, msrcNames,
		assetVersions, msrcVersions, installedKBs, agentOS, agentVer, agentArch, osAssetName)
	if err != nil {
		return nil, err
	}
	matched = m.enrichVersionStatus(matched, assets, installedKBs, agentVer)
	updateFacts, _ := m.store.GetAgentUpdateFacts(ctx, agentID)
	updateStatus, _ := m.store.GetAgentUpdateStatus(ctx, agentID)
	matched = applyWUAVerification(matched, updateFacts, updateStatus)
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
	agentOS, agentVer, agentArch := getAgentOSInfo(ctx, m.store, agentID)
	matched, err := m.feed.MatchAssets(ctx, rawNames, nil, assetVersions, nil, nil, agentOS, agentVer, agentArch, "")
	if err != nil {
		return nil, err
	}
	return matched, nil
}

// msrcScopeAssets keeps only Windows OS and installed-package assets for MSRC
// matching. SCA artifacts (npm/go-mod/pypi/maven directories) and hotfix rows
// are excluded: hotfixes are already passed as installedKBs.
func msrcScopeAssets(assets []AssetToMatch) ([]string, map[string]string, string) {
	versions := make(map[string]string)
	var names []string
	osAssetName := ""
	for _, a := range assets {
		switch strings.ToLower(a.Format) {
		case "os":
			osAssetName = a.Name
			fallthrough
		case "win":
		default:
			continue
		}
		if a.Name == "" {
			continue
		}
		names = append(names, a.Name)
		if a.Version != "" {
			mergeAssetVersion(versions, strings.ToLower(trimAssetName(a.Name)), a.Version)
		}
	}
	return dedupStrings(names), versions, osAssetName
}

// msrcFamilyToken derives the Windows family token of an agent OS so MSRC OS
// product rows ("Windows 11 Version 22H2 ...") can be pre-filtered by SQL.
func msrcFamilyToken(agentOS string) string {
	lower := strings.ToLower(agentOS)
	switch {
	case strings.Contains(lower, "windows server"):
		return "Windows Server"
	case strings.Contains(lower, "windows 11"):
		return "Windows 11"
	case strings.Contains(lower, "windows 10"):
		return "Windows 10"
	case strings.Contains(lower, "windows"):
		return "Windows"
	}
	return ""
}

func (m *Matcher) enrichVersionStatus(results []MatchedCVE, assets []AssetToMatch,
	installedKBs map[string]bool, agentVersion string) []MatchedCVE {
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
		if results[i].Source == "msrc" && results[i].OSProduct &&
			results[i].CpeVer != "" && msrcOSFixedByBuild(agentVersion, results[i].CpeVer) {
			results[i].MatchStatus = "fixed"
			if results[i].FixedVersion == "" {
				if results[i].KBArticle != "" {
					results[i].FixedVersion = results[i].KBArticle
				} else {
					results[i].FixedVersion = results[i].CpeVer
				}
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
		verification := r.VerificationSource
		if verification == "" {
			verification = "local"
		}
		entries = append(entries, &store.CVEResult{
			AgentID:            agentID,
			CVEID:              r.CVEID,
			AssetName:          r.AssetName,
			AssetVersion:       r.AssetVersion,
			FixedVersion:       r.FixedVersion,
			FixState:           r.FixState,
			KBArticle:          r.KBArticle,
			KBURL:              r.KBURL,
			VerificationSource: verification,
			Severity:           r.Severity,
			CVSSScore:          r.CVSSScore,
			Summary:            r.Summary,
			Source:             r.Source,
			Status:             status,
		})
	}
	return m.store.BulkUpsertCVEResults(ctx, entries)
}

func getAgentOSInfo(ctx context.Context, s *store.Store, agentID string) (string, string, string) {
	agent, err := s.GetAgent(ctx, agentID)
	if err != nil || agent == nil {
		return "", "", ""
	}
	return agent.OSType, agent.OSVersion, agent.Arch
}
