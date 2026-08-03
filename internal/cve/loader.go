package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

type Loader struct {
	feed *FeedManager
	msrc *MSRCClient
	nvd  *NVDClient
	osv  *OSVClient
	// redhatMu serializes RefreshRedHat runs so a startup preload and a
	// manual refresh cannot duplicate the long package_state detail crawl.
	redhatMu sync.Mutex
}

func NewLoader(feed *FeedManager, msrc *MSRCClient, nvd *NVDClient, osv *OSVClient) *Loader {
	return &Loader{feed: feed, msrc: msrc, nvd: nvd, osv: osv}
}

func (l *Loader) RefreshAllNVD(ctx context.Context, agents []AgentSnapshotSummary) {
	names := collectUniqueSoftware(agents)
	if len(names) == 0 {
		return
	}
	slog.Info("loader: refreshing nvd for all agents", "software", len(names))
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	loaded := 0
	for _, name := range names {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := l.LoadNVDForSoftware(ctx, n); err != nil {
				slog.Debug("loader: nvd refresh failed", "name", n, "error", err)
			} else {
				loaded++
			}
		}(name)
	}
	wg.Wait()
	slog.Info("loader: nvd refresh done", "loaded", loaded)
}

func (l *Loader) RefreshAllOSV(ctx context.Context, agents []AgentSnapshotSummary) {
	pkgAssets := collectPackageAssets(agents)
	if len(pkgAssets) == 0 {
		return
	}
	slog.Info("loader: refreshing osv", "packages", len(pkgAssets))
	sem := make(chan struct{}, 5)
	var mu sync.Mutex
	total := 0
	var wg sync.WaitGroup

	for _, a := range pkgAssets {
		wg.Add(1)
		go func(asset AssetToMatch) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp, err := l.osv.QuerySingle(ctx, asset)
			if err != nil {
				slog.Warn("loader: osv query failed", "pkg", asset.Name, "error", err)
				return
			}
			now := time.Now().UTC()
			var entries []*FeedEntry
			for _, vuln := range resp.Vulns {
				severity, score := extractOSVSeverity(vuln.Severity)
				affected := parseOSVAffected(vuln.Affected)
				if len(affected) == 0 {
					affected = []AffectedProduct{{Name: asset.Name}}
				}
				affectedJSON, _ := json.Marshal(affected)
				id := vuln.ID
				if id == "" {
					continue
				}
				entries = append(entries, &FeedEntry{
					Source:      "osv",
					SourceKey:   asset.Name + "@" + asset.Version + "/" + id,
					CVEID:       id,
					Affected:    affectedJSON,
					Severity:    severity,
					CVSSScore:   score,
					Summary:     vuln.Details,
					PublishedAt: vuln.Modified,
					FetchedAt:   now,
					TTLSeconds:  7 * 24 * 3600,
				})
			}
			if len(entries) > 0 {
				mu.Lock()
				_ = l.feed.BatchUpsert(ctx, entries)
				total += len(entries)
				mu.Unlock()
			}
		}(a)
	}
	wg.Wait()
	slog.Info("loader: osv refresh done", "cves", total)
}

func (l *Loader) LoadMSRCAll(ctx context.Context) error {
	updates, err := l.msrc.FetchUpdates(ctx)
	if err != nil {
		return fmt.Errorf("msrc fetch updates: %w", err)
	}

	months := groupMSRCByMonth(updates)
	slog.Info("loader: msrc months found", "count", len(months))

	var mu sync.Mutex
	var total int
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)

	sortedMonths := sortMonthKeys(months)
	recentMonths := recentMonthSet(12)

	for _, monthKey := range sortedMonths {
		exists, _ := l.feed.SourceMonthExists(ctx, monthKey)
		if exists {
			slog.Debug("loader: msrc month already populated, skipping", "month", monthKey)
			continue
		}
		if !recentMonths[monthKey] {
			continue
		}
		wg.Add(1)
		go func(key string, upds []MSRCUpdate) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			n := l.loadMSRCMonth(ctx, key, upds)
			mu.Lock()
			total += n
			mu.Unlock()
			slog.Info("loader: msrc month loaded", "month", key, "cves", n)
		}(monthKey, months[monthKey])
	}
	wg.Wait()
	return nil
}

func (l *Loader) LoadMSRCHistorical(ctx context.Context) {
	updates, err := l.msrc.FetchUpdates(ctx)
	if err != nil {
		slog.Error("loader: historical fetch failed", "error", err)
		return
	}
	months := groupMSRCByMonth(updates)
	recentMonths := recentMonthSet(12)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)
	var total int
	var mu sync.Mutex

	sortedMonths := sortMonthKeys(months)
	for _, monthKey := range sortedMonths {
		if recentMonths[monthKey] {
			continue
		}
		exists, _ := l.feed.SourceMonthExists(ctx, monthKey)
		if exists {
			continue
		}
		wg.Add(1)
		go func(key string, upds []MSRCUpdate) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			n := l.loadMSRCMonth(ctx, key, upds)
			mu.Lock()
			total += n
			mu.Unlock()
			slog.Info("loader: msrc historical month loaded", "month", key, "cves", n)
		}(monthKey, months[monthKey])
	}
	wg.Wait()
	slog.Info("loader: msrc historical all loaded", "total_cves", total)
}

func sortMonthKeys(months map[string][]MSRCUpdate) []string {
	keys := make([]string, 0, len(months))
	for k := range months {
		keys = append(keys, k)
	}
	parseMonthForSort := func(k string) time.Time {
		t, err := time.Parse("2006-Jan", k)
		if err != nil {
			return time.Time{}
		}
		return t
	}
	sort.Slice(keys, func(i, j int) bool {
		return parseMonthForSort(keys[i]).After(parseMonthForSort(keys[j]))
	})
	return keys
}

func recentMonthSet(n int) map[string]bool {
	now := time.Now().UTC()
	set := make(map[string]bool)
	for i := 0; i < n; i++ {
		m := now.AddDate(0, -i, 0)
		set[m.Format("2006-Jan")] = true
	}
	return set
}

func (l *Loader) RefreshMSRCCurrent(ctx context.Context) error {
	updates, err := l.msrc.FetchUpdates(ctx)
	if err != nil {
		return fmt.Errorf("msrc fetch updates: %w", err)
	}
	months := groupMSRCByMonth(updates)

	current := currentMonthLabel()
	if m, ok := months[current]; ok {
		if err := l.feed.DeleteBySourceKey(ctx, "msrc", current); err != nil {
			slog.Warn("loader: failed to delete old msrc current month", "month", current, "error", err)
		}
		n := l.loadMSRCMonth(ctx, current, m)
		slog.Info("loader: msrc current refreshed", "month", current, "cves", n)
		return nil
	}
	slog.Info("loader: no current month data in msrc", "expected", current)
	return nil
}

func (l *Loader) LoadNVDForSoftware(ctx context.Context, name string) error {
	if l.feed == nil {
		return nil
	}

	has, err := l.feed.HasFreshEntries(ctx, "nvd", name)
	if err != nil {
		slog.Warn("loader: check nvd fresh failed", "name", name, "error", err)
	}
	if has {
		slog.Debug("loader: nvd already fresh for", "name", name)
		return nil
	}

	entries, err := l.nvd.SearchByKeyword(ctx, name)
	if err != nil {
		slog.Warn("loader: nvd search failed for", "name", name, "error", err)
		return nil
	}
	if len(entries) == 0 {
		slog.Info("loader: nvd no results for", "name", name)
		return nil
	}

	feedEntries := make([]*FeedEntry, len(entries))
	for i := range entries {
		feedEntries[i] = &entries[i]
	}
	if err := l.feed.BatchUpsert(ctx, feedEntries); err != nil {
		return fmt.Errorf("batch upsert nvd: %w", err)
	}
	slog.Info("loader: nvd loaded for", "name", name, "cves", len(entries))
	return nil
}

func (l *Loader) RefreshExpiredNVD(ctx context.Context) {
	keys, err := l.feed.QueryExpired(ctx, "nvd")
	if err != nil {
		slog.Error("loader: query expired nvd failed", "error", err)
		return
	}
	for _, key := range keys {
		_ = l.feed.DeleteBySourceKey(ctx, "nvd", key)
	}
	if len(keys) > 0 {
		slog.Info("loader: cleared expired nvd entries", "count", len(keys))
	}
}

func (l *Loader) loadMSRCMonth(ctx context.Context, monthKey string, updates []MSRCUpdate) int {
	total := 0
	for _, u := range updates {
		doc, err := l.msrc.FetchCVRF(ctx, u.CvrfURL)
		if err != nil {
			slog.Warn("loader: msrc fetch cvrf failed", "url", u.CvrfURL, "error", err)
			continue
		}
		entries := l.msrc.parseCVRFToFeedEntries(doc, monthKey)
		if err := l.feed.BatchUpsert(ctx, entries); err != nil {
			slog.Error("loader: batch upsert msrc failed", "month", monthKey, "error", err)
		}
		total += len(entries)
	}
	return total
}

func groupMSRCByMonth(updates []MSRCUpdate) map[string][]MSRCUpdate {
	months := make(map[string][]MSRCUpdate)
	for _, u := range updates {
		key := parseMonthKey(u.InitialReleaseDate)
		months[key] = append(months[key], u)
	}
	return months
}

func parseMonthKey(dateStr string) string {
	dateStr = strings.ReplaceAll(strings.TrimSpace(dateStr), " ", "T")
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		t, err = time.Parse("2006-01-02", dateStr)
		if err != nil {
			return dateStr
		}
	}
	return t.Format("2006-Jan")
}

func currentMonthLabel() string {
	return time.Now().UTC().Format("2006-Jan")
}

func keywordFromName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, " (x64)")
	name = strings.TrimSuffix(name, " (x86)")
	name = strings.TrimSuffix(name, " (ARM64)")

	parts := strings.Fields(name)
	if len(parts) <= 3 {
		return name
	}
	if len(parts[0]) >= 3 && !strings.ContainsAny(parts[0], "0123456789") {
		return strings.Join(parts[:3], " ")
	}
	return name
}

func (l *Loader) loadOSV(ctx context.Context, assets []AssetToMatch) {
	batches := batchAssets(assets, 100)
	var allEntries []*FeedEntry
	for _, batch := range batches {
		resp, err := l.osv.QueryBatch(ctx, batch)
		if err != nil {
			slog.Warn("loader: osv batch failed", "error", err)
			continue
		}
		now := time.Now().UTC()
		for key, qr := range resp {
			for _, vuln := range qr.Vulns {
				severity, score := extractOSVSeverity(vuln.Severity)
				affected := parseOSVAffected(vuln.Affected)
				affectedJSON, _ := json.Marshal(affected)
				allEntries = append(allEntries, &FeedEntry{
					Source:      "osv",
					SourceKey:   key + "/" + vuln.ID,
					CVEID:       vuln.ID,
					Affected:    affectedJSON,
					Severity:    severity,
					CVSSScore:   score,
					Summary:     vuln.Summary,
					PublishedAt: vuln.Modified,
					FetchedAt:   now,
					TTLSeconds:  7 * 24 * 3600,
				})
			}
		}
	}
	if len(allEntries) > 0 {
		_ = l.feed.BatchUpsert(ctx, allEntries)
		slog.Info("loader: osv loaded", "cves", len(allEntries))
	}
}

func parseOSVAffected(affected []Affected) []AffectedProduct {
	var products []AffectedProduct
	for _, a := range affected {
		var introduced, fixed string
		for _, r := range a.Ranges {
			for _, ev := range r.Events {
				if ev.Introduced != "" && introduced == "" {
					introduced = ev.Introduced
				}
				if ev.Fixed != "" {
					fixed = ev.Fixed
				}
			}
		}
		if a.Package.Name == "" {
			continue
		}
		products = append(products, AffectedProduct{
			Name:      a.Package.Name,
			MinVer:    introduced,
			MaxVer:    fixed,
			FixedIn:   fixed,
			Ecosystem: a.Package.Ecosystem,
		})
	}
	if len(products) == 0 {
		return []AffectedProduct{}
	}
	return products
}

func extractOSVSeverity(severities []CVSS) (string, float64) {
	var maxScore float64
	for _, s := range severities {
		score := 0.0
		switch v := s.Score.(type) {
		case float64:
			score = v
		case string:
			if cvss := parseCVSSVector(v); cvss >= 0 {
				score = cvss
			} else {
				fmt.Sscanf(v, "%f", &score)
			}
		}
		if score > maxScore {
			maxScore = score
		}
	}
	return SeverityFromCVSS(maxScore), maxScore
}

func parseCVSSVector(v string) float64 {
	switch {
	case strings.HasPrefix(v, "CVSS:3.1/"):
		cvss, err := gocvss31.ParseVector(v)
		if err == nil {
			return cvss.BaseScore()
		}
	case strings.HasPrefix(v, "CVSS:3.0/"):
		cvss, err := gocvss30.ParseVector(v)
		if err == nil {
			return cvss.BaseScore()
		}
	case strings.HasPrefix(v, "CVSS:4.0/"):
		cvss, err := gocvss40.ParseVector(v)
		if err == nil {
			return cvss.Score()
		}
	case strings.HasPrefix(v, "CVSS:2.0/"):
		cvss, err := gocvss20.ParseVector(v)
		if err == nil {
			return cvss.BaseScore()
		}
	}
	return -1
}

func batchAssets(assets []AssetToMatch, batchSize int) [][]AssetToMatch {
	var batches [][]AssetToMatch
	for i := 0; i < len(assets); i += batchSize {
		end := i + batchSize
		if end > len(assets) {
			end = len(assets)
		}
		batches = append(batches, assets[i:end])
	}
	return batches
}

type AgentSnapshotSummary struct {
	AgentID   string
	OSType    string
	OSVersion string
	Assets    []byte
}

func collectUniqueSoftware(agents []AgentSnapshotSummary) []string {
	seen := make(map[string]bool)
	var names []string
	for _, ag := range agents {
		assets := AssetsFromJSON(ag.Assets)
		for _, a := range assets {
			if a.Format == "hotfix" || a.Name == "" {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(a.Name))
			if len(name) < 3 || seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

func collectPackageAssets(agents []AgentSnapshotSummary) []AssetToMatch {
	var result []AssetToMatch
	seen := make(map[string]bool)
	for _, ag := range agents {
		assets := AssetsFromJSON(ag.Assets)
		for _, a := range assets {
			if a.Format == "hotfix" || a.Format == "os" || a.Name == "" || a.Version == "" {
				continue
			}
			a.Ecosystem = OSVEcosystemForAgent(a.Format, ag.OSType, ag.OSVersion)
			key := a.Name + "\x00" + a.Version + "\x00" + a.Ecosystem
			if seen[key] {
				continue
			}
			seen[key] = true
			result = append(result, a)
		}
	}
	return result
}

// OSVEcosystemForAgent maps an asset format and agent OS to the OSV ecosystem
// name used for version queries. RPM packages are queried against the distro
// that actually installs them (AlmaLinux/Rocky Linux/Fedora/SUSE), falling back
// to Red Hat; apk packages use the Alpine ecosystem scoped to the distro
// version (e.g. "Alpine:v3.23").
func OSVEcosystemForAgent(format, agentOS, agentVersion string) string {
	if format == "apk" {
		if v := majorMinorFromVersion(agentVersion); v != "" {
			return "Alpine:v" + v
		}
		return "Alpine"
	}
	if format == "rpm" {
		lower := strings.ToLower(agentOS)
		switch {
		case strings.Contains(lower, "alma"):
			return "AlmaLinux"
		case strings.Contains(lower, "rocky"):
			return "Rocky Linux"
		case strings.Contains(lower, "fedora"):
			return "Fedora"
		case strings.Contains(lower, "suse"), strings.Contains(lower, "opensuse"):
			return "SUSE"
		default:
			return "Red Hat"
		}
	}
	if format == "deb" {
		if strings.Contains(strings.ToLower(agentOS), "ubuntu") {
			return ubuntuEcosystemForAgent(agentVersion)
		}
	}
	return EcosystemForFormat(format)
}

// ubuntuEcosystemForAgent maps an Ubuntu agent version to the OSV ecosystem
// used by Canonical records: LTS releases use "Ubuntu:<x.y>:LTS", non-LTS
// releases "Ubuntu:<x.y>", and unknown versions fall back to the bare
// "Ubuntu" prefix (which returns no records instead of a false match).
func ubuntuEcosystemForAgent(agentVersion string) string {
	v := majorMinorFromVersion(agentVersion)
	if v == "" {
		return "Ubuntu"
	}
	if isUbuntuLTS(v) {
		return "Ubuntu:" + v + ":LTS"
	}
	return "Ubuntu:" + v
}

// isUbuntuLTS reports whether a major.minor pair is an Ubuntu LTS release
// (even-year April releases such as 20.04, 22.04, 24.04, 26.04).
func isUbuntuLTS(v string) bool {
	major, minor, ok := strings.Cut(v, ".")
	if !ok || minor != "04" || major == "" {
		return false
	}
	switch major[len(major)-1] {
	case '0', '2', '4', '6', '8':
		return true
	}
	return false
}

// ubuntuEcosystemVersion extracts the release version from an OSV Ubuntu
// ecosystem name such as "Ubuntu:22.04:LTS" -> "22.04"; empty when absent.
func ubuntuEcosystemVersion(ecosystem string) string {
	s := strings.ToLower(strings.TrimSpace(ecosystem))
	if !strings.HasPrefix(s, "ubuntu:") {
		return ""
	}
	major, _, _ := strings.Cut(s[len("ubuntu:"):], ":")
	if major == "" {
		return ""
	}
	for _, r := range major {
		if !(r >= '0' && r <= '9' || r == '.') {
			return ""
		}
	}
	return major
}
