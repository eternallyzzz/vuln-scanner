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

	"vuln-scanner/internal/store"
)

type Loader struct {
	feed  *FeedManager
	store *store.Store
	msrc  *MSRCClient
	nvd   *NVDClient
	osv   *OSVClient
	cfg   *Config
	// redhatMu serializes RefreshRedHat runs so a startup preload and a
	// manual refresh cannot duplicate the long package_state detail crawl.
	redhatMu sync.Mutex
	// nvdParseMu serializes the one-time NVD reparse when nvd_parse_version
	// changes, so concurrent LoadNVDForSoftware calls cannot race deletion.
	nvdParseMu sync.Mutex
}

// msrcParseVersion is bumped whenever the CVRF parsing/matching semantics
// change so the MSRC feed is rebuilt once on the next server start.
const msrcParseVersion = "3"

// nvdParseVersion is bumped whenever NVD affected-product parsing semantics
// change so existing rows are rebuilt once on the next server start.
const nvdParseVersion = "1"

func NewLoader(feed *FeedManager, st *store.Store, msrc *MSRCClient, nvd *NVDClient, osv *OSVClient, cfg ...*Config) *Loader {
	c := DefaultConfig()
	if len(cfg) > 0 && cfg[0] != nil {
		c = cfg[0].Normalized()
	}
	return &Loader{feed: feed, store: st, msrc: msrc, nvd: nvd, osv: osv, cfg: c}
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
	pkgAssets := uniquePackageAssets(collectPackageAssets(agents))
	if len(pkgAssets) == 0 {
		return
	}
	var toQuery []AssetToMatch
	for _, a := range pkgAssets {
		st, _ := loadFeedState(ctx, l.store, "osv", "pkg:"+feedHash(a.Name, a.Ecosystem))
		if st.freshSince(l.cfg.OSVRefresh) {
			continue
		}
		toQuery = append(toQuery, a)
	}
	if len(toQuery) == 0 {
		slog.Info("loader: osv all packages fresh, skipping", "packages", len(pkgAssets))
		return
	}
	slog.Info("loader: refreshing osv", "packages", len(toQuery), "total", len(pkgAssets))

	results, err := l.osv.QueryPackages(ctx, toQuery)
	if err != nil {
		slog.Warn("loader: osv package query failed", "error", err)
	}

	now := time.Now().UTC()
	entriesByPkg := make(map[string][]*FeedEntry, len(toQuery))
	for _, a := range toQuery {
		key := osvPackageKey(a)
		resp, ok := results[key]
		if !ok {
			st, _ := loadFeedState(ctx, l.store, "osv", "pkg:"+feedHash(a.Name, a.Ecosystem))
			st.markError(fmt.Errorf("osv query returned no response for %s", key))
			_ = saveFeedState(ctx, l.store, "osv", "pkg:"+feedHash(a.Name, a.Ecosystem), st)
			continue
		}
		var entries []*FeedEntry
		for _, vuln := range resp.Vulns {
			severity, score := extractOSVSeverity(vuln.Severity)
			affected := parseOSVAffected(vuln.Affected)
			if len(affected) == 0 {
				affected = []AffectedProduct{{Name: a.Name}}
			}
			affectedJSON, _ := json.Marshal(affected)
			if vuln.ID == "" {
				continue
			}
			entries = append(entries, &FeedEntry{
				Source:      "osv",
				SourceKey:   key + "/" + vuln.ID,
				CVEID:       vuln.ID,
				Affected:    affectedJSON,
				Severity:    severity,
				CVSSScore:   score,
				Summary:     vuln.Details,
				PublishedAt: vuln.Modified,
				FetchedAt:   now,
				TTLSeconds:  int(l.cfg.OSVTTL.Seconds()),
			})
		}
		entriesByPkg[key] = entries
	}

	var allEntries []*FeedEntry
	for _, entries := range entriesByPkg {
		allEntries = append(allEntries, entries...)
	}
	upsertFailed := false
	if len(allEntries) > 0 {
		if err := l.feed.BatchUpsert(ctx, allEntries); err != nil {
			upsertFailed = true
			slog.Warn("loader: osv batch upsert failed", "error", err)
		}
	}
	for _, a := range toQuery {
		key := osvPackageKey(a)
		stateKey := "pkg:" + feedHash(a.Name, a.Ecosystem)
		st, _ := loadFeedState(ctx, l.store, "osv", stateKey)
		if entries, ok := entriesByPkg[key]; ok && !upsertFailed {
			st.markSuccess(len(entries))
		} else if upsertFailed {
			st.markError(fmt.Errorf("osv batch upsert failed"))
		} else {
			st.markError(fmt.Errorf("osv query returned no response for %s", key))
		}
		_ = saveFeedState(ctx, l.store, "osv", stateKey, st)
	}

	total := len(allEntries)
	slog.Info("loader: osv refresh done", "cves", total, "packages", len(toQuery))
}

func (l *Loader) LoadMSRCAll(ctx context.Context) error {
	rebuilt, err := l.EnsureMSRCParseVersion(ctx)
	if err != nil {
		return fmt.Errorf("ensure msrc parse version: %w", err)
	}
	st := FeedState{}
	if !rebuilt {
		st, err = loadFeedState(ctx, l.store, "msrc", "updates")
		if err != nil {
			slog.Warn("loader: msrc updates state load failed", "error", err)
		}
	}
	updates, next, notModified, err := l.msrc.FetchUpdatesWithState(ctx, st)
	if err != nil {
		return fmt.Errorf("msrc fetch updates: %w", err)
	}
	if notModified {
		slog.Info("loader: msrc updates unchanged, skipping")
		return nil
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
			n := l.loadMSRCMonth(ctx, key, upds, rebuilt)
			mu.Lock()
			total += n
			mu.Unlock()
			slog.Info("loader: msrc month loaded", "month", key, "cves", n)
		}(monthKey, months[monthKey])
	}
	wg.Wait()
	next.markSuccess(total)
	if err := saveFeedState(ctx, l.store, "msrc", "updates", next); err != nil {
		slog.Warn("loader: msrc updates state save failed", "error", err)
	}
	return nil
}

func (l *Loader) LoadMSRCHistorical(ctx context.Context) {
	st, err := loadFeedState(ctx, l.store, "msrc", "updates")
	if err != nil {
		slog.Warn("loader: msrc updates state load failed", "error", err)
	}
	updates, next, notModified, err := l.msrc.FetchUpdatesWithState(ctx, st)
	if err != nil {
		slog.Error("loader: historical fetch failed", "error", err)
		return
	}
	if notModified {
		slog.Info("loader: msrc updates unchanged, skipping historical")
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
			n := l.loadMSRCMonth(ctx, key, upds, false)
			mu.Lock()
			total += n
			mu.Unlock()
			slog.Info("loader: msrc historical month loaded", "month", key, "cves", n)
		}(monthKey, months[monthKey])
	}
	wg.Wait()
	next.markSuccess(total)
	if err := saveFeedState(ctx, l.store, "msrc", "updates", next); err != nil {
		slog.Warn("loader: msrc updates state save failed", "error", err)
	}
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
	st, err := loadFeedState(ctx, l.store, "msrc", "updates")
	if err != nil {
		slog.Warn("loader: msrc updates state load failed", "error", err)
	}
	updates, next, notModified, err := l.msrc.FetchUpdatesWithState(ctx, st)
	if err != nil {
		return fmt.Errorf("msrc fetch updates: %w", err)
	}
	if notModified {
		return nil
	}
	months := groupMSRCByMonth(updates)

	current := currentMonthLabel()
	if m, ok := months[current]; ok {
		n := l.loadMSRCMonth(ctx, current, m, false)
		slog.Info("loader: msrc current refreshed", "month", current, "cves", n)
		next.markSuccess(n)
		if err := saveFeedState(ctx, l.store, "msrc", "updates", next); err != nil {
			slog.Warn("loader: msrc updates state save failed", "error", err)
		}
		return nil
	}
	slog.Info("loader: no current month data in msrc", "expected", current)
	return nil
}

func (l *Loader) LoadNVDForSoftware(ctx context.Context, name string) error {
	if l.feed == nil {
		return nil
	}
	if err := l.EnsureNVDParseVersion(ctx); err != nil {
		slog.Warn("loader: ensure nvd parse version failed", "error", err)
	}

	stateKey := "kw:" + feedHash(name)
	st, err := loadFeedState(ctx, l.store, "nvd", stateKey)
	if err != nil {
		slog.Warn("loader: nvd state load failed", "name", name, "error", err)
	}
	if st.freshSince(l.cfg.NVDRefresh) {
		slog.Debug("loader: nvd state fresh for", "name", name)
		return nil
	}

	var entries []FeedEntry
	if st.Cursor != "" {
		if since, perr := time.Parse(time.RFC3339, st.Cursor); perr == nil {
			entries, err = l.nvd.SearchByKeywordSince(ctx, name, since.Add(-time.Hour))
		} else {
			slog.Warn("loader: nvd cursor parse failed, falling back to full search", "name", name, "error", perr)
			entries, err = l.nvd.SearchByKeyword(ctx, name)
		}
	} else {
		entries, err = l.nvd.SearchByKeyword(ctx, name)
	}
	if err != nil {
		st.markError(err)
		_ = saveFeedState(ctx, l.store, "nvd", stateKey, st)
		slog.Warn("loader: nvd search failed for", "name", name, "error", err)
		return nil
	}
	if len(entries) == 0 {
		st.Cursor = time.Now().UTC().Format(time.RFC3339)
		st.markSuccess(0)
		if err := saveFeedState(ctx, l.store, "nvd", stateKey, st); err != nil {
			slog.Warn("loader: nvd state save failed", "name", name, "error", err)
		}
		slog.Info("loader: nvd no results for", "name", name)
		return nil
	}

	feedEntries := make([]*FeedEntry, len(entries))
	for i := range entries {
		feedEntries[i] = &entries[i]
	}
	if err := l.feed.BatchUpsert(ctx, feedEntries); err != nil {
		st.markError(err)
		_ = saveFeedState(ctx, l.store, "nvd", stateKey, st)
		return fmt.Errorf("batch upsert nvd: %w", err)
	}
	st.Cursor = time.Now().UTC().Format(time.RFC3339)
	st.markSuccess(len(feedEntries))
	if err := saveFeedState(ctx, l.store, "nvd", stateKey, st); err != nil {
		slog.Warn("loader: nvd state save failed", "name", name, "error", err)
	}
	slog.Info("loader: nvd loaded for", "name", name, "cves", len(entries))
	return nil
}

// EnsureNVDParseVersion forces a full NVD re-fetch when the parser version
// has changed; old rows and cache state are removed so every software keyword
// is rebuilt with the current affected-range semantics.
func (l *Loader) EnsureNVDParseVersion(ctx context.Context) error {
	if l.store == nil || l.feed == nil {
		return nil
	}
	l.nvdParseMu.Lock()
	defer l.nvdParseMu.Unlock()

	cur, err := l.store.GetMeta(ctx, "nvd_parse_version")
	if err != nil {
		return err
	}
	if cur == nvdParseVersion {
		return nil
	}
	if err := l.feed.DeleteAllBySource(ctx, "nvd"); err != nil {
		return err
	}
	if err := l.store.DeleteMetaPrefix(ctx, "feed:nvd:"); err != nil {
		return err
	}
	return l.store.SetMeta(ctx, "nvd_parse_version", nvdParseVersion)
}

func (l *Loader) loadMSRCMonth(ctx context.Context, monthKey string, updates []MSRCUpdate, force bool) int {
	total := 0
	for _, u := range updates {
		stateKey := "cvrf:" + feedHash(u.CvrfURL)
		st, err := loadFeedState(ctx, l.store, "msrc", stateKey)
		if err != nil {
			slog.Warn("loader: msrc cvrf state load failed", "url", u.CvrfURL, "error", err)
		}
		if force {
			st.ETag = ""
			st.LastModified = ""
		}
		doc, next, notModified, err := l.msrc.FetchCVRFWithState(ctx, u.CvrfURL, st)
		if err != nil {
			st.markError(err)
			_ = saveFeedState(ctx, l.store, "msrc", stateKey, st)
			slog.Warn("loader: msrc fetch cvrf failed", "url", u.CvrfURL, "error", err)
			continue
		}
		if notModified {
			continue
		}
		entries := l.msrc.parseCVRFToFeedEntries(doc, monthKey)
		for _, e := range entries {
			e.TTLSeconds = int(l.cfg.MSRCTTL.Seconds())
		}
		if err := l.feed.BatchUpsert(ctx, entries); err != nil {
			st.markError(err)
			_ = saveFeedState(ctx, l.store, "msrc", stateKey, st)
			slog.Error("loader: batch upsert msrc failed", "month", monthKey, "error", err)
			continue
		}
		next.markSuccess(len(entries))
		if err := saveFeedState(ctx, l.store, "msrc", stateKey, next); err != nil {
			slog.Warn("loader: msrc cvrf state save failed", "url", u.CvrfURL, "error", err)
		}
		total += len(entries)
	}
	return total
}

// EnsureMSRCParseVersion forces a full MSRC re-fetch when the parser version
// has changed; old rows are removed so SourceMonthExists no longer skips
// already-loaded months.
func (l *Loader) EnsureMSRCParseVersion(ctx context.Context) (bool, error) {
	cur, err := l.store.GetMeta(ctx, "msrc_parse_version")
	if err != nil {
		return false, err
	}
	if cur == msrcParseVersion {
		return false, nil
	}
	if err := l.feed.DeleteAllBySource(ctx, "msrc"); err != nil {
		return false, err
	}
	if err := l.store.DeleteMetaPrefix(ctx, "feed:msrc:"); err != nil {
		return false, err
	}
	if err := l.store.SetMeta(ctx, "msrc_parse_version", msrcParseVersion); err != nil {
		return false, err
	}
	return true, nil
}

// SyncKBMetadata rebuilds kb_metadata from the per-product KB assignments in
// the MSRC feed. Verification statuses are preserved by the upsert.
func (l *Loader) SyncKBMetadata(ctx context.Context) error {
	infos, err := l.feed.ListMSRCKBs(ctx)
	if err != nil {
		return fmt.Errorf("list msrc kbs: %w", err)
	}
	type kbAgg struct {
		family  string
		title   string
		support string
		catalog string
	}
	byKB := make(map[string]*kbAgg)
	for _, info := range infos {
		a := byKB[info.KB]
		if a == nil {
			a = &kbAgg{}
			byKB[info.KB] = a
		}
		if a.title == "" {
			a.title = info.ProductName
		}
		if info.KBURL != "" {
			if strings.Contains(strings.ToLower(info.KBURL), "catalog.update.microsoft.com") {
				if a.catalog == "" {
					a.catalog = info.KBURL
				}
			} else if a.support == "" {
				a.support = info.KBURL
			}
		}
		if a.family == "" || a.family == "other" {
			if isMSRCWindowsFamilyProduct(info.ProductName) {
				a.family = "windows"
			} else if a.family == "" {
				a.family = "other"
			}
		}
	}
	for kb, a := range byKB {
		if num := extractKBNumber(kb); num > 0 && a.support == "" {
			a.support = fmt.Sprintf("https://support.microsoft.com/help/%d", num)
		}
		if a.catalog == "" {
			a.catalog = "https://www.catalog.update.microsoft.com/Search.aspx?q=" + kb
		}
		if err := l.store.UpsertKBMetadata(ctx, store.KBMetadata{
			KB:            kb,
			Title:         a.title,
			ProductFamily: a.family,
			SupportURL:    a.support,
			CatalogURL:    a.catalog,
		}); err != nil {
			slog.Warn("loader: upsert kb metadata failed", "kb", kb, "error", err)
		}
	}
	slog.Info("loader: kb metadata synced", "count", len(byKB))
	return nil
}

// isMSRCWindowsFamilyProduct reports whether a KB's affected product belongs
// to the Windows ecosystem (OS, .NET, Office, VS, ...) rather than a foreign
// platform such as Mac/Android/iOS/Linux/Azure/Surface.
func isMSRCWindowsFamilyProduct(productName string) bool {
	lower := strings.ToLower(productName)
	for _, token := range []string{
		"mac", "android", "ios", "ipados", "tvos", "watchos",
		"linux", "mariner", "azure", "xbox", "hololens", "surface", "chrome",
	} {
		if strings.Contains(lower, token) {
			return false
		}
	}
	return true
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
			// Service-fingerprint formats (network/web/db) carry products like
			// nginx/mysql that are not OSV package ecosystems; they are
			// matched through the name-based feeds instead.
			if a.Format == "hotfix" || a.Format == "os" || a.Format == "network" ||
				a.Format == "web" || a.Format == "db" || a.Name == "" || a.Version == "" {
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

// uniquePackageAssets collapses package assets to one query per
// name@ecosystem so OSV is not queried once per installed version.
func uniquePackageAssets(assets []AssetToMatch) []AssetToMatch {
	seen := make(map[string]bool, len(assets))
	out := make([]AssetToMatch, 0, len(assets))
	for _, a := range assets {
		if a.Ecosystem == "" {
			a.Ecosystem = EcosystemForFormat(a.Format)
		}
		key := osvPackageKey(a)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, a)
	}
	return out
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
