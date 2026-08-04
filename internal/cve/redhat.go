package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	redhatAPIBase   = "https://access.redhat.com/hydra/rest/securitydata"
	redhatCVEPage   = "https://access.redhat.com/security/cve/"
	redhatStartDate = "2000-01-01"
	redhatPageSize  = 1000
	redhatMaxPages  = 200
	// redhatDetailConcurrency bounds parallel per-CVE detail requests and
	// redhatDetailInterval rate-limits them globally. The detail endpoint is
	// the only place package_state is exposed and is protected by a WAF, so
	// the crawl stays polite and aborts when the WAF starts blocking.
	redhatDetailConcurrency    = 4
	redhatDetailInterval       = 200 * time.Millisecond
	redhatDetailTimeout        = 60 * time.Minute
	redhatDetailBlockThreshold = 15
	// redhatRecentDays widens detail fetching to CVEs disclosed recently even
	// when they have no affected_release yet (brand-new unfixed CVEs).
	redhatRecentDays = 90
	// redhatEnrichTTL is how long an already-fetched package_state enrichment
	// is considered fresh enough to skip re-fetching on a restart or refresh.
	redhatEnrichTTL = 24 * time.Hour
)

var redhatFeedURL = redhatAPIBase + "/cve.json"

// RedHatCVE is one record of the Red Hat Security Data API list endpoint.
type RedHatCVE struct {
	CVE                 string    `json:"CVE"`
	Severity            string    `json:"severity"`
	CVSS3Score          flexFloat `json:"cvss3_score"`
	CVSS3Vector         string    `json:"cvss3_scoring_vector"`
	CVSS2Score          flexFloat `json:"cvss_score"`
	PublicDate          string    `json:"public_date"`
	BugzillaDescription string    `json:"bugzilla_description"`
	ResourceURL         string    `json:"resource_url"`
	AffectedPackages    []string  `json:"affected_packages"`
}

// RedHatPackageState is one package_state entry of the per-CVE detail
// endpoint. It records products Red Hat has triaged but not necessarily fixed.
type RedHatPackageState struct {
	ProductName string `json:"product_name"`
	PackageName string `json:"package_name"`
	FixState    string `json:"fix_state"`
	CPE         string `json:"cpe"`
}

// RedHatCVEDetail is the per-CVE detail record. The list endpoint has no
// package_state, so unfixed products are only available here.
type RedHatCVEDetail struct {
	Name            string               `json:"name"`
	ThreatSeverity  string               `json:"threat_severity"`
	PackageState    []RedHatPackageState `json:"package_state"`
	AffectedRelease []struct {
		Package string `json:"package"`
		CPE     string `json:"cpe"`
	} `json:"affected_release"`
}

// flexFloat tolerates the API returning either a JSON number or an empty
// string for numeric fields such as cvss3_score.
type flexFloat float64

func (f *flexFloat) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		*f = 0
		return nil
	}
	*f = flexFloat(v)
	return nil
}

// RedHatClient fetches Red Hat security data.
type RedHatClient struct {
	http *http.Client
}

// NewRedHatClient returns a client with a generous timeout because pages are
// large.
func NewRedHatClient() *RedHatClient {
	return &RedHatClient{http: &http.Client{Timeout: 120 * time.Second}}
}

// FetchAll paginates through the full CVE list. Results are ordered by date.
func (c *RedHatClient) FetchAll(ctx context.Context) ([]RedHatCVE, error) {
	cves, _, _, err := c.FetchAllWithState(ctx, FeedState{})
	return cves, err
}

// FetchAllWithState paginates through the full CVE list. The Cursor field of
// st is used as the after= date; cached validators are sent with the first
// page so an unchanged feed can be skipped with a single 304.
func (c *RedHatClient) FetchAllWithState(ctx context.Context, st FeedState) ([]RedHatCVE, FeedState, bool, error) {
	after := st.Cursor
	if after == "" {
		after = redhatStartDate
	}
	firstURL := fmt.Sprintf("%s?after=%s&per_page=%d&page=1",
		redhatFeedURL, after, redhatPageSize)
	body, status, next, err := conditionalGet(ctx, c.http, http.MethodGet,
		firstURL, nil, map[string]string{
			"Accept":     "application/json",
			"User-Agent": "vuln-scanner/1.0",
		}, st)
	if err != nil {
		return nil, next, false, err
	}
	if status == http.StatusNotModified {
		return nil, next, true, nil
	}
	if status != http.StatusOK {
		return nil, next, false, fmt.Errorf("redhat fetch page 1: status %d: %s", status, truncate(body, 200))
	}

	var page []RedHatCVE
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, next, false, fmt.Errorf("redhat decode page 1: %w", err)
	}
	var all []RedHatCVE
	all = append(all, page...)
	for pageNum := 2; len(page) == redhatPageSize && pageNum <= redhatMaxPages; pageNum++ {
		u := fmt.Sprintf("%s?after=%s&per_page=%d&page=%d",
			redhatFeedURL, after, redhatPageSize, pageNum)
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, next, false, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "vuln-scanner/1.0")
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, next, false, fmt.Errorf("redhat fetch page %d: %w", pageNum, err)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, next, false, fmt.Errorf("redhat read page %d: %w", pageNum, readErr)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, next, false, fmt.Errorf("redhat fetch page %d: status %d: %s",
				pageNum, resp.StatusCode, truncate(body, 200))
		}
		var pageData []RedHatCVE
		if err := json.Unmarshal(body, &pageData); err != nil {
			return nil, next, false, fmt.Errorf("redhat decode page %d: %w", pageNum, err)
		}
		all = append(all, pageData...)
		page = pageData
	}
	return all, next, false, nil
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}

// FetchDetail fetches the per-CVE detail record including package_state.
// A 404 (CVE present in the list but absent from detail) returns (nil, nil).
func (c *RedHatClient) FetchDetail(ctx context.Context, cveID string) (*RedHatCVEDetail, error) {
	u := fmt.Sprintf("%s/cve/%s.json", redhatAPIBase, url.PathEscape(cveID))
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vuln-scanner/1.0")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("redhat detail %s: status %d: %s", cveID, resp.StatusCode, body)
	}
	var d RedHatCVEDetail
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("redhat decode detail %s: %w", cveID, err)
	}
	return &d, nil
}

// redhatDetailIDs returns the CVE IDs whose detail records should be fetched:
// every CVE that produces a stored entry for the present RHEL majors, plus
// every CVE disclosed in the last redhatRecentDays (which may be affected but
// not yet have any affected_release), minus CVEs already enriched within the
// freshness window. The detail endpoint is the only place package_state
// lives, so this set bounds the crawl instead of fetching all CVEs the list
// returns.
func redhatDetailIDs(cves []RedHatCVE, majors map[string]bool, now time.Time, skip map[string]bool) []string {
	cutoff := now.AddDate(0, 0, -redhatRecentDays)
	seen := make(map[string]bool)
	var ids []string
	for _, c := range cves {
		if c.CVE == "" || seen[c.CVE] || skip[c.CVE] {
			continue
		}
		published := parseRedHatDate(c.PublicDate, now)
		if published.Before(cutoff) && !redhatAffectedHasMajor(c.AffectedPackages, majors) {
			continue
		}
		seen[c.CVE] = true
		ids = append(ids, c.CVE)
	}
	return ids
}

// redhatAffectedHasMajor reports whether any affected_packages entry parses to
// one of the present RHEL majors.
func redhatAffectedHasMajor(packages []string, majors map[string]bool) bool {
	for _, p := range packages {
		if _, _, major, ok := parseRedHatNEVRA(p); ok && majors[major] {
			return true
		}
	}
	return false
}

// fetchRedHatDetails fetches per-CVE details with a bounded worker pool and a
// global rate limiter. Failures are logged and skipped; when the WAF starts
// returning 403s the remaining crawl is aborted, so a partial detail fetch
// degrades gracefully to list-only entries. The returned id list records the
// CVEs whose detail request completed (found or 404), so callers can track
// crawl freshness.
func fetchRedHatDetails(ctx context.Context, client *RedHatClient, ids []string) (map[string]*RedHatCVEDetail, []string) {
	details := make(map[string]*RedHatCVEDetail)
	if len(ids) == 0 {
		return details, nil
	}

	ctx, cancel := context.WithTimeout(ctx, redhatDetailTimeout)
	defer cancel()
	sem := make(chan struct{}, redhatDetailConcurrency)
	limiter := time.NewTicker(redhatDetailInterval)
	defer limiter.Stop()
	var wg sync.WaitGroup
	var mu sync.Mutex
	blocks := 0
	fetchedIDs := make([]string, 0, len(ids))
	for _, id := range ids {
		select {
		case <-limiter.C:
		case <-ctx.Done():
			goto done
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			goto done
		}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			d, err := client.FetchDetail(ctx, id)
			if err != nil {
				mu.Lock()
				if strings.Contains(err.Error(), "403") {
					blocks++
					if blocks >= redhatDetailBlockThreshold {
						cancel()
					}
				} else {
					slog.Warn("loader: redhat detail fetch failed", "cve", id, "error", err)
				}
				mu.Unlock()
				return
			}
			mu.Lock()
			fetchedIDs = append(fetchedIDs, id)
			if d != nil {
				details[id] = d
			}
			mu.Unlock()
		}(id)
	}
done:
	wg.Wait()
	if blocks > 0 {
		slog.Warn("loader: redhat detail fetch rate-limited",
			"blocked", blocks, "fetched", len(details))
	}
	return details, fetchedIDs
}

// RefreshRedHat fetches the Red Hat CVE feed and upserts entries for the RHEL
// major versions currently present among agents. The source is "redhat" and
// each feed row is scoped to one CVE and one RHEL major.
func (l *Loader) RefreshRedHat(ctx context.Context, agents []AgentSnapshotSummary) {
	if !l.redhatMu.TryLock() {
		slog.Info("loader: redhat refresh already running, skipping")
		return
	}
	defer l.redhatMu.Unlock()

	majors := presentRedHatMajors(agents)
	if len(majors) == 0 {
		return
	}
	slog.Info("loader: refreshing redhat feed", "majors", sortedKeys(majors))

	client := NewRedHatClient()
	st, err := loadFeedState(ctx, l.store, "redhat", "list")
	if err != nil {
		slog.Warn("loader: redhat state load failed", "error", err)
	}
	cves, next, notModified, err := client.FetchAllWithState(ctx, st)
	if err != nil {
		st.markError(err)
		_ = saveFeedState(ctx, l.store, "redhat", "list", st)
		slog.Warn("loader: redhat fetch failed", "error", err)
		return
	}
	if notModified {
		st.markSuccess(0)
		_ = saveFeedState(ctx, l.store, "redhat", "list", st)
		slog.Info("loader: redhat list unchanged, skipping")
		return
	}

	// package_state is only exposed by the per-CVE detail endpoint, so fetch
	// details for the CVEs we store plus recently disclosed CVEs. The crawl is
	// rate-limited and aborts on WAF blocks, degrading to list-only entries.
	now := time.Now().UTC()
	var maxDate time.Time
	for _, c := range cves {
		pub := parseRedHatDate(c.PublicDate, now)
		if pub.After(maxDate) {
			maxDate = pub
		}
	}
	if !maxDate.IsZero() {
		next.Cursor = maxDate.AddDate(0, 0, -7).Format("2006-01-02")
	}
	next.markSuccess(len(cves))
	if err := saveFeedState(ctx, l.store, "redhat", "list", next); err != nil {
		slog.Warn("loader: redhat state save failed", "error", err)
	}
	enriched, err := l.feed.RedHatEnriched(ctx)
	if err != nil {
		enriched = nil
		slog.Warn("loader: redhat enriched lookup failed", "error", err)
	}
	fresh, err := l.feed.RedHatDetailFresh(ctx, redhatEnrichTTL)
	if err != nil {
		fresh = nil
		slog.Warn("loader: redhat detail freshness lookup failed", "error", err)
	}
	detailIDs := redhatDetailIDs(cves, majors, now, fresh)
	details, fetchedIDs := fetchRedHatDetails(ctx, client, detailIDs)
	detailCount := 0
	for _, d := range details {
		if len(d.PackageState) > 0 {
			detailCount++
		}
	}
	slog.Info("loader: redhat details fetched", "requested", len(detailIDs),
		"details", len(details), "with_package_state", detailCount,
		"skipped_fresh", len(fresh))
	if err := l.feed.MarkRedHatDetailsFetched(ctx, fetchedIDs); err != nil {
		slog.Warn("loader: redhat detail fetch mark failed", "error", err)
	}
	if err := l.feed.PruneRedHatDetailFetch(ctx, 60*24*time.Hour); err != nil {
		slog.Warn("loader: redhat detail fetch prune failed", "error", err)
	}

	var entries []*FeedEntry
	for _, c := range cves {
		if c.CVE == "" {
			continue
		}
		perMajor := buildRedHatAffected(c.AffectedPackages, majors)
		if d := details[c.CVE]; d != nil {
			mergeRedHatPackageState(perMajor, d, majors)
		} else {
			// Preserve package_state enrichment from the previous refresh so
			// skipping a fresh detail crawl does not lose unfixed data.
			for _, major := range sortedKeys(majors) {
				if old, ok := enriched[c.CVE+"/rhel"+major]; ok {
					mergeExistingFixStates(perMajor, old.Affected, major)
				}
			}
		}
		if len(perMajor) == 0 {
			continue
		}
		severity, score := redHatSeverity(c)
		published := parseRedHatDate(c.PublicDate, now)
		for _, major := range sortedKeys(perMajor) {
			affectedJSON, _ := json.Marshal(perMajor[major])
			key := c.CVE + "/rhel" + major
			entries = append(entries, &FeedEntry{
				Source:      "redhat",
				SourceKey:   key,
				CVEID:       c.CVE,
				CVEURL:      redhatCVEPage + c.CVE,
				Affected:    affectedJSON,
				Severity:    severity,
				CVSSScore:   score,
				Summary:     c.BugzillaDescription,
				PublishedAt: published,
				FetchedAt:   now,
				TTLSeconds:  int(l.cfg.RedHatTTL.Seconds()),
			})
		}
	}
	if len(entries) == 0 {
		slog.Info("loader: redhat refresh done", "cves", len(cves), "entries", 0)
		return
	}
	if err := l.feed.BatchUpsert(ctx, entries); err != nil {
		slog.Warn("loader: redhat upsert failed", "error", err)
		return
	}
	slog.Info("loader: redhat refreshed", "cves", len(cves), "entries", len(entries))
}

var redhatElRe = regexp.MustCompile(`(?:^|[._])el(7|8|9|10)(?:[._]([0-9]+)|$)`)

// parseRedHatNEVRA parses an affected_packages entry such as
// "curl-0:7.76.1-26.el9_3.2" into name, EVR and RHEL major. Entries that are
// container paths, module streams or non-base products are rejected.
func parseRedHatNEVRA(s string) (name, evr, major string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "/") {
		return "", "", "", false
	}
	relIdx := strings.LastIndexByte(s, '-')
	if relIdx <= 0 || relIdx == len(s)-1 {
		return "", "", "", false
	}
	release := s[relIdx+1:]
	m := redhatElRe.FindStringSubmatch(release)
	if m == nil {
		return "", "", "", false
	}
	rest := s[:relIdx]
	verIdx := strings.LastIndexByte(rest, '-')
	if verIdx <= 0 {
		return "", "", "", false
	}
	name = rest[:verIdx]
	version := rest[verIdx+1:]
	if name == "" || version == "" || strings.ContainsAny(name, "/:") {
		return "", "", "", false
	}
	return name, version + "-" + release, m[1], true
}

// buildRedHatAffected converts affected_packages into per-major affected
// product lists, keeping distinct (name, EVR) pairs.
func buildRedHatAffected(packages []string, majors map[string]bool) map[string][]AffectedProduct {
	out := make(map[string][]AffectedProduct)
	seen := make(map[string]bool)
	for _, p := range packages {
		name, evr, major, ok := parseRedHatNEVRA(p)
		if !ok || !majors[major] {
			continue
		}
		key := major + "\x00" + name + "\x00" + evr
		if seen[key] {
			continue
		}
		seen[key] = true
		out[major] = append(out[major], AffectedProduct{
			Name:      name,
			FixedIn:   evr,
			Ecosystem: "Red Hat",
			Major:     major,
		})
	}
	for _, products := range out {
		sort.Slice(products, func(i, j int) bool {
			if products[i].Name != products[j].Name {
				return products[i].Name < products[j].Name
			}
			return products[i].FixedIn < products[j].FixedIn
		})
	}
	return out
}

// redHatUnfixedStates are package_state values meaning "affected, no
// published fix": the CVE is real for the product but Red Hat ships no fix.
var redHatUnfixedStates = map[string]bool{
	"affected":            true,
	"will not fix":        true,
	"fix deferred":        true,
	"under investigation": true,
}

var redhatELCPERe = regexp.MustCompile(`cpe:/o:redhat:enterprise_linux:(\d+)`)

// redHatCPEMajor extracts the RHEL major from a package_state CPE such as
// "cpe:/o:redhat:enterprise_linux:9"; empty when the CPE is not base RHEL.
func redHatCPEMajor(cpe string) string {
	m := redhatELCPERe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(cpe)))
	if m == nil {
		return ""
	}
	return m[1]
}

// mergeRedHatPackageState appends triaged-but-unfixed products to the
// per-major affected lists built from affected_packages. A package that also
// has a published fix keeps its fixed threshold; matching prefers it.
func mergeRedHatPackageState(perMajor map[string][]AffectedProduct, d *RedHatCVEDetail, majors map[string]bool) {
	if d == nil {
		return
	}
	seen := make(map[string]bool)
	for _, ps := range d.PackageState {
		state := strings.ToLower(strings.TrimSpace(ps.FixState))
		if !redHatUnfixedStates[state] {
			continue
		}
		major := redHatCPEMajor(ps.CPE)
		if major == "" || !majors[major] {
			continue
		}
		name := strings.TrimSpace(ps.PackageName)
		if name == "" {
			continue
		}
		key := major + "\x00" + name + "\x00" + state
		if seen[key] {
			continue
		}
		seen[key] = true
		perMajor[major] = append(perMajor[major], AffectedProduct{
			Name:      name,
			FixState:  ps.FixState,
			Ecosystem: "Red Hat",
			Major:     major,
		})
	}
}

// mergeExistingFixStates reapplies previously stored package_state products
// (Affected / Will not fix / Fix deferred / Under investigation) to a rebuilt
// per-major list. It is used when a fresh detail crawl was skipped, so a
// restart or refresh never loses unfixed data.
func mergeExistingFixStates(perMajor map[string][]AffectedProduct, raw []byte, major string) {
	var old []AffectedProduct
	if err := json.Unmarshal(raw, &old); err != nil {
		return
	}
	seen := make(map[string]bool)
	for _, ap := range old {
		if ap.FixState == "" || (ap.Major != "" && ap.Major != major) {
			continue
		}
		key := strings.ToLower(ap.Name) + "\x00" + strings.ToLower(ap.FixState)
		if seen[key] {
			continue
		}
		seen[key] = true
		ap.Major = major
		perMajor[major] = append(perMajor[major], ap)
	}
}

// presentRedHatMajors returns the set of RHEL major versions (7-10) present
// among agents. CentOS Stream is excluded because its package versions do not
// track RHEL exactly.
func presentRedHatMajors(agents []AgentSnapshotSummary) map[string]bool {
	out := make(map[string]bool)
	for _, ag := range agents {
		lower := strings.ToLower(ag.OSType)
		isRHEL := strings.Contains(lower, "red hat") || strings.Contains(lower, "centos") ||
			strings.Contains(lower, "rocky") || strings.Contains(lower, "alma")
		if !isRHEL {
			continue
		}
		if strings.Contains(lower, "centos") && strings.Contains(lower, "stream") {
			continue
		}
		major := majorFromVersion(ag.OSVersion)
		if majorInt, err := strconv.Atoi(major); err == nil && majorInt >= 7 && majorInt <= 10 {
			out[major] = true
		}
	}
	return out
}

func redHatSeverity(c RedHatCVE) (string, float64) {
	sev := strings.ToLower(c.Severity)
	var s string
	switch sev {
	case "critical":
		s = "CRITICAL"
	case "important":
		s = "HIGH"
	case "moderate":
		s = "MEDIUM"
	case "low":
		s = "LOW"
	default:
		s = "MEDIUM"
	}
	score := float64(c.CVSS3Score)
	if score <= 0 {
		score = float64(c.CVSS2Score)
	}
	return s, score
}

func parseRedHatDate(raw string, fallback time.Time) time.Time {
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	return fallback
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// matchRedHatEntry evaluates one redhat feed row against an agent. The row is
// already scoped to one RHEL major; entries are further scoped to the agent's
// minor where possible. Only exact package name matches are considered.
func matchRedHatEntry(e *FeedEntry, agentOS, agentVersion string, names []string,
	assetVersions map[string]string, lowerNames map[string]bool) []MatchedCVE {
	lowerOS := strings.ToLower(agentOS)
	if !isRHELFamilyAgent(lowerOS) {
		return nil
	}
	if strings.Contains(lowerOS, "centos") && strings.Contains(lowerOS, "stream") {
		return nil
	}
	agentMajor := majorFromVersion(agentVersion)
	if agentMajor == "" {
		return nil
	}

	var affected []AffectedProduct
	if err := json.Unmarshal(e.Affected, &affected); err != nil {
		return nil
	}

	type group struct {
		name      string
		evrs      []string
		fixStates []string
	}
	byName := make(map[string]*group)
	var order []string
	for _, ap := range affected {
		n := strings.ToLower(strings.TrimSpace(ap.Name))
		if n == "" || !lowerNames[n] {
			continue
		}
		if ap.Major != "" && ap.Major != agentMajor {
			continue
		}
		g, exists := byName[n]
		if !exists {
			g = &group{name: n}
			byName[n] = g
			order = append(order, n)
		}
		if evr := strings.TrimSpace(ap.FixedIn); evr != "" {
			if !containsString(g.evrs, evr) {
				g.evrs = append(g.evrs, evr)
			}
			continue
		}
		if state := strings.TrimSpace(ap.FixState); state != "" && !containsString(g.fixStates, state) {
			g.fixStates = append(g.fixStates, state)
		}
	}

	var results []MatchedCVE
	for _, n := range order {
		g := byName[n]
		installed := assetVersions[n]
		if installed == "" {
			continue
		}
		if fixed := selectRedHatFixed(g.evrs, agentVersion); fixed != "" {
			status := "active"
			if compareRPMVersions(installed, fixed) >= 0 {
				status = "fixed"
			}
			results = append(results, MatchedCVE{
				CVEID:        e.CVEID,
				AssetName:    originalCaseName(n, names),
				AssetVersion: installed,
				FixedVersion: fixed,
				Severity:     e.Severity,
				CVSSScore:    e.CVSSScore,
				Summary:      e.Summary,
				Source:       e.Source,
				MatchStatus:  status,
			})
			continue
		}
		// package_state entries carry no fixed version. They are reported as
		// active vulnerabilities only for genuine RHEL agents; derived distros
		// (AlmaLinux/Rocky/CentOS) may backport fixes Red Hat does not ship.
		if len(g.fixStates) == 0 || !isRedHatAgent(lowerOS) {
			continue
		}
		results = append(results, MatchedCVE{
			CVEID:        e.CVEID,
			AssetName:    originalCaseName(n, names),
			AssetVersion: installed,
			Severity:     e.Severity,
			CVSSScore:    e.CVSSScore,
			Summary:      e.Summary,
			Source:       e.Source,
			FixState:     g.fixStates[0],
			MatchStatus:  "active",
		})
	}
	return results
}

// selectRedHatFixed picks the effective fixed EVR among all fixes published for
// a package in one RHEL major. Fixes matching the agent's minor win (earliest
// fix in that minor is the threshold); otherwise fixes without a minor win;
// otherwise the newest known fix is used as a conservative threshold to avoid
// false "fixed" verdicts when the agent's minor has no published fix.
func selectRedHatFixed(evrs []string, agentVersion string) string {
	if len(evrs) == 0 {
		return ""
	}
	minor := minorFromVersion(agentVersion)
	var candidates []string
	for _, e := range evrs {
		if minor != "" && releaseMinor(e) == minor {
			candidates = append(candidates, e)
		}
	}
	if len(candidates) == 0 && minor == "" {
		for _, e := range evrs {
			if releaseMinor(e) == "" {
				candidates = append(candidates, e)
			}
		}
	}
	if len(candidates) == 0 {
		// Conservative fallback: only the newest known fix clears the CVE.
		best := evrs[0]
		for _, e := range evrs[1:] {
			if compareRPMVersions(e, best) > 0 {
				best = e
			}
		}
		return best
	}
	best := candidates[0]
	for _, e := range candidates[1:] {
		if compareRPMVersions(e, best) < 0 {
			best = e
		}
	}
	return best
}

// releaseMinor extracts the minor version from an EVR release tag such as
// "26.el9_3.2" -> "3", "43.el8" -> "". An empty string means no minor.
func releaseMinor(evr string) string {
	_, _, release := splitRPMEVR(evr)
	m := redhatElRe.FindStringSubmatch(release)
	if m == nil {
		return ""
	}
	return m[2]
}

// rpmReleaseMajor extracts the elN major from an EVR release tag such as
// "26.el9_3.2" -> "9"; an empty string means the release carries no elN tag.
func rpmReleaseMajor(evr string) string {
	_, _, release := splitRPMEVR(evr)
	m := redhatElRe.FindStringSubmatch(release)
	if m == nil {
		return ""
	}
	return m[1]
}

// majorFromVersion returns the first dot-separated token of an OS version
// ("9.4" -> "9").
func majorFromVersion(version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		return ""
	}
	major, _, _ := strings.Cut(v, ".")
	return major
}

// minorFromVersion returns the second dot-separated token of an OS version
// ("9.4" -> "4", "9" -> "").
func minorFromVersion(version string) string {
	v := strings.TrimSpace(version)
	_, minor, ok := strings.Cut(v, ".")
	if !ok {
		return ""
	}
	minor, _, _ = strings.Cut(minor, ".")
	return minor
}

func isRHELFamilyAgent(lowerOS string) bool {
	return strings.Contains(lowerOS, "red hat") || strings.Contains(lowerOS, "centos") ||
		strings.Contains(lowerOS, "rocky") || strings.Contains(lowerOS, "alma")
}

// isRedHatAgent reports whether the agent OS is genuine Red Hat Enterprise
// Linux, as opposed to a RHEL-derived distro such as AlmaLinux, Rocky Linux
// or CentOS.
func isRedHatAgent(lowerOS string) bool {
	return strings.Contains(lowerOS, "red hat")
}

func originalCaseName(lowerName string, names []string) string {
	for _, n := range names {
		if strings.ToLower(n) == lowerName {
			return n
		}
	}
	return lowerName
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
