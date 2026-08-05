package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"vuln-scanner/internal/store"
)

type FeedEntry struct {
	ID          int64           `json:"id"`
	Source      string          `json:"source"`
	SourceKey   string          `json:"source_key"`
	CVEID       string          `json:"cve_id"`
	CVEURL      string          `json:"cve_url"`
	Affected    json.RawMessage `json:"affected"`
	FixedKB     string          `json:"fixed_kb"`
	FixedVer    string          `json:"fixed_ver"`
	Severity    string          `json:"severity"`
	CVSSScore   float64         `json:"cvss_score"`
	Summary     string          `json:"summary"`
	PublishedAt time.Time       `json:"published_at"`
	FetchedAt   time.Time       `json:"fetched_at"`
	TTLSeconds  int             `json:"ttl_seconds"`
}

type AffectedProduct struct {
	Name   string `json:"name"`
	Vendor string `json:"vendor,omitempty"`
	MinVer string `json:"min_ver,omitempty"`
	MaxVer string `json:"max_ver,omitempty"`
	// MinExclusive/MaxInclusive refine the range bounds. Nil keeps the
	// legacy semantics: min inclusive, max exclusive. Newly parsed NVD CPEs
	// set these explicitly when the source says otherwise.
	MinExclusive *bool  `json:"min_exclusive,omitempty"`
	MaxInclusive *bool  `json:"max_inclusive,omitempty"`
	FixedIn      string `json:"fixed_in,omitempty"`
	KBURL        string `json:"kb_url,omitempty"`
	FixState     string `json:"fix_state,omitempty"`
	ProductID    string `json:"product_id,omitempty"`
	Ecosystem    string `json:"ecosystem,omitempty"`
	CPE          string `json:"cpe,omitempty"`
	CpeVer       string `json:"cpe_ver,omitempty"`
	Major        string `json:"major,omitempty"`
}

type FeedManager struct {
	pool *pgxpool.Pool
}

func NewFeedManager(s *store.Store) *FeedManager {
	return &FeedManager{pool: s.Pool()}
}

func (f *FeedManager) Upsert(ctx context.Context, entry *FeedEntry) error {
	_, err := f.pool.Exec(ctx, `
		INSERT INTO cve_feed (source, source_key, cve_id, cve_url, affected, fixed_kb, fixed_ver,
			severity, cvss_score, summary, published_at, fetched_at, ttl_seconds)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (source, source_key, cve_id) DO UPDATE
		SET cve_url=$4, affected=$5, fixed_kb=$6, fixed_ver=$7,
			severity=$8, cvss_score=$9, summary=$10, published_at=$11, fetched_at=$12, ttl_seconds=$13
	`, entry.Source, entry.SourceKey, entry.CVEID, entry.CVEURL, entry.Affected,
		entry.FixedKB, entry.FixedVer, entry.Severity, entry.CVSSScore, entry.Summary,
		entry.PublishedAt, entry.FetchedAt, entry.TTLSeconds)
	return err
}

func (f *FeedManager) BatchUpsert(ctx context.Context, entries []*FeedEntry) error {
	if len(entries) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, e := range entries {
		batch.Queue(`
			INSERT INTO cve_feed (source, source_key, cve_id, cve_url, affected, fixed_kb, fixed_ver,
				severity, cvss_score, summary, published_at, fetched_at, ttl_seconds)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			ON CONFLICT (source, source_key, cve_id) DO UPDATE
			SET cve_url=$4, affected=$5, fixed_kb=$6, fixed_ver=$7,
				severity=$8, cvss_score=$9, summary=$10, published_at=$11, fetched_at=$12, ttl_seconds=$13
		`, e.Source, e.SourceKey, e.CVEID, e.CVEURL, e.Affected,
			e.FixedKB, e.FixedVer, e.Severity, e.CVSSScore, e.Summary,
			e.PublishedAt, e.FetchedAt, e.TTLSeconds)
	}
	br := f.pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < len(entries); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("batch upsert row %d: %w", i, err)
		}
	}
	return nil
}

func (f *FeedManager) QueryByKB(ctx context.Context, kbArticle string) ([]FeedEntry, error) {
	rows, err := f.pool.Query(ctx, `
		SELECT id, source, source_key, cve_id, cve_url, affected, fixed_kb, fixed_ver,
			severity, cvss_score, summary, published_at, fetched_at, ttl_seconds
		FROM cve_feed WHERE source='msrc' AND fixed_kb=$1
	`, kbArticle)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFeedRows(rows)
}

// MSRCKBInfo is one (KB, product, URL) triple extracted from the affected
// products of MSRC feed rows; it is the source for kb_metadata.
type MSRCKBInfo struct {
	KB          string
	ProductName string
	KBURL       string
}

// ListMSRCKBs returns the distinct per-product KB assignments from the MSRC
// feed, including the product name and remediation URL each KB came from.
func (f *FeedManager) ListMSRCKBs(ctx context.Context) ([]MSRCKBInfo, error) {
	rows, err := f.pool.Query(ctx, `
		SELECT DISTINCT a->>'fixed_in' AS kb, a->>'name' AS product_name, a->>'kb_url' AS kb_url
		FROM cve_feed, jsonb_array_elements(cve_feed.affected) AS a
		WHERE source='msrc'
		  AND jsonb_typeof(cve_feed.affected) = 'array'
		  AND a->>'fixed_in' IS NOT NULL AND a->>'fixed_in' <> ''
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MSRCKBInfo
	for rows.Next() {
		var info MSRCKBInfo
		var kbURL *string
		if err := rows.Scan(&info.KB, &info.ProductName, &kbURL); err != nil {
			return nil, err
		}
		if kbURL != nil {
			info.KBURL = *kbURL
		}
		out = append(out, info)
	}
	return out, rows.Err()
}

func (f *FeedManager) QueryBySourceKey(ctx context.Context, source, sourceKey string) ([]FeedEntry, error) {
	rows, err := f.pool.Query(ctx, `
		SELECT id, source, source_key, cve_id, cve_url, affected, fixed_kb, fixed_ver,
			severity, cvss_score, summary, published_at, fetched_at, ttl_seconds
		FROM cve_feed WHERE source=$1 AND source_key=$2
	`, source, sourceKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFeedRows(rows)
}

// RedHatEnrichedEntry carries previously stored redhat package_state
// enrichment so a refresh can preserve it without re-fetching details.
type RedHatEnrichedEntry struct {
	Affected  []byte
	FetchedAt time.Time
}

// RedHatEnriched returns redhat feed rows that already carry package_state
// enrichment, keyed by source_key.
func (f *FeedManager) RedHatEnriched(ctx context.Context) (map[string]RedHatEnrichedEntry, error) {
	rows, err := f.pool.Query(ctx, `
		SELECT source_key, affected, fetched_at FROM cve_feed
		WHERE source='redhat' AND affected::text LIKE '%fix_state%'
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]RedHatEnrichedEntry)
	for rows.Next() {
		var e RedHatEnrichedEntry
		var key string
		if err := rows.Scan(&key, &e.Affected, &e.FetchedAt); err != nil {
			return nil, err
		}
		out[key] = e
	}
	return out, rows.Err()
}

// RedHatDetailFresh returns CVE IDs whose per-CVE detail was fetched within
// the given freshness window, keyed for O(1) lookup.
func (f *FeedManager) RedHatDetailFresh(ctx context.Context, ttl time.Duration) (map[string]bool, error) {
	rows, err := f.pool.Query(ctx, `
		SELECT cve_id FROM redhat_detail_fetch
		WHERE fetched_at > now() - ($1 * interval '1 second')
	`, int64(ttl.Seconds()))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// MarkRedHatDetailsFetched records the fetch time for the given CVE IDs so a
// later refresh can skip CVEs whose detail was crawled recently.
func (f *FeedManager) MarkRedHatDetailsFetched(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, id := range ids {
		batch.Queue(`
			INSERT INTO redhat_detail_fetch (cve_id, fetched_at) VALUES ($1, now())
			ON CONFLICT (cve_id) DO UPDATE SET fetched_at = EXCLUDED.fetched_at
		`, id)
	}
	br := f.pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < len(ids); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("mark redhat detail fetch row %d: %w", i, err)
		}
	}
	return nil
}

// PruneRedHatDetailFetch removes fetch markers older than the given window.
func (f *FeedManager) PruneRedHatDetailFetch(ctx context.Context, olderThan time.Duration) error {
	_, err := f.pool.Exec(ctx, `
		DELETE FROM redhat_detail_fetch WHERE fetched_at < now() - ($1 * interval '1 second')
	`, int64(olderThan.Seconds()))
	return err
}

func (f *FeedManager) QueryExpired(ctx context.Context, source string) ([]string, error) {
	rows, err := f.pool.Query(ctx, `
		SELECT DISTINCT source_key FROM cve_feed
		WHERE source=$1 AND fetched_at + (ttl_seconds * interval '1 second') < now()
	`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (f *FeedManager) SourceMonthExists(ctx context.Context, sourceKey string) (bool, error) {
	var exists bool
	err := f.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM cve_feed WHERE source='msrc' AND source_key=$1)
	`, sourceKey).Scan(&exists)
	return exists, err
}

func (f *FeedManager) DeleteBySourceKey(ctx context.Context, source, sourceKey string) error {
	_, err := f.pool.Exec(ctx, `
		DELETE FROM cve_feed WHERE source=$1 AND source_key=$2
	`, source, sourceKey)
	return err
}

func (f *FeedManager) DeleteAllBySource(ctx context.Context, source string) error {
	_, err := f.pool.Exec(ctx, `DELETE FROM cve_feed WHERE source=$1`, source)
	return err
}

func (f *FeedManager) HasFreshEntries(ctx context.Context, source string, name string) (bool, error) {
	var exists bool
	err := f.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM cve_feed WHERE source=$1
			AND fetched_at + (ttl_seconds * interval '1 second') >= now()
			AND EXISTS(
				SELECT 1 FROM jsonb_array_elements(affected) AS a
				WHERE a->>'name' ILIKE '%' || $2 || '%'
			)
		)
	`, source, name).Scan(&exists)
	return exists, err
}

func scanFeedRows(rows pgx.Rows) ([]FeedEntry, error) {
	var entries []FeedEntry
	for rows.Next() {
		var e FeedEntry
		if err := rows.Scan(&e.ID, &e.Source, &e.SourceKey, &e.CVEID, &e.CVEURL,
			&e.Affected, &e.FixedKB, &e.FixedVer, &e.Severity, &e.CVSSScore,
			&e.Summary, &e.PublishedAt, &e.FetchedAt, &e.TTLSeconds); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (f *FeedManager) MatchAssets(ctx context.Context, softwareNames []string, msrcNames []string,
	assetVersions, msrcVersions map[string]string, installedKBs map[string]bool,
	agentOS, agentVersion, agentArch, osAssetName string) ([]MatchedCVE, error) {
	if len(softwareNames) == 0 {
		return nil, nil
	}

	var allMatched []MatchedCVE
	seen := make(map[string]bool)

	for _, source := range []string{"debian", "msrc", "redhat", "nvd", "osv"} {
		matches := f.matchByName(ctx, source, softwareNames, msrcNames,
			assetVersions, msrcVersions, installedKBs, agentOS, agentVersion, agentArch, osAssetName)
		for _, m := range matches {
			key := m.CVEID + "|" + m.AssetName
			if !seen[key] {
				seen[key] = true
				allMatched = append(allMatched, m)
			}
		}
	}

	return allMatched, nil
}

func (f *FeedManager) matchByName(ctx context.Context, source string, names, msrcNames []string,
	assetVersions, msrcVersions map[string]string, installedKBs map[string]bool,
	agentOS, agentVersion, agentArch, osAssetName string) []MatchedCVE {
	if len(names) == 0 {
		return nil
	}

	// MSRC must only be matched against Windows OS/package assets. SCA names
	// (npm/go-mod/pypi/... directories) are excluded here to stop arbitrary
	// directory names from producing Windows patch recommendations.
	queryNames := names
	queryVersions := assetVersions
	if source == "msrc" && len(msrcNames) > 0 {
		queryNames = msrcNames
		queryVersions = msrcVersions
	}

	queryKBs := make([]string, 0, len(installedKBs))
	for kb := range installedKBs {
		queryKBs = append(queryKBs, kb)
	}

	searchNames := dedupStrings(queryNames)

	rows, err := f.pool.Query(ctx, `
		SELECT e.cve_id, e.cve_url, e.affected, e.fixed_kb, e.fixed_ver,
			e.severity, e.cvss_score, e.summary, e.source
		FROM cve_feed e
		WHERE e.source = $1
		AND jsonb_typeof(e.affected) = 'array'
		AND EXISTS (
			SELECT 1 FROM jsonb_array_elements(e.affected) AS a
			WHERE a->>'name' <> ''
			  AND (a->>'name' ILIKE ANY(SELECT '%' || n || '%' FROM unnest($2::text[]) AS n WHERE n <> ''))
		)
		ORDER BY
			CASE WHEN e.fixed_kb = ANY($3) THEN 0 ELSE 1 END,
			e.cvss_score DESC NULLS LAST,
			e.cve_id ASC,
			e.id ASC
		LIMIT CASE WHEN $1 = 'msrc' THEN 20000 ELSE 5000 END
	`, source, searchNames, queryKBs)
	if err != nil {
		slog.Error("matchByName query failed", "error", err, "names", len(names))
		return nil
	}
	defer rows.Close()

	lowerNames := make(map[string]bool, len(queryNames))
	for _, n := range queryNames {
		lowerNames[strings.ToLower(n)] = true
	}

	agentCPEIndex := buildAgentCPEIndex(queryNames, queryVersions)

	var results []MatchedCVE
	for rows.Next() {
		var e FeedEntry
		if err := rows.Scan(&e.CVEID, &e.CVEURL, &e.Affected, &e.FixedKB, &e.FixedVer,
			&e.Severity, &e.CVSSScore, &e.Summary, &e.Source); err != nil {
			continue
		}

		if e.Source == "redhat" {
			results = append(results, matchRedHatEntry(&e, agentOS, agentVersion,
				names, assetVersions, lowerNames)...)
			continue
		}

		var affected []AffectedProduct
		json.Unmarshal(e.Affected, &affected)
		for _, ap := range affected {
			if ap.Name == "" {
				continue
			}
			if !cpeMatches(ap, e.Source, agentCPEIndex, lowerNames) {
				continue
			}
			if !isRelevantProduct(ap, e.Source, agentOS, agentVersion, agentArch, lowerNames) {
				continue
			}
			status := "active"
			kb, kbURL := "", ""
			if e.Source == "msrc" {
				// Per-product KB from the CVRF remediation mapping; the
				// fallback e.FixedKB must not be smeared over products that
				// have their own remediation (or none).
				kb = ap.FixedIn
				kbURL = ap.KBURL
				if kb != "" && installedKBs != nil && isKBFixed(kb, installedKBs) {
					status = "fixed"
				}
			}
			installedVer := findInstalledVersionEco(ap.Name, ap.Ecosystem, queryVersions)
			if e.Source != "msrc" && e.Source != "debian" {
				hasRange := ap.MinVer != "" || ap.MaxVer != "" || ap.FixedIn != ""
				if !hasRange {
					continue
				}
				if installedVer == "" {
					continue
				}
				if !isVersionAffected(installedVer, ap) {
					continue
				}
				fixedVer := ap.FixedIn
				if fixedVer == "" {
					fixedVer = ap.MaxVer
				}
				if fixedVer != "" {
					if isDpkgEcosystem(ap.Ecosystem) {
						if compareDpkgVersions(installedVer, fixedVer) >= 0 {
							status = "fixed"
						}
					} else if isAPKEcosystem(ap.Ecosystem) {
						if apkVersionCompare(installedVer, fixedVer) >= 0 {
							status = "fixed"
						}
					} else if isRPMEcosystem(ap.Ecosystem) {
						if compareRPMVersions(installedVer, fixedVer) >= 0 {
							status = "fixed"
						}
					} else if compareVersions(installedVer, fixedVer) >= 0 {
						status = "fixed"
					}
				}
			}
			fixVer := ""
			if e.Source == "msrc" {
				fixVer = ap.FixedIn
			} else {
				fixVer = firstNonEmpty(e.FixedKB, e.FixedVer)
			}
			if fixVer == "" && e.Source != "msrc" {
				fixVer = firstNonEmpty(ap.FixedIn, ap.MaxVer)
			}
			assetName := resolveAssetName(e.Source, ap, agentCPEIndex, queryVersions, osAssetName)
			assetLower := strings.ToLower(assetName)
			for _, n := range queryNames {
				if strings.ToLower(n) == assetLower {
					assetName = n
					break
				}
			}
			if installedVer == "" {
				if v, ok := queryVersions[strings.ToLower(assetName)]; ok {
					installedVer = v
				}
			}

			results = append(results, MatchedCVE{
				CVEID:        e.CVEID,
				AssetName:    assetName,
				AssetVersion: installedVer,
				FixedVersion: fixVer,
				KBArticle:    kb,
				KBURL:        kbURL,
				CpeVer:       ap.CpeVer,
				OSProduct:    e.Source == "msrc" && isMSRCOSProductName(ap.Name),
				Severity:     e.Severity,
				CVSSScore:    e.CVSSScore,
				Summary:      e.Summary,
				Source:       e.Source,
				MatchStatus:  status,
			})
		}
	}
	return results
}

func resolveAssetName(source string, ap AffectedProduct, agentCPEIndex, assetVersions map[string]string, osAssetName string) string {
	// Exact package-name matches always win (e.g. "musl" must not resolve to
	// "musl-utils" just because the latter contains the former).
	lower := strings.ToLower(ap.Name)
	for _, name := range sortedMapKeys(assetVersions) {
		if strings.ToLower(name) == lower {
			return name
		}
	}
	if source == "msrc" || source == "nvd" {
		if source == "msrc" {
			isOS := ap.CPE != "" && extractCPEPart(ap.CPE) == "o"
			if !isOS && ap.CPE == "" {
				lower := strings.ToLower(ap.Name)
				isOS = strings.HasPrefix(lower, "windows ") && (strings.Contains(lower, " version ") ||
					strings.Contains(lower, " for ") && !strings.Contains(lower, "server"))
			}
			if isOS {
				if osAssetName != "" {
					return osAssetName
				}
				for _, name := range sortedMapKeys(assetVersions) {
					lower := strings.ToLower(name)
					if strings.HasPrefix(lower, "windows ") {
						parts := strings.SplitN(lower, " ", 3)
						if len(parts) >= 2 {
							switch parts[1] {
							case "11", "10", "8", "8.1", "7", "server":
								return name
							}
						}
					}
				}
			}
		}
		cpeProduct := strings.ToLower(ap.Name)
		if ap.CPE != "" {
			cpeProduct = strings.ToLower(extractCPEProduct(ap.CPE))
		}
		if matchedKey := findMatchingKey(cpeProduct, agentCPEIndex); matchedKey != "" {
			return matchedKey
		}
	}
	lower = strings.ToLower(ap.Name)
	for _, name := range sortedMapKeys(assetVersions) {
		if name != "" && len(name) >= 5 && (strings.Contains(lower, name) || strings.Contains(name, lower)) {
			return name
		}
	}
	return ap.Name
}

func findInstalledVersion(affectedName string, assetVersions map[string]string) string {
	lower := strings.ToLower(strings.TrimSpace(affectedName))
	if lower == "" || len(assetVersions) == 0 {
		return ""
	}

	names := make([]string, 0, len(assetVersions))
	for name := range assetVersions {
		names = append(names, name)
	}
	sort.Strings(names)

	// 1. Exact (case-insensitive) match is always preferred.
	for _, name := range names {
		if strings.ToLower(name) == lower {
			return assetVersions[name]
		}
	}

	// 2. Whole-token match: "7-zip" matches "7-Zip 23.01"; "git" does not
	// match "gitea" or "github".
	affectedTokens := versionNameTokens(lower)
	for _, name := range names {
		if tokenOverlap(affectedTokens, versionNameTokens(strings.ToLower(name))) {
			return assetVersions[name]
		}
	}

	// 3. Boundary prefix match: "git" matches "git-scm" but not "gitea".
	for _, name := range names {
		ln := strings.ToLower(name)
		if boundaryPrefix(ln, lower) || boundaryPrefix(lower, ln) {
			return assetVersions[name]
		}
	}
	return ""
}

// findInstalledVersionEco resolves the installed version, using exact package
// name matching for RPM ecosystems so that e.g. "openssl" never resolves to
// "openssl-libs".
func findInstalledVersionEco(affectedName, ecosystem string, assetVersions map[string]string) string {
	if isAPKEcosystem(ecosystem) || isRPMEcosystem(ecosystem) {
		if v, ok := assetVersions[strings.ToLower(strings.TrimSpace(affectedName))]; ok {
			return v
		}
		return ""
	}
	return findInstalledVersion(affectedName, assetVersions)
}

func versionNameTokens(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
}

func tokenOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func boundaryPrefix(s, prefix string) bool {
	if !strings.HasPrefix(s, prefix) || len(s) == len(prefix) {
		return false
	}
	next := s[len(prefix)]
	return !(next >= 'a' && next <= 'z' || next >= '0' && next <= '9')
}

func isVersionAffected(installed string, ap AffectedProduct) bool {
	minExclusive := ap.MinExclusive != nil && *ap.MinExclusive
	maxInclusive := ap.MaxInclusive != nil && *ap.MaxInclusive

	if ap.MinVer != "" {
		cmp := compareVersionForEcosystem(installed, ap.MinVer, ap.Ecosystem)
		if minExclusive {
			if cmp <= 0 {
				return false
			}
		} else if cmp < 0 {
			return false
		}
	}
	if ap.MaxVer != "" {
		cmp := compareVersionForEcosystem(installed, ap.MaxVer, ap.Ecosystem)
		if maxInclusive {
			if cmp > 0 {
				return false
			}
		} else if cmp >= 0 {
			return false
		}
	}
	return true
}

func compareVersionForEcosystem(a, b, ecosystem string) int {
	switch {
	case isDpkgEcosystem(ecosystem):
		return compareDpkgVersions(a, b)
	case isAPKEcosystem(ecosystem):
		return apkVersionCompare(a, b)
	case isRPMEcosystem(ecosystem):
		return compareRPMVersions(a, b)
	default:
		return compareVersions(a, b)
	}
}

func isDpkgEcosystem(ecosystem string) bool {
	return strings.HasPrefix(strings.ToLower(ecosystem), "debian") || strings.HasPrefix(strings.ToLower(ecosystem), "ubuntu")
}

func cleanVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if idx := strings.IndexByte(v, ':'); idx > 0 {
		v = v[idx+1:]
	}
	if idx := strings.Index(v, "-"); idx > 0 {
		v = v[:idx]
	}
	if idx := strings.Index(v, "+"); idx > 0 {
		v = v[:idx]
	}
	return v
}

func nameMatches(affectedName string, lowerNames map[string]bool) bool {
	lower := strings.ToLower(affectedName)
	if len(lower) < 3 {
		return false
	}
	if stopWords[lower] {
		return false
	}
	words := splitWords(lower)
	for n := range lowerNames {
		searchWords := splitWords(n)
		if anyWordMatch(words, searchWords) {
			return true
		}
	}
	return false
}

// isMSRCOSProductName reports whether an MSRC affected product is a Windows
// OS entry (e.g. "Windows 10 Version 1809 for x64-based Systems", "Windows
// Server 2019"). Such entries are matched against the agent OS itself rather
// than an installed software name.
func isMSRCOSProductName(productName string) bool {
	lower := strings.ToLower(productName)
	if !strings.HasPrefix(lower, "windows ") {
		return false
	}
	// Hardware-lab/toolkit products are not the operating system even though
	// they start with "Windows " (HLK, ADK, WDK, PE add-on).
	for _, toolkit := range []string{" hlk", " adk", " wdk", "pe add-on", "driver kit"} {
		if strings.Contains(lower, toolkit) {
			return false
		}
	}
	return strings.Contains(lower, " version ") || strings.Contains(lower, " for ") ||
		strings.Contains(lower, " server")
}

// msrcPlatformTokens are product-name words that describe the target platform
// or hardware rather than the software family. They are removed before the
// installed-asset token comparison so "for Mac"/"for Android" suffixes cannot
// leak into the family tokens.
var msrcPlatformTokens = map[string]bool{
	"mac": true, "android": true, "ios": true, "ipados": true, "tvos": true,
	"watchos": true, "linux": true, "chrome": true, "chromebook": true,
	"azure": true, "xbox": true, "hololens": true, "surface": true,
	"mariner": true, "based": true, "systems": true, "system": true,
	"32": true, "64": true, "bit": true, "x64": true, "x86": true,
	"arm64": true, "version": true, "edition": true, "for": true,
}

// msrcFamilyTokens are global stopwords that are meaningful product-family
// tokens inside MSRC product names (Remote Desktop, Visual Studio, .NET
// Framework/Runtime, Microsoft Office, ...).
var msrcFamilyTokens = map[string]bool{
	"remote": true, "desktop": true, "studio": true, "visual": true,
	"office": true, "framework": true, "runtime": true, "client": true,
	"server": true, "tools": true,
}

// msrcNameMatches requires every distinctive token of the affected MSRC
// product to appear inside a single installed asset name. Unlike
// nameMatches it never accepts a single shared word (e.g. "windows").
func msrcNameMatches(affectedName string, lowerNames map[string]bool) bool {
	words := splitWords(strings.ToLower(affectedName))
	var distinctive []string
	for _, w := range words {
		if len(w) < 3 || msrcPlatformTokens[w] || (stopWords[w] && !msrcFamilyTokens[w]) {
			continue
		}
		distinctive = append(distinctive, w)
	}
	// A single shared word is not enough for MSRC (e.g. "windows" or
	// "office"); require at least two distinctive family tokens inside one
	// installed asset name.
	if len(distinctive) < 2 {
		return false
	}
	for name := range lowerNames {
		nameSet := make(map[string]bool)
		for _, w := range splitWords(name) {
			nameSet[w] = true
		}
		all := true
		for _, w := range distinctive {
			if !nameSet[w] {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

var wordSeps = func(r rune) bool {
	return r == '_' || r == '-' || r == ':' || r == '/' || r == '.' || r == ' ' || r == '(' || r == ')'
}

func splitWords(s string) []string {
	parts := strings.FieldsFunc(s, wordSeps)
	var result []string
	for _, p := range parts {
		if len(p) >= 2 {
			result = append(result, p)
		}
	}
	return result
}

var stopWords = map[string]bool{
	"services": true, "server": true, "desktop": true, "workstation": true,
	"infrastructure": true, "enterprise": true, "management": true,
	"client": true, "network": true, "system": true, "software": true,
	"application": true, "support": true, "framework": true, "library": true,
	"component": true, "edition": true, "suite": true, "option": true,
	"agent": true, "provider": true, "professional": true, "standard": true,
	"extended": true, "development": true, "security": true, "platform": true,
	"tools": true, "runtime": true, "package": true, "driver": true,
	"service": true, "control": true, "manager": true, "portal": true,
	"engine": true, "core": true, "base": true, "common": true,
	"data": true, "file": true, "web": true, "mobile": true,
	"cloud": true, "virtual": true, "remote": true, "online": true,
	"advanced": true, "basic": true, "premium": true, "ultimate": true,
}

func anyWordMatch(affectedWords, searchWords []string) bool {
	for _, aw := range affectedWords {
		if len(aw) < 2 {
			continue
		}
		awIsStop := stopWords[aw]
		for _, sw := range searchWords {
			if len(sw) < 2 {
				continue
			}
			swIsStop := stopWords[sw]
			if awIsStop && swIsStop {
				continue
			}
			if sw == aw {
				return true
			}
		}
	}
	return false
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

var winVersionPattern = regexp.MustCompile(`[Vv]ersion\s+(\d{2}H\d|\d{4})`)

func isRelevantProduct(ap AffectedProduct, source, agentOS, agentVersion, agentArch string, lowerNames map[string]bool) bool {
	lower := strings.ToLower(agentOS)

	if source == "msrc" {
		return isRelevantMSRCProduct(ap, lower, agentVersion, agentArch, lowerNames)
	}
	if source == "nvd" {
		return isRelevantNVDProduct(ap, lower, agentVersion, lowerNames)
	}
	if source == "osv" {
		osEco := strings.ToLower(ap.Ecosystem)
		if isOsAgnosticEcosystem(osEco) {
			return true
		}
		isLinuxAgent := strings.Contains(lower, "linux") || strings.Contains(lower, "debian") || strings.Contains(lower, "ubuntu")
		var familyOK bool
		switch {
		case strings.HasPrefix(osEco, "debian"), strings.HasPrefix(osEco, "ubuntu"):
			familyOK = strings.Contains(lower, "debian") || strings.Contains(lower, "ubuntu")
		case strings.HasPrefix(osEco, "alma"):
			familyOK = strings.Contains(lower, "alma")
		case strings.HasPrefix(osEco, "rocky"):
			familyOK = strings.Contains(lower, "rocky")
		case strings.HasPrefix(osEco, "red hat"):
			familyOK = isRHELFamilyAgent(lower)
		case strings.HasPrefix(osEco, "fedora"):
			familyOK = strings.Contains(lower, "fedora")
		case strings.Contains(osEco, "suse"), strings.Contains(osEco, "opensuse"):
			familyOK = strings.Contains(lower, "suse")
		case strings.HasPrefix(osEco, "alpine"):
			familyOK = strings.Contains(lower, "alpine")
		default:
			familyOK = isLinuxAgent
		}
		if !familyOK {
			return false
		}
		// Ubuntu ecosystems are scoped per release ("Ubuntu:22.04:LTS");
		// only accept records matching the agent's major.minor so one CVE
		// record's other-release entries cannot match this agent.
		if v := ubuntuEcosystemVersion(osEco); v != "" {
			if av := majorMinorFromVersion(agentVersion); av != "" && v != av {
				return false
			}
		}
		// Alpine ecosystems are scoped per distro version ("Alpine:v3.17");
		// only accept records matching the agent's major.minor.
		if v := alpineEcosystemVersion(osEco); v != "" && v != majorMinorFromVersion(agentVersion) {
			return false
		}
		// OSV distro ecosystems encode the distro major in the ecosystem name
		// ("Rocky Linux:9"); when absent, RPM advisories carry elN release tags.
		// Either way, only accept entries whose major matches the agent.
		if em := osvEcosystemMajor(osEco); em != "" {
			if em != majorFromVersion(agentVersion) {
				return false
			}
		} else if isRPMEcosystem(osEco) {
			if fm := rpmReleaseMajor(ap.FixedIn); fm != "" && fm != majorFromVersion(agentVersion) {
				return false
			}
		}
		return true
	}
	if source == "debian" {
		return strings.Contains(lower, "debian") || strings.Contains(lower, "ubuntu")
	}
	return true
}

func isOsAgnosticEcosystem(osEco string) bool {
	return osEco == "pypi" || osEco == "npm" || osEco == "go" || osEco == "maven" ||
		osEco == "crates.io" || osEco == "nuget" || osEco == "packagist" || osEco == "oss-fuzz"
}

// osvEcosystemMajor extracts the distro major from OSV ecosystem names such as
// "Rocky Linux:9" -> "9"; empty when the ecosystem has no major suffix.
func osvEcosystemMajor(eco string) string {
	_, after, ok := strings.Cut(eco, ":")
	if !ok {
		return ""
	}
	after = strings.TrimSpace(after)
	if after == "" {
		return ""
	}
	for _, r := range after {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return after
}

func isRelevantMSRCProduct(ap AffectedProduct, agentOSLower, agentVersion, agentArch string, lowerNames map[string]bool) bool {
	lower := strings.ToLower(ap.Name)

	// Non-Windows platforms and non-PC hardware never apply to a Windows
	// agent. Exact installed-software presence is enforced separately by
	// cpeMatches/msrcNameMatches; this layer rejects the platform outright.
	if strings.Contains(lower, "for mac") || strings.Contains(lower, "mac os") ||
		strings.Contains(lower, "macos") || strings.Contains(lower, "for android") ||
		strings.Contains(lower, "android") || strings.Contains(lower, "for ios") ||
		strings.Contains(lower, "ios") || strings.Contains(lower, "ipados") ||
		strings.Contains(lower, "tvos") || strings.Contains(lower, "watchos") ||
		strings.Contains(lower, "chrome os") || strings.Contains(lower, "chromebook") ||
		strings.Contains(lower, "mariner") || strings.Contains(lower, "azure") ||
		strings.Contains(lower, "xbox") || strings.Contains(lower, "hololens") ||
		strings.Contains(lower, "surface") || strings.Contains(lower, "linux") {
		return false
	}

	// Windows testing toolkits (HLK/ADK/WDK/PE add-on) are not the OS; they
	// must only match when the exact tool is installed, never via the OS
	// family or an OS-typed CPE.
	if strings.Contains(lower, " hlk") || strings.Contains(lower, " adk") ||
		strings.Contains(lower, " wdk") || strings.Contains(lower, "pe add-on") ||
		strings.Contains(lower, "driver kit") {
		return false
	}

	if !strings.Contains(agentOSLower, "windows") {
		return false
	}

	// EOL families and platforms this agent cannot run on.
	if strings.Contains(lower, "windows rt") || strings.Contains(lower, "windows phone") ||
		strings.Contains(lower, "windows xp") || strings.Contains(lower, "windows vista") ||
		strings.Contains(lower, "windows 7") || strings.Contains(lower, "windows 8") ||
		strings.Contains(lower, "windows 8.1") || strings.Contains(lower, "server 2008") ||
		strings.Contains(lower, "server 2012") {
		return false
	}

	// Family gating: a Windows 10 product must never match a Windows 11
	// agent and vice versa. This also rejects versionless entries such as
	// "Windows 10 for x64-based Systems" on Windows 11 hosts.
	isWin10 := strings.Contains(agentOSLower, "windows 10")
	isWin11 := strings.Contains(agentOSLower, "windows 11")
	if strings.Contains(lower, "windows 10") && !isWin10 {
		return false
	}
	if strings.Contains(lower, "windows 11") && !isWin11 {
		return false
	}

	// Versionless entries are the RTM release of the family:
	// "Windows 10 for x64-based Systems" = Windows 10 1507 (build 10240),
	// "Windows 11 for x64-based Systems" = Windows 11 21H2 (build 22000).
	// They must never match a newer release, otherwise the wrong KB is
	// recommended (e.g. the Dec-2021 21H2 KB on a 22H2 machine).
	if strings.Contains(lower, "windows 11 for") && !agentBuildInRange(agentVersion, 22000, 22620) {
		return false
	}
	if strings.Contains(lower, "windows 10 for") && !agentBuildInRange(agentVersion, 10240, 10240) {
		return false
	}

	matches := winVersionPattern.FindStringSubmatch(ap.Name)
	if len(matches) >= 2 {
		if !msrcVersionMatches(matches[1], isWin10, isWin11, agentVersion) {
			return false
		}
	} else if strings.Contains(lower, "server 2016") {
		if !agentBuildInRange(agentVersion, 14393, 14393) {
			return false
		}
	} else if strings.Contains(lower, "server 2019") {
		if !agentBuildInRange(agentVersion, 17763, 17763) {
			return false
		}
	} else if strings.Contains(lower, "server 2022") || strings.Contains(lower, "server 2025") {
		if !agentBuildInRange(agentVersion, 20348, 20349) && !agentBuildGE(agentVersion, 26000) {
			return false
		}
	} else if strings.Contains(lower, "windows server") {
		if !agentBuildInRange(agentVersion, 20348, 20349) && !agentBuildGE(agentVersion, 26000) {
			return false
		}
	}

	if strings.Contains(lower, "edgehtml") {
		return false
	}
	if strings.Contains(lower, "internet explorer") && !containsAnyInNames(lowerNames, "internet explorer") {
		return false
	}

	return msrcArchCompatible(ap, agentArch)
}

// msrcVersionMatches maps an MSRC release label (22H2/21H2/1809/...) to the
// concrete Windows build ranges, keeping Windows 10 and Windows 11 releases
// apart (21H2/22H2 exist on both families with different builds).
func msrcVersionMatches(label string, isWin10, isWin11 bool, agentVersion string) bool {
	switch strings.ToUpper(label) {
	case "24H2":
		return agentBuildGE(agentVersion, 26100)
	case "23H2":
		return agentBuildInRange(agentVersion, 22631, 26099)
	case "22H2":
		if isWin11 {
			return agentBuildInRange(agentVersion, 22621, 22630)
		}
		if isWin10 {
			return agentBuildInRange(agentVersion, 19045, 19045)
		}
		return false
	case "21H2":
		if isWin11 {
			return agentBuildInRange(agentVersion, 22000, 22620)
		}
		if isWin10 {
			return agentBuildInRange(agentVersion, 19044, 19044)
		}
		return false
	case "21H1":
		return agentBuildInRange(agentVersion, 19043, 19043)
	case "20H2":
		return agentBuildInRange(agentVersion, 19042, 19042)
	case "2004":
		return agentBuildInRange(agentVersion, 19041, 19041)
	case "1909":
		return agentBuildInRange(agentVersion, 18363, 18363)
	case "1903":
		return agentBuildInRange(agentVersion, 18362, 18362)
	case "1809":
		return agentBuildInRange(agentVersion, 17763, 17763)
	case "1803":
		return agentBuildInRange(agentVersion, 17134, 17134)
	case "1709":
		return agentBuildInRange(agentVersion, 16299, 16299)
	case "1703":
		return agentBuildInRange(agentVersion, 15063, 15063)
	case "1607":
		return agentBuildInRange(agentVersion, 14393, 14393)
	case "1511":
		return agentBuildInRange(agentVersion, 10586, 10586)
	default:
		n, _ := strconv.Atoi(label)
		return n >= 2000 && agentBuildGE(agentVersion, n)
	}
}

// msrcArchCompatible gates architecture-specific MSRC products. With an
// unknown agent architecture we stay conservative: ARM64/32-bit-specific
// entries are rejected because they cannot be confirmed, x64 entries are
// allowed since x64 is the dominant Windows agent platform.
func msrcArchCompatible(ap AffectedProduct, agentArch string) bool {
	nameLower := strings.ToLower(ap.Name)
	cpeArch := extractCPEArch(ap.CPE)
	isARM := cpeArch == "arm64" || strings.Contains(nameLower, "arm64")
	isX86 := cpeArch == "x86" || extractCPETargetPlatform(ap.CPE) == "x86" ||
		strings.Contains(nameLower, "32-bit") || strings.Contains(nameLower, "x86-based")
	if isARM {
		return strings.Contains(strings.ToLower(agentArch), "arm") ||
			strings.Contains(strings.ToLower(agentArch), "aarch64")
	}
	if isX86 {
		a := strings.ToLower(agentArch)
		return strings.Contains(a, "386") || (strings.Contains(a, "x86") && !strings.Contains(a, "64"))
	}
	return true
}

func isRelevantNVDProduct(ap AffectedProduct, agentOSLower, agentVersion string, lowerNames map[string]bool) bool {
	vendor := strings.ToLower(ap.Vendor)
	lower := strings.ToLower(ap.Name)

	if strings.Contains(lower, "android") || strings.Contains(lower, "chrome_os") ||
		strings.Contains(lower, "macos") || strings.Contains(lower, "mac_os") ||
		strings.Contains(lower, "ios") || strings.Contains(lower, "tvos") ||
		strings.Contains(lower, "watchos") || strings.Contains(lower, "ipados") {
		return false
	}

	linuxVendors := []string{"debian", "canonical", "ubuntu", "redhat", "red_hat", "fedora", "fedoraproject",
		"centos", "novell", "suse", "opensuse", "linux", "gentoo", "almalinux", "rocky"}
	windowsVendors := []string{"microsoft"}

	hardwareVendors := []string{"cisco", "netapp", "avaya", "hp", "stonesoft", "amd",
		"apple", "advantech", "broadcom", "f5", "juniper", "huawei", "oracle", "ibm", "dell", "intel"}

	for _, hv := range hardwareVendors {
		if vendor == hv {
			return false
		}
	}

	isWindowsAgent := strings.Contains(agentOSLower, "windows")
	isLinuxAgent := strings.Contains(agentOSLower, "linux") || strings.Contains(agentOSLower, "debian") || strings.Contains(agentOSLower, "ubuntu")

	if isWindowsAgent {
		for _, lv := range linuxVendors {
			if vendor == lv {
				return false
			}
		}
		if strings.Contains(lower, "linux") || strings.Contains(lower, "debian") || strings.Contains(lower, "ubuntu") ||
			strings.Contains(lower, "fedora") || strings.Contains(lower, "centos") || strings.Contains(lower, "suse") ||
			strings.Contains(lower, "opensuse") || strings.Contains(lower, "gentoo") ||
			strings.Contains(lower, "almalinux") || strings.Contains(lower, "rocky") {
			return false
		}

		if vendor == "opensuse" || vendor == "gentoo" || vendor == "almalinux" || vendor == "rocky" {
			return false
		}
		if strings.Contains(lower, "windows_vista") || strings.Contains(lower, "windows_7") ||
			strings.Contains(lower, "windows_8") || strings.Contains(lower, "windows_rt") ||
			strings.Contains(lower, "windows_xp") || strings.Contains(lower, "windows_server_2003") ||
			strings.Contains(lower, "server_2008") || strings.Contains(lower, "server_2012") {
			return false
		}

		if vendor == "microsoft" {
			return false
		}

		if vendor == "mozilla" && !containsAny(lowerNames, "firefox", "thunderbird") {
			return false
		}
		if vendor == "mozilla" {
			prodName := strings.ToLower(ap.Name)
			if !strings.Contains(prodName, "firefox") && !strings.Contains(prodName, "thunderbird") {
				return false
			}
		}
		if vendor == "vmware" && !containsAny(lowerNames, "vmware", "workstation", "fusion", "player", "horizon") {
			return false
		}
	}
	if isLinuxAgent {
		for _, wv := range windowsVendors {
			if vendor == wv {
				return false
			}
		}
	}

	return true
}

func containsAny(names map[string]bool, targets ...string) bool {
	for _, t := range targets {
		if names[t] {
			return true
		}
	}
	return false
}

func containsAnyInNames(lowerNames map[string]bool, targets ...string) bool {
	for n := range lowerNames {
		for _, t := range targets {
			if strings.Contains(n, t) {
				return true
			}
		}
	}
	return false
}

func buildAgentCPEIndex(names []string, assetVersions map[string]string) map[string]string {
	out := make(map[string]string, len(names))
	for _, n := range names {
		lower := strings.ToLower(strings.TrimSpace(n))
		if lower == "" {
			continue
		}
		if v, ok := assetVersions[lower]; ok && v != "" {
			out[lower] = v
		}
		words := splitWords(lower)
		for _, w := range words {
			if len(w) >= 3 && !stopWords[w] {
				if _, exists := out[w]; !exists {
					if v, ok := assetVersions[lower]; ok && v != "" {
						out[w] = v
					}
				}
			}
		}
	}
	return out
}

func cpeMatches(ap AffectedProduct, source string, agentCPEIndex map[string]string, lowerNames map[string]bool) bool {
	cpeProduct := strings.ToLower(ap.Name)

	if source == "msrc" {
		if ap.CPE != "" {
			cpeProduct = strings.ToLower(extractCPEProduct(ap.CPE))
			vendor := strings.ToLower(extractVendorFromCPE(ap.CPE))
			if vendor != "" && vendor != "microsoft" {
				return false
			}
			if cpeProduct == "" {
				return false
			}
			if strings.Contains(cpeProduct, "mac") || strings.Contains(strings.ToLower(ap.Name), "mac") {
				return false
			}

			if extractCPEPart(ap.CPE) == "o" {
				return true
			}

			matchedKey := findMatchingKey(cpeProduct, agentCPEIndex)
			if matchedKey == "" {
				return false
			}

			agentVer := agentCPEIndex[matchedKey]
			return cpeVersionCompatible(ap.CpeVer, agentVer, matchedKey, agentCPEIndex)
		}
		// OS products without CPE are gated by isRelevantMSRCProduct; other
		// products must match the installed asset name strictly (all
		// distinctive tokens inside one asset), never via a single shared
		// word such as "windows".
		if isMSRCOSProductName(ap.Name) {
			return true
		}
		return msrcNameMatches(ap.Name, lowerNames)
	}

	if source == "nvd" {
		matchedKey := findMatchingKey(cpeProduct, agentCPEIndex)
		if matchedKey == "" {
			return false
		}
		agentVer := agentCPEIndex[matchedKey]
		return cpeVersionCompatible(ap.CpeVer, agentVer, matchedKey, agentCPEIndex)
	}

	if source == "osv" && (isAPKEcosystem(ap.Ecosystem) || isRPMEcosystem(ap.Ecosystem)) {
		return lowerNames[strings.ToLower(ap.Name)]
	}

	return nameMatches(ap.Name, lowerNames)
}

func findMatchingKey(product string, agentCPEIndex map[string]string) string {
	if _, ok := agentCPEIndex[product]; ok {
		return product
	}
	keys := sortedMapKeys(agentCPEIndex)
	best := ""
	for _, k := range keys {
		if tokenBoundaryContains(k, product) {
			if best == "" || len(k) < len(best) || (len(k) == len(best) && k < best) {
				best = k
			}
		}
	}
	if best != "" {
		return best
	}
	for _, k := range keys {
		// Reverse direction: a distinctive installed token inside a longer
		// CPE product (openssh <-> openssh-portable). The length floor keeps
		// short names like "git" or "node" from matching "gitlab"/"node.js".
		if len(k) >= 5 && tokenBoundaryContains(product, k) {
			return k
		}
	}
	return ""
}

// tokenBoundaryContains reports whether the needle appears as a contiguous
// run of whole word tokens inside the container. "git" is a token of
// "git for windows" but not of "gitea"; "openssh" is a token of
// "openssh-portable". This keeps CPE product matching aligned with the
// whole-token semantics used by nameMatches/findInstalledVersion.
func tokenBoundaryContains(container, needle string) bool {
	cw := splitWords(strings.ToLower(container))
	nw := splitWords(strings.ToLower(needle))
	if len(nw) == 0 || len(nw) > len(cw) {
		return false
	}
outer:
	for i := 0; i+len(nw) <= len(cw); i++ {
		for j := range nw {
			if cw[i+j] != nw[j] {
				continue outer
			}
		}
		return true
	}
	return false
}

func sortedMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func cpeVersionCompatible(feedCpeVer, agentVer, agentName string, agentCPEIndex map[string]string) bool {
	if feedCpeVer == "" || feedCpeVer == "*" || feedCpeVer == "-" {
		return true
	}
	if agentName != "" && strings.Contains(strings.ToLower(agentName), strings.ToLower(feedCpeVer)) {
		return true
	}
	for k := range agentCPEIndex {
		if !strings.HasPrefix(k, agentName) && !strings.Contains(k, agentName) &&
			!strings.Contains(agentName, k) {
			continue
		}
		if strings.Contains(k, feedCpeVer) {
			return true
		}
	}
	if agentVer != "" {
		agentClean := cleanVersion(agentVer)
		feedClean := cleanVersion(feedCpeVer)
		if strings.HasPrefix(agentClean, feedClean+".") || agentClean == feedClean {
			return true
		}
	}
	return false
}

func dedupStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		lower := strings.ToLower(strings.TrimSpace(s))
		if lower == "" || seen[lower] {
			continue
		}
		seen[lower] = true
		out = append(out, s)
	}
	return out
}

func parseWindowsBuild(version string) int {
	for _, part := range strings.Split(version, ".") {
		n, err := strconv.Atoi(part)
		if err == nil && n >= 10000 {
			return n
		}
	}
	return 0
}

func agentBuildGE(agentVersion string, minBuild int) bool {
	return parseWindowsBuild(agentVersion) >= minBuild
}

func agentBuildInRange(agentVersion string, minBuild, maxBuild int) bool {
	b := parseWindowsBuild(agentVersion)
	return b >= minBuild && b <= maxBuild
}

func isKBFixed(fixedKB string, installedKBs map[string]bool) bool {
	if installedKBs[fixedKB] {
		return true
	}
	fixedNum := extractKBNumber(fixedKB)
	if fixedNum == 0 {
		return false
	}
	fixedGroup := fixedNum / 10000
	for kb := range installedKBs {
		instNum := extractKBNumber(kb)
		if instNum == 0 {
			continue
		}
		if instNum/10000 == fixedGroup && instNum > fixedNum {
			return true
		}
	}
	return false
}

func extractKBNumber(kb string) int {
	n := 0
	for _, c := range kb {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}
