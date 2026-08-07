package cve

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"vuln-scanner/internal/collector"
	"vuln-scanner/internal/store"
)

// accuracyFixture is one full-chain matching scenario: an asset inventory,
// optional translation rules, optional WUA/WSUS facts, a small cve_feed
// snapshot and the ground-truth verdicts (cve_id, asset, status).
type accuracyFixture struct {
	Name         string                        `json:"name"`
	Platform     string                        `json:"platform"`
	AgentOS      string                        `json:"agent_os"`
	AgentVersion string                        `json:"agent_version"`
	AgentArch    string                        `json:"agent_arch,omitempty"`
	Assets       []accuracyAsset               `json:"assets"`
	InstalledKBs []string                      `json:"installed_kbs,omitempty"`
	Translations []accuracyTranslation         `json:"translations,omitempty"`
	WUAFacts     []collector.UpdateFact        `json:"wua_facts,omitempty"`
	WUASource    *collector.UpdateSourceStatus `json:"wua_source,omitempty"`
	Feed         []accuracyFeedEntry           `json:"feed"`
	Expected     []accuracyVerdict             `json:"expected"`
}

type accuracyAsset struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Format  string `json:"format,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
}

// accuracyTranslation mirrors store.TranslationRule with explicit JSON tags
// so fixtures stay readable.
type accuracyTranslation struct {
	Pattern        string `json:"pattern"`
	VendorPattern  string `json:"vendor_pattern,omitempty"`
	VersionPattern string `json:"version_pattern,omitempty"`
	HotfixKB       string `json:"hotfix_kb,omitempty"`
	Product        string `json:"product"`
	Platform       string `json:"platform,omitempty"`
	Priority       int    `json:"priority"`
}

type accuracyFeedEntry struct {
	Source    string            `json:"source"`
	CVEID     string            `json:"cve_id"`
	CVEURL    string            `json:"cve_url,omitempty"`
	Affected  []AffectedProduct `json:"affected"`
	FixedKB   string            `json:"fixed_kb,omitempty"`
	FixedVer  string            `json:"fixed_ver,omitempty"`
	Severity  string            `json:"severity,omitempty"`
	CVSSScore float64           `json:"cvss_score,omitempty"`
	Summary   string            `json:"summary,omitempty"`
}

type accuracyVerdict struct {
	CVEID        string `json:"cve_id"`
	Asset        string `json:"asset"`
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version,omitempty"`
	KBArticle    string `json:"kb_article,omitempty"`
	KBURL        string `json:"kb_url,omitempty"`
}

type accuracyMetrics struct {
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

func loadAccuracyFixtures(t *testing.T) []accuracyFixture {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "accuracy", "*.json"))
	if err != nil {
		t.Fatalf("glob accuracy fixtures: %v", err)
	}
	var fixtures []accuracyFixture
	for _, f := range files {
		if strings.HasSuffix(f, "snapshot.json") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read fixture %s: %v", f, err)
		}
		var fx accuracyFixture
		if err := json.Unmarshal(b, &fx); err != nil {
			t.Fatalf("decode fixture %s: %v", f, err)
		}
		if fx.Name == "" {
			fx.Name = filepath.Base(f)
		}
		fixtures = append(fixtures, fx)
	}
	sort.Slice(fixtures, func(i, j int) bool { return fixtures[i].Name < fixtures[j].Name })
	return fixtures
}

// evaluateAccuracyFixture runs the same pure decision chain production uses,
// with fixture data standing in for the PostgreSQL feed rows and store lookups.
func evaluateAccuracyFixture(fx accuracyFixture) ([]accuracyVerdict, error) {
	assets := make([]AssetToMatch, 0, len(fx.Assets))
	for _, a := range fx.Assets {
		assets = append(assets, AssetToMatch{
			Name:    a.Name,
			Version: a.Version,
			Format:  a.Format,
			Vendor:  a.Vendor,
		})
	}
	rules := make([]store.TranslationRule, 0, len(fx.Translations))
	for _, tr := range fx.Translations {
		rules = append(rules, store.TranslationRule{
			Pattern:        tr.Pattern,
			VendorPattern:  tr.VendorPattern,
			VersionPattern: tr.VersionPattern,
			HotfixKB:       tr.HotfixKB,
			Product:        tr.Product,
			Platform:       tr.Platform,
			Priority:       tr.Priority,
		})
	}
	tm, err := newTranslationMatcher(rules)
	if err != nil {
		return nil, err
	}
	installedKBs := make(map[string]bool, len(fx.InstalledKBs))
	for _, kb := range fx.InstalledKBs {
		installedKBs[kb] = true
	}

	var results []MatchedCVE
	if fx.Platform == "windows" {
		rawNames, translatedNames := extractSoftwareNames(assets, "windows", tm)
		searchNames := append(translatedNames, rawNames...)
		assetVersions := buildAssetVersions(assets, "windows", tm)
		msrcNames, msrcVersions, osAssetName := msrcScopeAssets(assets)
		if family := msrcFamilyToken(fx.AgentOS); family != "" {
			msrcNames = append(msrcNames, family)
		}
		for _, fe := range fx.Feed {
			qNames, qVers := searchNames, assetVersions
			if fe.Source == "msrc" {
				qNames, qVers = msrcNames, msrcVersions
			}
			results = append(results, matchFeedEntry(toFeedEntry(fe), qNames, qVers,
				lowerNameSet(qNames), buildAgentCPEIndex(qNames, qVers), installedKBs,
				fx.AgentOS, fx.AgentVersion, fx.AgentArch, osAssetName)...)
		}
		results = enrichVersionStatus(results, assets, installedKBs, fx.AgentVersion, tm.hotfixes())
		results = applyWUAVerification(results, fx.WUAFacts, fx.WUASource)
		return verdictsFromResults(selectBestMatches(results)), nil
	}

	rawNames, translatedNames := extractSoftwareNames(assets, "linux", tm)
	searchNames := append(translatedNames, rawNames...)
	assetVersions := buildAssetVersions(assets, "linux", tm)
	for _, fe := range fx.Feed {
		results = append(results, matchFeedEntry(toFeedEntry(fe), searchNames, assetVersions,
			lowerNameSet(searchNames), buildAgentCPEIndex(searchNames, assetVersions), installedKBs,
			fx.AgentOS, fx.AgentVersion, fx.AgentArch, "")...)
	}
	return verdictsFromResults(selectBestMatches(results)), nil
}

func toFeedEntry(fe accuracyFeedEntry) FeedEntry {
	raw, _ := json.Marshal(fe.Affected)
	return FeedEntry{
		Source:    fe.Source,
		CVEID:     fe.CVEID,
		CVEURL:    fe.CVEURL,
		Affected:  raw,
		FixedKB:   fe.FixedKB,
		FixedVer:  fe.FixedVer,
		Severity:  fe.Severity,
		CVSSScore: fe.CVSSScore,
		Summary:   fe.Summary,
	}
}

func lowerNameSet(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		if n != "" {
			out[strings.ToLower(n)] = true
		}
	}
	return out
}

func verdictsFromResults(results []MatchedCVE) []accuracyVerdict {
	out := make([]accuracyVerdict, 0, len(results))
	for _, r := range results {
		out = append(out, accuracyVerdict{
			CVEID:        r.CVEID,
			Asset:        r.AssetName,
			Status:       strings.ToLower(r.MatchStatus),
			FixedVersion: r.FixedVersion,
			KBArticle:    r.KBArticle,
			KBURL:        r.KBURL,
		})
	}
	return normalizedVerdicts(out)
}

func normalizedVerdicts(vs []accuracyVerdict) []accuracyVerdict {
	out := append([]accuracyVerdict(nil), vs...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].CVEID != out[j].CVEID {
			return out[i].CVEID < out[j].CVEID
		}
		if out[i].Asset != out[j].Asset {
			return out[i].Asset < out[j].Asset
		}
		if out[i].Status != out[j].Status {
			return out[i].Status < out[j].Status
		}
		if out[i].FixedVersion != out[j].FixedVersion {
			return out[i].FixedVersion < out[j].FixedVersion
		}
		if out[i].KBArticle != out[j].KBArticle {
			return out[i].KBArticle < out[j].KBArticle
		}
		return out[i].KBURL < out[j].KBURL
	})
	return out
}

func compareVerdicts(produced, expected []accuracyVerdict) accuracyMetrics {
	produced = alignVerdictMetadata(produced, expected)
	prod := verdictCounts(produced)
	exp := verdictCounts(expected)
	var m accuracyMetrics
	for key, pc := range prod {
		ec := exp[key]
		tp := pc
		if ec < tp {
			tp = ec
		}
		m.TP += tp
		m.FP += pc - tp
	}
	for key, ec := range exp {
		if _, ok := prod[key]; !ok {
			m.FN += ec
		}
	}
	m.Precision = metricRatio(m.TP, m.TP+m.FP)
	m.Recall = metricRatio(m.TP, m.TP+m.FN)
	m.F1 = f1Score(m.Precision, m.Recall)
	return m
}

func verdictCounts(vs []accuracyVerdict) map[string]int {
	m := make(map[string]int, len(vs))
	for _, v := range vs {
		m[fullVerdictKey(v)]++
	}
	return m
}

func fullVerdictKey(v accuracyVerdict) string {
	return strings.ToLower(v.CVEID) + "|" + strings.ToLower(v.Asset) + "|" +
		strings.ToLower(v.Status) + "|" + strings.ToLower(v.FixedVersion) + "|" +
		strings.ToLower(v.KBArticle) + "|" + strings.ToLower(v.KBURL)
}

func baseVerdictKey(v accuracyVerdict) string {
	return strings.ToLower(v.CVEID) + "|" + strings.ToLower(v.Asset) + "|" + strings.ToLower(v.Status)
}

func hasVerdictMetadata(v accuracyVerdict) bool {
	return v.FixedVersion != "" || v.KBArticle != "" || v.KBURL != ""
}

// alignVerdictMetadata keeps old fixtures (expected without fix metadata)
// compatible while letting new fixtures assert the full patch metadata: when
// the expected verdict carries no metadata, produced metadata is ignored for
// comparison so legacy ground truth does not need to be rewritten.
func alignVerdictMetadata(produced, expected []accuracyVerdict) []accuracyVerdict {
	out := append([]accuracyVerdict(nil), produced...)
	legacy := make(map[string]accuracyVerdict, len(expected))
	for _, e := range expected {
		if !hasVerdictMetadata(e) {
			legacy[baseVerdictKey(e)] = e
		}
	}
	for i := range out {
		if e, ok := legacy[baseVerdictKey(out[i])]; ok {
			out[i].FixedVersion = e.FixedVersion
			out[i].KBArticle = e.KBArticle
			out[i].KBURL = e.KBURL
		}
	}
	return out
}

func metricRatio(num, den int) float64 {
	if den == 0 {
		return 1
	}
	return float64(num) / float64(den)
}

func f1Score(p, r float64) float64 {
	if p+r == 0 {
		return 1
	}
	return 2 * p * r / (p + r)
}

func aggregateMetrics(fixtures []accuracyFixtureSnapshot) accuracyMetrics {
	var m accuracyMetrics
	for _, f := range fixtures {
		m.TP += f.Metrics.TP
		m.FP += f.Metrics.FP
		m.FN += f.Metrics.FN
	}
	m.Precision = metricRatio(m.TP, m.TP+m.FP)
	m.Recall = metricRatio(m.TP, m.TP+m.FN)
	m.F1 = f1Score(m.Precision, m.Recall)
	return m
}

func diffVerdicts(produced, expected []accuracyVerdict) []string {
	produced = alignVerdictMetadata(produced, expected)
	pc := verdictCounts(produced)
	ec := verdictCounts(expected)
	keys := make(map[string]bool, len(pc)+len(ec))
	for k := range pc {
		keys[k] = true
	}
	for k := range ec {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	var out []string
	for _, k := range sorted {
		p, e := pc[k], ec[k]
		for i := 0; i < p-e; i++ {
			out = append(out, "+ "+k)
		}
		for i := 0; i < e-p; i++ {
			out = append(out, "- "+k)
		}
	}
	return out
}

func TestAccuracyMetrics(t *testing.T) {
	produced := []accuracyVerdict{
		{CVEID: "CVE-1", Asset: "a", Status: "active"},
		{CVEID: "CVE-2", Asset: "b", Status: "active"},
		{CVEID: "CVE-3", Asset: "c", Status: "fixed"},
	}
	expected := []accuracyVerdict{
		{CVEID: "CVE-1", Asset: "a", Status: "active"},
		{CVEID: "CVE-3", Asset: "c", Status: "fixed"},
		{CVEID: "CVE-4", Asset: "d", Status: "active"},
	}
	m := compareVerdicts(produced, expected)
	if m.TP != 2 || m.FP != 1 || m.FN != 1 {
		t.Fatalf("TP/FP/FN = %d/%d/%d, want 2/1/1", m.TP, m.FP, m.FN)
	}
	if m.Precision != 2.0/3.0 || m.Recall != 2.0/3.0 || m.F1 != 2.0/3.0 {
		t.Fatalf("P/R/F1 = %v/%v/%v, want 2/3 each", m.Precision, m.Recall, m.F1)
	}

	empty := compareVerdicts(nil, nil)
	if empty.Precision != 1 || empty.Recall != 1 || empty.F1 != 1 {
		t.Fatalf("empty metrics P/R/F1 = %v/%v/%v, want 1/1/1", empty.Precision, empty.Recall, empty.F1)
	}
}
