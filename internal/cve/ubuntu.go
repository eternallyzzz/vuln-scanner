package cve

import (
	"compress/bzip2"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"
)

const ubuntuOVALBase = "https://security-metadata.canonical.com/oval/com.ubuntu.%s.cve.oval.xml.bz2"

// ubuntuReleaseForVersion maps an Ubuntu OS version (e.g. "22.04.5 LTS") to
// the OVAL series codename (e.g. "jammy"). Unknown versions return "".
func ubuntuReleaseForVersion(version string) string {
	v := majorMinorFromVersion(version)
	switch v {
	case "16.04":
		return "xenial"
	case "18.04":
		return "bionic"
	case "20.04":
		return "focal"
	case "22.04":
		return "jammy"
	case "23.04":
		return "lunar"
	case "23.10":
		return "mantic"
	case "24.04":
		return "noble"
	case "24.10":
		return "oracular"
	case "25.04":
		return "plucky"
	case "25.10":
		return "questing"
	case "26.04":
		return "resolute"
	default:
		return ""
	}
}

func ubuntuVersionForRelease(release string) string {
	switch release {
	case "xenial":
		return "16.04"
	case "bionic":
		return "18.04"
	case "focal":
		return "20.04"
	case "jammy":
		return "22.04"
	case "lunar":
		return "23.04"
	case "mantic":
		return "23.10"
	case "noble":
		return "24.04"
	case "oracular":
		return "24.10"
	case "plucky":
		return "25.04"
	case "questing":
		return "25.10"
	case "resolute":
		return "26.04"
	default:
		return ""
	}
}

func collectUbuntuReleases(agents []AgentSnapshotSummary) []string {
	seen := make(map[string]bool)
	var out []string
	for _, ag := range agents {
		if !strings.Contains(strings.ToLower(ag.OSType), "ubuntu") {
			continue
		}
		release := ubuntuReleaseForVersion(ag.OSVersion)
		if release == "" || seen[release] {
			continue
		}
		seen[release] = true
		out = append(out, release)
	}
	sort.Strings(out)
	return out
}

// UbuntuFeedClient downloads Canonical per-release OVAL security metadata.
type UbuntuFeedClient struct {
	http *http.Client
}

func NewUbuntuFeedClient() *UbuntuFeedClient {
	return &UbuntuFeedClient{http: &http.Client{Timeout: 90 * time.Second}}
}

func (c *UbuntuFeedClient) FetchRelease(ctx context.Context, release string) ([]*FeedEntry, error) {
	if release == "" {
		return nil, fmt.Errorf("ubuntu release is empty")
	}
	u := fmt.Sprintf(ubuntuOVALBase, release)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ubuntu oval http %d for %s", resp.StatusCode, release)
	}
	data, err := io.ReadAll(bzip2.NewReader(resp.Body))
	if err != nil {
		return nil, fmt.Errorf("ubuntu oval decompress %s: %w", release, err)
	}
	entries, err := ParseUbuntuOVAL(data, release)
	if err != nil {
		return nil, err
	}
	slog.Info("ubuntu oval fetched", "release", release, "entries", len(entries))
	return entries, nil
}

type ubuntuOvalRoot struct {
	Definitions []ubuntuDefinition `xml:"definitions>definition"`
	Tests       []ubuntuDpkgTest   `xml:"tests>dpkginfo_test"`
	Objects     []ubuntuDpkgObject `xml:"objects>dpkginfo_object"`
	States      []ubuntuDpkgState  `xml:"states>dpkginfo_state"`
}

type ubuntuDefinition struct {
	ID       string `xml:"id,attr"`
	Metadata struct {
		Title    string `xml:"title"`
		Affected struct {
			Platform string `xml:"platform"`
		} `xml:"affected"`
		References []struct {
			Source string `xml:"source,attr"`
			RefID  string `xml:"ref_id,attr"`
		} `xml:"reference"`
	} `xml:"metadata"`
	Criteria ubuntuCriteria `xml:"criteria"`
}

type ubuntuCriteria struct {
	Criterions []ubuntuCriterion `xml:"criterion"`
	Criterias  []ubuntuCriteria  `xml:"criteria"`
}

type ubuntuCriterion struct {
	TestRef string `xml:"test_ref,attr"`
}

type ubuntuDpkgTest struct {
	ID     string    `xml:"id,attr"`
	Object ubuntuRef `xml:"object"`
	State  ubuntuRef `xml:"state"`
}

type ubuntuDpkgObject struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
}

type ubuntuDpkgState struct {
	ID  string `xml:"id,attr"`
	EVR string `xml:"evr"`
}

type ubuntuRef struct {
	ObjectRef string `xml:"object_ref,attr"`
	StateRef  string `xml:"state_ref,attr"`
}

func (c *ubuntuCriteria) testRefs() []string {
	var out []string
	for _, cr := range c.Criterions {
		if cr.TestRef != "" {
			out = append(out, cr.TestRef)
		}
	}
	for _, sub := range c.Criterias {
		out = append(out, sub.testRefs()...)
	}
	return out
}

func ubuntuSeverityFromTitle(title string) string {
	lower := strings.ToLower(title)
	switch {
	case strings.Contains(lower, "critical"):
		return "CRITICAL"
	case strings.Contains(lower, "high"):
		return "HIGH"
	case strings.Contains(lower, "medium"):
		return "MEDIUM"
	case strings.Contains(lower, "low"):
		return "LOW"
	default:
		return "MEDIUM"
	}
}

// ParseUbuntuOVAL parses a Canonical per-release OVAL document into feed
// entries. Each CVE becomes one entry whose affected array carries the
// (package, ecosystem, fixed version) tuples extracted from the dpkginfo
// tests reachable from the definition criteria.
func ParseUbuntuOVAL(data []byte, release string) ([]*FeedEntry, error) {
	var root ubuntuOvalRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("ubuntu oval xml: %w", err)
	}
	objects := make(map[string]string)
	for _, o := range root.Objects {
		objects[o.ID] = o.Name
	}
	states := make(map[string]string)
	for _, s := range root.States {
		states[s.ID] = s.EVR
	}
	tests := make(map[string]ubuntuDpkgTest)
	for _, t := range root.Tests {
		tests[t.ID] = t
	}

	majorMinor := ubuntuVersionForRelease(release)
	eco := "Ubuntu:" + majorMinor
	if isUbuntuLTS(majorMinor) {
		eco += ":LTS"
	}

	type pkgFix struct {
		name string
		fix  string
	}
	byCVE := make(map[string]map[string]string) // cve -> pkg -> fix
	titles := make(map[string]string)
	for _, d := range root.Definitions {
		cve := ""
		for _, ref := range d.Metadata.References {
			if strings.EqualFold(ref.Source, "CVE") && ref.RefID != "" {
				cve = ref.RefID
				break
			}
		}
		if cve == "" {
			continue
		}
		titles[cve] = d.Metadata.Title
		pkgs := make(map[string]string)
		for _, testRef := range d.Criteria.testRefs() {
			t, ok := tests[testRef]
			if !ok {
				continue
			}
			name := objects[t.Object.ObjectRef]
			fix := states[t.State.StateRef]
			if name == "" || fix == "" {
				continue
			}
			if cur, ok := pkgs[name]; ok && cur != fix {
				// A CVE can fix several releases in one OVAL; keep the first
				// deterministic entry for this release file.
				continue
			}
			pkgs[name] = fix
		}
		if len(pkgs) == 0 {
			continue
		}
		byCVE[cve] = pkgs
	}

	now := time.Now().UTC()
	entries := make([]*FeedEntry, 0, len(byCVE))
	for cve, pkgs := range byCVE {
		names := make([]string, 0, len(pkgs))
		for name := range pkgs {
			names = append(names, name)
		}
		sort.Strings(names)
		affected := make([]AffectedProduct, 0, len(names))
		for _, name := range names {
			affected = append(affected, AffectedProduct{
				Name:      name,
				Ecosystem: eco,
				FixedIn:   pkgs[name],
			})
		}
		raw, _ := json.Marshal(affected)
		entries = append(entries, &FeedEntry{
			Source:      "ubuntu",
			SourceKey:   release + "/" + cve,
			CVEID:       cve,
			CVEURL:      "https://ubuntu.com/security/" + cve,
			Affected:    raw,
			Severity:    ubuntuSeverityFromTitle(titles[cve]),
			Summary:     titles[cve],
			PublishedAt: now,
			FetchedAt:   now,
			TTLSeconds:  int((12 * time.Hour).Seconds()),
		})
	}
	return entries, nil
}

// RefreshAllUbuntu fetches Canonical OVAL metadata for every Ubuntu release
// present in the agent fleet, one release per refresh window.
func (l *Loader) RefreshAllUbuntu(ctx context.Context, agents []AgentSnapshotSummary) {
	releases := collectUbuntuReleases(agents)
	if len(releases) == 0 {
		return
	}
	client := NewUbuntuFeedClient()
	for _, release := range releases {
		st, _ := loadFeedState(ctx, l.store, "ubuntu", "release:"+release)
		if st.freshSince(l.cfg.UbuntuRefresh) {
			continue
		}
		entries, err := client.FetchRelease(ctx, release)
		if err != nil {
			st.markError(err)
			_ = saveFeedState(ctx, l.store, "ubuntu", "release:"+release, st)
			slog.Warn("loader: ubuntu oval refresh failed", "release", release, "error", err)
			continue
		}
		if err := l.feed.BatchUpsert(ctx, entries); err != nil {
			st.markError(fmt.Errorf("ubuntu batch upsert: %w", err))
		} else {
			st.markSuccess(len(entries))
		}
		if err := saveFeedState(ctx, l.store, "ubuntu", "release:"+release, st); err != nil {
			slog.Warn("loader: ubuntu feed state save failed", "release", release, "error", err)
		}
	}
}
