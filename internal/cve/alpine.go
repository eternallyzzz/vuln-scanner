package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"
)

const alpineSecDBBase = "https://secdb.alpinelinux.org/%s/%s.json"

type alpineSecDB struct {
	DistroVersion string `json:"distroversion"`
	RepoName      string `json:"reponame"`
	Packages      []struct {
		Pkg struct {
			Name     string              `json:"name"`
			Secfixes map[string][]string `json:"secfixes"`
		} `json:"pkg"`
	} `json:"packages"`
}

// AlpineFeedClient downloads the official Alpine secdb JSON (main and
// community) for one release line such as "v3.20".
type AlpineFeedClient struct {
	http *http.Client
}

func NewAlpineFeedClient() *AlpineFeedClient {
	return &AlpineFeedClient{http: &http.Client{Timeout: 90 * time.Second}}
}

func (c *AlpineFeedClient) FetchRelease(ctx context.Context, release string) ([]*FeedEntry, error) {
	if release == "" {
		return nil, fmt.Errorf("alpine release is empty")
	}
	var all []*FeedEntry
	for _, repo := range []string{"main", "community"} {
		entries, err := c.fetchRepo(ctx, release, repo)
		if err != nil {
			return nil, err
		}
		all = append(all, entries...)
	}
	slog.Info("alpine secdb fetched", "release", release, "entries", len(all))
	return all, nil
}

func (c *AlpineFeedClient) fetchRepo(ctx context.Context, release, repo string) ([]*FeedEntry, error) {
	u := fmt.Sprintf(alpineSecDBBase, release, repo)
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
		return nil, fmt.Errorf("alpine secdb http %d for %s/%s", resp.StatusCode, release, repo)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	entries, err := ParseAlpineSecDB(data, release, repo)
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// ParseAlpineSecDB converts one secdb JSON document into feed entries. The
// secfixes map is version -> [CVE...], so each CVE/package pair becomes one
// affected product with the fixed version that closes it.
func ParseAlpineSecDB(data []byte, release, repo string) ([]*FeedEntry, error) {
	var doc alpineSecDB
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("alpine secdb json: %w", err)
	}
	now := time.Now().UTC()
	eco := "Alpine:" + release
	type entryKey struct {
		cve string
		pkg string
	}
	byKey := make(map[entryKey]*FeedEntry)
	var order []entryKey
	for _, p := range doc.Packages {
		name := p.Pkg.Name
		if name == "" {
			continue
		}
		for version, cves := range p.Pkg.Secfixes {
			for _, cve := range cves {
				if cve == "" {
					continue
				}
				key := entryKey{cve: cve, pkg: name}
				e, ok := byKey[key]
				if !ok {
					affected, _ := json.Marshal([]AffectedProduct{{
						Name:      name,
						Ecosystem: eco,
						FixedIn:   version,
					}})
					e = &FeedEntry{
						Source:      "alpine",
						SourceKey:   release + "/" + repo + "/" + name + "/" + cve + "/" + version,
						CVEID:       cve,
						CVEURL:      "https://security.alpinelinux.org/vuln/" + cve,
						Affected:    affected,
						Severity:    "MEDIUM",
						PublishedAt: now,
						FetchedAt:   now,
						TTLSeconds:  int((12 * time.Hour).Seconds()),
					}
					byKey[key] = e
					order = append(order, key)
				}
			}
		}
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].cve != order[j].cve {
			return order[i].cve < order[j].cve
		}
		return order[i].pkg < order[j].pkg
	})
	entries := make([]*FeedEntry, 0, len(order))
	for _, k := range order {
		entries = append(entries, byKey[k])
	}
	return entries, nil
}

// RefreshAllAlpine fetches secdb metadata for every Alpine release present
// in the agent fleet, one release per refresh window.
func (l *Loader) RefreshAllAlpine(ctx context.Context, agents []AgentSnapshotSummary) {
	releases := collectAlpineReleases(agents)
	if len(releases) == 0 {
		return
	}
	client := NewAlpineFeedClient()
	for _, release := range releases {
		st, _ := loadFeedState(ctx, l.store, "alpine", "release:"+release)
		if st.freshSince(l.cfg.AlpineRefresh) {
			continue
		}
		entries, err := client.FetchRelease(ctx, release)
		if err != nil {
			st.markError(err)
			_ = saveFeedState(ctx, l.store, "alpine", "release:"+release, st)
			slog.Warn("loader: alpine secdb refresh failed", "release", release, "error", err)
			continue
		}
		if err := l.feed.BatchUpsert(ctx, entries); err != nil {
			st.markError(fmt.Errorf("alpine batch upsert: %w", err))
		} else {
			st.markSuccess(len(entries))
		}
		if err := saveFeedState(ctx, l.store, "alpine", "release:"+release, st); err != nil {
			slog.Warn("loader: alpine feed state save failed", "release", release, "error", err)
		}
	}
}

func collectAlpineReleases(agents []AgentSnapshotSummary) []string {
	seen := make(map[string]bool)
	var out []string
	for _, ag := range agents {
		if !strings.Contains(strings.ToLower(ag.OSType), "alpine") {
			continue
		}
		v := majorMinorFromVersion(ag.OSVersion)
		if v == "" {
			continue
		}
		release := "v" + v
		if seen[release] {
			continue
		}
		seen[release] = true
		out = append(out, release)
	}
	sort.Strings(out)
	return out
}
