package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const debianTrackerURL = "https://security-tracker.debian.org/tracker/data/json"

type DebianTrackerClient struct {
	http *http.Client
}

type DebianTrackerData map[string]map[string]DebianVulnEntry

type DebianVulnEntry struct {
	Description string                   `json:"description"`
	Scope       string                   `json:"scope"`
	Releases    map[string]DebianRelease `json:"releases"`
}

type DebianRelease struct {
	Status       string            `json:"status"`
	FixedVersion string            `json:"fixed_version"`
	Urgency      string            `json:"urgency"`
	Repositories map[string]string `json:"repositories"`
}

func NewDebianTrackerClient() *DebianTrackerClient {
	return &DebianTrackerClient{
		http: &http.Client{Timeout: 120 * time.Second},
	}
}

func (c *DebianTrackerClient) FetchAll(ctx context.Context) (DebianTrackerData, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", debianTrackerURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch debian tracker: %w", err)
	}
	defer resp.Body.Close()

	var data DebianTrackerData
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("decode debian tracker: %w", err)
	}
	return data, nil
}

func (l *Loader) RefreshDebianTracker(ctx context.Context, agents []AgentSnapshotSummary) {
	pkgAssets := collectPackageAssets(agents)
	if len(pkgAssets) == 0 {
		return
	}

	releaseName := debianReleaseName(agents)

	client := NewDebianTrackerClient()
	data, err := client.FetchAll(ctx)
	if err != nil {
		slog.Warn("loader: debian tracker fetch failed", "error", err)
		return
	}

	agentPkgs := make(map[string]bool, len(pkgAssets))
	for _, a := range pkgAssets {
		agentPkgs[strings.ToLower(a.Name)] = true
	}

	now := time.Now().UTC()
	var entries []*FeedEntry
	total := 0
	matchedPkgs := 0

	for pkgName, cveMap := range data {
		lower := strings.ToLower(pkgName)
		if !agentPkgs[lower] {
			continue
		}
		matchedPkgs++
		for cveID, vuln := range cveMap {
			if !strings.HasPrefix(cveID, "CVE-") {
				continue
			}
			rel, ok := vuln.Releases[releaseName]
			if !ok {
				continue
			}
			if rel.Status == "resolved" {
				continue
			}
			if rel.Urgency == "unimportant" || rel.Urgency == "end-of-life" {
				continue
			}
			fixedVer := rel.FixedVersion
			if fixedVer == "" {
				fixedVer = "0"
			}

			severity := mapDebianSeverity(rel.Urgency)
			affected := []AffectedProduct{{
				Name:      pkgName,
				FixedIn:   rel.FixedVersion,
				Ecosystem: "Debian",
			}}
			affectedJSON, _ := json.Marshal(affected)

			entries = append(entries, &FeedEntry{
				Source:      "debian",
				SourceKey:   pkgName + "/" + cveID,
				CVEID:       cveID,
				Affected:    affectedJSON,
				FixedVer:    fixedVer,
				Severity:    severity,
				CVSSScore:   urgencyToScore(rel.Urgency),
				Summary:     vuln.Description,
				PublishedAt: now,
				FetchedAt:   now,
				TTLSeconds:  7 * 24 * 3600,
			})
			total++
		}
	}

	if len(entries) > 0 {
		if err := l.feed.BatchUpsert(ctx, entries); err != nil {
			slog.Warn("loader: debian tracker upsert failed", "error", err)
			return
		}
	}
	slog.Info("loader: debian tracker refreshed", "cves", total, "matched_pkgs", matchedPkgs)
}

func mapDebianSeverity(urgency string) string {
	switch urgency {
	case "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	default:
		return "MEDIUM"
	}
}

func urgencyToScore(urgency string) float64 {
	switch urgency {
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 2.5
	default:
		return 5.0
	}
}

func debianReleaseName(agents []AgentSnapshotSummary) string {
	for _, a := range agents {
		if strings.Contains(strings.ToLower(a.OSType), "debian") {
			switch {
			case strings.HasPrefix(a.OSVersion, "13"):
				return "trixie"
			case strings.HasPrefix(a.OSVersion, "12"):
				return "bookworm"
			case strings.HasPrefix(a.OSVersion, "11"):
				return "bullseye"
			case strings.HasPrefix(a.OSVersion, "10"):
				return "buster"
			}
		}
	}
	return "bookworm"
}
