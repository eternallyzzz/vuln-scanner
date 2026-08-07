package cve

import (
	"encoding/json"
	"testing"
)

func TestSourceCatalogRanksNativeSources(t *testing.T) {
	for _, native := range []string{"debian", "ubuntu", "redhat", "alpine", "msrc"} {
		if sourceRank(native) != 0 {
			t.Errorf("sourceRank(%q) = %d, want 0 (native)", native, sourceRank(native))
		}
	}
	for _, generic := range []string{"nvd", "osv", "custom"} {
		if sourceRank(generic) != 1 {
			t.Errorf("sourceRank(%q) = %d, want 1 (generic)", generic, sourceRank(generic))
		}
	}
	seen := map[string]bool{}
	for _, s := range sourceOrder {
		if seen[s] {
			t.Fatalf("duplicate source in catalog: %s", s)
		}
		seen[s] = true
	}
	if len(sourceOrder) != 8 {
		t.Fatalf("sourceOrder = %v, want 8 entries", sourceOrder)
	}
}

func TestMatchFeedEntryUbuntuAndAlpine(t *testing.T) {
	queryNames := []string{"openssl"}
	lowerNames := map[string]bool{"openssl": true}
	agentCPE := map[string]string{}

	ubuntuEntry := func() FeedEntry {
		raw, _ := json.Marshal([]AffectedProduct{{
			Name: "openssl", Ecosystem: "Ubuntu:22.04:LTS", FixedIn: "3.0.2-0ubuntu1.18",
		}})
		return FeedEntry{Source: "ubuntu", CVEID: "CVE-T-0001", Affected: raw,
			Severity: "HIGH", CVSSScore: 7.0}
	}

	active := matchFeedEntry(ubuntuEntry(),
		queryNames, map[string]string{"openssl": "3.0.2-0ubuntu1.17"},
		lowerNames, agentCPE, nil, "Ubuntu 22.04.5 LTS", "22.04.5", "amd64", "")
	if len(active) != 1 || active[0].MatchStatus != "active" ||
		active[0].FixedVersion != "3.0.2-0ubuntu1.18" {
		t.Fatalf("ubuntu active match = %+v", active)
	}

	fixed := matchFeedEntry(ubuntuEntry(),
		queryNames, map[string]string{"openssl": "3.0.2-0ubuntu1.18"},
		lowerNames, agentCPE, nil, "Ubuntu 22.04.5 LTS", "22.04.5", "amd64", "")
	if len(fixed) != 1 || fixed[0].MatchStatus != "fixed" {
		t.Fatalf("ubuntu fixed match = %+v", fixed)
	}

	// A jammy record must not match a noble agent (release scoping).
	wrongRelease := matchFeedEntry(ubuntuEntry(),
		queryNames, map[string]string{"openssl": "3.0.2-0ubuntu1.17"},
		lowerNames, agentCPE, nil, "Ubuntu 24.04.2 LTS", "24.04.2", "amd64", "")
	if len(wrongRelease) != 0 {
		t.Fatalf("ubuntu cross-release match = %+v, want none", wrongRelease)
	}

	alpineRaw, _ := json.Marshal([]AffectedProduct{{
		Name: "openssl", Ecosystem: "Alpine:v3.20", FixedIn: "3.3.2-r1",
	}})
	alpineEntry := FeedEntry{Source: "alpine", CVEID: "CVE-T-0002", Affected: alpineRaw}
	alpineActive := matchFeedEntry(alpineEntry,
		queryNames, map[string]string{"openssl": "3.3.2-r0"},
		lowerNames, agentCPE, nil, "Alpine Linux 3.20", "3.20.3", "x86_64", "")
	if len(alpineActive) != 1 || alpineActive[0].MatchStatus != "active" ||
		alpineActive[0].FixedVersion != "3.3.2-r1" {
		t.Fatalf("alpine active match = %+v", alpineActive)
	}
}
