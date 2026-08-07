package server

import (
	"testing"

	"vuln-scanner/internal/patch"
	"vuln-scanner/internal/store"
)

func TestBuildKBCandidatesPerKBGroup(t *testing.T) {
	rec := store.FixRecommendation{
		AssetName: "Windows 11 Pro 22H2",
		Action:    "install_patch",
		KBs: []store.KBPatchRecommendation{
			{Kb: "KB5008218", CVEIDs: []string{"CVE-2021-43893", "CVE-2021-43883"}},
			{Kb: "KB5008215", CVEIDs: []string{"CVE-2021-41379"}},
		},
	}
	meta := map[string]store.KBMetadata{}
	downloads := map[string][]store.KBDownload{
		"KB5008218": {{KB: "KB5008218", OSFamily: "windows 11", Arch: "x64", URL: "https://catalog.s.download.windowsupdate.com/d/x/windows11.0-kb5008218-x64.msu", SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},
		"KB5008215": {{KB: "KB5008215", OSFamily: "windows 11", Arch: "x64", URL: "https://catalog.s.download.windowsupdate.com/d/x/windows11.0-kb5008215-x64.msu", SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},
	}
	agent := store.Agent{OSType: "Windows 11 Pro 22H2", OSVersion: "10.0.22621.4043", Arch: "amd64"}

	candidates, skipped := buildKBCandidates(&patch.Config{}, rec, meta, downloads, agent, nil)
	if len(skipped) != 0 {
		t.Fatalf("skipped = %d, want 0", len(skipped))
	}
	if len(candidates) != 2 {
		t.Fatalf("candidates = %d, want 2", len(candidates))
	}
	if candidates[0].FixValue != "KB5008218" || candidates[0].FixType != "kb" {
		t.Fatalf("first candidate fix = %q/%q", candidates[0].FixType, candidates[0].FixValue)
	}
	if len(candidates[0].CVEIDs) != 2 || candidates[1].CVEIDs[0] != "CVE-2021-41379" {
		t.Fatalf("KB groups must keep their own CVE sets: %+v", candidates)
	}

	filtered, _ := buildKBCandidates(&patch.Config{}, rec, meta, downloads, agent,
		map[string]bool{"CVE-2021-43893": true})
	if len(filtered) != 1 || len(filtered[0].CVEIDs) != 1 || filtered[0].CVEIDs[0] != "CVE-2021-43893" {
		t.Fatalf("CVE filter must narrow KB group, got %+v", filtered)
	}
}

func TestBuildKBCandidatesSkipsNonDeployable(t *testing.T) {
	rec := store.FixRecommendation{
		AssetName: "Windows 11 Pro 22H2",
		Action:    "install_patch",
		KBs: []store.KBPatchRecommendation{
			{Kb: "KB5008218", CVEIDs: []string{"CVE-2021-43893"}},
		},
	}
	downloads := map[string][]store.KBDownload{
		"KB5008218": {{KB: "KB5008218", OSFamily: "windows 11", Arch: "x64", URL: "https://example.invalid/x.msu"}},
	}
	agent := store.Agent{OSType: "Windows 11 Pro 22H2", OSVersion: "10.0.22621.4043", Arch: "amd64"}
	candidates, skipped := buildKBCandidates(&patch.Config{}, rec, nil, downloads, agent, nil)
	if len(skipped) != 1 || len(candidates) != 0 {
		t.Fatalf("non-deployable KB must be skipped: candidates=%d skipped=%d", len(candidates), len(skipped))
	}
}
