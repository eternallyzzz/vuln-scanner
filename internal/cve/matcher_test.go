package cve

import "testing"

func TestMergeAssetVersionKeepsHighest(t *testing.T) {
	m := map[string]string{}
	mergeAssetVersion(m, "git", "1.0.0")
	mergeAssetVersion(m, "git", "2.45.1")
	mergeAssetVersion(m, "git", "")
	mergeAssetVersion(m, "git", "0.9.0")
	if got := m["git"]; got != "2.45.1" {
		t.Fatalf("got %q, want 2.45.1", got)
	}

	mergeAssetVersion(m, "python", "2.7.16")
	mergeAssetVersion(m, "python", "3.11.2")
	if got := m["python"]; got != "3.11.2" {
		t.Fatalf("got %q, want 3.11.2", got)
	}
}
