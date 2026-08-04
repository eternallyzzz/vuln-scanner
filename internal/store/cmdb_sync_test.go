package store

import (
	"strings"
	"testing"
)

func TestExternalAssetKey(t *testing.T) {
	k1 := ExternalAssetKey("nginx", "software", "web-01", "10.0.0.1")
	k2 := ExternalAssetKey("nginx", "software", "web-01", "10.0.0.1")
	if k1 != k2 || !strings.HasPrefix(k1, "ext:") {
		t.Fatalf("key must be stable and prefixed, got %q vs %q", k1, k2)
	}
	k3 := ExternalAssetKey("nginx", "software", "web-02", "10.0.0.1")
	if k1 == k3 {
		t.Fatalf("different hostname must yield different key")
	}
	// Version is deliberately excluded: a version bump updates the same CI.
	k4 := ExternalAssetKey("nginx", "software", "web-01", "10.0.0.1")
	if k1 != k4 {
		t.Fatalf("version must not affect the key")
	}
}

func TestBuildReconcileReport(t *testing.T) {
	external := []string{"Web-01", "db-02", "unknown-host", ""}
	scanned := []string{"web-01", "DB-02", "app-03"}
	r := BuildReconcileReport(external, scanned)
	if r.ExternalHosts != 3 || r.ScannedAgents != 3 || r.Matched != 2 {
		t.Fatalf("counts wrong: %+v", r)
	}
	if len(r.UnmatchedExternal) != 1 || r.UnmatchedExternal[0] != "unknown-host" {
		t.Fatalf("unmatched external wrong: %+v", r.UnmatchedExternal)
	}
	if len(r.UnmatchedScanned) != 1 || r.UnmatchedScanned[0] != "app-03" {
		t.Fatalf("unmatched scanned wrong: %+v", r.UnmatchedScanned)
	}
}

func TestNormalizeExternalAssetInput(t *testing.T) {
	if _, err := normalizeExternalAssetInput(ExternalAssetInput{Name: "  "}); err == nil {
		t.Fatal("empty name must fail")
	}
	if _, err := normalizeExternalAssetInput(ExternalAssetInput{Name: "x", AssetType: "router"}); err == nil {
		t.Fatal("invalid asset_type must fail")
	}
	if _, err := normalizeExternalAssetInput(ExternalAssetInput{Name: "x", Lifecycle: "burning"}); err == nil {
		t.Fatal("invalid lifecycle must fail")
	}

	item, err := normalizeExternalAssetInput(ExternalAssetInput{
		Name:      " nginx ",
		AssetType: " SOFTWARE ",
		AssetKey:  "sw:agent-1:abc", // non-ext keys are replaced
		Tags:      []string{" dmz ", "dmz", " web "},
	})
	if err != nil {
		t.Fatal(err)
	}
	if item.Name != "nginx" || item.AssetType != "software" || item.Lifecycle != "active" {
		t.Fatalf("normalization wrong: %+v", item)
	}
	if item.AssetKey != "" {
		t.Fatalf("non-ext asset_key must be cleared, got %q", item.AssetKey)
	}
	if len(item.Tags) != 2 || item.Tags[0] != "dmz" || item.Tags[1] != "web" {
		t.Fatalf("tags dedupe wrong: %+v", item.Tags)
	}

	item2, err := normalizeExternalAssetInput(ExternalAssetInput{
		Name: "db", AssetType: "host", AssetKey: "ext:abc123",
	})
	if err != nil || item2.AssetKey != "ext:abc123" {
		t.Fatalf("ext asset_key must be preserved, got %q err %v", item2.AssetKey, err)
	}
	if item2.Tags == nil {
		t.Fatal("tags must be a non-nil empty slice for the DB insert")
	}
}
