package patch

import (
	"strings"
	"testing"
)

func TestExpandFixSetAddsInstalledDependency(t *testing.T) {
	rules := []DependencyRule{
		{AssetName: "curl", FixType: "version", DependencyAsset: "libcurl4",
			DependencyFixType: "version", Required: true, Enabled: true, Reason: "same advisory"},
	}
	main := FixSetItem{AssetName: "curl", FixType: "version", FixValue: "8.4.0", Action: "upgrade_package"}

	items, err := ExpandFixSet(main, rules, map[string]bool{"curl": true, "libcurl4": true})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2 (curl + libcurl4)", len(items))
	}
	if items[0].AssetName != "curl" || items[1].AssetName != "libcurl4" {
		t.Fatalf("unexpected order/content: %+v", items)
	}
	if len(items[0].Dependencies) != 1 || items[0].Dependencies[0].AssetName != "libcurl4" {
		t.Fatalf("main dependencies = %+v", items[0].Dependencies)
	}
}

func TestExpandFixSetSkipsMissingAndDisabled(t *testing.T) {
	rules := []DependencyRule{
		{AssetName: "curl", FixType: "version", DependencyAsset: "libcurl4",
			DependencyFixType: "version", Required: true, Enabled: true},
		{AssetName: "curl", FixType: "version", DependencyAsset: "libcurl4-doc",
			DependencyFixType: "version", Required: true, Enabled: false},
	}
	main := FixSetItem{AssetName: "curl", FixType: "version", FixValue: "8.4.0"}
	items, err := ExpandFixSet(main, rules, map[string]bool{"curl": true})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want only main (dependency not installed/disabled)", len(items))
	}
}

func TestExpandFixSetRejectsSelfAndDedupes(t *testing.T) {
	rules := []DependencyRule{
		{AssetName: "a", FixType: "version", DependencyAsset: "b",
			DependencyFixType: "version", Required: true, Enabled: true},
		{AssetName: "b", FixType: "version", DependencyAsset: "a",
			DependencyFixType: "version", Required: true, Enabled: true},
		{AssetName: "a", FixType: "version", DependencyAsset: "b",
			DependencyFixType: "version", Required: true, Enabled: true},
	}
	main := FixSetItem{AssetName: "a", FixType: "version", FixValue: "1.0"}
	items, err := ExpandFixSet(main, rules, map[string]bool{"a": true, "b": true})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2 (a + b, no self/back edge)", len(items))
	}
}

func TestHashFixSetStableAndSensitive(t *testing.T) {
	a := []FixSetItem{
		{AssetName: "curl", FixType: "version", FixValue: "8.4.0", CVEIDs: []string{"CVE-2", "CVE-1"}},
		{AssetName: "libcurl4", FixType: "version", FixValue: ""},
	}
	b := []FixSetItem{
		{AssetName: "curl", FixType: "version", FixValue: "8.4.0", CVEIDs: []string{"CVE-1", "CVE-2"}},
		{AssetName: "libcurl4", FixType: "version", FixValue: ""},
	}
	if HashFixSet(a) != HashFixSet(b) {
		t.Fatal("hash must be stable regardless of CVE ordering")
	}
	c := []FixSetItem{{AssetName: "curl", FixType: "version", FixValue: "9.0.0"}}
	if HashFixSet(a) == HashFixSet(c) {
		t.Fatal("hash must change when the main fix changes")
	}
}

func TestBuildCommandsForFixSet(t *testing.T) {
	items := []FixSetItem{
		{AssetName: "curl", FixType: "version", FixValue: "8.4.0"},
		{AssetName: "libcurl4", FixType: "version", FixValue: ""},
	}
	cmd, err := BuildCommandsForFixSet(&Config{}, items, "Debian 12", "12")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !cmd.Deployable {
		t.Fatal("version fix set must be deployable")
	}
	if len(cmd.ArgvLists) != 4 {
		t.Fatalf("argv lists = %d, want 4 (apt-get update + install for each of 2 items)", len(cmd.ArgvLists))
	}
	if !strings.Contains(cmd.Display, "curl") || !strings.Contains(cmd.Display, "libcurl4") {
		t.Fatalf("display missing packages: %q", cmd.Display)
	}
}
