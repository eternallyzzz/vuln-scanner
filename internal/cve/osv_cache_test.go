package cve

import "testing"

func TestOSVPackageKeyAndDedupe(t *testing.T) {
	in := []AssetToMatch{
		{Name: "curl", Version: "1", Format: "rpm", Ecosystem: "AlmaLinux"},
		{Name: "curl", Version: "2", Format: "rpm", Ecosystem: "AlmaLinux"},
		{Name: "curl", Version: "3", Format: "apk", Ecosystem: "Alpine:v3.23"},
	}
	out := uniquePackageAssets(in)
	if len(out) != 2 {
		t.Fatalf("unique packages = %d, want 2", len(out))
	}
	if got := osvPackageKey(out[0]); got != "curl@AlmaLinux" {
		t.Fatalf("osvPackageKey = %q", got)
	}
}
