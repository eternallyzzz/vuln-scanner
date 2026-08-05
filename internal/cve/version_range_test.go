package cve

import (
	"encoding/json"
	"testing"
)

func TestIsVersionAffectedLegacyBounds(t *testing.T) {
	ap := AffectedProduct{MinVer: "1.0", MaxVer: "2.0", Ecosystem: "npm"}
	if !isVersionAffected("1.0", ap) {
		t.Fatal("legacy min bound must be inclusive")
	}
	if !isVersionAffected("1.5", ap) {
		t.Fatal("in-range version must be affected")
	}
	if isVersionAffected("2.0", ap) {
		t.Fatal("legacy max bound must be exclusive")
	}
	if isVersionAffected("2.0.1", ap) {
		t.Fatal("version above max must not be affected")
	}
	if isVersionAffected("0.9", ap) {
		t.Fatal("version below min must not be affected")
	}
}

func TestIsVersionAffectedNVDInclusiveMax(t *testing.T) {
	ap := AffectedProduct{MinVer: "1.0", MaxVer: "2.0", MaxInclusive: boolPtr(true), Ecosystem: "npm"}
	if !isVersionAffected("2.0", ap) {
		t.Fatal("max inclusive bound must include the boundary")
	}
	if isVersionAffected("2.0.1", ap) {
		t.Fatal("version above max must not be affected")
	}
}

func TestIsVersionAffectedNVDExclusiveMin(t *testing.T) {
	ap := AffectedProduct{MinVer: "1.0", MaxVer: "2.0", MinExclusive: boolPtr(true), Ecosystem: "npm"}
	if isVersionAffected("1.0", ap) {
		t.Fatal("min exclusive bound must exclude the boundary")
	}
	if !isVersionAffected("1.0.1", ap) {
		t.Fatal("version above min must be affected")
	}
}

func TestCompareVersionsSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0", "1.0.0-alpha", 1},
		{"1.0.0+build", "1.0.0", 0},
		{"1.10.0", "1.2.0", 1},
		{"v1.2.3", "1.2.3", 0},
		{"1.0.0-rc.1", "1.0.0-rc.2", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareVersionsFallback(t *testing.T) {
	if got := compareVersions("1.0.0a", "1.0.0b"); got != -1 {
		t.Fatalf("fallback compare = %d, want -1", got)
	}
}

func TestCompareCalVer(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2023.1", "2023.10", -1},
		{"2023.10", "2023.1", 1},
		{"2023.1", "2023.1", 0},
		{"2023", "2023.1", -1},
		{"2024.1.1", "2023.12.31", 1},
		{"2024.1.1.2", "2024.1.1.10", -1},
		{"23.1", "2023.1", -1},
		{"14.0", "14.3", -1},
	}
	for _, c := range cases {
		got, ok := compareCalVer(c.a, c.b)
		if !ok {
			t.Errorf("compareCalVer(%q, %q) did not parse", c.a, c.b)
			continue
		}
		if got != c.want {
			t.Errorf("compareCalVer(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	if _, ok := compareCalVer("1.2.3", "1.2.4"); ok {
		t.Fatal("1.2.3 must not parse as CalVer")
	}
	if _, ok := compareCalVer("9.7p1-2", "9.8p1-1"); ok {
		t.Fatal("non-CalVer versions must not parse")
	}
}

func TestComparePEP440(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0a1", "1.0b1", -1},
		{"1.0b1", "1.0rc1", -1},
		{"1.0rc1", "1.0", -1},
		{"1.0", "1.0.post1", -1},
		{"1.0.post1", "1.0.post2", -1},
		{"1.0.dev1", "1.0a1", -1},
		{"1.0.dev1", "1.0", -1},
		{"1.0.post1.dev1", "1.0.post1", -1},
		{"1.0.post1.dev1", "1.0.dev1", 1},
		{"1!2.0", "2.0", 1},
		{"1.0a", "1.0a0", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.0-1", "1.0", 1},
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0rc.1", "1.0.0rc.2", -1},
		{"1.0.0", "1.0.0a1", 1},
		{"1.0c1", "1.0rc1", 0},
	}
	for _, c := range cases {
		got, ok := comparePEP440(c.a, c.b)
		if !ok {
			t.Errorf("comparePEP440(%q, %q) did not parse", c.a, c.b)
			continue
		}
		if got != c.want {
			t.Errorf("comparePEP440(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	// Strings outside the supported PEP 440 shape must fall through.
	if _, ok := comparePEP440("9.7p1-2", "9.8p1-1"); ok {
		t.Fatal("9.7p1-2 must not parse as PEP440")
	}
	if _, ok := comparePEP440("1.0+build", "1.0"); ok {
		t.Fatal("local labels are not supported (mirrors Wazuh regex)")
	}
}

func TestCompareMajorMinor(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2", "1.3", -1},
		{"1-2", "1.3", -1},
		{"2.0", "1.9", 1},
		{"1.2", "1.2", 0},
	}
	for _, c := range cases {
		got, ok := compareMajorMinor(c.a, c.b)
		if !ok {
			t.Errorf("compareMajorMinor(%q, %q) did not parse", c.a, c.b)
			continue
		}
		if got != c.want {
			t.Errorf("compareMajorMinor(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	if _, ok := compareMajorMinor("1.2.3", "1.2.4"); ok {
		t.Fatal("1.2.3 must not parse as MajorMinor")
	}
}

func TestCompareVersionsWazuhChain(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2023.1", "2023.10", -1},   // CalVer
		{"14.0", "14.3", -1},        // CalVer (two-digit year)
		{"1.0.0a", "1.0.0b", -1},    // PEP440
		{"1.0.dev1", "1.0", -1},     // PEP440 dev
		{"9.7p1-2", "9.8p1-1", -1},  // numeric fallback
		{"1.0.0+build", "1.0.0", 0}, // semver
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareDpkgVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1:2.0", "2.0", 1},
		{"2.0", "1:2.0", -1},
		{"1:1.0", "2.0", 1},
		{"1:2.0-1", "1:2.0", 1},
		{"1:2.0", "1:2.0-1", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"3.0.11-1~deb12u2", "3.0.11-1~deb12u3", -1},
		{"1.0a", "1.0b", -1},
		{"1.0a", "1.0", 1},
		{"1.0", "1.0a", -1},
	}
	for _, c := range cases {
		if got := compareDpkgVersions(c.a, c.b); got != c.want {
			t.Errorf("compareDpkgVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestNVDCPEVersionFlags(t *testing.T) {
	c := NewNVDClient()
	raw := json.RawMessage(`[{
		"nodes": [{
			"operator": "OR",
			"cpeMatch": [
				{
					"vulnerable": true,
					"criteria": "cpe:/a:vendor:product",
					"versionStartExcluding": "1.0.0",
					"versionEndIncluding": "2.0.0"
				},
				{
					"vulnerable": true,
					"criteria": "cpe:/a:vendor:other",
					"versionStartIncluding": "3.0",
					"versionEndExcluding": "4.0"
				}
			]
		}]
	}]`)
	products := c.extractAffectedProducts(NVDCVE{Configurations: raw})
	if len(products) != 2 {
		t.Fatalf("products = %d, want 2", len(products))
	}
	byName := make(map[string]AffectedProduct)
	for _, p := range products {
		byName[p.Name] = p
	}
	p := byName["product"]
	if p.MinVer != "1.0.0" || p.MinExclusive == nil || !*p.MinExclusive {
		t.Fatalf("exclusive min not parsed: %+v", p)
	}
	if p.MaxVer != "2.0.0" || p.MaxInclusive == nil || !*p.MaxInclusive {
		t.Fatalf("inclusive max not parsed: %+v", p)
	}
	o := byName["other"]
	if o.MinVer != "3.0" || o.MinExclusive != nil {
		t.Fatalf("default min must stay inclusive: %+v", o)
	}
	if o.MaxVer != "4.0" || o.MaxInclusive != nil {
		t.Fatalf("default max must stay exclusive: %+v", o)
	}
}

func TestNVDIsVersionAffectedUsesInclusiveMax(t *testing.T) {
	affected, err := json.Marshal([]AffectedProduct{{
		MaxVer:       "2.0.0",
		MaxInclusive: boolPtr(true),
	}})
	if err != nil {
		t.Fatal(err)
	}
	c := NewNVDClient()
	entries := []FeedEntry{{Affected: affected}}
	if !c.IsVersionAffected(entries, "2.0.0") {
		t.Fatal("inclusive max boundary must be affected")
	}
	if c.IsVersionAffected(entries, "2.0.1") {
		t.Fatal("version above inclusive max must not be affected")
	}
	if c.IsVersionAffected(entries, "") {
		t.Fatal("empty version must not be affected")
	}
}
