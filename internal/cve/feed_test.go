package cve

import (
	"encoding/json"
	"testing"
)

func TestFindInstalledVersionExactWins(t *testing.T) {
	versions := map[string]string{
		"git":    "2.45.1",
		"gitea":  "1.21.22",
		"github": "3.4.1",
	}
	if got := findInstalledVersion("git", versions); got != "2.45.1" {
		t.Fatalf("git: got %q, want 2.45.1", got)
	}
	if got := findInstalledVersion("gitea", versions); got != "1.21.22" {
		t.Fatalf("gitea: got %q, want 1.21.22", got)
	}
}

func TestFindInstalledVersionNoSubstringFalseMatch(t *testing.T) {
	versions := map[string]string{
		"github desktop": "3.4.1",
		"gitea":          "1.21.22",
		"gitlab":         "16.0.0",
	}
	if got := findInstalledVersion("git", versions); got != "" {
		t.Fatalf("git must not match substring assets, got %q", got)
	}
}

func TestFindInstalledVersionTokenAndBoundary(t *testing.T) {
	versions := map[string]string{
		"7-zip 23.01": "23.01",
		"git-scm":     "2.45.1",
	}
	if got := findInstalledVersion("7-zip", versions); got != "23.01" {
		t.Fatalf("7-zip: got %q, want 23.01", got)
	}
	if got := findInstalledVersion("git", versions); got != "2.45.1" {
		t.Fatalf("git-scm boundary: got %q, want 2.45.1", got)
	}
}

func TestFindInstalledVersionDeterministic(t *testing.T) {
	versions := map[string]string{
		"git":      "2.45.1",
		"git-lfs":  "3.5.1",
		"gitea":    "1.21.22",
		"7-zip":    "23.01",
		"openssl":  "3.0.11",
		"openssl2": "9.9.9",
	}
	for i := 0; i < 20; i++ {
		if got := findInstalledVersion("git", versions); got != "2.45.1" {
			t.Fatalf("iteration %d: git got %q", i, got)
		}
		if got := findInstalledVersion("openssl", versions); got != "3.0.11" {
			t.Fatalf("iteration %d: openssl got %q", i, got)
		}
	}
}

func TestFindMatchingKeyDeterministicShortest(t *testing.T) {
	idx := map[string]string{
		"golang-1.19":     "1.19.8",
		"golang-1.19-go":  "1.19.8",
		"golang-1.19-src": "1.19.8",
		"golang-1.19-doc": "1.19.8",
	}
	for i := 0; i < 20; i++ {
		if got := findMatchingKey("golang-1.19", idx); got != "golang-1.19" {
			t.Fatalf("iteration %d: got %q, want golang-1.19", i, got)
		}
	}

	exact := map[string]string{"gitea": "1.21.22", "github": "3.4.1", "git": "2.45.1"}
	if got := findMatchingKey("git", exact); got != "git" {
		t.Fatalf("git: got %q, want git", got)
	}

	// Whole-token matching must not let "python" leak onto "python3"
	// (git->gitea class); distro packages are covered by translation aliases.
	prefix := map[string]string{"python3.11": "3.11.2", "python3": "3.11.2"}
	if got := findMatchingKey("python", prefix); got != "" {
		t.Fatalf("python: got %q, want no match without alias", got)
	}
	token := map[string]string{"git for windows": "2.45.1"}
	if got := findMatchingKey("git", token); got != "git for windows" {
		t.Fatalf("git: got %q, want git for windows (whole token)", got)
	}
}

func TestResolveAssetNameExactWins(t *testing.T) {
	versions := map[string]string{"musl": "1.2.5-r21", "musl-utils": "1.2.5-r21"}
	ap := AffectedProduct{Name: "musl", Ecosystem: "Alpine:v3.23"}
	if got := resolveAssetName("osv", ap, nil, versions, ""); got != "musl" {
		t.Fatalf("exact package name must win, got %q", got)
	}
	// The containment heuristic still resolves short names when no exact match.
	ap2 := AffectedProduct{Name: "git"}
	versions2 := map[string]string{"git-scm": "2.45.1"}
	if got := resolveAssetName("osv", ap2, nil, versions2, ""); got != "git-scm" {
		t.Fatalf("containment fallback broken, got %q", got)
	}
}

func TestCPEVersionCompatible(t *testing.T) {
	idx := map[string]string{
		"openssl":   "3.0.6",
		"libssl1.1": "1.1.1n",
		"lib11.1":   "9.9.9",
	}
	cases := []struct {
		name      string
		feedVer   string
		agentVer  string
		agentName string
		index     map[string]string
		want      bool
	}{
		{name: "empty feed version accepted", feedVer: "", agentVer: "3.0.6", agentName: "openssl", index: idx, want: true},
		{name: "star feed version accepted", feedVer: "*", agentVer: "3.0.6", agentName: "openssl", index: idx, want: true},
		{name: "dash feed version accepted", feedVer: "-", agentVer: "3.0.6", agentName: "openssl", index: idx, want: true},
		{name: "exact version", feedVer: "3.0.6", agentVer: "3.0.6", agentName: "openssl", index: idx, want: true},
		{name: "feed is segment prefix", feedVer: "1.0", agentVer: "1.0.3", agentName: "openssl", index: idx, want: true},
		{name: "agent is segment prefix", feedVer: "1.0.3", agentVer: "1.0", agentName: "openssl", index: idx, want: true},
		{name: "major segment drift", feedVer: "1.0", agentVer: "10.0", agentName: "openssl", index: idx, want: false},
		{name: "longer numeric segment", feedVer: "1.0.3", agentVer: "1.0.30", agentName: "openssl", index: idx, want: false},
		{name: "letter suffix differs", feedVer: "1.0.1f", agentVer: "1.0.1g", agentName: "openssl", index: idx, want: false},
		{name: "partial patch is not prefix", feedVer: "1.0.1", agentVer: "1.0.1f", agentName: "openssl", index: idx, want: false},
		{name: "version embedded in name", feedVer: "1.1", agentVer: "1.0.2", agentName: "libssl1.1", index: map[string]string{"libssl1.1": "1.0.2"}, want: true},
		{name: "version embedded in related key", feedVer: "1.1", agentVer: "1.0.2", agentName: "libssl", index: map[string]string{"libssl": "1.0.2", "libssl1.1": "1.0.2"}, want: true},
		{name: "numeric token is not a version boundary", feedVer: "1.1", agentVer: "9.9.9", agentName: "lib11.1", index: map[string]string{"lib11.1": "9.9.9"}, want: false},
		{name: "unrelated embedded name", feedVer: "1.1", agentVer: "9.9.9", agentName: "other", index: map[string]string{"libssl1.1": "1.0.2"}, want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cpeVersionCompatible(c.feedVer, c.agentVer, c.agentName, c.index); got != c.want {
				t.Fatalf("cpeVersionCompatible(%q, %q, %q) = %v, want %v",
					c.feedVer, c.agentVer, c.agentName, got, c.want)
			}
		})
	}
}

func TestVersionEmbeddedInNameBoundaries(t *testing.T) {
	cases := []struct {
		name, ver string
		want      bool
	}{
		{"libssl1.1", "1.1", true},
		{"lib11.1", "1.1", false},
		{"libssl1.10", "1.1", false},
		{"libssl1.1-1", "1.1", true},
		{"openssl-1.0.1f", "1.0.1", true},
		{"openssl-1.0.1f", "1.0.1f", true},
		{"libssl1.1f", "1.1", true},
		{"", "1.1", false},
		{"libssl1.1", "", false},
	}
	for _, c := range cases {
		if got := versionEmbeddedInName(c.name, c.ver); got != c.want {
			t.Errorf("versionEmbeddedInName(%q, %q) = %v, want %v", c.name, c.ver, got, c.want)
		}
	}
}

func TestVersionSegmentPrefixCompatible(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.0", "1.0.3", true},
		{"1.0.3", "1.0", true},
		{"1.0.3", "1.0.3", true},
		{"1.0", "10.0", false},
		{"1.0.3", "1.0.30", false},
		{"1.0.1", "1.0.1f", false},
		{"v1.0", "1.0.3", true},
		{"1:3.0.7-24.el8", "3.0.7", true},
	}
	for _, c := range cases {
		if got := versionSegmentPrefixCompatible(c.a, c.b); got != c.want {
			t.Errorf("versionSegmentPrefixCompatible(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestCleanAffectedProductsConsistency(t *testing.T) {
	mk := func(ap AffectedProduct) json.RawMessage {
		b, err := json.Marshal([]AffectedProduct{ap})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := []struct {
		name   string
		source string
		ap     AffectedProduct
		want   bool
	}{
		{name: "valid fixed at exclusive max", source: "nvd", ap: AffectedProduct{Name: "nginx", MaxVer: "1.22.0", FixedIn: "1.22.0"}, want: true},
		{name: "valid fixed above inclusive max", source: "nvd", ap: AffectedProduct{Name: "log4j", MaxVer: "2.14.1", MaxInclusive: boolPtr(true), FixedIn: "2.15.0"}, want: true},
		{name: "fixed below exclusive max rejected", source: "nvd", ap: AffectedProduct{Name: "nginx", MaxVer: "1.22.0", FixedIn: "1.20.0"}, want: false},
		{name: "fixed equals inclusive max rejected", source: "nvd", ap: AffectedProduct{Name: "log4j", MaxVer: "2.14.1", MaxInclusive: boolPtr(true), FixedIn: "2.14.1"}, want: false},
		{name: "min above max rejected", source: "nvd", ap: AffectedProduct{Name: "x", MinVer: "2.0", MaxVer: "1.0"}, want: false},
		{name: "msrc kb url mismatch rejected", source: "msrc", ap: AffectedProduct{Name: "Windows 11", FixedIn: "KB5008218", KBURL: "https://support.microsoft.com/help/9999999"}, want: false},
		{name: "msrc kb without url accepted", source: "msrc", ap: AffectedProduct{Name: "Windows 11", FixedIn: "KB5008218"}, want: true},
		{name: "empty name rejected", source: "nvd", ap: AffectedProduct{Name: ""}, want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := len(cleanAffectedProducts(c.source, mk(c.ap))) == 1
			if got != c.want {
				t.Fatalf("cleanAffectedProducts(%q, %+v) valid=%v, want %v", c.source, c.ap, got, c.want)
			}
		})
	}
}

func TestIsRelevantProductUbuntuScoping(t *testing.T) {
	names := map[string]bool{"openssl": true}
	ap := AffectedProduct{Name: "openssl", Ecosystem: "Ubuntu:22.04:LTS", FixedIn: "3.0.2-0ubuntu1.18"}
	if !isRelevantProduct(ap, "osv", "Ubuntu 22.04.5 LTS", "22.04.5", "", names) {
		t.Fatal("22.04 agent must accept Ubuntu:22.04:LTS record")
	}
	if isRelevantProduct(ap, "osv", "Ubuntu 24.04.2 LTS", "24.04.2", "", names) {
		t.Fatal("24.04 agent must not accept Ubuntu:22.04:LTS record")
	}
	if isRelevantProduct(ap, "osv", "Debian GNU/Linux", "12", "", names) {
		t.Fatal("Debian agent must not accept an Ubuntu record")
	}

	ap2 := AffectedProduct{Name: "openssl", Ecosystem: "Ubuntu:24.10", FixedIn: "3.3.2-1ubuntu1"}
	if !isRelevantProduct(ap2, "osv", "Ubuntu 24.10", "24.10", "", names) {
		t.Fatal("24.10 agent must accept Ubuntu:24.10 record")
	}
	if isRelevantProduct(ap2, "osv", "Ubuntu 22.04.5 LTS", "22.04.5", "", names) {
		t.Fatal("22.04 agent must not accept Ubuntu:24.10 record")
	}
}
