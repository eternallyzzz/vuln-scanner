package cve

import "testing"

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
