package cve

import (
	"testing"

	"vuln-scanner/internal/store"
)

func TestFindMatchingKeyTokenBoundaries(t *testing.T) {
	cases := []struct {
		name    string
		product string
		index   map[string]string
		want    string
	}{
		{
			name:    "exact wins",
			product: "git",
			index:   map[string]string{"gitea": "1.21", "git": "2.45.1"},
			want:    "git",
		},
		{
			name:    "no substring false positive",
			product: "git",
			index:   map[string]string{"gitea": "1.21", "gitt": "0.1"},
			want:    "",
		},
		{
			name:    "product is a whole token",
			product: "git",
			index:   map[string]string{"git for windows": "2.45.1"},
			want:    "git for windows",
		},
		{
			name:    "multi-token product contiguous",
			product: "visual studio",
			index:   map[string]string{"visual studio code": "1.85"},
			want:    "visual studio code",
		},
		{
			name:    "reverse distinctive token",
			product: "openssh-portable",
			index:   map[string]string{"openssh": "9.7p1"},
			want:    "openssh",
		},
		{
			name:    "reverse short token blocked",
			product: "node.js",
			index:   map[string]string{"node": "20.11"},
			want:    "",
		},
		{
			name:    "no cross token for 7-zip",
			product: "7-zip",
			index:   map[string]string{"7zip": "21.0"},
			want:    "",
		},
		{
			name:    "python does not leak onto python3",
			product: "python",
			index:   map[string]string{"python3": "3.11.2"},
			want:    "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := findMatchingKey(c.product, c.index); got != c.want {
				t.Fatalf("findMatchingKey(%q) = %q, want %q", c.product, got, c.want)
			}
		})
	}
}

func TestTokenBoundaryContains(t *testing.T) {
	cases := []struct {
		container, needle string
		want              bool
	}{
		{"git for windows", "git", true},
		{"gitea", "git", false},
		{"github", "git", false},
		{"git", "git", true},
		{"openssh-portable", "openssh", true},
		{"node.js", "node", true},
		{"python3", "python", false},
		{"7-zip", "7zip", false},
		{"7zip", "7-zip", false},
	}
	for _, c := range cases {
		if got := tokenBoundaryContains(c.container, c.needle); got != c.want {
			t.Errorf("tokenBoundaryContains(%q, %q) = %v, want %v",
				c.container, c.needle, got, c.want)
		}
	}
}

func TestNameMatchesGiteaNotGit(t *testing.T) {
	if nameMatches("git", map[string]bool{"gitea": true}) {
		t.Fatal("gitea asset must not match the git affected product")
	}
	if !nameMatches("git", map[string]bool{"git for windows": true}) {
		t.Fatal("git for windows asset must match the git affected product")
	}
}

func TestTranslationAliases(t *testing.T) {
	rules := []store.TranslationRule{
		{Pattern: `^PostgreSQL .*`, Product: "postgresql", Platform: "any", Priority: 10},
		{Pattern: `^MySQL .*`, Product: "mysql", Platform: "any", Priority: 10},
		{Pattern: `^python[0-9].*`, Product: "python", Platform: "any", Priority: 10},
		{Pattern: `^Git for Windows.*`, Product: "git", Platform: "windows", Priority: 10},
	}
	tm, err := newTranslationMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}

	tr, ok := tm.match("PostgreSQL 16.2", "", "linux")
	if !ok || tr.Product != "postgresql" {
		t.Fatalf("PostgreSQL = %+v ok=%v, want postgresql", tr, ok)
	}
	tr, ok = tm.match("MySQL 8.0", "", "linux")
	if !ok || tr.Product != "mysql" {
		t.Fatalf("MySQL = %+v ok=%v, want mysql", tr, ok)
	}
	tr, ok = tm.match("python3.11", "", "debian")
	if !ok || tr.Product != "python" {
		t.Fatalf("python3 = %+v ok=%v, want python", tr, ok)
	}
	tr, ok = tm.match("Git for Windows 2.45.1", "", "windows")
	if !ok || tr.Product != "git" {
		t.Fatalf("Git for Windows = %+v ok=%v, want git", tr, ok)
	}
	if _, ok := tm.match("Git for Windows 2.45.1", "", "linux"); ok {
		t.Fatal("windows-scoped alias must not match on linux")
	}
}
