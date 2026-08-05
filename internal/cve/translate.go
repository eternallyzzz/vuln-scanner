package cve

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"vuln-scanner/internal/store"
)

// Translation is the outcome of applying a package translation rule.
type Translation struct {
	Product  string
	Version  string
	HotfixKB string
}

type compiledTranslationRule struct {
	pattern        *regexp.Regexp
	vendorPattern  *regexp.Regexp
	versionPattern *regexp.Regexp
	product        string
	hotfixKB       string
	platform       string
}

// translationMatcher applies package translation rules in priority order.
// The matching logic is pure Go so it can be unit tested without a database.
type translationMatcher struct {
	rules []compiledTranslationRule
}

func newTranslationMatcher(rules []store.TranslationRule) (*translationMatcher, error) {
	sorted := append([]store.TranslationRule(nil), rules...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Priority > sorted[j].Priority
	})

	compiled := make([]compiledTranslationRule, 0, len(sorted))
	for _, r := range sorted {
		pat, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile translation pattern %q: %w", r.Pattern, err)
		}
		var vendorRe, versionRe *regexp.Regexp
		if r.VendorPattern != "" {
			vendorRe, err = regexp.Compile(r.VendorPattern)
			if err != nil {
				return nil, fmt.Errorf("compile vendor pattern %q: %w", r.VendorPattern, err)
			}
		}
		if r.VersionPattern != "" {
			versionRe, err = regexp.Compile(r.VersionPattern)
			if err != nil {
				return nil, fmt.Errorf("compile version pattern %q: %w", r.VersionPattern, err)
			}
		}
		compiled = append(compiled, compiledTranslationRule{
			pattern:        pat,
			vendorPattern:  vendorRe,
			versionPattern: versionRe,
			product:        r.Product,
			hotfixKB:       r.HotfixKB,
			platform:       strings.ToLower(r.Platform),
		})
	}
	return &translationMatcher{rules: compiled}, nil
}

// match returns the highest-priority translation whose platform is
// compatible, whose pattern matches the package name, and whose vendor
// pattern (when set) matches the asset vendor. When a version pattern is
// present but yields no match, the translation still succeeds and Version
// stays empty so the caller falls back to the asset's own version.
func (m *translationMatcher) match(name, vendor, platform string) (Translation, bool) {
	if m == nil || len(m.rules) == 0 {
		return Translation{}, false
	}
	platform = strings.ToLower(platform)
	for _, r := range m.rules {
		if r.platform != "any" && r.platform != platform {
			continue
		}
		if !r.pattern.MatchString(name) {
			continue
		}
		if r.vendorPattern != nil {
			if vendor == "" || !r.vendorPattern.MatchString(vendor) {
				continue
			}
		}
		out := Translation{Product: r.product, HotfixKB: r.hotfixKB}
		if r.versionPattern != nil {
			if sub := r.versionPattern.FindStringSubmatch(name); sub != nil {
				if len(sub) > 1 && sub[1] != "" {
					out.Version = sub[1]
				} else {
					out.Version = sub[0]
				}
			}
		}
		return out, true
	}
	return Translation{}, false
}

// hotfixes maps lowercased translated product names to the hotfix KB that
// remediates them, for rules that declare one.
func (m *translationMatcher) hotfixes() map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string)
	for _, r := range m.rules {
		if r.hotfixKB != "" {
			out[strings.ToLower(r.product)] = r.hotfixKB
		}
	}
	return out
}
