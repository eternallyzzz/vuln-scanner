package cve

import (
	"testing"

	"vuln-scanner/internal/store"
)

func testTranslationRules() []store.TranslationRule {
	return []store.TranslationRule{
		{
			Pattern:        `^LibreOffice .*`,
			VendorPattern:  `(?i)the document foundation`,
			VersionPattern: ` (\d+(?:\.\d+)+)\s*$`,
			Product:        "libreoffice",
			Platform:       "windows",
			Priority:       10,
		},
		{
			Pattern:        `^Skype for Business Basic .*`,
			VendorPattern:  `(?i)microsoft corporation`,
			VersionPattern: ` (\d+)\s*$`,
			HotfixKB:       "KB3114960",
			Product:        "skype_for_business",
			Platform:       "windows",
			Priority:       10,
		},
		{
			Pattern:  `^Git$`,
			Product:  "git",
			Platform: "any",
			Priority: 5,
		},
	}
}

func TestTranslationMatcherLibreOffice(t *testing.T) {
	tm, err := newTranslationMatcher(testTranslationRules())
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := tm.match("LibreOffice 4.2.0.1", "The Document Foundation", "windows")
	if !ok {
		t.Fatal("LibreOffice rule must match")
	}
	if tr.Product != "libreoffice" || tr.Version != "4.2.0.1" {
		t.Fatalf("translation = %+v, want libreoffice/4.2.0.1", tr)
	}
}

func TestTranslationMatcherSkypeHotfix(t *testing.T) {
	tm, err := newTranslationMatcher(testTranslationRules())
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := tm.match("Skype for Business Basic 2016", "Microsoft Corporation", "windows")
	if !ok {
		t.Fatal("Skype rule must match")
	}
	if tr.Product != "skype_for_business" || tr.Version != "2016" || tr.HotfixKB != "KB3114960" {
		t.Fatalf("translation = %+v, want skype_for_business/2016/KB3114960", tr)
	}
}

func TestTranslationMatcherVendorMismatch(t *testing.T) {
	tm, err := newTranslationMatcher(testTranslationRules())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tm.match("LibreOffice 4.2.0.1", "Some Other Vendor", "windows"); ok {
		t.Fatal("vendor mismatch must not translate")
	}
	if _, ok := tm.match("LibreOffice 4.2.0.1", "", "windows"); ok {
		t.Fatal("missing vendor must not translate a vendor-scoped rule")
	}
}

func TestTranslationMatcherPlatform(t *testing.T) {
	tm, err := newTranslationMatcher(testTranslationRules())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tm.match("LibreOffice 4.2.0.1", "The Document Foundation", "linux"); ok {
		t.Fatal("windows-scoped rule must not match on linux")
	}
	tr, ok := tm.match("Git", "", "linux")
	if !ok || tr.Product != "git" {
		t.Fatalf("any-platform rule must match, got %+v ok=%v", tr, ok)
	}
}

func TestTranslationMatcherVersionExtractionFallback(t *testing.T) {
	tm, err := newTranslationMatcher(testTranslationRules())
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := tm.match("LibreOffice (x64)", "The Document Foundation", "windows")
	if !ok || tr.Product != "libreoffice" {
		t.Fatalf("rule must still translate when version extraction fails: %+v ok=%v", tr, ok)
	}
	if tr.Version != "" {
		t.Fatalf("version = %q, want empty fallback", tr.Version)
	}
}

func TestTranslationMatcherPriority(t *testing.T) {
	rules := []store.TranslationRule{
		{Pattern: `^LibreOffice .*`, Product: "low", Platform: "windows", Priority: 1},
		{Pattern: `^LibreOffice .*`, Product: "high", Platform: "windows", Priority: 99},
	}
	tm, err := newTranslationMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := tm.match("LibreOffice 4.2.0.1", "", "windows")
	if !ok || tr.Product != "high" {
		t.Fatalf("translation = %+v ok=%v, want high-priority rule", tr, ok)
	}
}

func TestTranslationMatcherNil(t *testing.T) {
	var tm *translationMatcher
	if _, ok := tm.match("anything", "", "windows"); ok {
		t.Fatal("nil matcher must not match")
	}
	if tm.hotfixes() != nil {
		t.Fatal("nil matcher must return nil hotfix map")
	}
}
