package server

import (
	"testing"

	"vuln-scanner/internal/store"
)

func TestMsrcLinks(t *testing.T) {
	catalog := "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5008218"
	adv, patch := msrcLinks("CVE-2021-43893", catalog)
	if adv != "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-43893" {
		t.Fatalf("advisory URL wrong: %q", adv)
	}
	if patch != "https://support.microsoft.com/help/5008218" {
		t.Fatalf("patch URL must be the support help page, got %q", patch)
	}

	// Advisory IDs get the Update Guide advisory page plus the KB help page.
	adv, patch = msrcLinks("ADV180012", "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB4467708")
	if adv != "https://msrc.microsoft.com/update-guide/advisory/ADV180012" {
		t.Fatalf("ADV advisory URL wrong: %q", adv)
	}
	if patch != "https://support.microsoft.com/help/4467708" {
		t.Fatalf("ADV patch URL wrong: %q", patch)
	}

	// KB extracted from a bare KB value also works.
	_, patch = msrcLinks("CVE-2021-43893", "KB5008218")
	if patch != "https://support.microsoft.com/help/5008218" {
		t.Fatalf("bare KB patch URL wrong: %q", patch)
	}

	// Unknown IDs keep the stored URL; no KB means no patch URL.
	adv, patch = msrcLinks("SOME-OTHER-ID", "https://example.com/x")
	if adv != "https://example.com/x" || patch != "" {
		t.Fatalf("fallback wrong: adv=%q patch=%q", adv, patch)
	}
}

func TestEnrichAdvisoryURLs(t *testing.T) {
	results := []store.CVEResult{
		{CVEID: "CVE-2021-43893", Source: "msrc"},
		{CVEID: "GHSA-abc", Source: "osv"},
		{CVEID: "ADV180012", Source: "msrc"},
	}
	enrichAdvisoryURLs(results)
	if results[0].AdvisoryURL != "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-43893" {
		t.Fatalf("msrc CVE must get advisory URL, got %q", results[0].AdvisoryURL)
	}
	if results[1].AdvisoryURL != "" {
		t.Fatalf("non-msrc row must not get advisory URL: %+v", results[1])
	}
	if results[2].AdvisoryURL != "https://msrc.microsoft.com/update-guide/advisory/ADV180012" {
		t.Fatalf("ADV row must get advisory URL, got %q", results[2].AdvisoryURL)
	}
}

func TestEnrichKBLinks(t *testing.T) {
	kbs := []store.KBPatchRecommendation{
		{Kb: "KB5008218", CVEIDs: []string{"CVE-2021-43893", "CVE-2021-43883"}},
		{Kb: "KB4565489", CVEIDs: nil},
	}
	enrichKBLinks(kbs)
	if kbs[0].ReferenceURL != "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-43893" {
		t.Fatalf("first CVE reference wrong: %q", kbs[0].ReferenceURL)
	}
	if kbs[0].PatchURL != "https://support.microsoft.com/help/5008218" {
		t.Fatalf("patch URL wrong: %q", kbs[0].PatchURL)
	}
	if kbs[1].ReferenceURL != "" {
		t.Fatalf("empty CVE list must leave reference empty, got %q", kbs[1].ReferenceURL)
	}
	if kbs[1].PatchURL != "https://support.microsoft.com/help/4565489" {
		t.Fatalf("KB help URL wrong: %q", kbs[1].PatchURL)
	}
}
