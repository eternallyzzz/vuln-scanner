package server

import (
	"testing"

	"vuln-scanner/internal/store"
)

func TestAdvisoryURLFor(t *testing.T) {
	if got := advisoryURLFor("CVE-2021-43893", "https://example.com/x"); got !=
		"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-43893" {
		t.Fatalf("CVE advisory URL wrong: %q", got)
	}
	if got := advisoryURLFor("ADV180012", "https://example.com/x"); got !=
		"https://msrc.microsoft.com/update-guide/advisory/ADV180012" {
		t.Fatalf("ADV advisory URL wrong: %q", got)
	}
	if got := advisoryURLFor("SOME-OTHER-ID", "https://example.com/x"); got != "https://example.com/x" {
		t.Fatalf("fallback advisory URL wrong: %q", got)
	}
}

func TestCatalogURLForKB(t *testing.T) {
	if got := catalogURLForKB("KB5008218"); got !=
		"https://www.catalog.update.microsoft.com/Search.aspx?q=KB5008218" {
		t.Fatalf("catalog URL wrong: %q", got)
	}
	if got := catalogURLForKB("no-kb"); got != "" {
		t.Fatalf("non-KB must produce no URL, got %q", got)
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
	meta := map[string]store.KBMetadata{
		"KB5008218": {
			KB: "KB5008218", ProductFamily: "windows",
			SupportURL:     "https://support.microsoft.com/help/5008218",
			CatalogURL:     "https://www.catalog.update.microsoft.com/Search.aspx?q=KB5008218",
			DownloadURL:    "https://catalog.s.download.windowsupdate.com/d/x/windows11.0-kb5008218-x64.msu",
			DownloadSHA256: "S28F+jYcZfOWxmbJegW2u45MQRo=",
			Status:         "ok",
		},
	}
	enrichKBLinks(kbs, meta)

	if kbs[0].ReferenceURL != "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-43893" {
		t.Fatalf("first CVE reference wrong: %q", kbs[0].ReferenceURL)
	}
	if kbs[0].PatchURL != "https://catalog.s.download.windowsupdate.com/d/x/windows11.0-kb5008218-x64.msu" {
		t.Fatalf("resolved download must be the primary patch URL, got %q", kbs[0].PatchURL)
	}
	if len(kbs[0].Links) != 4 {
		t.Fatalf("expected advisory+support+download+catalog links, got %d", len(kbs[0].Links))
	}
	if kbs[0].Links[2].Type != "download" || !kbs[0].Links[2].Verified {
		t.Fatalf("download link must be present and verified: %+v", kbs[0].Links)
	}
	if kbs[1].ReferenceURL != "" {
		t.Fatalf("empty CVE list must leave reference empty, got %q", kbs[1].ReferenceURL)
	}
	if kbs[1].PatchURL != "https://www.catalog.update.microsoft.com/Search.aspx?q=KB4565489" {
		t.Fatalf("unverified KB must fall back to catalog, got %q", kbs[1].PatchURL)
	}
}

func TestBestPatchURLBrokenSupportFallsBack(t *testing.T) {
	m := store.KBMetadata{
		SupportURL: "https://support.microsoft.com/help/4512507",
		CatalogURL: "https://www.catalog.update.microsoft.com/Search.aspx?q=KB4512507",
		Status:     "broken",
	}
	if got := bestPatchURL(m); got != m.CatalogURL {
		t.Fatalf("broken support link must not be primary, got %q", got)
	}
}

func TestBestPatchURLDownloadWins(t *testing.T) {
	m := store.KBMetadata{
		SupportURL:  "https://support.microsoft.com/help/5018427",
		CatalogURL:  "https://www.catalog.update.microsoft.com/Search.aspx?q=KB5018427",
		DownloadURL: "https://catalog.s.download.windowsupdate.com/d/x/windows11.0-kb5018427-x64.msu",
		Status:      "ok",
	}
	if got := bestPatchURL(m); got != m.DownloadURL {
		t.Fatalf("download must win over support, got %q", got)
	}
}
