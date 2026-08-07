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
			SupportURL: "https://support.microsoft.com/help/5008218",
			CatalogURL: "https://www.catalog.update.microsoft.com/Search.aspx?q=KB5008218",
			Status:     "ok",
		},
	}
	downloads := map[string][]store.KBDownload{
		"KB5008218": {{
			KB: "KB5008218", OSFamily: "windows 11", Arch: "x64",
			URL:    "https://catalog.s.download.windowsupdate.com/d/x/windows11.0-kb5008218-x64.msu",
			SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		}},
	}
	enrichKBLinks(kbs, meta, downloads, "Windows 11 Pro 23H2", "amd64")

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
	if got := bestPatchURL(m, nil, "", ""); got != m.CatalogURL {
		t.Fatalf("broken support link must not be primary, got %q", got)
	}
}

func TestBestPatchURLDownloadWins(t *testing.T) {
	m := store.KBMetadata{
		SupportURL: "https://support.microsoft.com/help/5018427",
		CatalogURL: "https://www.catalog.update.microsoft.com/Search.aspx?q=KB5018427",
		Status:     "ok",
	}
	downloads := []store.KBDownload{{
		KB: "KB5018427", OSFamily: "windows 11", Arch: "x64",
		URL:    "https://catalog.s.download.windowsupdate.com/d/x/windows11.0-kb5018427-x64.msu",
		SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}}
	want := downloads[0].URL
	if got := bestPatchURL(m, downloads, "Windows 11 Pro 23H2", "amd64"); got != want {
		t.Fatalf("download must win over support, got %q", got)
	}
}

func TestBestPatchURLUnverifiedDownloadFallsBack(t *testing.T) {
	m := store.KBMetadata{
		SupportURL: "https://support.microsoft.com/help/5018427",
		CatalogURL: "https://www.catalog.update.microsoft.com/Search.aspx?q=KB5018427",
		Status:     "ok",
	}
	downloads := []store.KBDownload{{
		KB: "KB5018427", OSFamily: "windows 11", Arch: "x64",
		URL: "https://catalog.s.download.windowsupdate.com/d/x/windows11.0-kb5018427-x64.msu",
	}}
	if got := bestPatchURL(m, downloads, "Windows 11 Pro 23H2", "amd64"); got != m.SupportURL {
		t.Fatalf("unverified download must not be auto-deployable, got %q", got)
	}
}

func TestSelectKBDownloadPrefersAgentVariant(t *testing.T) {
	downloads := []store.KBDownload{
		{KB: "KB1", OSFamily: "windows 10", Arch: "x64", URL: "win10"},
		{KB: "KB1", OSFamily: "windows 11", Arch: "x64", URL: "win11"},
		{KB: "KB1", OSFamily: "server", Arch: "x64", URL: "server"},
		{KB: "KB1", OSFamily: "windows 11", Arch: "arm64", URL: "win11-arm"},
	}
	if got := selectKBDownload(downloads, "windows 11", "amd64"); got.URL != "win11" {
		t.Fatalf("windows 11 x64 selection = %q, want win11", got.URL)
	}
	if got := selectKBDownload(downloads, "windows 11", "arm64"); got.URL != "win11-arm" {
		t.Fatalf("windows 11 arm64 selection = %q, want win11-arm", got.URL)
	}
	if got := selectKBDownload(downloads, "windows 11", "aarch64"); got.URL != "win11-arm" {
		t.Fatalf("windows 11 aarch64 selection = %q, want win11-arm", got.URL)
	}
	if got := selectKBDownload(downloads, kbOSFamily("windows server 2019"), "amd64"); got.URL != "server" {
		t.Fatalf("server selection = %q, want server", got.URL)
	}
}
