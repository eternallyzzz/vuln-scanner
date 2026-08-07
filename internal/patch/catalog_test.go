package patch

import (
	"strings"
	"testing"
)

const searchPageFixture = `
<table>
<tr id="11111111-2222-3333-4444-555555555555_R0" style="border-width:0px;">
    <td class="resultsbottomBorder resultspadding" id="11111111-2222-3333-4444-555555555555_C1_R0">
        <a id='11111111-2222-3333-4444-555555555555_link' href= "javascript:void(0);" onclick='goToDetails("11111111-2222-3333-4444-555555555555");' class="contentTextItemSpacerNoBreakLink">
            2022-10 Cumulative Update for Windows 11 Version 22H2 for ARM64-based Systems (KB5018427)
        </a>
    </td>
</tr>
<tr id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee_R0" style="border-width:0px;">
    <td class="resultsbottomBorder resultspadding" id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee_C1_R0">
        <a id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee_link' href= "javascript:void(0);" onclick='goToDetails("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");' class="contentTextItemSpacerNoBreakLink">
            2022-10 Cumulative Update for Windows 11 Version 22H2 for x64-based Systems (KB5018427)
        </a>
    </td>
</tr>
</table>`

func TestParseCatalogSearchResults(t *testing.T) {
	entries := parseCatalogSearchResults(searchPageFixture)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].GUID != "11111111-2222-3333-4444-555555555555" ||
		!strings.Contains(entries[0].Title, "ARM64-based") {
		t.Fatalf("first entry wrong: %+v", entries[0])
	}
	if entries[1].GUID != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" ||
		!strings.Contains(entries[1].Title, "x64-based") {
		t.Fatalf("second entry wrong: %+v", entries[1])
	}
}

func TestSelectCatalogEntry(t *testing.T) {
	entries := parseCatalogSearchResults(searchPageFixture)

	got := selectCatalogEntry(entries, "windows 11 pro 22h2", "amd64")
	if !strings.Contains(got.Title, "x64-based") {
		t.Fatalf("x64 agent must pick the x64 entry, got %+v", got)
	}

	got = selectCatalogEntry(entries, "windows 11 pro 22h2", "arm64")
	if !strings.Contains(got.Title, "ARM64-based") {
		t.Fatalf("arm64 agent must pick the arm64 entry, got %+v", got)
	}

	got = selectCatalogEntry(entries, "", "")
	if !strings.Contains(got.Title, "x64-based") {
		t.Fatalf("unknown arch must default to x64, got %+v", got)
	}
}

func TestParseCatalogDownloadInfo(t *testing.T) {
	page := `
downloadInformation[0] = new Object();
downloadInformation[0].files[0] = new Object();
downloadInformation[0].files[0].url = 'https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2022/10/windows11.0-kb5018427-x64_abc.msu';
downloadInformation[0].files[0].digest = 'S28F+jYcZfOWxmbJegW2u45MQRo=';
downloadInformation[0].files[0].sha256 = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
`
	u, sha := parseCatalogDownloadInfo(page)
	if u != "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2022/10/windows11.0-kb5018427-x64_abc.msu" {
		t.Fatalf("download url wrong: %q", u)
	}
	if sha != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("sha256 wrong: %q", sha)
	}

	noSHA := `
downloadInformation[0].files[0].url = 'https://catalog.s.download.windowsupdate.com/d/x/kb1-x64.msu';
downloadInformation[0].files[0].digest = 'S28F+jYcZfOWxmbJegW2u45MQRo=';
downloadInformation[0].files[0].sha256 = '';
`
	_, sha = parseCatalogDownloadInfo(noSHA)
	if sha != "" {
		t.Fatalf("non-SHA256 digest must not be returned, got %q", sha)
	}
}

func TestCatalogEntryMatchesKB(t *testing.T) {
	if !catalogEntryMatchesKB("2022-10 Cumulative Update for Windows 11 (KB5018427)", "KB5018427") {
		t.Fatal("matching catalog title must pass")
	}
	if catalogEntryMatchesKB("2022-10 Cumulative Update for Windows 11 (KB5008218)", "KB5018427") {
		t.Fatal("wrong KB title must fail")
	}
	if catalogEntryMatchesKB("no kb here", "KB5018427") {
		t.Fatal("title without KB must fail")
	}
}

func TestCatalogDownloadMatchesKB(t *testing.T) {
	if !catalogDownloadMatchesKB("https://catalog.s.download.windowsupdate.com/d/x/windows11.0-kb5018427-x64.msu", "KB5018427") {
		t.Fatal("matching .msu filename must pass")
	}
	if catalogDownloadMatchesKB("https://catalog.s.download.windowsupdate.com/d/x/windows11.0-kb5008218-x64.msu", "KB5018427") {
		t.Fatal("wrong KB filename must fail")
	}
	if catalogDownloadMatchesKB("https://catalog.s.download.windowsupdate.com/d/x/windows11.0-kb5018427-x64.cab", "KB5018427") {
		t.Fatal("non-msu must fail")
	}
}

func TestCatalogKBNumber(t *testing.T) {
	if catalogKBNumber("KB5018427") != 5018427 {
		t.Fatal("kb number parse failed")
	}
	if catalogKBNumber("x") != 0 {
		t.Fatal("non-kb must be 0")
	}
}
