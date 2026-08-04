package cve

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseCVRFPerProductKB(t *testing.T) {
	doc := &CVRFDocument{
		DocumentTitle: ValueWrapper{Value: "Test Security Update"},
		ProductTree: CVRFProductTree{
			Branch: []CVRFBranch{{
				Name: "Microsoft",
				Items: []CVRFItem{
					{ProductID: "p1", Value: "Windows 11 Version 22H2 for x64-based Systems"},
					{ProductID: "p2", Value: "Windows 10 Version 1809 for x64-based Systems"},
					{ProductID: "p3", Value: "Windows 11 version 21H2 for x64-based Systems"},
				},
			}},
			FullProductName: []CVRFFullProductName{},
		},
		Vulnerability: []CVRFVulnerability{{
			Title: ValueWrapper{Value: "Some CVE"},
			CVE:   "CVE-2021-43207",
			CVSSScoreSets: []CVRFScoreSet{{
				BaseScore: ValueWrapper{Value: "7.5"},
			}},
			Remediations: []CVRFRemediation{
				{URL: "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5008218", ProductID: []string{"p1", "p2"}, FixedBuild: "10.0.22621.674"},
				{URL: "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5008215", ProductID: []string{"p3"}, FixedBuild: "10.0.22000.675"},
			},
			ProductStatuses: []CVRFStatus{{ProductID: []string{"p1", "p2", "p3"}}},
			Threats:         []CVRFThreat{{Type: 3, Description: ValueWrapper{Value: "Important"}}},
		}},
	}

	client := NewMSRCClient()
	entries := client.parseCVRFToFeedEntries(doc, "2021-Dec")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].FixedKB != "KB5008218" {
		t.Fatalf("compat fixed_kb should be the first KB, got %q", entries[0].FixedKB)
	}
	var affected []AffectedProduct
	if err := json.Unmarshal(entries[0].Affected, &affected); err != nil {
		t.Fatal(err)
	}
	if len(affected) != 3 {
		t.Fatalf("expected 3 affected products, got %d", len(affected))
	}
	byID := map[string]AffectedProduct{}
	for _, ap := range affected {
		byID[ap.ProductID] = ap
	}
	if byID["p1"].FixedIn != "KB5008218" || byID["p2"].FixedIn != "KB5008218" {
		t.Fatalf("p1/p2 must keep their own KB: %+v %+v", byID["p1"], byID["p2"])
	}
	if byID["p1"].CpeVer != "10.0.22621.674" || byID["p3"].CpeVer != "10.0.22000.675" {
		t.Fatalf("FixedBuild must flow into CpeVer: %+v %+v", byID["p1"], byID["p3"])
	}
	if byID["p3"].FixedIn != "KB5008215" {
		t.Fatalf("p3 must get the Windows 11 KB, got %q", byID["p3"].FixedIn)
	}
	if !strings.Contains(byID["p3"].KBURL, "KB5008215") {
		t.Fatalf("p3 kb_url wrong: %q", byID["p3"].KBURL)
	}
}

func TestParseCVRFAmbiguousRemediationsDoNotSmear(t *testing.T) {
	doc := &CVRFDocument{
		DocumentTitle: ValueWrapper{Value: "Test"},
		ProductTree: CVRFProductTree{
			Branch: []CVRFBranch{{
				Name: "Microsoft",
				Items: []CVRFItem{
					{ProductID: "p1", Value: "Windows 10 Version 1809"},
					{ProductID: "p2", Value: "Microsoft Remote Desktop for Mac"},
				},
			}},
		},
		Vulnerability: []CVRFVulnerability{{
			Title: ValueWrapper{Value: "X"},
			CVE:   "CVE-2019-1181",
			Remediations: []CVRFRemediation{
				{URL: "https://support.microsoft.com/help/4512507"},
				{URL: "https://support.microsoft.com/help/9999999"},
			},
			ProductStatuses: []CVRFStatus{{ProductID: []string{"p1", "p2"}}},
			Threats:         []CVRFThreat{{Type: 3, Description: ValueWrapper{Value: "Important"}}},
		}},
	}
	client := NewMSRCClient()
	entries := client.parseCVRFToFeedEntries(doc, "2019-Aug")
	var affected []AffectedProduct
	json.Unmarshal(entries[0].Affected, &affected)
	for _, ap := range affected {
		if ap.FixedIn != "" {
			t.Fatalf("ambiguous remediations must not assign a KB, got %+v", ap)
		}
	}
	if entries[0].FixedKB != "" {
		t.Fatalf("ambiguous entry must not carry a fixed_kb, got %q", entries[0].FixedKB)
	}
}

func TestParseCVRFSingleRemediationFallback(t *testing.T) {
	doc := &CVRFDocument{
		DocumentTitle: ValueWrapper{Value: "Test"},
		ProductTree: CVRFProductTree{
			Branch: []CVRFBranch{{
				Name: "Microsoft",
				Items: []CVRFItem{
					{ProductID: "p1", Value: "Windows 10 Version 1809"},
					{ProductID: "p2", Value: "Windows Server 2019"},
				},
			}},
		},
		Vulnerability: []CVRFVulnerability{{
			Title: ValueWrapper{Value: "X"},
			CVE:   "CVE-2021-41379",
			Remediations: []CVRFRemediation{
				{URL: "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5007206", FixedBuild: "10.0.19044.1230"},
			},
			ProductStatuses: []CVRFStatus{{ProductID: []string{"p1", "p2"}}},
			Threats:         []CVRFThreat{{Type: 3, Description: ValueWrapper{Value: "Important"}}},
		}},
	}
	client := NewMSRCClient()
	entries := client.parseCVRFToFeedEntries(doc, "2021-Sep")
	var affected []AffectedProduct
	json.Unmarshal(entries[0].Affected, &affected)
	for _, ap := range affected {
		if ap.FixedIn != "KB5007206" {
			t.Fatalf("single remediation must apply to all products, got %+v", ap)
		}
		if ap.CpeVer != "10.0.19044.1230" {
			t.Fatalf("single remediation FixedBuild must apply to all products, got %+v", ap)
		}
	}
}

func TestIsRelevantMSRCProduct(t *testing.T) {
	cases := []struct {
		name      string
		ap        AffectedProduct
		agentOS   string
		agentVer  string
		agentArch string
		installed []string
		want      bool
	}{
		{"win10 versionless on win11", AffectedProduct{Name: "Windows 10 for x64-based Systems"}, "windows 11 pro 22h2", "10.0.22621", "amd64", nil, false},
		{"win11 versionless on win11 22H2", AffectedProduct{Name: "Windows 11 for x64-based Systems"}, "windows 11 pro 22h2", "10.0.22621", "amd64", nil, false},
		{"win11 versionless on win11 21H2", AffectedProduct{Name: "Windows 11 for x64-based Systems"}, "windows 11 pro 21h2", "10.0.22000", "amd64", nil, true},
		{"win10 versionless on win10 22H2", AffectedProduct{Name: "Windows 10 for x64-based Systems"}, "windows 10 pro 22h2", "10.0.19045", "amd64", nil, false},
		{"win10 1809 on win11", AffectedProduct{Name: "Windows 10 Version 1809 for x64-based Systems"}, "windows 11 pro 22h2", "10.0.22621", "amd64", nil, false},
		{"win11 21H2 on win11 22H2", AffectedProduct{Name: "Windows 11 version 21H2 for x64-based Systems"}, "windows 11 pro 22h2", "10.0.22621", "amd64", nil, false},
		{"win11 22H2 on win11 22H2", AffectedProduct{Name: "Windows 11 Version 22H2 for x64-based Systems"}, "windows 11 pro 22h2", "10.0.22621", "amd64", nil, true},
		{"win11 22H2 on win10", AffectedProduct{Name: "Windows 11 Version 22H2 for x64-based Systems"}, "windows 10 pro 22h2", "10.0.19045", "amd64", nil, false},
		{"win10 22H2 on win10", AffectedProduct{Name: "Windows 10 Version 22H2 for x64-based Systems"}, "windows 10 pro 22h2", "10.0.19045", "amd64", nil, true},
		{"rdp for mac", AffectedProduct{Name: "Microsoft Remote Desktop for Mac"}, "windows 11 pro 22h2", "10.0.22621", "amd64", []string{"Microsoft Remote Desktop for Mac"}, false},
		{"rdp for android", AffectedProduct{Name: "Microsoft Remote Desktop for Android"}, "windows 11 pro 22h2", "10.0.22621", "amd64", nil, false},
		{"azure product", AffectedProduct{Name: "Azure Security Center"}, "windows 11 pro 22h2", "10.0.22621", "amd64", nil, false},
		{"surface hardware", AffectedProduct{Name: "Microsoft Surface Laptop 4"}, "windows 11 pro 22h2", "10.0.22621", "amd64", nil, false},
		{"hlk toolkit", AffectedProduct{Name: "Windows 11 HLK 23H2"}, "windows 11 pro 22h2", "10.0.22621", "amd64", []string{"Windows 11 HLK 23H2"}, false},
		{"adk toolkit", AffectedProduct{Name: "Windows ADK for Windows 10, version 1607"}, "windows 11 pro 22h2", "10.0.22621", "amd64", nil, false},
		{"server 2019 on client", AffectedProduct{Name: "Windows Server 2019"}, "windows 11 pro 22h2", "10.0.22621", "amd64", nil, false},
		{"server 2019 on server", AffectedProduct{Name: "Windows Server 2019"}, "windows server 2019", "10.0.17763", "amd64", nil, true},
		{"arm64 on x64", AffectedProduct{Name: "Windows 11 Version 22H2 for ARM64-based Systems"}, "windows 11 pro 22h2", "10.0.22621", "amd64", nil, false},
		{"arm64 on arm64", AffectedProduct{Name: "Windows 11 Version 22H2 for ARM64-based Systems"}, "windows 11 pro 22h2", "10.0.22621", "arm64", nil, true},
		{"win10 21H2 build 19044", AffectedProduct{Name: "Windows 10 Version 21H2 for x64-based Systems"}, "windows 10 pro 21h2", "10.0.19044", "amd64", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			names := make(map[string]bool)
			for _, n := range tc.installed {
				names[strings.ToLower(n)] = true
			}
			got := isRelevantMSRCProduct(tc.ap, tc.agentOS, tc.agentVer, tc.agentArch, names)
			if got != tc.want {
				t.Fatalf("isRelevantMSRCProduct(%q, %q, %q) = %v, want %v",
					tc.ap.Name, tc.agentOS, tc.agentVer, got, tc.want)
			}
		})
	}
}

func TestMsrcNameMatchesStrict(t *testing.T) {
	names := map[string]bool{
		"microsoft remote desktop": true,
		"remote-server":            true,
	}
	if !msrcNameMatches("Microsoft Remote Desktop", names) {
		t.Fatal("installed Microsoft Remote Desktop must match")
	}
	if msrcNameMatches("Microsoft Remote Desktop", map[string]bool{"remote-server": true}) {
		t.Fatal("single shared token must not match")
	}
	if msrcNameMatches("Windows 10 for x64-based Systems", map[string]bool{"windows 11 pro 22h2": true}) {
		t.Fatal("OS product must not match via loose token overlap")
	}
}

func TestMsrcScopeAssetsExcludesSCA(t *testing.T) {
	assets := []AssetToMatch{
		{Name: "Windows 11 Pro 22H2", Version: "6.3.22621", Format: "os"},
		{Name: "Microsoft Office", Version: "16.0.1", Format: "win"},
		{Name: "remote-server", Version: "1.0.0", Format: "npm"},
		{Name: "office", Version: "0.5.0", Format: "go-mod"},
	}
	names, versions, osAsset := msrcScopeAssets(assets)
	if len(names) != 2 {
		t.Fatalf("expected 2 msrc assets, got %v", names)
	}
	if osAsset != "Windows 11 Pro 22H2" {
		t.Fatalf("os asset name wrong: %q", osAsset)
	}
	if _, ok := versions["windows 11 pro 22h2"]; !ok {
		t.Fatalf("OS asset version missing: %v", versions)
	}
	for _, n := range names {
		if n == "remote-server" || n == "office" {
			t.Fatalf("SCA asset leaked into MSRC scope: %q", n)
		}
	}
}

func TestMsrcFamilyToken(t *testing.T) {
	if got := msrcFamilyToken("windows 11 pro 22h2"); got != "Windows 11" {
		t.Fatalf("got %q, want Windows 11", got)
	}
	if got := msrcFamilyToken("windows 10 enterprise"); got != "Windows 10" {
		t.Fatalf("got %q, want Windows 10", got)
	}
	if got := msrcFamilyToken("windows server 2019"); got != "Windows Server" {
		t.Fatalf("got %q, want Windows Server", got)
	}
	if got := msrcFamilyToken("debian gnu/linux"); got != "" {
		t.Fatalf("linux must not get a family token, got %q", got)
	}
}

func TestIsMSRCOSProductName(t *testing.T) {
	if !isMSRCOSProductName("Windows 11 Version 22H2 for x64-based Systems") {
		t.Fatal("real OS product must be detected")
	}
	if !isMSRCOSProductName("Windows Server 2019") {
		t.Fatal("server product must be detected")
	}
	if isMSRCOSProductName("Windows 11 HLK 23H2") {
		t.Fatal("HLK toolkit must not be treated as OS")
	}
	if isMSRCOSProductName("Windows SDK") {
		t.Fatal("SDK must not be treated as OS")
	}
}

func TestIsMSRCWindowsFamilyProduct(t *testing.T) {
	if !isMSRCWindowsFamilyProduct("Windows 10 Version 1809 for x64-based Systems") {
		t.Fatal("windows OS product must be windows family")
	}
	if !isMSRCWindowsFamilyProduct("Microsoft .NET Framework 4.8") {
		t.Fatal(".NET product must be windows family")
	}
	if isMSRCWindowsFamilyProduct("Microsoft Remote Desktop for Mac") {
		t.Fatal("Mac product must not be windows family")
	}
	if isMSRCWindowsFamilyProduct("Azure Security Center") {
		t.Fatal("Azure product must not be windows family")
	}
}
