package cve

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseRedHatNEVRA(t *testing.T) {
	cases := []struct {
		in, name, evr, major string
		ok                   bool
	}{
		{"curl-0:7.76.1-26.el9_3.2", "curl", "0:7.76.1-26.el9_3.2", "9", true},
		{"openssl-1:1.1.1g-16.el8_4", "openssl", "1:1.1.1g-16.el8_4", "8", true},
		{"bash-0:4.4.19-14.el8", "bash", "0:4.4.19-14.el8", "8", true},
		{"nodejs-1:16.13.1-3.module_el8.5.0+2605+45d748af", "nodejs", "1:16.13.1-3.module_el8.5.0+2605+45d748af", "8", true},
		{"jbcs-httpd24-curl-0:8.4.0-2.el7jbcs", "", "", "", false},
		{"openshift-logging/loki-rhel8-operator:v5.7.13-12", "", "", "", false},
		{"nodejs:14-8040020230306170312.522a0ee4", "", "", "", false},
		{"jbcs-httpd24-curl", "", "", "", false},
		{"", "", "", "", false},
	}
	for _, c := range cases {
		name, evr, major, ok := parseRedHatNEVRA(c.in)
		if ok != c.ok || name != c.name || evr != c.evr || major != c.major {
			t.Errorf("parseRedHatNEVRA(%q) = (%q, %q, %q, %v), want (%q, %q, %q, %v)",
				c.in, name, evr, major, ok, c.name, c.evr, c.major, c.ok)
		}
	}
}

func TestBuildRedHatAffected(t *testing.T) {
	pkgs := []string{
		"curl-0:7.61.1-22.el8_6.12",
		"curl-0:7.61.1-22.el8_6.12",
		"curl-0:7.61.1-33.el8_9.5",
		"curl-0:7.76.1-26.el9_3.2",
		"jbcs-httpd24-curl-0:8.4.0-2.el8jbcs",
		"openshift-logging/loki-rhel8-operator:v5.7.13-12",
	}
	out := buildRedHatAffected(pkgs, map[string]bool{"8": true, "9": true})
	if len(out["8"]) != 2 {
		t.Fatalf("rhel8 products = %d, want 2: %+v", len(out["8"]), out["8"])
	}
	if len(out["9"]) != 1 || out["9"][0].Name != "curl" || out["9"][0].FixedIn != "0:7.76.1-26.el9_3.2" {
		t.Fatalf("rhel9 products wrong: %+v", out["9"])
	}
	if out["8"][0].Major != "8" || out["8"][0].Ecosystem != "Red Hat" {
		t.Fatalf("rhel8 product metadata wrong: %+v", out["8"][0])
	}
}

func TestPresentRedHatMajors(t *testing.T) {
	agents := []AgentSnapshotSummary{
		{OSType: "Rocky Linux", OSVersion: "9.4"},
		{OSType: "AlmaLinux", OSVersion: "8.10"},
		{OSType: "CentOS Linux", OSVersion: "7.9"},
		{OSType: "CentOS Stream", OSVersion: "9"},
		{OSType: "Debian GNU/Linux", OSVersion: "12"},
		{OSType: "Windows 10", OSVersion: "10.0.19045"},
	}
	majors := presentRedHatMajors(agents)
	if !majors["7"] || !majors["8"] || !majors["9"] {
		t.Fatalf("expected majors 7,8,9, got %v", majors)
	}
	if len(majors) != 3 {
		t.Fatalf("unexpected major set %v", majors)
	}
}

func TestRedHatSeverity(t *testing.T) {
	cases := []struct {
		c     RedHatCVE
		sev   string
		score float64
	}{
		{RedHatCVE{Severity: "critical", CVSS3Score: 9.8}, "CRITICAL", 9.8},
		{RedHatCVE{Severity: "important", CVSS3Score: 8.1}, "HIGH", 8.1},
		{RedHatCVE{Severity: "moderate", CVSS3Score: 5.3}, "MEDIUM", 5.3},
		{RedHatCVE{Severity: "low", CVSS3Score: 3.7}, "LOW", 3.7},
		{RedHatCVE{Severity: "important", CVSS2Score: 6.5}, "HIGH", 6.5},
		{RedHatCVE{Severity: "weird"}, "MEDIUM", 0},
	}
	for _, c := range cases {
		sev, score := redHatSeverity(c.c)
		if sev != c.sev || score != c.score {
			t.Errorf("redHatSeverity(%+v) = (%q, %v), want (%q, %v)",
				c.c, sev, score, c.sev, c.score)
		}
	}
}

func TestRedHatCVEDecodeFlexNumeric(t *testing.T) {
	raw := `[
		{"CVE":"CVE-2023-38545","severity":"important","cvss3_score":"8.1","cvss_score":"","public_date":"2023-10-10T00:00:00Z","affected_packages":["curl-0:7.76.1-26.el9_3.2"]},
		{"CVE":"CVE-2024-0001","severity":"low","cvss3_score":3.7,"cvss_score":2.0,"affected_packages":[]}
	]`
	var cves []RedHatCVE
	if err := json.Unmarshal([]byte(raw), &cves); err != nil {
		t.Fatal(err)
	}
	if len(cves) != 2 {
		t.Fatalf("got %d cves, want 2", len(cves))
	}
	if float64(cves[0].CVSS3Score) != 8.1 || cves[0].CVSS2Score != 0 {
		t.Fatalf("string/empty numeric decode wrong: %+v", cves[0])
	}
	if float64(cves[1].CVSS3Score) != 3.7 || float64(cves[1].CVSS2Score) != 2.0 {
		t.Fatalf("number numeric decode wrong: %+v", cves[1])
	}
	if len(cves[0].AffectedPackages) != 1 || cves[0].AffectedPackages[0] != "curl-0:7.76.1-26.el9_3.2" {
		t.Fatalf("affected packages wrong: %+v", cves[0].AffectedPackages)
	}
}

func TestSelectRedHatFixed(t *testing.T) {
	evrs := []string{
		"0:7.61.1-22.el8_6.12",
		"0:7.61.1-30.el8_8.9",
		"0:7.61.1-33.el8_9.5",
	}
	cases := []struct {
		agentVersion, want string
	}{
		{"8.6", "0:7.61.1-22.el8_6.12"},
		{"8.8", "0:7.61.1-30.el8_8.9"},
		{"8.9", "0:7.61.1-33.el8_9.5"},
		{"8.7", "0:7.61.1-33.el8_9.5"}, // no matching minor -> conservative newest
		{"8", "0:7.61.1-33.el8_9.5"},   // no minor -> conservative newest
	}
	for _, c := range cases {
		if got := selectRedHatFixed(evrs, c.agentVersion); got != c.want {
			t.Errorf("selectRedHatFixed(%v, %q) = %q, want %q", evrs, c.agentVersion, got, c.want)
		}
	}
}

func TestMatchRedHatEntry(t *testing.T) {
	affected := []AffectedProduct{
		{Name: "curl", FixedIn: "0:7.76.1-23.el9_2.4", Ecosystem: "Red Hat", Major: "9"},
		{Name: "curl", FixedIn: "0:7.76.1-26.el9_3.2", Ecosystem: "Red Hat", Major: "9"},
		{Name: "curl", FixedIn: "0:7.61.1-33.el8_9.5", Ecosystem: "Red Hat", Major: "8"},
	}
	raw, _ := json.Marshal(affected)
	entry := &FeedEntry{
		CVEID:     "CVE-2023-38545",
		Affected:  raw,
		Severity:  "HIGH",
		CVSSScore: 8.1,
		Summary:   "curl heap overflow",
		Source:    "redhat",
	}

	names := []string{"curl"}
	assetVersions := map[string]string{"curl": "0:7.76.1-23.el9_2.3"}
	lowerNames := map[string]bool{"curl": true}

	res := matchRedHatEntry(entry, "rocky linux", "9.2", names, assetVersions, lowerNames)
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(res), res)
	}
	if res[0].MatchStatus != "active" || res[0].FixedVersion != "0:7.76.1-23.el9_2.4" {
		t.Fatalf("unexpected result: %+v", res[0])
	}

	assetVersions["curl"] = "0:7.76.1-23.el9_2.4"
	res = matchRedHatEntry(entry, "rocky linux", "9.2", names, assetVersions, lowerNames)
	if len(res) != 1 || res[0].MatchStatus != "fixed" {
		t.Fatalf("expected fixed after upgrade, got %+v", res)
	}

	// Wrong RHEL major must not match.
	res = matchRedHatEntry(entry, "rocky linux", "7.9", names, assetVersions, lowerNames)
	if len(res) != 0 {
		t.Fatalf("major mismatch must not match, got %+v", res)
	}

	// CentOS Stream is excluded from the redhat source.
	res = matchRedHatEntry(entry, "centos stream", "9", names, assetVersions, lowerNames)
	if len(res) != 0 {
		t.Fatalf("centos stream must not match redhat source, got %+v", res)
	}

	// Exact package names only: "openssl" must not match "openssl-libs".
	names2 := []string{"openssl-libs"}
	assetVersions2 := map[string]string{"openssl-libs": "1:1.1.1k-12.el8_5"}
	lowerNames2 := map[string]bool{"openssl-libs": true}
	affected2, _ := json.Marshal([]AffectedProduct{
		{Name: "openssl", FixedIn: "1:1.1.1k-14.el8_7", Ecosystem: "Red Hat", Major: "8"},
	})
	entry2 := &FeedEntry{CVEID: "CVE-X", Affected: affected2, Source: "redhat"}
	if res := matchRedHatEntry(entry2, "rocky linux", "8.5", names2, assetVersions2, lowerNames2); len(res) != 0 {
		t.Fatalf("openssl must not match openssl-libs, got %+v", res)
	}
}

func TestOSVEcosystemForAgent(t *testing.T) {
	cases := []struct {
		format, os, ver, want string
	}{
		{"rpm", "AlmaLinux", "", "AlmaLinux"},
		{"rpm", "Rocky Linux", "", "Rocky Linux"},
		{"rpm", "Fedora", "", "Fedora"},
		{"rpm", "Red Hat Enterprise Linux", "", "Red Hat"},
		{"rpm", "CentOS Linux", "", "Red Hat"},
		{"rpm", "openSUSE Leap", "", "SUSE"},
		{"deb", "Debian GNU/Linux", "", "Debian"},
		{"deb", "Ubuntu 22.04.5 LTS", "22.04.5", "Ubuntu:22.04:LTS"},
		{"deb", "ubuntu 24.04.2 LTS", "24.04.2", "Ubuntu:24.04:LTS"},
		{"deb", "Ubuntu 26.04", "26.04", "Ubuntu:26.04:LTS"},
		{"deb", "Ubuntu 24.10", "24.10", "Ubuntu:24.10"},
		{"deb", "Ubuntu 23.04", "23.04", "Ubuntu:23.04"},
		{"deb", "Ubuntu", "", "Ubuntu"},
		{"npm", "Debian GNU/Linux", "", "npm"},
		{"apk", "Alpine Linux", "3.23.3", "Alpine:v3.23"},
		{"apk", "Alpine Linux", "3.17.3", "Alpine:v3.17"},
		{"apk", "Alpine Linux", "", "Alpine"},
	}
	for _, c := range cases {
		if got := OSVEcosystemForAgent(c.format, c.os, c.ver); got != c.want {
			t.Errorf("OSVEcosystemForAgent(%q, %q, %q) = %q, want %q",
				c.format, c.os, c.ver, got, c.want)
		}
	}
}

func TestUbuntuEcosystemHelpers(t *testing.T) {
	cases := []struct {
		version, ecosystem string
		lts                bool
	}{
		{"20.04.6", "Ubuntu:20.04:LTS", true},
		{"22.04.5", "Ubuntu:22.04:LTS", true},
		{"24.04.2", "Ubuntu:24.04:LTS", true},
		{"26.04", "Ubuntu:26.04:LTS", true},
		{"24.10", "Ubuntu:24.10", false},
		{"23.04", "Ubuntu:23.04", false},
		{"18.04", "Ubuntu:18.04:LTS", true},
	}
	for _, c := range cases {
		if got := ubuntuEcosystemForAgent(c.version); got != c.ecosystem {
			t.Errorf("ubuntuEcosystemForAgent(%q) = %q, want %q", c.version, got, c.ecosystem)
		}
		if got := isUbuntuLTS(majorMinorFromVersion(c.version)); got != c.lts {
			t.Errorf("isUbuntuLTS(%q) = %v, want %v", c.version, got, c.lts)
		}
	}
	if got := ubuntuEcosystemForAgent(""); got != "Ubuntu" {
		t.Errorf("empty version should fall back to Ubuntu, got %q", got)
	}
	if got := ubuntuEcosystemForAgent("weird"); got != "Ubuntu:weird" {
		t.Errorf("unparseable version should use raw major, got %q", got)
	}
	eco := []struct{ in, want string }{
		{"Ubuntu:22.04:LTS", "22.04"},
		{"ubuntu:24.10", "24.10"},
		{"Ubuntu:26.04:LTS", "26.04"},
		{"Ubuntu", ""},
		{"Ubuntu:Pro:24.04:LTS", ""},
		{"Debian:12", ""},
	}
	for _, c := range eco {
		if got := ubuntuEcosystemVersion(c.in); got != c.want {
			t.Errorf("ubuntuEcosystemVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMergeRedHatPackageState(t *testing.T) {
	raw := `{
		"name": "CVE-2026-18358",
		"threat_severity": "Moderate",
		"package_state": [
			{"product_name":"Red Hat Enterprise Linux 10","fix_state":"Affected","package_name":"gnome-remote-desktop","cpe":"cpe:/o:redhat:enterprise_linux:10"},
			{"product_name":"Red Hat Enterprise Linux 8","fix_state":"Not affected","package_name":"gnome-remote-desktop","cpe":"cpe:/o:redhat:enterprise_linux:8"},
			{"product_name":"Red Hat Enterprise Linux 9","fix_state":"Will not fix","package_name":"openssl","cpe":"cpe:/o:redhat:enterprise_linux:9"},
			{"product_name":"Red Hat Enterprise Linux 9","fix_state":"Under investigation","package_name":"openssl","cpe":"cpe:/o:redhat:enterprise_linux:9"},
			{"product_name":"Red Hat AMQ Broker 7","fix_state":"Affected","package_name":"log4j-core","cpe":"cpe:/a:redhat:amq_broker:7"}
		],
		"affected_release": []
	}`
	var d RedHatCVEDetail
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatal(err)
	}

	perMajor := map[string][]AffectedProduct{
		"9":  {{Name: "curl", FixedIn: "0:7.76.1-26.el9_3.2", Ecosystem: "Red Hat", Major: "9"}},
		"10": {},
	}
	mergeRedHatPackageState(perMajor, &d, map[string]bool{"9": true, "10": true})
	if len(perMajor["10"]) != 1 || perMajor["10"][0].Name != "gnome-remote-desktop" ||
		perMajor["10"][0].FixState != "Affected" || perMajor["10"][0].FixedIn != "" {
		t.Fatalf("rhel10 unfixed product wrong: %+v", perMajor["10"])
	}
	var states []string
	for _, ap := range perMajor["9"] {
		if ap.FixState != "" {
			states = append(states, ap.FixState)
		}
	}
	if len(states) != 2 || states[0] != "Will not fix" || states[1] != "Under investigation" {
		t.Fatalf("rhel9 unfixed states wrong: %v (all: %+v)", states, perMajor["9"])
	}
	// Majors absent from the agent set are not added.
	if _, ok := perMajor["8"]; ok {
		t.Fatal("rhel8 must not be added (Not affected + absent major)")
	}

	// Missing majors filter must drop the rhel10 entry.
	perMajor2 := map[string][]AffectedProduct{}
	mergeRedHatPackageState(perMajor2, &d, map[string]bool{"9": true})
	if _, ok := perMajor2["10"]; ok {
		t.Fatalf("rhel10 must be filtered when major not present: %+v", perMajor2)
	}
}

func TestMatchRedHatEntryUnfixed(t *testing.T) {
	affected := []AffectedProduct{
		{Name: "gnome-remote-desktop", FixState: "Affected", Ecosystem: "Red Hat", Major: "9"},
	}
	raw, _ := json.Marshal(affected)
	entry := &FeedEntry{
		CVEID:     "CVE-2026-18358",
		Affected:  raw,
		Severity:  "MEDIUM",
		CVSSScore: 7.5,
		Summary:   "gnome-remote-desktop denial of service",
		Source:    "redhat",
	}
	names := []string{"gnome-remote-desktop"}
	assetVersions := map[string]string{"gnome-remote-desktop": "42.4-3.el9"}
	lowerNames := map[string]bool{"gnome-remote-desktop": true}

	// Genuine RHEL agent gets an active vuln with no fixed version.
	res := matchRedHatEntry(entry, "Red Hat Enterprise Linux", "9.2", names, assetVersions, lowerNames)
	if len(res) != 1 {
		t.Fatalf("rhel agent: got %d results, want 1: %+v", len(res), res)
	}
	if res[0].MatchStatus != "active" || res[0].FixedVersion != "" || res[0].FixState != "Affected" {
		t.Fatalf("unfixed result wrong: %+v", res[0])
	}

	// Derived distros must not inherit the unfixed verdict.
	for _, os := range []string{"AlmaLinux", "Rocky Linux", "CentOS Linux"} {
		if res := matchRedHatEntry(entry, os, "9.2", names, assetVersions, lowerNames); len(res) != 0 {
			t.Fatalf("%s must not get unfixed result, got %+v", os, res)
		}
	}
}

func TestMatchRedHatEntryPrefersFixedThreshold(t *testing.T) {
	affected := []AffectedProduct{
		{Name: "openssl", FixedIn: "1:3.0.7-27.el9", Ecosystem: "Red Hat", Major: "9"},
		{Name: "openssl", FixState: "Affected", Ecosystem: "Red Hat", Major: "9"},
	}
	raw, _ := json.Marshal(affected)
	entry := &FeedEntry{
		CVEID:     "CVE-2024-0001",
		Affected:  raw,
		Severity:  "HIGH",
		CVSSScore: 7.4,
		Source:    "redhat",
	}
	names := []string{"openssl"}
	assetVersions := map[string]string{"openssl": "1:3.0.7-23.el9"}
	lowerNames := map[string]bool{"openssl": true}
	res := matchRedHatEntry(entry, "Red Hat Enterprise Linux", "9.4", names, assetVersions, lowerNames)
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1 (fixed threshold wins): %+v", len(res), res)
	}
	if res[0].FixedVersion != "1:3.0.7-27.el9" || res[0].FixState != "" {
		t.Fatalf("expected fixed-threshold result only, got %+v", res[0])
	}
}

func TestRedHatDetailIDs(t *testing.T) {
	now := time.Now().UTC()
	cves := []RedHatCVE{
		{CVE: "CVE-2026-18358", PublicDate: now.AddDate(0, 0, -3).Format(time.RFC3339)},
		{CVE: "CVE-2023-38545", PublicDate: now.AddDate(0, -2, 0).Format(time.RFC3339),
			AffectedPackages: []string{"curl-0:7.76.1-26.el9_3.2"}},
		{CVE: "CVE-2020-0001", PublicDate: now.AddDate(-3, 0, 0).Format(time.RFC3339),
			AffectedPackages: []string{"curl-0:7.61.1-22.el8_6.12"}},
		{CVE: "CVE-2026-11111", PublicDate: now.AddDate(0, 0, -1).Format(time.RFC3339)},
		{CVE: "", PublicDate: now.AddDate(0, 0, -1).Format(time.RFC3339)},
	}
	ids := redhatDetailIDs(cves, map[string]bool{"9": true}, now,
		map[string]bool{"CVE-2026-11111": true})
	want := []string{"CVE-2026-18358", "CVE-2023-38545"}
	if len(ids) != len(want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("ids = %v, want %v", ids, want)
		}
	}
}

func TestMergeExistingFixStates(t *testing.T) {
	raw, _ := json.Marshal([]AffectedProduct{
		{Name: "curl", FixedIn: "0:7.76.1-26.el9_3.2", Ecosystem: "Red Hat", Major: "9"},
		{Name: "curl", FixState: "Affected", Ecosystem: "Red Hat", Major: "9"},
		{Name: "openssl", FixState: "Will not fix", Ecosystem: "Red Hat", Major: "9"},
		{Name: "bash", FixState: "Affected", Ecosystem: "Red Hat", Major: "8"},
	})
	perMajor := map[string][]AffectedProduct{
		"9": {{Name: "curl", FixedIn: "0:7.76.1-33.el9_9.1", Ecosystem: "Red Hat", Major: "9"}},
	}
	mergeExistingFixStates(perMajor, raw, "9")
	if len(perMajor["9"]) != 3 {
		t.Fatalf("rhel9 products = %d, want 3: %+v", len(perMajor["9"]), perMajor["9"])
	}
	found := map[string]string{}
	for _, ap := range perMajor["9"] {
		found[ap.Name] = ap.FixState
	}
	if found["curl"] != "Affected" || found["openssl"] != "Will not fix" {
		t.Fatalf("fix states wrong: %+v", perMajor["9"])
	}
	if _, ok := perMajor["8"]; ok {
		t.Fatalf("wrong major must not be added: %+v", perMajor)
	}
}

func TestReleaseMinor(t *testing.T) {
	cases := []struct {
		evr, want string
	}{
		{"0:7.61.1-22.el8_6.12", "6"},
		{"0:7.76.1-26.el9_3.2", "3"},
		{"0:4.4.19-14.el8", ""},
		{"1:16.13.1-3.module_el8.5.0+2605+45d748af", "5"},
	}
	for _, c := range cases {
		if got := releaseMinor(c.evr); got != c.want {
			t.Errorf("releaseMinor(%q) = %q, want %q", c.evr, got, c.want)
		}
	}
}

func TestRPMReleaseMajor(t *testing.T) {
	cases := []struct {
		evr, want string
	}{
		{"0:7.76.1-26.el9_3.2", "9"},
		{"0:7.61.1-22.el8_6.12", "8"},
		{"0:5.1.8-6.el9_1", "9"},
		{"1:16.13.1-3.module_el8.5.0+2605+45d748af", "8"},
		{"1.1.1d-11.25.1", ""},
	}
	for _, c := range cases {
		if got := rpmReleaseMajor(c.evr); got != c.want {
			t.Errorf("rpmReleaseMajor(%q) = %q, want %q", c.evr, got, c.want)
		}
	}
}

func TestOSVRPMEntryMajorFilter(t *testing.T) {
	ap := AffectedProduct{Name: "curl", Ecosystem: "Rocky Linux", FixedIn: "0:8.12.1-2.el10_1.2"}
	if isRelevantProduct(ap, "osv", "rocky linux", "9.2", "", nil) {
		t.Fatal("el10 advisory must not match a Rocky 9 host")
	}
	ap.Ecosystem = "Rocky Linux:10"
	if isRelevantProduct(ap, "osv", "rocky linux", "9.2", "", nil) {
		t.Fatal("Rocky Linux:10 ecosystem must not match a Rocky 9 host")
	}
	ap.Ecosystem = "Rocky Linux:9"
	if !isRelevantProduct(ap, "osv", "rocky linux", "9.2", "", nil) {
		t.Fatal("Rocky Linux:9 ecosystem must match a Rocky 9 host")
	}
	ap.Ecosystem = "Rocky Linux"
	ap.FixedIn = "0:7.76.1-23.el9_2.6"
	if !isRelevantProduct(ap, "osv", "rocky linux", "9.2", "", nil) {
		t.Fatal("el9 advisory must match a Rocky 9 host")
	}
	// Debian entries are not rpm-scoped and must stay unaffected.
	deb := AffectedProduct{Name: "openssl", Ecosystem: "Debian:12", FixedIn: "3.0.11-1~deb12u2"}
	if !isRelevantProduct(deb, "osv", "debian gnu/linux", "12", "", nil) {
		t.Fatal("debian osv entry must still match a debian host")
	}
	if isRelevantProduct(deb, "osv", "rocky linux", "9.2", "", nil) {
		t.Fatal("debian osv entry must not match a rocky host")
	}
}

func TestOSVAlpineEntryVersionFilter(t *testing.T) {
	ap := AffectedProduct{Name: "openssl", Ecosystem: "Alpine:v3.17", FixedIn: "1.1.1q-r1"}
	if !isRelevantProduct(ap, "osv", "alpine linux", "3.17.3", "", nil) {
		t.Fatal("Alpine:v3.17 entry must match an Alpine 3.17 host")
	}
	if isRelevantProduct(ap, "osv", "alpine linux", "3.23.3", "", nil) {
		t.Fatal("Alpine:v3.17 entry must not match an Alpine 3.23 host")
	}
	if isRelevantProduct(ap, "osv", "rocky linux", "9.2", "", nil) {
		t.Fatal("Alpine entry must not match a rocky host")
	}
	// Plain "Alpine" ecosystem (no version) still matches any Alpine host.
	plain := AffectedProduct{Name: "openssl", Ecosystem: "Alpine", FixedIn: "1.1.1q-r1"}
	if !isRelevantProduct(plain, "osv", "alpine linux", "3.23.3", "", nil) {
		t.Fatal("plain Alpine entry must match an Alpine host")
	}
}

func TestOSVEcosystemMajor(t *testing.T) {
	cases := []struct {
		eco, want string
	}{
		{"Rocky Linux:9", "9"},
		{"Rocky Linux:10", "10"},
		{"AlmaLinux:8", "8"},
		{"Debian:12", "12"},
		{"Rocky Linux", ""},
		{"npm", ""},
	}
	for _, c := range cases {
		if got := osvEcosystemMajor(c.eco); got != c.want {
			t.Errorf("osvEcosystemMajor(%q) = %q, want %q", c.eco, got, c.want)
		}
	}
}
