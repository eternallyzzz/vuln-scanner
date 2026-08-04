package cve

import (
	"strings"
	"testing"
)

func TestParseEPSSAPI(t *testing.T) {
	data := []byte(`{"data":[{"cve":"CVE-2023-1234","epss":"0.97318","percentile":"0.99622"},{"cve":"CVE-2021-44228","epss":"0.97001","percentile":"0.98500"}],"meta":{"total":2,"offset":0,"limit":1000}}`)
	entries, total, err := parseEPSSAPI(data)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(entries) != 2 {
		t.Fatalf("page wrong: total=%d len=%d", total, len(entries))
	}
	if entries[0].CVEID != "CVE-2023-1234" || entries[0].EPSSScore != 0.97318 {
		t.Fatalf("entry wrong: %+v", entries[0])
	}
}

func TestParseEPSSReader(t *testing.T) {
	csvData := "cve,epss,percentile,date\nCVE-2023-1234,0.97318,0.99622,2026-07-15\nCVE-2021-44228,0.97001,0.98500,2026-07-15\n"
	entries, err := parseEPSSReader(strings.NewReader(csvData))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[1].CVEID != "CVE-2021-44228" || entries[1].EPSSPercentile != 0.985 {
		t.Fatalf("csv parse wrong: %+v", entries)
	}
}

func TestParseKEV(t *testing.T) {
	data := []byte(`{"vulnerabilities":[
		{"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j","dateAdded":"2021-12-10","knownRansomwareCampaignUse":"Known"},
		{"cveID":"CVE-2023-1234","vendorProject":"X","product":"Y","dateAdded":"2023-01-01","knownRansomwareCampaignUse":"Unknown"}
	]}`)
	entries, err := parseKEV(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || !entries[0].KEV || !entries[0].KnownRansomware ||
		entries[0].KEVAdded != "2021-12-10" || entries[1].KnownRansomware {
		t.Fatalf("kev parse wrong: %+v", entries)
	}
}
