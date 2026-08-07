package cve

import (
	"encoding/json"
	"testing"
)

const testUbuntuOVAL = `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <definitions>
    <definition id="oval:com.ubuntu.jammy:def:202230298001" version="1" class="vulnerability">
      <metadata>
        <title>CVE-2022-29800 on Ubuntu 22.04 LTS (jammy) - medium.</title>
        <affected><platform>Ubuntu 22.04</platform></affected>
        <reference source="CVE" ref_id="CVE-2022-29800" url="https://ubuntu.com/security/CVE-2022-29800"/>
      </metadata>
      <criteria operator="AND">
        <criterion test_ref="oval:com.ubuntu.jammy:tst:202230298001000" comment="networkd-dispatcher"/>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.jammy:tst:202230298001000" version="1" check="all">
      <linux-def:object object_ref="oval:com.ubuntu.jammy:obj:202230298001000"/>
      <linux-def:state state_ref="oval:com.ubuntu.jammy:ste:202230298001000"/>
    </linux-def:dpkginfo_test>
  </tests>
  <objects>
    <linux-def:dpkginfo_object id="oval:com.ubuntu.jammy:obj:202230298001000" version="1">
      <linux-def:name>networkd-dispatcher</linux-def:name>
    </linux-def:dpkginfo_object>
  </objects>
  <states>
    <linux-def:dpkginfo_state id="oval:com.ubuntu.jammy:ste:202230298001000" version="1">
      <linux-def:evr>0:2.1-2~ubuntu20.04.2</linux-def:evr>
    </linux-def:dpkginfo_state>
  </states>
</oval_definitions>`

func TestUbuntuReleaseForVersion(t *testing.T) {
	cases := map[string]string{
		"20.04.6 LTS": "focal",
		"22.04.5 LTS": "jammy",
		"24.04.2 LTS": "noble",
		"24.10":       "oracular",
		"99.99":       "",
	}
	for version, want := range cases {
		if got := ubuntuReleaseForVersion(version); got != want {
			t.Errorf("ubuntuReleaseForVersion(%q) = %q, want %q", version, got, want)
		}
	}
}

func TestParseUbuntuOVAL(t *testing.T) {
	entries, err := ParseUbuntuOVAL([]byte(testUbuntuOVAL), "jammy")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Source != "ubuntu" || e.CVEID != "CVE-2022-29800" {
		t.Fatalf("entry = %s/%s", e.Source, e.CVEID)
	}
	if e.Severity != "MEDIUM" {
		t.Fatalf("severity = %q, want MEDIUM", e.Severity)
	}
	var affected []AffectedProduct
	if err := json.Unmarshal(e.Affected, &affected); err != nil {
		t.Fatalf("affected decode: %v", err)
	}
	if len(affected) != 1 {
		t.Fatalf("affected = %d, want 1", len(affected))
	}
	ap := affected[0]
	if ap.Name != "networkd-dispatcher" || ap.FixedIn != "0:2.1-2~ubuntu20.04.2" ||
		ap.Ecosystem != "Ubuntu:22.04:LTS" {
		t.Fatalf("affected = %+v", ap)
	}
}
