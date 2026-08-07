package cve

import (
	"encoding/json"
	"testing"
)

func TestParseAlpineSecDB(t *testing.T) {
	data := []byte(`{
	  "distroversion": "v3.20",
	  "reponame": "main",
	  "packages": [
	    {"pkg": {"name": "openssl", "secfixes": {
	      "3.3.2-r0": ["CVE-2024-0727"],
	      "3.3.2-r1": ["CVE-2024-2511"]
	    }}}
	  ]
	}`)
	entries, err := ParseAlpineSecDB(data, "v3.20", "main")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	first := entries[0]
	if first.CVEID != "CVE-2024-0727" {
		t.Fatalf("first cve = %q", first.CVEID)
	}
	var affected []AffectedProduct
	if err := json.Unmarshal(first.Affected, &affected); err != nil {
		t.Fatalf("affected decode: %v", err)
	}
	if len(affected) != 1 {
		t.Fatalf("affected = %d, want 1", len(affected))
	}
	if affected[0].Name != "openssl" || affected[0].Ecosystem != "Alpine:v3.20" ||
		affected[0].FixedIn != "3.3.2-r0" {
		t.Fatalf("affected = %+v", affected[0])
	}
	if entries[1].CVEID != "CVE-2024-2511" || entries[1].FixedVer != "" {
		t.Fatalf("second entry = %+v", entries[1])
	}
}
