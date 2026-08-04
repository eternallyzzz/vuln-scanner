package server

import (
	"bytes"
	"testing"
)

func TestParseExternalImportJSON(t *testing.T) {
	body := `{"assets":[
		{"name":"nginx","version":"1.25","asset_type":"software","hostname":"web-01","tags":["dmz","web"]},
		{"name":"db","asset_type":"host","ip":"10.0.0.2"}
	]}`
	items, err := parseExternalImportJSON(bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Name != "nginx" || items[0].Version != "1.25" ||
		items[1].AssetType != "host" || items[1].IP != "10.0.0.2" {
		t.Fatalf("json parse wrong: %+v", items)
	}
	if len(items[0].Tags) != 2 || items[0].Tags[1] != "web" {
		t.Fatalf("tags wrong: %+v", items[0].Tags)
	}

	bare, err := parseExternalImportJSON(bytes.NewReader([]byte(`[{"name":"x","version":"1"}]`)))
	if err != nil || len(bare) != 1 || bare[0].Name != "x" {
		t.Fatalf("bare array parse wrong: %+v err %v", bare, err)
	}

	if _, err := parseExternalImportJSON(bytes.NewReader([]byte(`{"foo":1}`))); err == nil {
		t.Fatal("invalid JSON must fail")
	}
}

func TestParseExternalImportCSV(t *testing.T) {
	csv := "asset_key,name,version,asset_type,hostname,ip,tags\n" +
		",nginx,1.25,software,web-01,10.0.0.1,dmz;web\n" +
		",db,1,host,db-01,10.0.0.2,\n"
	items, err := parseExternalImportCSV(bytes.NewReader([]byte(csv)))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(items), items)
	}
	if items[0].Name != "nginx" || items[0].AssetType != "software" || items[0].Hostname != "web-01" {
		t.Fatalf("row 1 wrong: %+v", items[0])
	}
	if len(items[0].Tags) != 2 || items[0].Tags[0] != "dmz" || items[0].Tags[1] != "web" {
		t.Fatalf("row 1 tags wrong: %+v", items[0].Tags)
	}
	if items[1].AssetType != "host" || items[1].IP != "10.0.0.2" {
		t.Fatalf("row 2 wrong: %+v", items[1])
	}

	if _, err := parseExternalImportCSV(bytes.NewReader([]byte("name,version\n,1\n"))); err == nil {
		t.Fatal("row without name must fail")
	}
}
