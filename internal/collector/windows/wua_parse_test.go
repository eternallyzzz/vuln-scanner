package windows

import (
	"testing"
	"time"
)

func TestParseWUAUpdatesArray(t *testing.T) {
	raw := []byte(`[
		{"kb":"kb5034441","title":"2024-01 Security Update for Windows 11 Version 22H2","state":"pending","severity":"Critical","reboot_required":true},
		{"kb":"KB5028185","title":"2023-07 Cumulative Update","state":"installed","severity":"","reboot_required":false}
	]`)
	when := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
	facts, err := ParseWUAUpdates(raw, "wsus", when)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 2 {
		t.Fatalf("expected 2 facts, got %d", len(facts))
	}
	if facts[0].KB != "KB5034441" || facts[0].State != "pending" ||
		facts[0].Source != "wsus" || !facts[0].RebootRequired {
		t.Fatalf("pending fact wrong: %+v", facts[0])
	}
	if facts[1].KB != "KB5028185" || facts[1].State != "installed" ||
		facts[1].Source != "wsus" {
		t.Fatalf("installed fact wrong: %+v", facts[1])
	}
	if !facts[0].CollectedAt.Equal(when) {
		t.Fatalf("collected_at wrong: %v", facts[0].CollectedAt)
	}
}

func TestParseWUAUpdatesSingleObject(t *testing.T) {
	raw := []byte(`{"kb":"KB5001","title":"Test","state":"pending","severity":"Important"}`)
	facts, err := ParseWUAUpdates(raw, "wua", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 || facts[0].KB != "KB5001" || facts[0].State != "pending" {
		t.Fatalf("single object parse wrong: %+v", facts)
	}
}

func TestParseWUAUpdatesError(t *testing.T) {
	_, err := ParseWUAUpdates([]byte(`{"error":"The remote server machine is unavailable"}`), "wua", time.Time{})
	if err == nil {
		t.Fatal("error payload must produce an error")
	}
}

func TestParseWUAUpdatesStripsCLIXML(t *testing.T) {
	raw := []byte("#< CLIXML\r\n[{\"kb\":\"KB5001\",\"title\":\"Test\",\"state\":\"pending\"}]\r\n<Objs Version=\"1.1\"><Obj/></Objs>")
	facts, err := ParseWUAUpdates(raw, "wua", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 || facts[0].KB != "KB5001" {
		t.Fatalf("CLIXML-wrapped facts parse wrong: %+v", facts)
	}
}

func TestParseWUAUpdatesSkipsNoKB(t *testing.T) {
	facts, err := ParseWUAUpdates([]byte(`[{"title":"No KB here","state":"pending"}]`), "wua", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 0 {
		t.Fatalf("expected no facts, got %+v", facts)
	}
}

func TestParseWUAUpdatesDefaults(t *testing.T) {
	facts, err := ParseWUAUpdates([]byte(`[{"title":"Security Update KB5034441","state":"Installed"}]`), "", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 {
		t.Fatalf("expected 1 fact, got %d", len(facts))
	}
	if facts[0].State != "installed" || facts[0].Source != "wua" {
		t.Fatalf("defaults wrong: %+v", facts[0])
	}
	if facts[0].KB != "KB5034441" {
		t.Fatalf("kb extraction wrong: %q", facts[0].KB)
	}
}
