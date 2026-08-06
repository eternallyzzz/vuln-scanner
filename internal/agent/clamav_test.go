package agent

import (
	"testing"
)

func TestParseClamAVOutput(t *testing.T) {
	out := `/tmp/eicar.com: Eicar-Test-Signature FOUND
/srv/www/malware.bin: Win.Trojan.Test-1 FOUND

----------- SCAN SUMMARY -----------
Known viruses: 1
Engine version: 1.0.0
Scanned directories: 2
Infected files: 2
`
	findings := ParseClamAVOutput(out)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
	if findings[0].Path != "/tmp/eicar.com" || findings[0].Name != "Eicar-Test-Signature" {
		t.Fatalf("first finding wrong: %+v", findings[0])
	}
	if findings[0].Source != "clamav" || findings[0].FindingType != "malware" ||
		findings[0].Severity != "HIGH" {
		t.Fatalf("first finding metadata wrong: %+v", findings[0])
	}
	if findings[1].Path != "/srv/www/malware.bin" || findings[1].Name != "Win.Trojan.Test-1" {
		t.Fatalf("second finding wrong: %+v", findings[1])
	}
}

func TestParseClamAVOutputEmptyAndSummaryOnly(t *testing.T) {
	if got := ParseClamAVOutput(""); len(got) != 0 {
		t.Fatalf("empty output must yield no findings, got %+v", got)
	}
	summary := `----------- SCAN SUMMARY -----------
Known viruses: 1
Infected files: 0
`
	if got := ParseClamAVOutput(summary); len(got) != 0 {
		t.Fatalf("summary-only output must yield no findings, got %+v", got)
	}
}

func TestParseClamAVOutputIgnoresMalformedLines(t *testing.T) {
	out := "/tmp/no-colon FOUND\n/tmp/missing-suffix.txt: Win.Test-1\n"
	if got := ParseClamAVOutput(out); len(got) != 0 {
		t.Fatalf("malformed lines must be ignored, got %+v", got)
	}
}
