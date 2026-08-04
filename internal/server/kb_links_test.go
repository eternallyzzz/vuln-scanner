package server

import (
	"strings"
	"testing"
)

func TestSupportPageHasKB(t *testing.T) {
	cases := []struct {
		name  string
		title string
		body  string
		kbNum int
		want  bool
	}{
		{
			name:  "real windows update page",
			title: "October 11, 2022&#x2014;KB5018427 (OS Build 22621.674) | Microsoft Support",
			kbNum: 5018427,
			want:  true,
		},
		{
			name:  "real page with kb in body only",
			title: "March 2017 Security Only Quality Update for Windows 7 SP1",
			body:  "This update KB4012212 is available for download.",
			kbNum: 4012212,
			want:  true,
		},
		{
			name:  "unrelated fallback article",
			title: "MS16-062: Security update for kernel mode drivers: May 10, 2016",
			body:  "This article describes the security update for kernel mode drivers.",
			kbNum: 9999999,
			want:  false,
		},
		{
			name:  "case and space variant",
			title: "December 14, 2021 - kb 5008218 (OS Build 17763.2366)",
			kbNum: 5008218,
			want:  true,
		},
		{
			name:  "not found title vetoes",
			title: "This page could not be found | Microsoft Support",
			body:  "KB12345 might be referenced in navigation.",
			kbNum: 12345,
			want:  false,
		},
		{
			name:  "zero kb never valid",
			title: "KB0",
			kbNum: 0,
			want:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := supportPageHasKB(tc.title, tc.body, tc.kbNum); got != tc.want {
				t.Fatalf("supportPageHasKB(%q, %q, %d) = %v, want %v",
					tc.title, tc.body, tc.kbNum, got, tc.want)
			}
		})
	}
}

func TestExtractTitle(t *testing.T) {
	raw := "<html><head><title>October 11, 2022&#x2014;KB5018427 | Microsoft Support</title></head></html>"
	if got := extractTitle(raw); got != "October 11, 2022&#x2014;KB5018427 | Microsoft Support" {
		t.Fatalf("title extraction wrong: %q", got)
	}
	if got := extractTitle("<html></html>"); got != "" {
		t.Fatalf("missing title must be empty, got %q", got)
	}
}

func TestKBNumber(t *testing.T) {
	if kbNumber("KB5018427") != 5018427 {
		t.Fatal("KB number parse failed")
	}
	if kbNumber("no-kb") != 0 {
		t.Fatal("non-KB must be 0")
	}
}

func TestNotSupportedPageVetoWorksThroughUnescape(t *testing.T) {
	// Entity-encoded marker must still veto.
	title := "This page could not be found"
	if supportPageHasKB(title, strings.Repeat("KB55555 ", 10), 55555) {
		t.Fatal("not-found title must veto body matches")
	}
}
