package server

import "testing"

func TestNormalizeKBDownloadImport(t *testing.T) {
	valid, err := normalizeKBDownloadImport(kbDownloadImport{
		KB:       "KB5008218",
		OSFamily: "Windows 11",
		Arch:     "AMD64",
		Title:    "Windows 11 update",
		URL:      "https://catalog.s.download.windowsupdate.com/d/x/windows11.0-kb5008218-x64.msu",
		SHA256:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("valid import rejected: %v", err)
	}
	if valid.OSFamily != "windows 11" || valid.Arch != "x64" {
		t.Fatalf("normalization failed: %+v", valid)
	}
	if valid.SHA256 != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("sha256 should be lowercased, got %q", valid.SHA256)
	}

	cases := []kbDownloadImport{
		{KB: "5008218", URL: "https://x/1.msu"},
		{KB: "KB5008218", Arch: "x86", URL: "https://x/1.msu"},
		{KB: "KB5008218", OSFamily: "windows 7", URL: "https://x/1.msu"},
		{KB: "KB5008218", URL: "file:///tmp/x.msu"},
		{KB: "KB5008218", URL: "https://x/1.msu", SHA256: "zz"},
	}
	for i, c := range cases {
		if _, err := normalizeKBDownloadImport(c); err == nil {
			t.Fatalf("case %d should be rejected: %+v", i, c)
		}
	}
}
