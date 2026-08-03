//go:build linux || darwin

package apk

import (
	"strings"
	"testing"
)

func TestParseInstalledDB(t *testing.T) {
	db := "" +
		"C:Q1abc\n" +
		"P:openssl\n" +
		"V:3.0.16-r0\n" +
		"A:x86_64\n" +
		"T:the OpenSSL toolkit\n" +
		"m:Alpine Linux\n" +
		"\n" +
		"P:busybox\n" +
		"V:1.36.1-r9\n" +
		"A:x86_64\n" +
		"\n" +
		"P:missing-version\n" +
		"A:x86_64\n" +
		"\n" +
		"garbage line\n" +
		"P:last-pkg\n" +
		"V:1.2.3-r0\n"
	assets := parseInstalledDB(strings.NewReader(db))
	if len(assets) != 3 {
		t.Fatalf("got %d assets, want 3: %+v", len(assets), assets)
	}
	if assets[0].Name != "openssl" || assets[0].Version != "3.0.16-r0" ||
		assets[0].Arch != "x86_64" || assets[0].Format != "apk" {
		t.Fatalf("openssl asset wrong: %+v", assets[0])
	}
	if assets[0].Vendor != "Alpine Linux" {
		t.Fatalf("vendor wrong: %+v", assets[0])
	}
	if assets[1].Name != "busybox" || assets[1].Version != "1.36.1-r9" {
		t.Fatalf("busybox asset wrong: %+v", assets[1])
	}
	if assets[2].Name != "last-pkg" {
		t.Fatalf("last block without trailing blank line wrong: %+v", assets[2])
	}
}
