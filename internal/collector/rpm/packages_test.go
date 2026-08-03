//go:build linux || darwin

package rpm

import "testing"

func TestParseRPMQuery(t *testing.T) {
	out := "" +
		"curl\x1f0\x1f7.61.1\x1f22.el8\x1fx86_64\x1f1620000000\x1fCentOS\n" +
		"openssl-libs\x1f1\x1f1.1.1k\x1f12.el8_5\x1fx86_64\x1f1620000001\x1fCentOS\n" +
		"nodejs\x1f1\x1f16.13.1\x1f3.module_el8.5.0+2605+45d748af\x1fx86_64\x1f1620000002\x1fCentOS\n" +
		"bash\x1f(none)\x1f4.4.19\x1f14.el8\x1fnoarch\x1f(none)\x1fCentOS\n" +
		"\n" +
		"badline\n"
	assets := parseRPMQuery(out)
	if len(assets) != 4 {
		t.Fatalf("got %d assets, want 4: %+v", len(assets), assets)
	}
	if assets[0].Name != "curl" || assets[0].Version != "7.61.1-22.el8" {
		t.Fatalf("curl asset wrong: %+v", assets[0])
	}
	if assets[0].Format != "rpm" || assets[0].Arch != "x86_64" {
		t.Fatalf("curl metadata wrong: %+v", assets[0])
	}
	if assets[0].InstallDate != "2021-05-03T00:00:00Z" {
		t.Fatalf("install date wrong: %q", assets[0].InstallDate)
	}
	if assets[1].Version != "1:1.1.1k-12.el8_5" {
		t.Fatalf("epoch version wrong: %q", assets[1].Version)
	}
	if assets[2].Version != "1:16.13.1-3.module_el8.5.0+2605+45d748af" {
		t.Fatalf("module version wrong: %q", assets[2].Version)
	}
	if assets[3].Version != "4.4.19-14.el8" || assets[3].InstallDate != "" {
		t.Fatalf("(none) epoch/installtime handling wrong: %+v", assets[3])
	}
}

func TestEVRString(t *testing.T) {
	cases := []struct {
		epoch, version, release, want string
	}{
		{"0", "1.2.3", "1.el8", "1.2.3-1.el8"},
		{"(none)", "1.2.3", "1.el8", "1.2.3-1.el8"},
		{"", "1.2.3", "1.el8", "1.2.3-1.el8"},
		{"1", "1.2.3", "1.el8", "1:1.2.3-1.el8"},
	}
	for _, c := range cases {
		if got := evrString(c.epoch, c.version, c.release); got != c.want {
			t.Errorf("evrString(%q, %q, %q) = %q, want %q",
				c.epoch, c.version, c.release, got, c.want)
		}
	}
}
