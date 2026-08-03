package cve

import "testing"

func TestCompareRPMVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.0.1", -1},
		{"1.0.1", "1.0", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0^git1", "1.0", 1},
		{"1.0", "1.0^git1", -1},
		{"1:1.0", "0:2.0", 1},
		{"0:2.0", "1:1.0", -1},
		{"2.0", "1:1.0", -1},
		{"1.1.1k-12.el8_5", "1.1.1k-14.el8_7", -1},
		{"1.1.1k-14.el8_7", "1.1.1k-12.el8_5", 1},
		{"7.61.1-22.el8", "7.61.1-22.el8_6.12", -1},
		{"7.61.1-30.el8_8.9", "7.61.1-22.el8_6.12", 1},
		{"1:16.13.1-3.module_el8.5.0+2605+45d748af", "1:16.13.1-3.module_el8.5.0+2605+45d748af", 0},
		{"1:16.13.1-3.module_el8.5.0+2605+45d748af", "1:16.13.1-3.module_el8.5.0+2606+45d748af", -1},
		{"3.0.7-27.el9", "3.0.7-25.el9_4", 1},
		{"3.0.7-25.el9_4", "3.0.7-27.el9", -1},
		{"2.4.6-89.el7_6.4", "2.4.6-89.el7_6.4", 0},
		{"8.0.1-1.el9_4", "8.0.1-1.el9_4", 0},
		{"1.0-1", "1.0", 1},
		{"1.0", "1.0-1", -1},
		{"2.4.37-43.el8", "2.4.37-44.el8", -1},
		{"1.0.a", "1.0.b", -1},
		{"1.0b", "1.0a", 1},
	}
	for _, c := range cases {
		if got := compareRPMVersions(c.a, c.b); got != c.want {
			t.Errorf("compareRPMVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSplitRPMEVR(t *testing.T) {
	cases := []struct {
		evr, epoch, version, release string
	}{
		{"1:1.1.1k-12.el8_5", "1", "1.1.1k", "12.el8_5"},
		{"7.61.1-22.el8", "", "7.61.1", "22.el8"},
		{"1:16.13.1-3.module_el8.5.0+2605+45d748af", "1", "16.13.1", "3.module_el8.5.0+2605+45d748af"},
		{"1.0-1.x86_64", "", "1.0", "1"},
		{"2.4.37-43.el8", "", "2.4.37", "43.el8"},
	}
	for _, c := range cases {
		epoch, version, release := splitRPMEVR(c.evr)
		if epoch != c.epoch || version != c.version || release != c.release {
			t.Errorf("splitRPMEVR(%q) = (%q, %q, %q), want (%q, %q, %q)",
				c.evr, epoch, version, release, c.epoch, c.version, c.release)
		}
	}
}

func TestIsRPMEcosystem(t *testing.T) {
	for _, eco := range []string{"Red Hat", "AlmaLinux", "Rocky Linux", "Fedora", "SUSE", "openSUSE", "CentOS"} {
		if !isRPMEcosystem(eco) {
			t.Errorf("isRPMEcosystem(%q) = false, want true", eco)
		}
	}
	for _, eco := range []string{"Debian", "Ubuntu", "PyPI", "npm", "Go"} {
		if isRPMEcosystem(eco) {
			t.Errorf("isRPMEcosystem(%q) = true, want false", eco)
		}
	}
}
