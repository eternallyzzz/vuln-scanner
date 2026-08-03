package cve

import "testing"

func TestAPKVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.1.1q-r0", "1.1.1q-r1", -1},
		{"1.1.1q-r1", "1.1.1q-r0", 1},
		{"1.1.1w-r0", "1.1.1q-r0", 1},
		{"3.0.8-r0", "3.0.8-r2", -1},
		{"3.0.16-r0", "3.0.16-r0", 0},
		{"1.0_alpha1", "1.0", -1},
		{"1.0_beta1", "1.0_alpha2", 1},
		{"1.0_rc1", "1.0_beta2", 1},
		{"1.0_rc1", "1.0", -1},
		{"1.0_p1", "1.0", 1},
		{"1:1.0", "0:2.0", 1},
		{"2.0", "1:1.0", -1},
		{"1.0", "1.0.1", -1},
		{"1.0a", "1.0", 1},
		{"1.0", "1.0a", -1},
		{"1.0.0_alpha", "1.0.0", -1},
	}
	for _, c := range cases {
		if got := apkVersionCompare(c.a, c.b); got != c.want {
			t.Errorf("apkVersionCompare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestAlpineEcosystemHelpers(t *testing.T) {
	if !isAPKEcosystem("Alpine:v3.17") || !isAPKEcosystem("Alpine") {
		t.Fatal("alpine ecosystems must be recognized")
	}
	if isAPKEcosystem("Rocky Linux:9") {
		t.Fatal("rocky ecosystem must not be apk")
	}
	cases := []struct {
		eco, want string
	}{
		{"Alpine:v3.17", "3.17"},
		{"Alpine:v3.23", "3.23"},
		{"Alpine", ""},
		{"Alpine:3.17", ""},
		{"Rocky Linux:9", ""},
	}
	for _, c := range cases {
		if got := alpineEcosystemVersion(c.eco); got != c.want {
			t.Errorf("alpineEcosystemVersion(%q) = %q, want %q", c.eco, got, c.want)
		}
	}
}

func TestMajorMinorFromVersion(t *testing.T) {
	cases := []struct {
		ver, want string
	}{
		{"3.23.3", "3.23"},
		{"3.23", "3.23"},
		{"9.8", "9.8"},
		{"9", "9"},
		{"", ""},
	}
	for _, c := range cases {
		if got := majorMinorFromVersion(c.ver); got != c.want {
			t.Errorf("majorMinorFromVersion(%q) = %q, want %q", c.ver, got, c.want)
		}
	}
}
