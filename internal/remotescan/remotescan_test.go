package remotescan

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	t.Setenv("REMOTE_SCAN_MASTER_KEY", strings.Repeat("a", 64))
	cases := []struct {
		name string
		cfg  *Config
		want bool
	}{
		{"disabled ok", &Config{Enabled: false, MasterKeyEnv: ""}, true},
		{"nil ok", nil, true},
		{"enabled defaults", &Config{Enabled: true, MasterKeyEnv: "REMOTE_SCAN_MASTER_KEY", TimeoutSeconds: 30, Concurrency: 8}, true},
		{"missing key env", &Config{Enabled: true, MasterKeyEnv: "NOPE", TimeoutSeconds: 30, Concurrency: 8}, false},
		{"bad timeout", &Config{Enabled: true, MasterKeyEnv: "REMOTE_SCAN_MASTER_KEY", TimeoutSeconds: 0, Concurrency: 8}, false},
		{"bad concurrency", &Config{Enabled: true, MasterKeyEnv: "REMOTE_SCAN_MASTER_KEY", TimeoutSeconds: 30, Concurrency: 99}, false},
	}
	for _, c := range cases {
		got := c.cfg.Validate() == nil
		if got != c.want {
			t.Errorf("%s: Validate() error-present=%v, want %v", c.name, !got, c.want)
		}
	}
}

func TestParseMasterKey(t *testing.T) {
	want := []byte(strings.Repeat("\x01", 32))
	valid := []string{
		hex.EncodeToString(want),
		base64.StdEncoding.EncodeToString(want),
		base64.RawStdEncoding.EncodeToString(want),
		base64.URLEncoding.EncodeToString(want),
		base64.RawURLEncoding.EncodeToString(want),
		string(want),
	}
	for _, in := range valid {
		got, err := ParseMasterKey(in)
		if err != nil {
			t.Errorf("ParseMasterKey(%q) error: %v", in, err)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("ParseMasterKey(%q) = %q, want %q", in, got, want)
		}
	}
	invalid := []string{"", "abc", strings.Repeat("a", 63)}
	for _, in := range invalid {
		if _, err := ParseMasterKey(in); err == nil {
			t.Errorf("ParseMasterKey(%q) should fail", in)
		}
	}
}

func TestCipherRoundtrip(t *testing.T) {
	key, _ := ParseMasterKey(strings.Repeat("a", 64))
	cp, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := cp.Encrypt([]byte("s3cr3t"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := cp.Decrypt(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "s3cr3t" {
		t.Fatalf("Decrypt(Encrypt(x)) = %q", got)
	}
	empty, err := cp.Encrypt(nil)
	if err != nil || empty != "" {
		t.Fatalf("Encrypt(nil) = %q, %v", empty, err)
	}
	if _, err := cp.Decrypt("not-base64!"); err == nil {
		t.Fatal("Decrypt invalid base64 should fail")
	}
	other, _ := ParseMasterKey(strings.Repeat("b", 64))
	cp2, _ := NewCipher(other)
	if _, err := cp2.Decrypt(sealed); err == nil {
		t.Fatal("Decrypt with wrong key should fail")
	}
}

func TestParseOSRelease(t *testing.T) {
	name, version := ParseOSRelease("NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\n")
	if name != "Ubuntu" || version != "24.04" {
		t.Fatalf("ParseOSRelease = (%q, %q)", name, version)
	}
	name, version = ParseOSRelease("")
	if name != "linux" || version != "" {
		t.Fatalf("ParseOSRelease empty = (%q, %q)", name, version)
	}
}

func TestParseDPKGAndRPM(t *testing.T) {
	deb := ParseDPKGQuery("openssl\t3.0.13-1ubuntu3\ncurl\t8.5.0-2\n\nbad-line\n")
	if len(deb) != 2 || deb[0].Name != "openssl" || deb[0].Version != "3.0.13-1ubuntu3" || deb[0].Format != "deb" {
		t.Fatalf("ParseDPKGQuery = %+v", deb)
	}
	rpm := ParseRPMQuery("openssl-libs\t3.0.7-27.el9\nbash\t5.1.8-9.el9\n")
	if len(rpm) != 2 || rpm[0].Name != "openssl-libs" || rpm[0].Version != "3.0.7-27.el9" || rpm[0].Format != "rpm" {
		t.Fatalf("ParseRPMQuery = %+v", rpm)
	}
}

func TestParseDarwinAndBrew(t *testing.T) {
	name, version := ParseSwVers("ProductName: macOS\nProductVersion: 14.5\nBuildVersion: 23F79\n")
	if name != "macos" || version != "14.5" {
		t.Fatalf("ParseSwVers = (%q, %q)", name, version)
	}
	brew := ParseBrewList("jq 1.7.1\nyq 4.44.1\n")
	if len(brew) != 2 || brew[0].Name != "jq" || brew[0].Version != "1.7.1" || brew[0].Format != "brew" {
		t.Fatalf("ParseBrewList = %+v", brew)
	}
}

func TestParseWindowsJSON(t *testing.T) {
	caption, version, arch := ParseWindowsOSJSON(`{"Caption":"Microsoft Windows 11 Pro","Version":"10.0.22631","OSArchitecture":"64-bit"}`)
	if caption != "Microsoft Windows 11 Pro" || version != "10.0.22631" || arch != "64-bit" {
		t.Fatalf("ParseWindowsOSJSON = (%q, %q, %q)", caption, version, arch)
	}
	fixes := ParseHotfixJSON(`[{"HotFixID":"KB5034441","InstalledOn":"2024-01-10"},{"HotFixID":"KB5027397","InstalledOn":"2024-02-01"}]`)
	if len(fixes) != 2 || fixes[0].Name != "KB5034441" || fixes[0].Format != "hotfix" {
		t.Fatalf("ParseHotfixJSON = %+v", fixes)
	}
	apps := ParseWindowsAppsJSON(`[{"DisplayName":"7-Zip","DisplayVersion":"23.01","Publisher":"Igor Pavlov"}]`)
	if len(apps) != 1 || apps[0].Name != "7-Zip" || apps[0].Version != "23.01" || apps[0].Format != "win" {
		t.Fatalf("ParseWindowsAppsJSON = %+v", apps)
	}
	if got := NormalizeArch("x86_64"); got != "amd64" {
		t.Fatalf("NormalizeArch(x86_64) = %q", got)
	}
	if got := NormalizeWindowsArch("ARM64"); got != "arm64" {
		t.Fatalf("NormalizeWindowsArch(ARM64) = %q", got)
	}
}
