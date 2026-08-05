package compliance

import (
	"testing"
	"time"

	"vuln-scanner/internal/collector"
)

func intPtr(n int) *int       { return &n }
func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

func checkByID(t *testing.T, r Report, id string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("check %q not evaluated", id)
	return Check{}
}

func TestParseSSHDConfig(t *testing.T) {
	cases := []struct {
		name, text, key, wantValue string
		wantFound                  bool
	}{
		{"last match wins", "# PermitRootLogin yes\nPermitRootLogin no\n", "PermitRootLogin", "no", true},
		{"inline comment", "PermitEmptyPasswords no # keep safe\n", "PermitEmptyPasswords", "no", true},
		{"missing", "Port 22\n", "PermitRootLogin", "", false},
		{"empty text", "", "PermitRootLogin", "", false},
		{"case insensitive", "permitrootlogin yes\n", "PermitRootLogin", "yes", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			value, found := parseSSHDConfig(c.text, c.key)
			if found != c.wantFound || value != c.wantValue {
				t.Fatalf("parseSSHDConfig = (%q, %v), want (%q, %v)", value, found, c.wantValue, c.wantFound)
			}
		})
	}
}

func TestHasEmptyShadowPassword(t *testing.T) {
	cases := []struct {
		name string
		text string
		want bool
	}{
		{"all hashes set", "root:$6$abc:18000:0:99999:7:::\nuser:$y$xyz:18000:0:99999:7:::\n", false},
		{"empty hash", "root::18000:0:99999:7:::\n", true},
		{"locked accounts are not empty", "root:!::18000:0:99999:7:::\nuser:*:18000:0:99999:7:::\n", false},
		{"empty text", "", false},
		{"malformed line skipped", "root\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasEmptyShadowPassword(c.text); got != c.want {
				t.Fatalf("hasEmptyShadowPassword = %v, want %v", got, c.want)
			}
		})
	}
}

func TestEvaluateWindows(t *testing.T) {
	now := time.Now()
	good := Facts{
		Platform:           "windows",
		Accounts:           []collector.AccountInfo{{Name: "guest", Disabled: true}},
		TPMEnabled:         true,
		DiskEncryption:     "BitLocker C:On",
		Antivirus:          "Windows Defender",
		FirewallProfiles:   map[string]bool{"domain": true, "public": true, "private": true},
		EnableLUA:          intPtr(1),
		FDenyTSConnections: intPtr(0),
		RDPUserAuth:        intPtr(1),
		SMB1:               intPtr(0),
		AutoAdminLogon:     strPtr("0"),
		UpdateReachable:    boolPtr(true),
	}
	r := Evaluate(good, now)
	if r.Total != 10 || r.Passed != 10 || r.Failed != 0 || r.NA != 0 {
		t.Fatalf("good windows report = %+v, want 10/10 passed", r)
	}
	if r.Score != 100 {
		t.Fatalf("score = %v, want 100", r.Score)
	}
	if r.Benchmark != Benchmark {
		t.Fatalf("benchmark = %q, want %q", r.Benchmark, Benchmark)
	}

	cases := []struct {
		name  string
		facts Facts
		want  map[string]string
	}{
		{
			name:  "firewall profile disabled",
			facts: Facts{Platform: "windows", FirewallProfiles: map[string]bool{"domain": true, "private": false}},
			want:  map[string]string{"windows.firewall_profiles_enabled": "fail"},
		},
		{
			name:  "firewall profiles unknown",
			facts: Facts{Platform: "windows"},
			want:  map[string]string{"windows.firewall_profiles_enabled": "na"},
		},
		{
			name:  "guest enabled",
			facts: Facts{Platform: "windows", Accounts: []collector.AccountInfo{{Name: "Guest", Disabled: false}}},
			want:  map[string]string{"windows.guest_account_disabled": "fail"},
		},
		{
			name:  "guest missing",
			facts: Facts{Platform: "windows"},
			want:  map[string]string{"windows.guest_account_disabled": "na"},
		},
		{
			name:  "tpm missing",
			facts: Facts{Platform: "windows"},
			want:  map[string]string{"windows.tpm_enabled": "fail"},
		},
		{
			name:  "bitlocker off and unknown",
			facts: Facts{Platform: "windows", DiskEncryption: "BitLocker C:Off"},
			want:  map[string]string{"windows.bitlocker_enabled": "fail"},
		},
		{
			name:  "antivirus missing",
			facts: Facts{Platform: "windows"},
			want:  map[string]string{"windows.antivirus_enabled": "fail"},
		},
		{
			name:  "uac disabled and unknown",
			facts: Facts{Platform: "windows", EnableLUA: intPtr(0)},
			want:  map[string]string{"windows.uac_enabled": "fail"},
		},
		{
			name: "rdp enabled without nla",
			facts: Facts{Platform: "windows",
				FDenyTSConnections: intPtr(0), RDPUserAuth: intPtr(0)},
			want: map[string]string{"windows.rdp_nla_enforced": "fail"},
		},
		{
			name:  "rdp unknown",
			facts: Facts{Platform: "windows"},
			want:  map[string]string{"windows.rdp_nla_enforced": "na"},
		},
		{
			name:  "smb1 enabled and unknown",
			facts: Facts{Platform: "windows", SMB1: intPtr(1)},
			want:  map[string]string{"windows.smb1_disabled": "fail"},
		},
		{
			name:  "autologon enabled",
			facts: Facts{Platform: "windows", AutoAdminLogon: strPtr("1")},
			want:  map[string]string{"windows.autologon_disabled": "fail"},
		},
		{
			name:  "autologon unset is pass",
			facts: Facts{Platform: "windows"},
			want:  map[string]string{"windows.autologon_disabled": "pass"},
		},
		{
			name: "update source unreachable",
			facts: Facts{Platform: "windows",
				UpdateReachable: boolPtr(false), UpdateFactCount: 0},
			want: map[string]string{"windows.update_configured": "fail"},
		},
		{
			name:  "update unknown with facts",
			facts: Facts{Platform: "windows", UpdateFactCount: 3},
			want:  map[string]string{"windows.update_configured": "pass"},
		},
		{
			name:  "update unknown without facts",
			facts: Facts{Platform: "windows"},
			want:  map[string]string{"windows.update_configured": "na"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := Evaluate(c.facts, now)
			for id, want := range c.want {
				if got := checkByID(t, rep, id).Status; got != want {
					t.Fatalf("check %s = %q, want %q", id, got, want)
				}
			}
		})
	}
}

func TestEvaluateLinux(t *testing.T) {
	now := time.Now()
	good := Facts{
		Platform:       "linux",
		FirewallRules:  []collector.FirewallRule{{Name: "inbound", Action: "allow"}},
		Services:       []collector.ServiceInfo{{Name: "auditd.service", State: "active"}},
		SELinux:        "enforcing",
		AppArmor:       "enabled",
		SSHDConfig:     "PermitRootLogin no\nPermitEmptyPasswords no\n",
		RandomizeVA:    intPtr(2),
		IPForward:      intPtr(0),
		DiskEncryption: "LUKS",
		ShadowText:     "root:$6$abc:18000:0:99999:7:::\n",
	}
	r := Evaluate(good, now)
	if r.Total != 10 || r.Passed != 10 || r.Failed != 0 || r.NA != 0 {
		t.Fatalf("good linux report = %+v, want 10/10 passed", r)
	}
	if r.Score != 100 {
		t.Fatalf("score = %v, want 100", r.Score)
	}

	cases := []struct {
		name  string
		facts Facts
		want  map[string]string
	}{
		{
			name:  "root login enabled and missing",
			facts: Facts{Platform: "linux", SSHDConfig: "PermitRootLogin yes\n"},
			want:  map[string]string{"linux.ssh_root_login_disabled": "fail"},
		},
		{
			name:  "root login missing",
			facts: Facts{Platform: "linux", SSHDConfig: "Port 22\n"},
			want:  map[string]string{"linux.ssh_root_login_disabled": "na"},
		},
		{
			name:  "empty passwords enabled",
			facts: Facts{Platform: "linux", SSHDConfig: "PermitEmptyPasswords yes\n"},
			want:  map[string]string{"linux.ssh_empty_passwords_disabled": "fail"},
		},
		{
			name:  "no firewall",
			facts: Facts{Platform: "linux"},
			want:  map[string]string{"linux.firewall_active": "fail"},
		},
		{
			name:  "ufw active without rules",
			facts: Facts{Platform: "linux", UFWActive: true},
			want:  map[string]string{"linux.firewall_active": "pass"},
		},
		{
			name:  "selinux permissive and unknown",
			facts: Facts{Platform: "linux", SELinux: "permissive"},
			want:  map[string]string{"linux.selinux_enforcing": "fail"},
		},
		{
			name:  "apparmor missing",
			facts: Facts{Platform: "linux"},
			want:  map[string]string{"linux.apparmor_enabled": "na"},
		},
		{
			name:  "aslr weak and unknown",
			facts: Facts{Platform: "linux", RandomizeVA: intPtr(0)},
			want:  map[string]string{"linux.kernel_aslr_enabled": "fail"},
		},
		{
			name:  "ip forward enabled",
			facts: Facts{Platform: "linux", IPForward: intPtr(1)},
			want:  map[string]string{"linux.ip_forward_disabled": "fail"},
		},
		{
			name:  "auditd inactive",
			facts: Facts{Platform: "linux", Services: []collector.ServiceInfo{{Name: "auditd.service", State: "inactive"}}},
			want:  map[string]string{"linux.auditd_running": "fail"},
		},
		{
			name:  "auditd missing",
			facts: Facts{Platform: "linux"},
			want:  map[string]string{"linux.auditd_running": "na"},
		},
		{
			name:  "disk encryption unknown",
			facts: Facts{Platform: "linux"},
			want:  map[string]string{"linux.disk_encryption_enabled": "na"},
		},
		{
			name:  "empty shadow password",
			facts: Facts{Platform: "linux", ShadowText: "root::18000:0:99999:7:::\n"},
			want:  map[string]string{"linux.no_empty_password_accounts": "fail"},
		},
		{
			name:  "shadow unreadable",
			facts: Facts{Platform: "linux"},
			want:  map[string]string{"linux.no_empty_password_accounts": "na"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := Evaluate(c.facts, now)
			for id, want := range c.want {
				if got := checkByID(t, rep, id).Status; got != want {
					t.Fatalf("check %s = %q, want %q", id, got, want)
				}
			}
		})
	}
}

func TestEvaluateScoreEdges(t *testing.T) {
	now := time.Now()
	// The firewall check is fail when nothing is detected, so a fully-na
	// set does not exist by design. Verify na checks stay out of the score:
	// one fail + nine na => score 0.
	nearlyAllNA := Facts{Platform: "linux"}
	r := Evaluate(nearlyAllNA, now)
	if r.Total != 10 || r.Passed != 0 || r.Failed != 1 || r.NA != 9 {
		t.Fatalf("nearly-na report = %+v, want 0/1/9", r)
	}
	if r.Score != 0 {
		t.Fatalf("na-only score = %v, want 0", r.Score)
	}

	mixed := Facts{
		Platform: "linux",
		// Pass: firewall, aslr, ip_forward.
		// Fail: ssh root login, ssh empty passwords, selinux.
		// NA: apparmor, auditd, disk encryption, shadow.
		FirewallRules: []collector.FirewallRule{{Name: "x"}},
		SELinux:       "permissive",
		SSHDConfig:    "PermitRootLogin yes\nPermitEmptyPasswords yes\n",
		RandomizeVA:   intPtr(2),
		IPForward:     intPtr(0),
	}
	r = Evaluate(mixed, now)
	if r.Passed != 3 || r.Failed != 3 || r.NA != 4 {
		t.Fatalf("mixed report = %+v, want 3/3/4", r)
	}
	if r.Score != 50 {
		t.Fatalf("mixed score = %v, want 50", r.Score)
	}

	unknown := Evaluate(Facts{Platform: "freebsd"}, now)
	if unknown.Total != 0 || len(unknown.Checks) != 0 {
		t.Fatalf("unsupported platform report = %+v, want empty", unknown)
	}
}
