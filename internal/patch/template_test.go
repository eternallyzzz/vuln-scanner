package patch

import "testing"

func testCfg() *Config {
	return &Config{Enabled: true, AgentTimeoutSeconds: 600}
}

func TestBuildCommandVersion(t *testing.T) {
	cmd, err := BuildCommand(testCfg(), "version", "1.2.3", "openssl", "")
	if err != nil {
		t.Fatal(err)
	}
	if !cmd.Deployable {
		t.Fatal("version task should be deployable")
	}
	if len(cmd.ArgvLists) != 2 {
		t.Fatalf("expected update+install argv lists, got %d", len(cmd.ArgvLists))
	}
	last := cmd.ArgvLists[1]
	if last[len(last)-1] != "openssl" {
		t.Fatalf("last argv must be package name, got %v", last)
	}
}

func TestBuildCommandForAgentDnf(t *testing.T) {
	cmd, err := BuildCommandForAgent(testCfg(), "version", "1.2.3", "openssl", "",
		"rocky linux", "9.4")
	if err != nil {
		t.Fatal(err)
	}
	if !cmd.Deployable {
		t.Fatal("dnf task should be deployable")
	}
	if len(cmd.ArgvLists) != 1 {
		t.Fatalf("expected one dnf argv list, got %d", len(cmd.ArgvLists))
	}
	argv := cmd.ArgvLists[0]
	if len(argv) < 2 || argv[0] != "dnf" || argv[len(argv)-1] != "openssl" {
		t.Fatalf("unexpected dnf argv: %v", argv)
	}
	if cmd.Display != "dnf -y update openssl" {
		t.Fatalf("unexpected display %q", cmd.Display)
	}
}

func TestBuildCommandForAgentYum(t *testing.T) {
	cmd, err := BuildCommandForAgent(testCfg(), "version", "1.2.3", "openssl", "",
		"centos linux", "7.9")
	if err != nil {
		t.Fatal(err)
	}
	argv := cmd.ArgvLists[0]
	if argv[0] != "yum" || argv[len(argv)-1] != "openssl" {
		t.Fatalf("unexpected yum argv: %v", argv)
	}
	if cmd.Display != "yum -y update openssl" {
		t.Fatalf("unexpected display %q", cmd.Display)
	}
}

func TestBuildCommandForAgentAptFallback(t *testing.T) {
	cmd, err := BuildCommandForAgent(testCfg(), "version", "1.2.3", "openssl", "",
		"debian gnu/linux", "12")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd.ArgvLists) != 2 || cmd.ArgvLists[0][0] != "apt-get" {
		t.Fatalf("expected apt argv lists, got %v", cmd.ArgvLists)
	}
}

func TestBuildCommandForAgentApk(t *testing.T) {
	cmd, err := BuildCommandForAgent(testCfg(), "version", "3.0.16-r1", "openssl", "",
		"Alpine Linux", "3.23.3")
	if err != nil {
		t.Fatal(err)
	}
	if !cmd.Deployable {
		t.Fatal("apk task should be deployable")
	}
	if len(cmd.ArgvLists) != 1 {
		t.Fatalf("expected one apk argv list, got %d", len(cmd.ArgvLists))
	}
	argv := cmd.ArgvLists[0]
	if len(argv) < 2 || argv[0] != "apk" || argv[len(argv)-1] != "openssl" {
		t.Fatalf("unexpected apk argv: %v", argv)
	}
	if cmd.Display != "apk upgrade openssl" {
		t.Fatalf("unexpected display %q", cmd.Display)
	}
}

func TestPackageManagerForAgent(t *testing.T) {
	cases := []struct {
		os, version, want string
	}{
		{"Alpine Linux", "3.23.3", "apk"},
		{"Rocky Linux", "9.4", "dnf"},
		{"AlmaLinux", "8.10", "dnf"},
		{"Red Hat Enterprise Linux", "7.9", "yum"},
		{"CentOS Linux", "7.9", "yum"},
		{"Debian GNU/Linux", "12", "apt"},
		{"Ubuntu", "22.04", "apt"},
		{"Windows 10", "10.0.19045", "apt"},
	}
	for _, c := range cases {
		if got := packageManagerForAgent(c.os, c.version); string(got) != c.want {
			t.Errorf("packageManagerForAgent(%q, %q) = %q, want %q",
				c.os, c.version, got, c.want)
		}
	}
}

func TestBuildCommandRejectsInjection(t *testing.T) {
	bad := []string{
		"openssl; rm -rf /",
		"openssl$(id)",
		"openssl && apt-get remove",
		"-y",
		"a b",
		"../openssl",
		"openssl/../etc",
	}
	for _, name := range bad {
		if _, err := BuildCommand(testCfg(), "version", "1.0", name, ""); err == nil {
			t.Fatalf("asset name %q must be rejected", name)
		}
	}
}

func TestBuildCommandKB(t *testing.T) {
	cmd, err := BuildCommand(testCfg(), "kb", "KB123", "Windows", "https://download.microsoft.com/download/x/kb123.msu")
	if err != nil {
		t.Fatal(err)
	}
	if !cmd.Deployable {
		t.Fatal("allowlisted kb url should be deployable")
	}
	if len(cmd.ArgvLists) != 1 || cmd.ArgvLists[0][0] != "powershell" {
		t.Fatalf("unexpected kb argv: %v", cmd.ArgvLists)
	}

	for _, url := range []string{
		"http://evil.example.com/kb.msu",
		"https://evil.example.com/kb.msu",
		"file:///etc/passwd",
		"",
	} {
		cmd, err := BuildCommand(testCfg(), "kb", "KB123", "Windows", url)
		if err != nil {
			t.Fatalf("url %q: %v", url, err)
		}
		if cmd.Deployable {
			t.Fatalf("url %q must not be deployable", url)
		}
	}
}

func TestBuildCommandNone(t *testing.T) {
	cmd, err := BuildCommand(testCfg(), "none", "", "foo", "")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Deployable || len(cmd.ArgvLists) != 0 {
		t.Fatal("none task must not be deployable")
	}
}

func TestRiskFromCVSS(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{9.8, "CRITICAL"},
		{7.5, "HIGH"},
		{5.0, "MEDIUM"},
		{2.0, "LOW"},
		{0, "LOW"},
	}
	for _, c := range cases {
		if got := RiskFromCVSS(c.score); got != c.want {
			t.Fatalf("score %v: got %s want %s", c.score, got, c.want)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := &Config{Enabled: true, AgentTimeoutSeconds: 10}
	if err := cfg.Validate(); err == nil {
		t.Fatal("timeout < 30 must be rejected")
	}
	cfg.AgentTimeoutSeconds = 600
	cfg.AptCommand = "apt-get install -y --only-upgrade; rm -rf /"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unsafe apt command must be rejected")
	}
	cfg.AptCommand = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default should validate: %v", err)
	}
	cfg.DnfCommand = "dnf -y update; rm -rf /"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unsafe dnf command must be rejected")
	}
	cfg.DnfCommand = ""
	cfg.YumCommand = "yum -y update && reboot"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unsafe yum command must be rejected")
	}
	cfg.YumCommand = ""
	cfg.ApkCommand = "apk upgrade; rm -rf /"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unsafe apk command must be rejected")
	}
	cfg.ApkCommand = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("defaults should validate after reset: %v", err)
	}
}
