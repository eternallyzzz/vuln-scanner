// Package compliance evaluates a curated CIS-inspired configuration baseline
// on the agent. All evaluation logic is pure Go so it can be unit tested
// without a database or a live OS; platform-specific fact gathering lives in
// build-tagged files.
package compliance

import (
	"math"
	"strconv"
	"strings"
	"time"

	"vuln-scanner/internal/collector"
)

// Benchmark is the baseline identifier reported by the agent. v1 is a
// curated subset, not a CIS certification.
const Benchmark = "cis-v1"

// Check is one baseline item with a pass/fail/na verdict and evidence.
type Check struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Group    string `json:"group"`
	Status   string `json:"status"` // pass | fail | na
	Evidence string `json:"evidence,omitempty"`
}

// Report is the agent-side evaluation result for one host.
type Report struct {
	Benchmark string    `json:"benchmark"`
	Score     float64   `json:"score"`
	Total     int       `json:"total"`
	Passed    int       `json:"passed"`
	Failed    int       `json:"failed"`
	NA        int       `json:"na"`
	Checks    []Check   `json:"checks"`
	CheckedAt time.Time `json:"checked_at"`
}

// Facts are the raw inputs checks evaluate. Fields are populated by the
// platform-specific CollectFacts implementations; nil/empty fields degrade
// to na so a single failed telemetry command never blocks the whole report.
type Facts struct {
	Platform string // "windows" | "linux"

	// Common telemetry reused from the latest SystemInfo snapshot.
	Accounts        []collector.AccountInfo
	FirewallRules   []collector.FirewallRule
	Services        []collector.ServiceInfo
	TPMEnabled      bool
	DiskEncryption  string
	Antivirus       string
	SELinux         string
	AppArmor        string
	UpdateReachable *bool
	UpdateFactCount int

	// Windows-only raw facts.
	FirewallProfiles   map[string]bool // profile (lower) -> enabled
	EnableLUA          *int
	FDenyTSConnections *int
	RDPUserAuth        *int
	SMB1               *int
	AutoAdminLogon     *string

	// Linux-only raw facts.
	SSHDConfig  string // raw /etc/ssh/sshd_config text
	RandomizeVA *int
	IPForward   *int
	ShadowText  string // raw /etc/shadow text, empty when unreadable
	UFWActive   bool
}

// Evaluate runs the fixed v1 check list for the facts' platform and computes
// the compliance score. Score = passed/(passed+failed)*100, rounded to one
// decimal; na checks are excluded from the denominator.
func Evaluate(f Facts, now time.Time) Report {
	var checks []Check
	switch f.Platform {
	case "windows":
		checks = evaluateWindows(f)
	case "linux":
		checks = evaluateLinux(f)
	}
	r := Report{
		Benchmark: Benchmark,
		Checks:    checks,
		CheckedAt: now,
	}
	for _, c := range checks {
		r.Total++
		switch c.Status {
		case "pass":
			r.Passed++
		case "fail":
			r.Failed++
		default:
			r.NA++
		}
	}
	if denom := r.Passed + r.Failed; denom > 0 {
		r.Score = math.Round(float64(r.Passed)/float64(denom)*1000) / 10
	}
	return r
}

func evaluateWindows(f Facts) []Check {
	return []Check{
		checkFirewallProfiles(f),
		checkGuestAccount(f),
		checkTPM(f),
		checkBitLocker(f),
		checkAntivirus(f),
		checkUAC(f),
		checkRDPNLA(f),
		checkSMB1(f),
		checkAutoLogon(f),
		checkWindowsUpdate(f),
	}
}

func evaluateLinux(f Facts) []Check {
	return []Check{
		checkSSHRootLogin(f),
		checkSSHEmptyPasswords(f),
		checkLinuxFirewall(f),
		checkSELinux(f),
		checkAppArmor(f),
		checkASLR(f),
		checkIPForward(f),
		checkAuditd(f),
		checkLinuxDiskEncryption(f),
		checkEmptyShadowPasswords(f),
	}
}

func checkFirewallProfiles(f Facts) Check {
	c := Check{ID: "windows.firewall_profiles_enabled", Title: "Windows 防火墙所有配置文件均已启用", Group: "网络与防火墙"}
	if len(f.FirewallProfiles) == 0 {
		c.Status = "na"
		c.Evidence = "无法获取防火墙配置文件状态"
		return c
	}
	var disabled []string
	for profile, enabled := range f.FirewallProfiles {
		if !enabled {
			disabled = append(disabled, profile)
		}
	}
	if len(disabled) == 0 {
		c.Status = "pass"
		c.Evidence = "Domain/Public/Private 均启用"
		return c
	}
	c.Status = "fail"
	c.Evidence = "已禁用的配置文件: " + strings.Join(disabled, ", ")
	return c
}

func checkGuestAccount(f Facts) Check {
	c := Check{ID: "windows.guest_account_disabled", Title: "Guest 账户已禁用", Group: "账户与认证"}
	for _, a := range f.Accounts {
		if !strings.EqualFold(a.Name, "guest") {
			continue
		}
		if a.Disabled {
			c.Status = "pass"
			c.Evidence = "Guest 已禁用"
		} else {
			c.Status = "fail"
			c.Evidence = "Guest 未禁用"
		}
		return c
	}
	c.Status = "na"
	c.Evidence = "未找到 Guest 账户（可能无权限枚举）"
	return c
}

func checkTPM(f Facts) Check {
	c := Check{ID: "windows.tpm_enabled", Title: "TPM 已启用", Group: "设备安全"}
	if f.TPMEnabled {
		c.Status = "pass"
		c.Evidence = "TPM 存在"
	} else {
		c.Status = "fail"
		c.Evidence = "TPM 未启用"
	}
	return c
}

func checkBitLocker(f Facts) Check {
	c := Check{ID: "windows.bitlocker_enabled", Title: "BitLocker 卷已加密", Group: "数据保护"}
	switch {
	case f.DiskEncryption == "":
		c.Status = "na"
		c.Evidence = "无法获取 BitLocker 状态"
	case strings.Contains(f.DiskEncryption, ":On"):
		c.Status = "pass"
		c.Evidence = f.DiskEncryption
	default:
		c.Status = "fail"
		c.Evidence = f.DiskEncryption
	}
	return c
}

func checkAntivirus(f Facts) Check {
	c := Check{ID: "windows.antivirus_enabled", Title: "防病毒软件已安装", Group: "系统加固"}
	if f.Antivirus != "" {
		c.Status = "pass"
		c.Evidence = f.Antivirus
	} else {
		c.Status = "fail"
		c.Evidence = "未检测到防病毒产品"
	}
	return c
}

func checkUAC(f Facts) Check {
	c := Check{ID: "windows.uac_enabled", Title: "UAC 已启用", Group: "系统加固"}
	if f.EnableLUA == nil {
		c.Status = "na"
		c.Evidence = "无法读取 EnableLUA"
		return c
	}
	if *f.EnableLUA == 1 {
		c.Status = "pass"
		c.Evidence = "EnableLUA=1"
	} else {
		c.Status = "fail"
		c.Evidence = "EnableLUA=0"
	}
	return c
}

func checkRDPNLA(f Facts) Check {
	c := Check{ID: "windows.rdp_nla_enforced", Title: "远程桌面需 NLA 或已禁用", Group: "网络与防火墙"}
	if f.FDenyTSConnections != nil && *f.FDenyTSConnections == 1 {
		c.Status = "pass"
		c.Evidence = "远程桌面已禁用"
		return c
	}
	if f.RDPUserAuth != nil {
		if *f.RDPUserAuth == 1 {
			c.Status = "pass"
			c.Evidence = "NLA 已启用"
			return c
		}
		c.Status = "fail"
		c.Evidence = "远程桌面已启用且未强制 NLA"
		return c
	}
	if f.FDenyTSConnections != nil && *f.FDenyTSConnections == 0 {
		c.Status = "fail"
		c.Evidence = "远程桌面已启用，无法确认 NLA"
		return c
	}
	c.Status = "na"
	c.Evidence = "无法读取远程桌面配置"
	return c
}

func checkSMB1(f Facts) Check {
	c := Check{ID: "windows.smb1_disabled", Title: "SMBv1 已禁用", Group: "网络与防火墙"}
	if f.SMB1 == nil {
		c.Status = "na"
		c.Evidence = "无法读取 SMB1 配置"
		return c
	}
	if *f.SMB1 == 1 {
		c.Status = "fail"
		c.Evidence = "SMB1=1"
	} else {
		c.Status = "pass"
		c.Evidence = "SMB1 未启用"
	}
	return c
}

func checkAutoLogon(f Facts) Check {
	c := Check{ID: "windows.autologon_disabled", Title: "自动登录已禁用", Group: "账户与认证"}
	if f.AutoAdminLogon == nil || *f.AutoAdminLogon == "" || *f.AutoAdminLogon == "0" {
		c.Status = "pass"
		c.Evidence = "未配置自动登录"
		return c
	}
	if *f.AutoAdminLogon == "1" {
		c.Status = "fail"
		c.Evidence = "AutoAdminLogon=1"
	} else {
		c.Status = "pass"
		c.Evidence = "AutoAdminLogon=" + *f.AutoAdminLogon
	}
	return c
}

func checkWindowsUpdate(f Facts) Check {
	c := Check{ID: "windows.update_configured", Title: "Windows 更新源可用", Group: "更新与补丁"}
	switch {
	case f.UpdateReachable != nil && *f.UpdateReachable:
		c.Status = "pass"
		c.Evidence = "更新源可达"
	case f.UpdateFactCount > 0:
		c.Status = "pass"
		c.Evidence = "已获取更新事实"
	case f.UpdateReachable != nil:
		c.Status = "fail"
		c.Evidence = "更新源不可达且无更新事实"
	default:
		c.Status = "na"
		c.Evidence = "无更新源状态"
	}
	return c
}

func checkSSHRootLogin(f Facts) Check {
	c := Check{ID: "linux.ssh_root_login_disabled", Title: "SSH 禁止 root 直接登录", Group: "账户与认证"}
	value, found := parseSSHDConfig(f.SSHDConfig, "PermitRootLogin")
	switch {
	case !found:
		c.Status = "na"
		c.Evidence = "sshd_config 未配置 PermitRootLogin"
	case value == "no" || value == "prohibit-password":
		c.Status = "pass"
		c.Evidence = "PermitRootLogin=" + value
	default:
		c.Status = "fail"
		c.Evidence = "PermitRootLogin=" + value
	}
	return c
}

func checkSSHEmptyPasswords(f Facts) Check {
	c := Check{ID: "linux.ssh_empty_passwords_disabled", Title: "SSH 禁止空密码登录", Group: "账户与认证"}
	value, found := parseSSHDConfig(f.SSHDConfig, "PermitEmptyPasswords")
	switch {
	case !found:
		c.Status = "na"
		c.Evidence = "sshd_config 未配置 PermitEmptyPasswords"
	case value == "no":
		c.Status = "pass"
		c.Evidence = "PermitEmptyPasswords=no"
	default:
		c.Status = "fail"
		c.Evidence = "PermitEmptyPasswords=" + value
	}
	return c
}

func checkLinuxFirewall(f Facts) Check {
	c := Check{ID: "linux.firewall_active", Title: "防火墙已激活（iptables/nftables/ufw）", Group: "网络与防火墙"}
	if len(f.FirewallRules) > 0 || f.UFWActive {
		c.Status = "pass"
		c.Evidence = "检测到防火墙规则或 ufw 处于 active"
	} else {
		c.Status = "fail"
		c.Evidence = "未检测到防火墙规则且 ufw 未激活"
	}
	return c
}

func checkSELinux(f Facts) Check {
	c := Check{ID: "linux.selinux_enforcing", Title: "SELinux 处于 enforcing", Group: "系统加固"}
	switch strings.ToLower(strings.TrimSpace(f.SELinux)) {
	case "enforcing":
		c.Status = "pass"
		c.Evidence = "SELinux=enforcing"
	case "permissive", "disabled":
		c.Status = "fail"
		c.Evidence = "SELinux=" + f.SELinux
	default:
		c.Status = "na"
		c.Evidence = "未检测到 SELinux"
	}
	return c
}

func checkAppArmor(f Facts) Check {
	c := Check{ID: "linux.apparmor_enabled", Title: "AppArmor 已启用", Group: "系统加固"}
	if strings.TrimSpace(f.AppArmor) != "" {
		c.Status = "pass"
		c.Evidence = "AppArmor=" + f.AppArmor
	} else {
		c.Status = "na"
		c.Evidence = "未检测到 AppArmor"
	}
	return c
}

func checkASLR(f Facts) Check {
	c := Check{ID: "linux.kernel_aslr_enabled", Title: "内核地址空间随机化已启用", Group: "内核加固"}
	if f.RandomizeVA == nil {
		c.Status = "na"
		c.Evidence = "无法读取 randomize_va_space"
		return c
	}
	if *f.RandomizeVA == 2 {
		c.Status = "pass"
		c.Evidence = "randomize_va_space=2"
	} else {
		c.Status = "fail"
		c.Evidence = "randomize_va_space=" + strconv.Itoa(*f.RandomizeVA)
	}
	return c
}

func checkIPForward(f Facts) Check {
	c := Check{ID: "linux.ip_forward_disabled", Title: "IP 转发已禁用", Group: "网络与防火墙"}
	if f.IPForward == nil {
		c.Status = "na"
		c.Evidence = "无法读取 ip_forward"
		return c
	}
	if *f.IPForward == 0 {
		c.Status = "pass"
		c.Evidence = "ip_forward=0"
	} else {
		c.Status = "fail"
		c.Evidence = "ip_forward=" + strconv.Itoa(*f.IPForward)
	}
	return c
}

func checkAuditd(f Facts) Check {
	c := Check{ID: "linux.auditd_running", Title: "auditd 审计服务运行中", Group: "审计与日志"}
	var found bool
	for _, svc := range f.Services {
		if !strings.Contains(strings.ToLower(svc.Name), "auditd") {
			continue
		}
		found = true
		state := strings.ToLower(svc.State)
		if state == "active" || state == "running" || state == "started" {
			c.Status = "pass"
			c.Evidence = svc.Name + "=" + svc.State
			return c
		}
	}
	if found {
		c.Status = "fail"
		c.Evidence = "auditd 服务存在但未运行"
	} else {
		c.Status = "na"
		c.Evidence = "未检测到 auditd 服务"
	}
	return c
}

func checkLinuxDiskEncryption(f Facts) Check {
	c := Check{ID: "linux.disk_encryption_enabled", Title: "磁盘加密（LUKS）已启用", Group: "数据保护"}
	if strings.Contains(strings.ToUpper(f.DiskEncryption), "LUKS") {
		c.Status = "pass"
		c.Evidence = f.DiskEncryption
	} else {
		c.Status = "na"
		c.Evidence = "未检测到 LUKS（容器/虚拟机环境可能无法判定）"
	}
	return c
}

func checkEmptyShadowPasswords(f Facts) Check {
	c := Check{ID: "linux.no_empty_password_accounts", Title: "不存在空密码账户", Group: "账户与认证"}
	if f.ShadowText == "" {
		c.Status = "na"
		c.Evidence = "无法读取 /etc/shadow"
		return c
	}
	if hasEmptyShadowPassword(f.ShadowText) {
		c.Status = "fail"
		c.Evidence = "存在密码字段为空的账户"
	} else {
		c.Status = "pass"
		c.Evidence = "所有账户密码字段非空"
	}
	return c
}
