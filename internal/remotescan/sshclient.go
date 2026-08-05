package remotescan

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"vuln-scanner/internal/collector"

	"golang.org/x/crypto/ssh"
)

const maxOutputBytes = 16 << 20 // 16 MiB per command output

const linuxPackagesCommand = `command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Package}\t${Version}\n' || (command -v rpm >/dev/null 2>&1 && rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n')`

const psPrefix = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "

const windowsOSCommand = `powershell -NoProfile -Command "` + psPrefix +
	`(Get-CimInstance Win32_OperatingSystem) | Select-Object Caption,Version,OSArchitecture | ConvertTo-Json -Compress"`

const windowsHotfixCommand = `powershell -NoProfile -Command "` + psPrefix +
	`Get-HotFix | ForEach-Object { [PSCustomObject]@{HotFixID=$_.HotFixID; InstalledOn=$_.InstalledOn.ToString('yyyy-MM-dd')} } | ConvertTo-Json -Compress"`

const windowsAppsCommand = `powershell -NoProfile -Command "` + psPrefix +
	`Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Select-Object DisplayName,DisplayVersion,Publisher | ConvertTo-Json -Compress"`

// Collect connects to address (host:port) with the given credential, runs the
// read-only OS-appropriate command set, and returns the parsed inventory.
// Host keys are verified with the provided trust-on-first-use policy.
func Collect(ctx context.Context, address string, cred Credential, policy HostKeyPolicy, opts Options) (*Inventory, error) {
	if opts.TimeoutSeconds <= 0 {
		opts.TimeoutSeconds = 30
	}
	timeout := time.Duration(opts.TimeoutSeconds) * time.Second

	var gotKey ssh.PublicKey
	clientCfg := &ssh.ClientConfig{
		User:    cred.Username,
		Timeout: timeout,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			gotKey = key
			if policy.Get == nil {
				return nil
			}
			stored, err := policy.Get(address)
			if err != nil {
				return fmt.Errorf("load host key: %w", err)
			}
			if len(stored) > 0 && !bytes.Equal(stored, key.Marshal()) {
				return fmt.Errorf("host key changed for %s", address)
			}
			return nil
		},
	}
	switch cred.AuthType {
	case AuthTypeKey:
		var signer ssh.Signer
		var err error
		if cred.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(cred.PrivateKey), []byte(cred.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(cred.PrivateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		clientCfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	default:
		clientCfg.Auth = []ssh.AuthMethod{ssh.Password(cred.Password)}
	}

	client, err := ssh.Dial("tcp", address, clientCfg)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	inv, err := collectInventory(ctx, client, opts)
	if err != nil {
		return nil, err
	}
	if gotKey != nil && policy.Put != nil {
		// Persisting the host key is best effort; a failure only means the
		// next scan re-accepts the key (ToFU) instead of failing the result.
		_ = policy.Put(address, gotKey.Marshal())
	}
	return inv, nil
}

func collectInventory(ctx context.Context, client *ssh.Client, opts Options) (*Inventory, error) {
	unameOut, unameErr := runCommand(ctx, client, "uname -s", opts)
	kernel := strings.ToLower(strings.TrimSpace(unameOut))
	switch {
	case unameErr == nil && strings.Contains(kernel, "linux"):
		return collectLinux(ctx, client, opts)
	case unameErr == nil && strings.Contains(kernel, "darwin"):
		return collectDarwin(ctx, client, opts)
	}
	winOut, winErr := runCommand(ctx, client, windowsOSCommand, opts)
	if winErr == nil {
		return collectWindows(ctx, client, opts, winOut)
	}
	return nil, fmt.Errorf("unsupported remote OS (uname: %q err=%v; powershell: %q err=%v)",
		strings.TrimSpace(unameOut), unameErr, strings.TrimSpace(winOut), winErr)
}

func collectLinux(ctx context.Context, client *ssh.Client, opts Options) (*Inventory, error) {
	inv := &Inventory{OSType: "linux"}
	inv.Hostname, _ = runCommand(ctx, client, "hostname", opts)
	inv.Hostname = strings.TrimSpace(inv.Hostname)

	uname, err := runCommand(ctx, client, "uname -s -r -m", opts)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(uname)
	if len(fields) > 1 {
		inv.Kernel = fields[1]
	}
	if len(fields) > 2 {
		inv.Arch = NormalizeArch(fields[2])
	}

	osrel, _ := runCommand(ctx, client, "cat /etc/os-release", opts)
	name, version := ParseOSRelease(osrel)
	inv.OS = strings.ToLower(name)
	inv.Version = version

	pkgsOut, _ := runCommand(ctx, client, linuxPackagesCommand, opts)
	assets := ParseDPKGQuery(pkgsOut)
	if len(assets) == 0 {
		assets = ParseRPMQuery(pkgsOut)
	}
	inv.Assets = append(inv.Assets, osAsset(inv.OS, inv.Version))
	inv.Assets = append(inv.Assets, assets...)
	return inv, nil
}

func collectDarwin(ctx context.Context, client *ssh.Client, opts Options) (*Inventory, error) {
	inv := &Inventory{OSType: "darwin", OS: "macos"}
	inv.Hostname, _ = runCommand(ctx, client, "hostname", opts)
	inv.Hostname = strings.TrimSpace(inv.Hostname)

	swVers, err := runCommand(ctx, client, "sw_vers", opts)
	if err != nil {
		return nil, err
	}
	_, inv.Version = ParseSwVers(swVers)
	archOut, _ := runCommand(ctx, client, "uname -m", opts)
	inv.Arch = NormalizeArch(archOut)

	brewOut, _ := runCommand(ctx, client, `command -v brew >/dev/null 2>&1 && brew list --versions`, opts)
	inv.Assets = append(inv.Assets, osAsset(inv.OS, inv.Version))
	inv.Assets = append(inv.Assets, ParseBrewList(brewOut)...)
	return inv, nil
}

func collectWindows(ctx context.Context, client *ssh.Client, opts Options, osOut string) (*Inventory, error) {
	inv := &Inventory{OSType: "windows", OS: "windows"}
	caption, version, arch := ParseWindowsOSJSON(osOut)
	inv.Version = version
	inv.Arch = NormalizeWindowsArch(arch)
	if caption != "" {
		inv.Hostname = caption
	}

	hostnameOut, _ := runCommand(ctx, client, "hostname", opts)
	if strings.TrimSpace(hostnameOut) != "" {
		inv.Hostname = strings.TrimSpace(hostnameOut)
	}

	fixesOut, _ := runCommand(ctx, client, windowsHotfixCommand, opts)
	appsOut, _ := runCommand(ctx, client, windowsAppsCommand, opts)
	inv.Assets = append(inv.Assets, osAsset(inv.OS, inv.Version))
	inv.Assets = append(inv.Assets, ParseHotfixJSON(fixesOut)...)
	inv.Assets = append(inv.Assets, ParseWindowsAppsJSON(appsOut)...)
	return inv, nil
}

func osAsset(name, version string) collector.Asset {
	return collector.Asset{
		Name:    name,
		Version: version,
		Format:  "os",
		Type:    "OS",
	}
}

func runCommand(ctx context.Context, client *ssh.Client, command string, opts Options) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	var stdout, stderr limitedBuffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- sess.Run(command)
	}()
	select {
	case err := <-done:
		if err != nil {
			return stdout.String(), fmt.Errorf("command %q: %w (stderr: %s)", command, err, strings.TrimSpace(stderr.String()))
		}
		return stdout.String(), nil
	case <-ctx.Done():
		_ = sess.Close()
		return "", ctx.Err()
	}
}

type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.max <= 0 {
		b.max = maxOutputBytes
	}
	remaining := b.max - b.buf.Len()
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	return b.buf.String()
}
