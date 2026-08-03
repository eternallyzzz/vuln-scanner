package main

import (
	"fmt"
	"os"
	"os/exec"
)

func installService() error {
	binPath, err := os.Executable()
	if err != nil {
		return err
	}

	dest := "/usr/local/bin/vuln-agent"
	if binPath != dest {
		if err := copyFile(binPath, dest); err != nil {
			return fmt.Errorf("copy binary: %w", err)
		}
	}

	unit := `[Unit]
Description=VulnScanner Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vuln-agent run
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
`

	if err := os.WriteFile("/etc/systemd/system/vuln-agent.service", []byte(unit), 0644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}

	cmds := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "vuln-agent"},
		{"systemctl", "start", "vuln-agent"},
	}

	for _, args := range cmds {
		if output, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %s", args[1], string(output))
		}
	}

	return nil
}

func uninstallService() error {
	exec.Command("systemctl", "stop", "vuln-agent").Run()
	exec.Command("systemctl", "disable", "vuln-agent").Run()
	os.Remove("/etc/systemd/system/vuln-agent.service")
	exec.Command("systemctl", "daemon-reload").Run()
	os.Remove("/usr/local/bin/vuln-agent")
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0755)
}
