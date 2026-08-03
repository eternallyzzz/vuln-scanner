package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func installService() error {
	binPath, err := os.Executable()
	if err != nil {
		return err
	}

	destDir := filepath.Join(os.Getenv("ProgramFiles"), "VulnScanner")
	dest := filepath.Join(destDir, "vuln-agent.exe")

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	if binPath != dest {
		data, err := os.ReadFile(binPath)
		if err != nil {
			return fmt.Errorf("read binary: %w", err)
		}
		if err := os.WriteFile(dest, data, 0755); err != nil {
			return fmt.Errorf("write binary: %w", err)
		}
	}

	output, err := exec.Command("sc.exe", "create", "VulnAgent",
		"binPath=", dest+" run",
		"start=", "auto",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc create: %s", string(output))
	}

	output, err = exec.Command("sc.exe", "start", "VulnAgent").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc start: %s", string(output))
	}

	return nil
}

func uninstallService() error {
	exec.Command("sc.exe", "stop", "VulnAgent").Run()
	exec.Command("sc.exe", "delete", "VulnAgent").Run()

	destDir := filepath.Join(os.Getenv("ProgramFiles"), "VulnScanner")
	os.RemoveAll(destDir)
	return nil
}
