//go:build windows

package agent

import (
	"fmt"
	"os/exec"
)

// configureProcessGroup is a no-op on Windows; cancellation uses taskkill.
func configureProcessGroup(_ *exec.Cmd) {}

func killProcessTree(pid int) {
	_ = exec.Command("taskkill", "/PID", fmt.Sprint(pid), "/T", "/F").Run()
}
