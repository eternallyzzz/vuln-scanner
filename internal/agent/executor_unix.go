//go:build !windows

package agent

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup puts the child in its own process group so the whole
// tree can be killed on cancel.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killProcessTree(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
