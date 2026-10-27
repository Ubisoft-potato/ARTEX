//go:build !windows

package mcpstdio

import (
	"os/exec"
	"syscall"
)

// configureProcess puts the child in a new process group whose id equals its
// pid, so every descendant can be signalled with kill(-pid).
func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminateGroup(pid int) {
	if pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGTERM)
	}
}

func forceKillGroup(pid int) {
	if pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
}
