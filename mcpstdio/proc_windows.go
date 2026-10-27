//go:build windows

package mcpstdio

import (
	"os/exec"
	"strconv"
)

// configureProcess is a no-op on Windows; there is no POSIX process group.
func configureProcess(cmd *exec.Cmd) {}

// terminateGroup / forceKillGroup use taskkill /T so the whole child tree
// (npm → node → Chromium) is terminated, not just the wrapper.
func terminateGroup(pid int) { taskkill(pid, false) }
func forceKillGroup(pid int) { taskkill(pid, true) }

func taskkill(pid int, force bool) {
	if pid <= 0 {
		return
	}
	args := []string{"/T", "/PID", strconv.Itoa(pid)}
	if force {
		args = append(args, "/F")
	}
	_ = exec.Command("taskkill", args...).Run()
}
