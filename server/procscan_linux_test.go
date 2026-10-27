//go:build linux

package server

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestKillProcTreesTerminatesRealTree proves the reaper kills a real
// parent→child chain (the shape of Bash→python→Chromium) and leaves nothing
// behind. The tree is rooted at a shell spawned by this test, so no other
// process is touched.
func TestKillProcTreesTerminatesRealTree(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "sleep 60 & wait")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot spawn shell: %v", err)
	}
	shell := cmd.Process.Pid
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	var tree procTree
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		pids := cgroupProcs()
		procs := make([]procInfo, 0, len(pids))
		for _, pid := range pids {
			if pi, ok := readProcInfo(pid); ok {
				procs = append(procs, pi)
			}
		}
		for _, tr := range buildProcTrees(procs, os.Getpid()) {
			if tr.Root == shell && len(tr.PIDs) >= 2 {
				tree = tr
				break
			}
		}
		if len(tree.PIDs) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(tree.PIDs) < 2 {
		t.Fatalf("shell tree not observed: %+v", tree)
	}

	if n := killProcTrees([]procTree{tree}, time.Second); n != 1 {
		t.Fatalf("killProcTrees returned %d, want 1", n)
	}
	_ = cmd.Wait()
	waited = true

	for _, pid := range tree.PIDs {
		if pid == shell {
			continue // reaped by cmd.Wait above
		}
		if !waitProcGone(pid, 3*time.Second) {
			t.Fatalf("pid %d survived tree kill", pid)
		}
	}
}

func waitProcGone(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !procAlive(pid) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
