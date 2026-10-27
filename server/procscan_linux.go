//go:build linux

package server

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// cgroupProcs lists every PID in this service's cgroup subtree. Walking the
// directory (instead of only cgroup.procs at the root) also covers child
// scopes an agent might create, and catches processes that were reparented to
// PID 1 after their shell exited.
func cgroupProcs() []int {
	base, ok := cgroupPath()
	if !ok {
		return nil
	}
	seen := make(map[int]bool)
	var out []int
	_ = filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "cgroup.procs" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, f := range strings.Fields(string(b)) {
			pid, err := strconv.Atoi(f)
			if err == nil && pid > 0 && !seen[pid] {
				seen[pid] = true
				out = append(out, pid)
			}
		}
		return nil
	})
	return out
}

// readProcInfo snapshots one process: parent, RSS, CPU ticks, start tick and
// command line.
func readProcInfo(pid int) (procInfo, bool) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return procInfo{}, false
	}
	s := string(raw)
	open := strings.IndexByte(s, '(')
	closeIdx := strings.LastIndexByte(s, ')')
	if open < 0 || closeIdx <= open || closeIdx+2 >= len(s) {
		return procInfo{}, false
	}
	comm := s[open+1 : closeIdx]
	// Fields after ") " start at stat field 3 (state): [1]=ppid,
	// [11]=utime, [12]=stime, [20]=starttime.
	f := strings.Fields(s[closeIdx+2:])
	if len(f) < 21 {
		return procInfo{}, false
	}
	ppid, _ := strconv.Atoi(f[1])
	utime, _ := strconv.ParseUint(f[11], 10, 64)
	stime, _ := strconv.ParseUint(f[12], 10, 64)
	start, _ := strconv.ParseUint(f[20], 10, 64)
	return procInfo{
		PID:       pid,
		PPID:      ppid,
		RSS:       procRSS(pid),
		CPUTicks:  utime + stime,
		StartTick: start,
		Cmd:       procCmdline(pid, comm),
	}, true
}

func procRSS(pid int) int64 {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 {
			if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				return kb * 1024
			}
		}
	}
	return 0
}

func procCmdline(pid int, comm string) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil || len(b) == 0 {
		return comm
	}
	s := strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
	if s == "" {
		return comm
	}
	return s
}

func procStartTick(pid int) (uint64, bool) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return 0, false
	}
	f := strings.Fields(s[i+2:])
	if len(f) < 21 {
		return 0, false
	}
	start, err := strconv.ParseUint(f[20], 10, 64)
	return start, err == nil
}

func procAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// killProcTrees terminates every member of the given trees: SIGTERM first,
// a short grace period, then SIGKILL for whatever survived. A PID is only
// signalled if its kernel start tick still matches the snapshot, so a recycled
// PID can never be hit.
func killProcTrees(trees []procTree, grace time.Duration) int {
	self := os.Getpid()
	var victims []int
	for _, t := range trees {
		for _, pid := range t.PIDs {
			if pid <= 1 || pid == self {
				continue
			}
			if start, ok := procStartTick(pid); ok && t.Starts[pid] == start {
				victims = append(victims, pid)
			}
		}
	}
	if len(victims) == 0 {
		return 0
	}
	for _, pid := range victims {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		alive := false
		for _, pid := range victims {
			if procAlive(pid) {
				alive = true
				break
			}
		}
		if !alive {
			return len(trees)
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, pid := range victims {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	return len(trees)
}
