package server

import "strings"

// procInfo is one process snapshot used by the cgroup memory guard.
type procInfo struct {
	PID       int
	PPID      int
	RSS       int64
	CPUTicks  uint64
	StartTick uint64
	Cmd       string
}

// procTree is a root process plus every descendant that lives in the same
// cgroup. RSS/CPU are sums over the tree. Starts keeps each member's kernel
// start tick so a kill can refuse to signal a recycled PID.
type procTree struct {
	Root      int
	StartTick uint64
	PIDs      []int
	Starts    map[int]uint64
	RSS       int64
	CPU       uint64
	Cmd       string
}

// buildProcTrees groups cgroup processes into killable trees.
//
// A tree root is always a process the supervisor may terminate as a unit:
//   - a direct child of self (each tool/MCP run), or
//   - a reparented orphan (ppid == 1) — but ONLY when self itself is a
//     top-level member of the cgroup. That is the systemd case: the cgroup is
//     dedicated to artex, so any other top-level PID is an orphan left by one
//     of artex's own tools. When artex is nested inside a shared cgroup (a
//     start.sh session, a test runner, a login shell), only self's descendants
//     are considered, so the guard can never climb up or sideways into the
//     desktop/sshd/other session processes. self is never part of a tree.
func buildProcTrees(procs []procInfo, self int) []procTree {
	index := make(map[int]procInfo, len(procs))
	children := make(map[int][]int, len(procs))
	for _, p := range procs {
		index[p.PID] = p
	}
	for _, p := range procs {
		children[p.PPID] = append(children[p.PPID], p.PID)
	}

	selfProc, selfSeen := index[self]
	dedicated := selfSeen
	if dedicated {
		if _, ok := index[selfProc.PPID]; ok {
			dedicated = false // self's parent is in the cgroup → shared cgroup
		}
	}

	roots := make([]int, 0, len(procs))
	for _, p := range procs {
		if p.PID == self || p.PID <= 1 {
			continue
		}
		if p.PPID == self {
			roots = append(roots, p.PID)
			continue
		}
		if dedicated && p.PPID == 1 {
			roots = append(roots, p.PID) // reparented tool orphan
		}
	}

	out := make([]procTree, 0, len(roots))
	seen := make(map[int]bool, len(procs))
	for _, root := range roots {
		if seen[root] {
			continue
		}
		t := procTree{
			Root:      root,
			StartTick: index[root].StartTick,
			Starts:    make(map[int]uint64),
			Cmd:       index[root].Cmd,
		}
		var walk func(pid int)
		walk = func(pid int) {
			if seen[pid] {
				return
			}
			seen[pid] = true
			p := index[pid]
			t.PIDs = append(t.PIDs, pid)
			t.Starts[pid] = p.StartTick
			t.RSS += p.RSS
			t.CPU += p.CPUTicks
			for _, c := range children[pid] {
				walk(c)
			}
		}
		walk(root)
		out = append(out, t)
	}
	return out
}

// containsAny reports whether any PID in the set belongs to this tree.
func (t procTree) containsAny(pids map[int]bool) bool {
	if len(pids) == 0 {
		return false
	}
	for _, pid := range t.PIDs {
		if pids[pid] {
			return true
		}
	}
	return false
}

// shortCmd is a compact human label for logs.
func shortCmd(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if len(cmd) > 120 {
		return cmd[:120] + "…"
	}
	return cmd
}
