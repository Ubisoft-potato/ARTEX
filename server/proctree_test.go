package server

import "testing"

func TestBuildProcTreesGroupsRootsAndOrphans(t *testing.T) {
	const self = 1000
	procs := []procInfo{
		{PID: self, PPID: 1, RSS: 50 << 20, StartTick: 1, Cmd: "artex"},
		// Tool chain: bash → python → chromium helpers.
		{PID: 2000, PPID: self, RSS: 10 << 20, CPUTicks: 5, StartTick: 10, Cmd: "bash -c python3 scan.py"},
		{PID: 2001, PPID: 2000, RSS: 800 << 20, CPUTicks: 100, StartTick: 11, Cmd: "python3 scan.py"},
		{PID: 2002, PPID: 2001, RSS: 300 << 20, CPUTicks: 20, StartTick: 12, Cmd: "chromium"},
		// Reparented nohup orphan: parent 1 is outside the cgroup.
		{PID: 3000, PPID: 1, RSS: 400 << 20, CPUTicks: 7, StartTick: 20, Cmd: "python3 daemon.py"},
		{PID: 3001, PPID: 3000, RSS: 100 << 20, CPUTicks: 3, StartTick: 21, Cmd: "chromium"},
		// Tiny one-shot helper.
		{PID: 4000, PPID: self, RSS: 2 << 20, StartTick: 30, Cmd: "grep"},
	}

	trees := buildProcTrees(procs, self)
	if len(trees) != 3 {
		t.Fatalf("got %d trees, want 3: %+v", len(trees), trees)
	}
	byRoot := map[int]procTree{}
	for _, tr := range trees {
		byRoot[tr.Root] = tr
	}
	if _, ok := byRoot[self]; ok {
		t.Fatal("self must never be a killable tree root")
	}

	tool := byRoot[2000]
	if len(tool.PIDs) != 3 || tool.RSS != 1110<<20 || tool.CPU != 125 {
		t.Fatalf("tool tree = %+v", tool)
	}
	if tool.Cmd != "bash -c python3 scan.py" || tool.StartTick != 10 {
		t.Fatalf("tool root metadata = %+v", tool)
	}

	orphan := byRoot[3000]
	if len(orphan.PIDs) != 2 || orphan.RSS != 500<<20 {
		t.Fatalf("orphan tree = %+v", orphan)
	}

	if trees[0].Starts[2001] != 11 {
		t.Fatalf("start ticks not captured: %+v", trees[0].Starts)
	}
}

func TestBuildProcTreesNeverEscapesASharedCgroup(t *testing.T) {
	// artex nested inside a session cgroup: sshd-session → shell → … → us.
	const self = 400
	procs := []procInfo{
		{PID: 100, PPID: 9, RSS: 1 << 30, StartTick: 1, Cmd: "sshd-session"},
		{PID: 200, PPID: 100, RSS: 1 << 30, StartTick: 2, Cmd: "desktop"},
		{PID: self, PPID: 200, RSS: 50 << 20, StartTick: 3, Cmd: "artex"},
		{PID: 401, PPID: self, RSS: 300 << 20, StartTick: 4, Cmd: "bash -c scan"},
		{PID: 402, PPID: 401, RSS: 200 << 20, StartTick: 5, Cmd: "python3 scan.py"},
	}
	trees := buildProcTrees(procs, self)
	if len(trees) != 1 || trees[0].Root != 401 {
		t.Fatalf("shared cgroup must only expose self's children, got %+v", trees)
	}
	for _, tr := range trees {
		if tr.Root == 100 || tr.Root == 200 || tr.Root == self {
			t.Fatalf("escaped into the session tree: %+v", tr)
		}
	}
}

func TestProcTreeContainsAny(t *testing.T) {
	tr := procTree{PIDs: []int{1, 2, 3}}
	if !tr.containsAny(map[int]bool{3: true}) {
		t.Fatal("expected membership")
	}
	if tr.containsAny(map[int]bool{9: true}) {
		t.Fatal("unexpected membership")
	}
	if tr.containsAny(nil) {
		t.Fatal("nil set must not match")
	}
}
