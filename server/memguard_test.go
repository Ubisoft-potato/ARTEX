package server

import (
	"testing"
	"time"
)

func TestMemGuardIdleTracksCPUActivity(t *testing.T) {
	now := time.Now()
	g := newMemGuard()
	big := procTree{Root: 10, StartTick: 1, PIDs: []int{10}, Starts: map[int]uint64{10: 1}, RSS: 1 << 30, CPU: 100}
	small := procTree{Root: 20, StartTick: 2, PIDs: []int{20}, Starts: map[int]uint64{20: 2}, RSS: 10 << 20, CPU: 100}
	g.observe([]procTree{big, small}, now)

	if got := g.pick([]procTree{big, small}, 200<<20, time.Minute, now); len(got) != 0 {
		t.Fatalf("fresh trees must not be picked: %+v", got)
	}

	later := now.Add(10 * time.Minute)
	g.observe([]procTree{big, small}, later) // no CPU delta → idle
	got := g.pick([]procTree{big, small}, 200<<20, 5*time.Minute, later)
	if len(got) != 1 || got[0].Root != 10 {
		t.Fatalf("pick = %+v, want only the 1G tree", got)
	}

	// Burning CPU makes it active again.
	burning := big
	burning.CPU = 200
	burningAt := later.Add(6 * time.Minute)
	g.observe([]procTree{burning, small}, burningAt)
	if got := g.pick([]procTree{burning, small}, 200<<20, 5*time.Minute, burningAt); len(got) != 0 {
		t.Fatalf("active tree picked: %+v", got)
	}
}

func TestMemGuardHeaviestIgnoresIdleButHonoursFloor(t *testing.T) {
	g := newMemGuard()
	a := procTree{Root: 1, StartTick: 1, RSS: 900 << 20}
	b := procTree{Root: 2, StartTick: 1, RSS: 300 << 20}
	c := procTree{Root: 3, StartTick: 1, RSS: 50 << 20}
	got := g.heaviest([]procTree{a, b, c}, 200<<20, 5)
	if len(got) != 2 || got[0].Root != 1 || got[1].Root != 2 {
		t.Fatalf("heaviest = %+v", got)
	}
	if limited := g.heaviest([]procTree{a, b, c}, 200<<20, 1); len(limited) != 1 || limited[0].Root != 1 {
		t.Fatalf("limit = %+v", limited)
	}
}

func TestMemGuardTreeFloorEnv(t *testing.T) {
	t.Setenv("ARTEX_MEMGUARD_TREE_MB", "512")
	if got := memguardTreeMinRSS(); got != 512<<20 {
		t.Fatalf("floor = %d", got)
	}
	t.Setenv("ARTEX_MEMGUARD_TREE_MB", "bogus")
	if got := memguardTreeMinRSS(); got != defaultTreeMinRSS {
		t.Fatalf("fallback = %d", got)
	}
}

func TestMemGuardObservePrunesVanishedTrees(t *testing.T) {
	g := newMemGuard()
	tr := procTree{Root: 7, StartTick: 7, RSS: 1 << 30}
	g.observe([]procTree{tr}, time.Now())
	if len(g.lastCPU) != 1 {
		t.Fatalf("state size = %d", len(g.lastCPU))
	}
	g.observe(nil, time.Now())
	if len(g.lastCPU) != 0 || len(g.lastActive) != 0 {
		t.Fatalf("state not pruned: %d/%d", len(g.lastCPU), len(g.lastActive))
	}
}
