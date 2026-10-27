package server

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/mcpstdio"
)

// Memory guard thresholds. The 2026-10-27 freeze happened because nothing was
// watching the cgroup: artex sat at its 5 GB MemoryMax while the desktop and
// Postgres competed for the remaining 2.8 GB, the 1 GB swap (on a virtual IDE
// disk) started thrashing, and the whole VM locked up before the OOM killer
// could produce a log line.
const (
	memWarnRatio = 0.75 // log only
	memReapRatio = 0.85 // drop long-idle MCP servers and process trees
	memHardRatio = 0.93 // escalate: drop idle >1 min, then the largest trees

	memAvailableLow  = 1 << 30 // 1 GiB free on the host → same as 85 %
	memAvailableCrit = 512 << 20

	// defaultTreeMinRSS ignores tiny helpers (grep/head/sleep) while keeping
	// anything that can plausibly push the box into swap in scope.
	defaultTreeMinRSS = 200 << 20
)

// watchMemoryPressure is a last-resort safety valve over the WHOLE service
// cgroup. It tracks every process tree under artex — not just MCP servers:
// agent Bash/custom-tool children (python, Chromium launched by a script,
// scanners, …) are included too.
//
// It never allocates work and never touches artex itself. Under pressure it
// sends SIGTERM/SIGKILL to the selected process trees (recycling protection:
// PID + kernel start tick must match). MCP servers are separated out so the
// lazy client can re-dial them on the next call.
//
// Disable with ARTEX_MEMGUARD=off; tune the tree-size floor with
// ARTEX_MEMGUARD_TREE_MB (default 200).
func (s *Server) watchMemoryPressure() {
	if strings.EqualFold(os.Getenv("ARTEX_MEMGUARD"), "off") {
		log.Printf("[memguard] 已禁用 (ARTEX_MEMGUARD=off)")
		return
	}
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	minTreeRSS := memguardTreeMinRSS()
	if used, limit, ok := cgroupMemory(); ok {
		log.Printf("[memguard] 已启用: cgroup %s/%s, 覆盖 MCP 与 agent 子进程树(≥%s), 75%% 告警 / 85%% 回收长期空闲 / 93%% 分级强制回收",
			humanMem(used), humanMem(limit), humanMem(minTreeRSS))
	} else {
		log.Printf("[memguard] 已启用: 无数值型 cgroup 限制，按系统可用内存判定")
	}

	guard := newMemGuard()
	var lastReport time.Time
	var hardTicks int
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}

		now := time.Now()
		// Track activity on every tick, not only under pressure, otherwise
		// every tree would look "just started" when memory first gets tight.
		all := scanCgroupTrees()
		mcpTrees, generic := splitMCPTrees(all)
		guard.observe(generic, now)

		used, limit, cgOK := cgroupMemory()
		avail, availOK := memAvailable()
		ratio := 0.0
		if cgOK && limit > 0 {
			ratio = float64(used) / float64(limit)
		}
		lowMem := availOK && avail < memAvailableLow
		if !(cgOK && ratio >= memWarnRatio) && !lowMem {
			hardTicks = 0
			continue
		}

		critical := (cgOK && ratio >= memHardRatio) || (availOK && avail < memAvailableCrit)
		var victims []procTree
		mcpReaped, treeReaped := 0, 0
		switch {
		case critical:
			// Emergency brake. First drop servers/trees idle for over a minute;
			// if the very next tick is still critical, escalate to the largest
			// trees regardless of idleness (killing only as many as needed).
			hardTicks++
			if hardTicks == 1 {
				mcpReaped = mcpstdio.CloseIdle(time.Minute)
				victims = guard.pick(generic, minTreeRSS, time.Minute, now)
			} else {
				mcpReaped = mcpstdio.CloseIdle(0)
				victims = guard.heaviest(generic, minTreeRSS, 3)
			}
		case (cgOK && ratio >= memReapRatio) || lowMem:
			// An agent thinking between tool calls can be idle for minutes;
			// only truly abandoned work (15 min without CPU) goes here.
			hardTicks = 0
			mcpReaped = mcpstdio.CloseIdle(15 * time.Minute)
			victims = guard.pick(generic, minTreeRSS, 15*time.Minute, now)
		default:
			hardTicks = 0
		}

		for _, t := range victims {
			log.Printf("[memguard] 回收 cgroup 进程树: pid=%d 进程=%d rss=%s 空闲=%s cmd=%q",
				t.Root, len(t.PIDs), humanMem(t.RSS),
				guard.idle(t, now).Truncate(time.Second), shortCmd(t.Cmd))
			if killProcTrees([]procTree{t}, 1500*time.Millisecond) > 0 {
				treeReaped++
			}
			if critical && hardTicks >= 2 {
				// Stop as soon as the cgroup is back to a safe band.
				time.Sleep(300 * time.Millisecond)
				if u, l, ok := cgroupMemory(); ok && l > 0 && float64(u)/float64(l) < 0.90 {
					break
				}
			}
		}
		if mcpReaped > 0 || treeReaped > 0 {
			debug.FreeOSMemory()
		}
		if mcpReaped == 0 && treeReaped == 0 && time.Since(lastReport) < time.Minute {
			continue
		}
		lastReport = now

		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		heavy, heavyRSS := 0, int64(0)
		for _, t := range generic {
			if t.RSS >= minTreeRSS {
				heavy++
				heavyRSS += t.RSS
			}
		}
		mcpRSS := int64(0)
		for _, t := range mcpTrees {
			mcpRSS += t.RSS
		}
		log.Printf("[memguard] %s%s MCP %d 个/%s, 其他重进程 %d 个/%s, Go heap %s, 回收 MCP %d + 进程树 %d",
			cgroupDesc(cgOK, used, limit, ratio),
			availDesc(availOK, avail),
			len(mcpTrees), humanMem(mcpRSS), heavy, humanMem(heavyRSS),
			humanMem(int64(ms.HeapAlloc)), mcpReaped, treeReaped)
		for _, c := range topConsumers(mcpTrees, generic, minTreeRSS, guard, now, 3) {
			log.Printf("[memguard]   最大: %s pid=%d rss=%s 空闲=%s",
				c.name, c.pid, humanMem(c.rss), c.idle.Truncate(time.Second))
		}
	}
}

// --- cgroup process-tree scanning ---

// scanCgroupTrees snapshots the service cgroup and groups it into killable
// trees (direct children of artex, plus reparented orphans).
func scanCgroupTrees() []procTree {
	pids := cgroupProcs()
	if len(pids) == 0 {
		return nil
	}
	procs := make([]procInfo, 0, len(pids))
	for _, pid := range pids {
		if pi, ok := readProcInfo(pid); ok {
			procs = append(procs, pi)
		}
	}
	return buildProcTrees(procs, os.Getpid())
}

// splitMCPTrees separates trees owned by a live MCP client (handled by
// mcpstdio, which can re-dial lazily) from everything else.
func splitMCPTrees(all []procTree) (mcp, generic []procTree) {
	roots := make(map[int]bool)
	for _, in := range mcpstdio.Live() {
		roots[in.PID] = true
	}
	for _, t := range all {
		if t.containsAny(roots) {
			mcp = append(mcp, t)
			continue
		}
		generic = append(generic, t)
	}
	return mcp, generic
}

// --- idle/CPU tracking ---

type memGuard struct {
	lastCPU    map[string]uint64
	lastActive map[string]time.Time
}

func newMemGuard() *memGuard {
	return &memGuard{lastCPU: map[string]uint64{}, lastActive: map[string]time.Time{}}
}

func treeKey(t procTree) string {
	return strconv.Itoa(t.Root) + ":" + strconv.FormatUint(t.StartTick, 10)
}

// observe updates last-active for each tree from its CPU-time delta. A tree is
// "idle" when it has burned no CPU since the previous tick (spawning/blocking
// on the network for a long time counts as idle, which is what we want under
// memory pressure).
func (g *memGuard) observe(trees []procTree, now time.Time) {
	seen := make(map[string]bool, len(trees))
	for _, t := range trees {
		k := treeKey(t)
		seen[k] = true
		prev, ok := g.lastCPU[k]
		if !ok || t.CPU > prev {
			g.lastActive[k] = now
		}
		g.lastCPU[k] = t.CPU
	}
	for k := range g.lastCPU {
		if !seen[k] {
			delete(g.lastCPU, k)
			delete(g.lastActive, k)
		}
	}
}

func (g *memGuard) idle(t procTree, now time.Time) time.Duration {
	if at, ok := g.lastActive[treeKey(t)]; ok {
		return now.Sub(at)
	}
	return 0
}

// pick returns heavy trees idle for at least idleFor, heaviest first.
func (g *memGuard) pick(trees []procTree, minRSS int64, idleFor time.Duration, now time.Time) []procTree {
	var out []procTree
	for _, t := range trees {
		if t.RSS < minRSS {
			continue
		}
		if idleFor > 0 && g.idle(t, now) < idleFor {
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RSS > out[j].RSS })
	return out
}

// heaviest returns the n largest heavy trees regardless of idleness.
func (g *memGuard) heaviest(trees []procTree, minRSS int64, n int) []procTree {
	out := make([]procTree, 0, len(trees))
	for _, t := range trees {
		if t.RSS >= minRSS {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RSS > out[j].RSS })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// --- logging helpers ---

type memConsumer struct {
	name string
	pid  int
	rss  int64
	idle time.Duration
}

func topConsumers(mcpTrees, generic []procTree, minRSS int64, g *memGuard, now time.Time, n int) []memConsumer {
	infos := make(map[int]mcpstdio.Info)
	for _, in := range mcpstdio.Live() {
		infos[in.PID] = in
	}
	out := make([]memConsumer, 0, len(mcpTrees)+len(generic))
	for _, t := range mcpTrees {
		name, idle := "MCP", time.Duration(0)
		if in, ok := infos[t.Root]; ok {
			name = "MCP:" + in.Server
			idle = now.Sub(in.LastUsed)
		}
		out = append(out, memConsumer{name: name, pid: t.Root, rss: t.RSS, idle: idle})
	}
	for _, t := range generic {
		if t.RSS < minRSS {
			continue
		}
		out = append(out, memConsumer{
			name: "cgroup:" + shortCmd(t.Cmd),
			pid:  t.Root,
			rss:  t.RSS,
			idle: g.idle(t, now),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rss > out[j].rss })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func memguardTreeMinRSS() int64 {
	v := strings.TrimSpace(os.Getenv("ARTEX_MEMGUARD_TREE_MB"))
	if v == "" {
		return defaultTreeMinRSS
	}
	mb, err := strconv.ParseFloat(v, 64)
	if err != nil || mb <= 0 {
		return defaultTreeMinRSS
	}
	return int64(mb * float64(1<<20))
}

func cgroupDesc(ok bool, used, limit int64, ratio float64) string {
	if !ok {
		return ""
	}
	return "cgroup " + humanMem(used) + "/" + humanMem(limit) +
		" (" + strconv.Itoa(int(ratio*100)) + "%)"
}

func availDesc(ok bool, avail int64) string {
	if !ok {
		return ""
	}
	return " 可用 " + humanMem(avail)
}

// cgroupPath resolves this process's cgroup v2 directory.
func cgroupPath() (string, bool) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			rel := strings.TrimSpace(strings.TrimPrefix(line, "0::"))
			if rel == "" {
				return "", false
			}
			return filepath.Join("/sys/fs/cgroup", rel), true
		}
	}
	return "", false
}

// cgroupMemory reads this process's cgroup v2 usage/limit.
func cgroupMemory() (used, limit int64, ok bool) {
	base, ok := cgroupPath()
	if !ok {
		return 0, 0, false
	}
	if b, err := os.ReadFile(filepath.Join(base, "memory.current")); err == nil {
		used, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	} else {
		return 0, 0, false
	}
	b, err := os.ReadFile(filepath.Join(base, "memory.max"))
	if err != nil {
		return 0, 0, false
	}
	s := strings.TrimSpace(string(b))
	if s == "" || s == "max" {
		return 0, 0, false
	}
	limit, _ = strconv.ParseInt(s, 10, 64)
	return used, limit, limit > 0
}

// memAvailable reads the kernel's free-memory estimate for the whole VM.
func memAvailable() (int64, bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 {
			if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				return kb * 1024, true
			}
		}
	}
	return 0, false
}

func humanMem(n int64) string {
	const (
		mib = 1 << 20
		gib = 1 << 30
	)
	if n >= gib {
		return strconv.FormatFloat(float64(n)/float64(gib), 'f', 1, 64) + "G"
	}
	return strconv.FormatInt(n/mib, 10) + "M"
}
