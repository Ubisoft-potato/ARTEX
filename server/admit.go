package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Autumn-27/artex/mcpstdio"
	actool "github.com/Autumn-27/norma/tool"
)

// Admission control: the memory guard is reactive (a 20s watchdog). Before a
// process is spawned we also need an up-front check, otherwise an agent can
// launch Chromium into a cgroup that is already at 90% and hit the 4 GB hard
// limit before the next watchdog tick — the cgroup OOM then makes systemd tear
// the whole service down (OOMPolicy=kill + Restart=on-failure).
//
// Policy (default on):
//   - spawning any stdio MCP needs 256 MB cgroup headroom;
//   - invoking its first browser tool (which launches Chromium) needs 600 MB;
//   - if short, synchronously reap idle trees, wait up to 30 s, check again,
//     and only then refuse the call with a retryable tool error.
//
// Disable with ARTEX_MEMGUARD_ADMIT=off (ARTEX_MEMGUARD=off disables both the
// watchdog and admission).
const (
	admitSpawnHeadroom   = int64(256 << 20)
	admitToolHeadroom    = int64(256 << 20)
	admitBrowserHeadroom = int64(600 << 20)
	admitMinAvailable    = int64(768 << 20)
	admitWaitMax         = 30 * time.Second
	admitPoll            = 2 * time.Second
)

func admissionEnabled() bool {
	if strings.EqualFold(os.Getenv("ARTEX_MEMGUARD"), "off") {
		return false
	}
	if strings.EqualFold(os.Getenv("ARTEX_MEMGUARD_ADMIT"), "off") {
		return false
	}
	return true
}

// admissionApplies reports whether this MCP tool needs the pre-call check.
// browser_close always passes: it frees memory, so blocking it would be
// counter-productive.
func admissionApplies(server, tool string) bool {
	return !(server == "browser" && tool == "browser_close")
}

// admitStdioSpawn gates spawning a stdio MCP process. No waiting: an MCP
// server that cannot start now will be retried by the next tool call.
func admitStdioSpawn() error {
	if !admissionEnabled() || admissionOK(admitSpawnHeadroom) {
		return nil
	}
	reclaimed := reapIdleNow(15 * time.Minute)
	if admissionOK(admitSpawnHeadroom) {
		log.Printf("[memguard] 准入检查: 已回收 %d 个空闲进程，允许启动 MCP", reclaimed)
		return nil
	}
	reclaimed += reapIdleNow(5 * time.Minute)
	if admissionOK(admitSpawnHeadroom) {
		log.Printf("[memguard] 准入检查: 已回收 %d 个空闲进程，允许启动 MCP", reclaimed)
		return nil
	}
	used, limit, avail, cgOK, availOK := memorySnapshot()
	err := fmt.Errorf("内存不足，暂不启动 MCP 服务（需要约 %s 余量；%s）；已回收 %d 个空闲进程，请稍后重试",
		humanMem(admitSpawnHeadroom), memAdmissionDesc(used, limit, avail, cgOK, availOK), reclaimed)
	log.Printf("[memguard] %s", err)
	return err
}

// admitToolCall gates one tool call on an MCP server. The browser's first page
// operation is the expensive one (Chromium ~300–500 MB), so it gets a larger
// headroom requirement and the wait-and-retry treatment.
func admitToolCall(ctx context.Context, server, tool string) error {
	if !admissionEnabled() || !admissionApplies(server, tool) {
		return nil
	}
	need := admitToolHeadroom
	if server == "browser" && !browserRunning() {
		need = admitBrowserHeadroom
	}
	if admissionOK(need) {
		return nil
	}

	reclaimed := reapIdleNow(5 * time.Minute)
	if reclaimed > 0 {
		log.Printf("[memguard] 准入检查: 为 %s/%s 回收了 %d 个空闲进程", server, tool, reclaimed)
	}
	deadline := time.Now().Add(admitWaitMax)
	for {
		if admissionOK(need) {
			return nil
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			break
		}
		if remain > admitPoll {
			remain = admitPoll
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(remain):
		}
		reapIdleNow(5 * time.Minute)
	}

	used, limit, avail, cgOK, availOK := memorySnapshot()
	err := fmt.Errorf("内存不足，暂不执行 %s/%s（需要约 %s 余量；%s）；已回收空闲进程并等待 %s，请稍后重试",
		server, tool, humanMem(need), memAdmissionDesc(used, limit, avail, cgOK, availOK), admitWaitMax)
	log.Printf("[memguard] %s", err)
	return err
}

func admissionOK(need int64) bool {
	used, limit, avail, cgOK, availOK := memorySnapshot()
	return headroomOK(used, limit, avail, cgOK, availOK, need)
}

func memorySnapshot() (used, limit, avail int64, cgOK, availOK bool) {
	used, limit, cgOK = cgroupMemory()
	avail, availOK = memAvailable()
	return used, limit, avail, cgOK, availOK
}

// headroomOK is the pure decision function: the cgroup must keep `need` bytes
// free, and the VM must not be below the emergency floor. When there is no
// cgroup limit, MemAvailable has to cover both.
func headroomOK(used, limit, avail int64, cgOK, availOK bool, need int64) bool {
	if cgOK && limit > 0 && limit-used < need {
		return false
	}
	if availOK {
		floor := admitMinAvailable
		if !cgOK {
			floor += need
		}
		if avail < floor {
			return false
		}
	}
	return true
}

func memAdmissionDesc(used, limit, avail int64, cgOK, availOK bool) string {
	parts := make([]string, 0, 2)
	if cgOK && limit > 0 {
		head := limit - used
		if head < 0 {
			head = 0
		}
		parts = append(parts, fmt.Sprintf("cgroup %s/%s，余量 %s", humanMem(used), humanMem(limit), humanMem(head)))
	}
	if availOK {
		parts = append(parts, "系统可用 "+humanMem(avail))
	}
	if len(parts) == 0 {
		return "内存状态未知"
	}
	return strings.Join(parts, "，")
}

// browserRunning reports whether the browser MCP already has a Chromium child.
// If it does, a normal tool call is cheap and only needs the base headroom.
func browserRunning() bool {
	roots := make(map[int]bool)
	for _, in := range mcpstdio.Live() {
		if in.Server == "browser" {
			roots[in.PID] = true
		}
	}
	if len(roots) == 0 {
		return false
	}
	for _, t := range scanCgroupTrees() {
		if !t.containsAny(roots) {
			continue
		}
		for _, pid := range t.PIDs {
			p, ok := readProcInfo(pid)
			if !ok {
				continue
			}
			c := strings.ToLower(p.Cmd)
			if strings.Contains(c, "chrome") || strings.Contains(c, "chromium") {
				return true
			}
		}
	}
	return false
}

// reapIdleNow synchronously closes idle MCP clients and kills idle heavy
// process trees. It shares the watchdog's idle history, so a tree that is
// actively burning CPU is never selected.
func reapIdleNow(minIdle time.Duration) int {
	n := mcpstdio.CloseIdle(minIdle)
	_, generic := splitMCPTrees(scanCgroupTrees())
	now := time.Now()
	for _, t := range globalMemGuard.pick(generic, memguardTreeMinRSS(), minIdle, now) {
		log.Printf("[memguard] 准入回收 cgroup 进程树: pid=%d 进程=%d rss=%s 空闲=%s cmd=%q",
			t.Root, len(t.PIDs), humanMem(t.RSS),
			globalMemGuard.idle(t, now).Truncate(time.Second), shortCmd(t.Cmd))
		if killProcTrees([]procTree{t}, 1500*time.Millisecond) > 0 {
			n++
		}
	}
	return n
}

// --- tool-call wrappers for eagerly connected stdio clients ---

// admittedClient applies the admission check to tools of a stdio MCP client
// that was connected eagerly (no cached tool list yet). Lazy clients do the
// check inside their own proxy (server/lazymcp.go).
type admittedClient struct {
	mcpClient
	name string
}

func (c admittedClient) Tools(ctx context.Context) ([]actool.CoreTool, error) {
	ts, err := c.mcpClient.Tools(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]actool.CoreTool, len(ts))
	for i, t := range ts {
		out[i] = admittedTool{CoreTool: t, server: c.name, tool: shortToolName(t.Name())}
	}
	return out, nil
}

type admittedTool struct {
	actool.CoreTool
	server string
	tool   string
}

func (a admittedTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	if err := admitToolCall(ctx, a.server, a.tool); err != nil {
		return actool.Errorf("Error: " + err.Error()), nil
	}
	return a.CoreTool.Call(ctx, in, tc)
}

func shortToolName(full string) string {
	if i := strings.LastIndex(full, "__"); i >= 0 {
		return full[i+2:]
	}
	return full
}
