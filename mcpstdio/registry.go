package mcpstdio

import (
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Info is a snapshot of one live MCP server for logging and diagnostics.
type Info struct {
	PID      int
	Server   string
	Command  string
	Started  time.Time
	LastUsed time.Time
	RSS      int64 // bytes, 0 when unavailable (non-Linux or already gone)
}

var (
	regMu sync.Mutex
	live  = map[*Client]struct{}{}
)

func register(c *Client) {
	regMu.Lock()
	live[c] = struct{}{}
	regMu.Unlock()
}

func unregister(c *Client) {
	regMu.Lock()
	delete(live, c)
	regMu.Unlock()
}

// Count reports how many MCP servers are currently running.
func Count() int {
	regMu.Lock()
	defer regMu.Unlock()
	return len(live)
}

// Live snapshots the running servers, oldest first.
func Live() []Info {
	regMu.Lock()
	clients := make([]*Client, 0, len(live))
	for c := range live {
		clients = append(clients, c)
	}
	regMu.Unlock()

	out := make([]Info, 0, len(clients))
	for _, c := range clients {
		pid := c.PID()
		out = append(out, Info{
			PID:      pid,
			Server:   c.server,
			Command:  commandLine(c),
			Started:  c.startedAt,
			LastUsed: c.lastUsedAt(),
			RSS:      processRSS(pid),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out
}

// TotalRSS is the summed RSS of all live MCP servers (their root processes;
// the watchdog's per-process view is enough to spot the big ones).
func TotalRSS() int64 {
	var n int64
	regMu.Lock()
	clients := make([]*Client, 0, len(live))
	for c := range live {
		clients = append(clients, c)
	}
	regMu.Unlock()
	for _, c := range clients {
		n += processRSS(c.PID())
	}
	return n
}

// CloseIdle terminates servers that have not served a tool call for olderThan.
// Used by the memory watchdog: an idle server is, by definition, not doing work
// for any agent, so reaping it cannot interrupt a task mid-call. Returns the
// number of servers closed.
func CloseIdle(olderThan time.Duration) int {
	regMu.Lock()
	var victims []*Client
	for c := range live {
		if time.Since(c.lastUsedAt()) >= olderThan {
			victims = append(victims, c)
		}
	}
	regMu.Unlock()

	for _, c := range victims {
		idle := time.Since(c.lastUsedAt()).Truncate(time.Second)
		log.Printf("[mcp] 回收空闲 MCP: %s pid=%d 已空闲 %s", c.server, c.PID(), idle)
		_ = c.Close()
	}
	return len(victims)
}

// KillAll terminates every live server and its process tree. Called on shutdown
// so a non-systemd launch (start.sh) cannot leave MCP/Chromium orphans behind.
func KillAll() int {
	regMu.Lock()
	clients := make([]*Client, 0, len(live))
	for c := range live {
		clients = append(clients, c)
	}
	regMu.Unlock()
	for _, c := range clients {
		_ = c.Close()
	}
	if len(clients) > 0 {
		log.Printf("[mcp] 已清理 %d 个 MCP 子进程组", len(clients))
	}
	return len(clients)
}

func commandLine(c *Client) string {
	if c == nil || c.cmd == nil {
		return ""
	}
	return strings.Join(c.cmd.Args, " ")
}

// processRSS reads VmRSS for pid on Linux; returns 0 elsewhere.
func processRSS(pid int) int64 {
	if pid <= 0 {
		return 0
	}
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
