//go:build !windows

package mcpstdio

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeServer is a minimal newline-delimited JSON-RPC MCP server. It spawns a
// long-lived grandchild (standing in for Chromium) and records its pid, so the
// test can prove Close() kills the whole process tree rather than the wrapper.
const fakeServer = `#!/bin/sh
sleep 300 &
echo "$!" > "$GRANDCHILD_FILE"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"fake","version":"1"}}}\n' "$id" ;;
    *'"method":"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"ping","description":"ping tool","inputSchema":{"type":"object","properties":{"x":{"type":"string"}}}}]}}\n' "$id" ;;
  esac
done
`

func TestStdioClientHandshakeAndGroupTeardown(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-mcp.sh")
	if err := os.WriteFile(script, []byte(fakeServer), 0o755); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(dir, "grandchild.pid")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := NewStdioClient(ctx, "fake", "/bin/sh", map[string]string{"GRANDCHILD_FILE": pidFile}, script)
	if err != nil {
		t.Fatalf("NewStdioClient: %v", err)
	}
	if c.PID() <= 0 {
		t.Fatal("server has no pid")
	}
	if Count() != 1 {
		t.Fatalf("live registry count = %d, want 1", Count())
	}

	tools, err := c.Tools(ctx)
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name() != "mcp__fake__ping" {
		t.Fatalf("unexpected tools: %+v", tools)
	}

	gpid := waitPIDFile(t, pidFile)
	if gpid <= 0 {
		t.Fatal("fake server did not report a grandchild pid")
	}
	if err := syscall.Kill(gpid, 0); err != nil {
		t.Fatalf("grandchild %d not running before Close: %v", gpid, err)
	}

	start := time.Now()
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	waitGone(t, gpid)
	waitGone(t, c.PID())
	if Count() != 0 {
		t.Fatalf("live registry count = %d after Close, want 0", Count())
	}
	t.Logf("teardown took %s", time.Since(start).Truncate(time.Millisecond))
}

func TestCloseIdleReapsOnlyIdleServers(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-mcp.sh")
	if err := os.WriteFile(script, []byte(fakeServer), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	start := func(name string) *Client {
		c, err := NewStdioClient(ctx, name, "/bin/sh", map[string]string{"GRANDCHILD_FILE": filepath.Join(dir, name+".pid")}, script)
		if err != nil {
			t.Fatalf("start %s: %v", name, err)
		}
		return c
	}
	idle := start("idle")
	active := start("active")
	defer active.Close()
	// Make idleness explicit: `idle` last served an hour ago, `active` just now.
	idle.mu.Lock()
	idle.lastUsed = time.Now().Add(-time.Hour)
	idle.mu.Unlock()
	active.touch()

	if n := CloseIdle(2 * time.Minute); n != 1 {
		t.Fatalf("CloseIdle closed %d servers, want 1", n)
	}
	if Count() != 1 {
		t.Fatalf("live registry count = %d, want 1 (active must survive)", Count())
	}
	waitGone(t, idle.PID())
}

func waitPIDFile(t *testing.T, path string) int {
	t.Helper()
	for i := 0; i < 100; i++ {
		if b, err := os.ReadFile(path); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return 0
}

func waitGone(t *testing.T, pid int) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("process %d survived teardown", pid)
}
