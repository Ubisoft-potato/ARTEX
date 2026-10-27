package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/mcp"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// lazyMCP exposes a stdio MCP server's tools from the cache WITHOUT starting the
// server. The process (npx → node → Chromium, easily 300 MB) is spawned on the
// first tool call and torn down by Close at the end of the run.
//
// This is the main memory fix for multi-agent runs: every planner/worker/main
// session used to spawn its own MCP+Chromium at start even when it never opened
// a page. With 7 concurrent agents that baseline alone reached ~2 GB, and one
// browser per active worker pushed the 5 GB cgroup into swap and froze the VM.
//
// If no tool list has ever been cached the caller falls back to connecting
// eagerly (connectMCP), which also populates the cache.
type lazyMCP struct {
	name    string
	cached  []db.MCPTool
	connect func(context.Context) (mcpClient, error)

	ensureMu sync.Mutex // serialises the first connect
	mu       sync.Mutex
	live     mcpClient
	tools    map[string]actool.CoreTool // full mcp__server__tool → live tool
	closed   bool
}

func newLazyMCP(name string, cached []db.MCPTool, connect func(context.Context) (mcpClient, error)) *lazyMCP {
	return &lazyMCP{name: name, cached: cached, connect: connect}
}

// connectMCPForRun returns a lazy stdio client when the server's tools are
// already cached, and an eagerly connected client otherwise (first run after
// install, or a non-stdio transport, which is cheap to dial). The lazy client's
// subprocess only starts if the agent actually calls one of its tools.
func connectMCPForRun(ctx context.Context, pg *db.DB, m *db.MCPServer) (mcpClient, error) {
	if m.Transport == "stdio" && pg != nil {
		if cached, err := pg.MCPToolsDetailed(m.ID); err == nil && len(cached) > 0 {
			srv := m
			return newLazyMCP(srv.Name, cached, func(c context.Context) (mcpClient, error) {
				return connectMCP(c, srv)
			}), nil
		}
	}
	return connectMCP(ctx, m)
}

// Tools builds the tool surface from the cache. No subprocess is started.
func (l *lazyMCP) Tools(context.Context) ([]actool.CoreTool, error) {
	out := make([]actool.CoreTool, 0, len(l.cached))
	for _, ct := range l.cached {
		ct := ct
		full := mcp.ToolName(l.name, ct.Name)
		schema := ct.Schema
		if len(schema) == 0 {
			schema = map[string]any{"type": "object"}
		}
		out = append(out, actool.Build(actool.Spec{
			Name:        full,
			Description: ct.Description,
			Schema:      schema,
			Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
				return permission.AskUser("call MCP tool " + full + "?")
			},
			Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
				t, err := l.resolve(ctx, full, ct.Name)
				if err != nil {
					return actool.Errorf("Error: " + err.Error()), nil
				}
				return t.Call(ctx, in, tc)
			},
		}))
	}
	return out, nil
}

// resolve returns the live tool, connecting the server on first use.
func (l *lazyMCP) resolve(ctx context.Context, full, short string) (actool.CoreTool, error) {
	tools, err := l.ensure(ctx)
	if err != nil {
		return nil, err
	}
	t := tools[full]
	if t == nil {
		// The cache can be stale (server upgraded/renamed its tools). Say so
		// clearly instead of a generic "unknown tool".
		return nil, fmt.Errorf("MCP 服务 %s 上已没有工具 %q（工具列表可能已变化，请重新发现该 MCP）", l.name, short)
	}
	return t, nil
}

func (l *lazyMCP) ensure(ctx context.Context) (map[string]actool.CoreTool, error) {
	l.dropDead()

	l.mu.Lock()
	tools, closed := l.tools, l.closed
	l.mu.Unlock()
	if tools != nil {
		return tools, nil
	}
	if closed {
		return nil, fmt.Errorf("MCP 服务 %s 已关闭", l.name)
	}

	l.ensureMu.Lock()
	defer l.ensureMu.Unlock()
	// Another goroutine may have connected while we waited for the lock.
	l.dropDead()
	l.mu.Lock()
	tools, closed = l.tools, l.closed
	l.mu.Unlock()
	if tools != nil {
		return tools, nil
	}
	if closed {
		return nil, fmt.Errorf("MCP 服务 %s 已关闭", l.name)
	}

	log.Printf("[mcp] %s 首次调用，按需启动 stdio 服务", l.name)
	cctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	cl, err := l.connect(cctx)
	if err != nil {
		return nil, fmt.Errorf("MCP 服务 %s 启动失败: %w", l.name, err)
	}
	ts, err := cl.Tools(cctx)
	if err != nil {
		_ = cl.Close()
		return nil, fmt.Errorf("MCP 服务 %s 工具列表失败: %w", l.name, err)
	}
	m := make(map[string]actool.CoreTool, len(ts))
	for _, t := range ts {
		m[t.Name()] = t
	}
	l.mu.Lock()
	if l.closed { // run ended while we were connecting
		l.mu.Unlock()
		_ = cl.Close()
		return nil, fmt.Errorf("MCP 服务 %s 已关闭", l.name)
	}
	l.live = cl
	l.tools = m
	l.mu.Unlock()
	return m, nil
}

// aliveChecker is implemented by mcpstdio.Client. A live client can be reaped
// by the memory watchdog while its run is still going; the next tool call must
// re-dial instead of reusing a dead connection.
type aliveChecker interface{ Alive() bool }

func (l *lazyMCP) dropDead() {
	l.mu.Lock()
	cl := l.live
	if cl == nil {
		l.mu.Unlock()
		return
	}
	a, ok := cl.(aliveChecker)
	if !ok || a.Alive() {
		l.mu.Unlock()
		return
	}
	l.live = nil
	l.tools = nil
	l.mu.Unlock()
	_ = cl.Close()
	log.Printf("[mcp] %s 的连接已被回收，下次调用将重新启动", l.name)
}

// Close terminates the server if it was started. Safe to call when it never
// was, and safe to call more than once.
func (l *lazyMCP) Close() error {
	l.mu.Lock()
	l.closed = true
	cl := l.live
	l.live = nil
	l.tools = nil
	l.mu.Unlock()
	if cl != nil {
		return cl.Close()
	}
	return nil
}
