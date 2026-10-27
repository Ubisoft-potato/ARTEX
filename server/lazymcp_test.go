package server

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

type fakeMCPClient struct {
	tools  []actool.CoreTool
	closed atomic.Bool
}

func (f *fakeMCPClient) Tools(context.Context) ([]actool.CoreTool, error) { return f.tools, nil }
func (f *fakeMCPClient) Close() error {
	f.closed.Store(true)
	return nil
}

func TestLazyMCPDefersSpawnUntilFirstCall(t *testing.T) {
	var connects int32
	live := &fakeMCPClient{tools: []actool.CoreTool{actool.Build(actool.Spec{
		Name:        "mcp__browser__navigate",
		Description: "navigate",
		Schema:      map[string]any{"type": "object"},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Text("ok"), nil
		},
	})}}
	l := newLazyMCP("browser", []db.MCPTool{{
		Name: "navigate", Description: "navigate", Schema: map[string]any{"type": "object"},
	}}, func(context.Context) (mcpClient, error) {
		atomic.AddInt32(&connects, 1)
		return live, nil
	})

	tools, err := l.Tools(context.Background())
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name() != "mcp__browser__navigate" {
		t.Fatalf("unexpected tools: %+v", tools)
	}
	if got := atomic.LoadInt32(&connects); got != 0 {
		t.Fatalf("Tools() spawned the server (%d connects); it must stay lazy", got)
	}

	res, err := tools[0].Call(context.Background(), json.RawMessage(`{"x":"1"}`), &actool.ToolContext{})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got := res.Flatten(); got != "ok" {
		t.Fatalf("call result = %q, want ok", got)
	}
	if got := atomic.LoadInt32(&connects); got != 1 {
		t.Fatalf("connects = %d, want 1", got)
	}

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !live.closed.Load() {
		t.Fatal("Close did not close the live client")
	}
}

func TestLazyMCPConnectsOnceUnderConcurrency(t *testing.T) {
	var connects int32
	live := &fakeMCPClient{tools: []actool.CoreTool{actool.Build(actool.Spec{
		Name:        "mcp__browser__navigate",
		Description: "navigate",
		Schema:      map[string]any{"type": "object"},
		Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Text("ok"), nil
		},
	})}}
	l := newLazyMCP("browser", []db.MCPTool{{Name: "navigate"}},
		func(context.Context) (mcpClient, error) {
			atomic.AddInt32(&connects, 1)
			return live, nil
		})

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := l.resolve(context.Background(), "mcp__browser__navigate", "navigate"); err != nil {
				t.Errorf("resolve: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt32(&connects); got != 1 {
		t.Fatalf("connects = %d, want 1", got)
	}
	_ = l.Close()
}

func TestLazyMCPReconnectsAfterWatchdogReapsClient(t *testing.T) {
	newClient := func() *reapableClient {
		c := &reapableClient{}
		c.alive.Store(true)
		c.tools = []actool.CoreTool{actool.Build(actool.Spec{
			Name:        "mcp__browser__navigate",
			Description: "navigate",
			Schema:      map[string]any{"type": "object"},
			Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
				return actool.Text("ok"), nil
			},
		})}
		return c
	}
	first, second := newClient(), newClient()
	var connectCount int32
	l := newLazyMCP("browser", []db.MCPTool{{Name: "navigate"}},
		func(context.Context) (mcpClient, error) {
			if atomic.AddInt32(&connectCount, 1) == 1 {
				return first, nil
			}
			return second, nil
		})

	if _, err := l.resolve(context.Background(), "mcp__browser__navigate", "navigate"); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	first.alive.Store(false) // simulated memory-guard reap
	if _, err := l.resolve(context.Background(), "mcp__browser__navigate", "navigate"); err != nil {
		t.Fatalf("resolve after reap: %v", err)
	}
	if got := atomic.LoadInt32(&connectCount); got != 2 {
		t.Fatalf("connect count = %d, want 2 (must re-dial after a reap)", got)
	}
	_ = l.Close()
}

type reapableClient struct {
	fakeMCPClient
	alive atomic.Bool
}

func (f *reapableClient) Alive() bool { return f.alive.Load() }

func TestLazyMCPClosedRunDoesNotLeakClient(t *testing.T) {
	live := &fakeMCPClient{}
	l := newLazyMCP("browser", []db.MCPTool{{Name: "navigate"}},
		func(context.Context) (mcpClient, error) { return live, nil })
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := l.resolve(context.Background(), "mcp__browser__navigate", "navigate"); err == nil {
		t.Fatal("resolve on a closed run must fail")
	}
}
