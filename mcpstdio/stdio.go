// Package mcpstdio is ARTEX's stdio MCP client.
//
// It is a fork of the SDK's stdio transport with one crucial difference: the
// child server is started in its OWN PROCESS GROUP and Close() tears the whole
// group down (SIGTERM → grace period → SIGKILL).
//
// Upstream only calls exec.Cmd.Process.Kill() on the direct child. For a server
// launched as `npx @playwright/mcp`, that child is the npm wrapper; the real
// server (node) and the headless Chromium it spawns keep running as orphans.
// They are not reaped by anything, each holds a few hundred MB, and over a day
// of multi-agent work they push the cgroup into swap until the whole VM locks
// up (the 2026-10-23 cgroup OOM and the 2026-10-27 hard freeze).
//
// The client also keeps the tail of the server's stderr for diagnostics and
// registers itself so a memory watchdog can reap idle servers under pressure.
package mcpstdio

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// ToolName mirrors mcp.ToolName so stdio tools share the mcp__server__tool
// naming scheme with the HTTP transports.
func ToolName(server, name string) string { return "mcp__" + server + "__" + name }

// --- JSON-RPC transport (same wire behaviour as the SDK) ---

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("mcp rpc error %d: %s", e.Code, e.Message) }

type conn struct {
	w       io.Writer
	mu      sync.Mutex
	nextID  int
	pending map[int]chan rpcResponse
	closeCh chan struct{}
	once    sync.Once
}

func newConn(r io.Reader, w io.Writer) *conn {
	c := &conn{w: w, pending: map[int]chan rpcResponse{}, closeCh: make(chan struct{})}
	go c.readLoop(r)
	return c
}

func (c *conn) readLoop(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var resp rpcResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			continue // notifications / non-response frames are ignored
		}
		if resp.ID == 0 {
			continue
		}
		c.mu.Lock()
		ch := c.pending[resp.ID]
		delete(c.pending, resp.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- resp
		}
	}
	c.once.Do(func() { close(c.closeCh) })
}

func (c *conn) notify(method string, params any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeLocked(rpcRequest{JSONRPC: "2.0", Method: method, Params: params})
}

func (c *conn) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	ch := make(chan rpcResponse, 1)
	c.pending[id] = ch
	err := c.writeLocked(rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeCh:
		return nil, fmt.Errorf("mcp: connection closed")
	case resp := <-ch:
		if resp.Error != nil {
			return nil, resp.Error
		}
		return resp.Result, nil
	}
}

func (c *conn) writeLocked(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = c.w.Write(data)
	return err
}

// --- client ---

// Client is a connection to one stdio MCP server.
type Client struct {
	server string
	conn   *conn
	cmd    *exec.Cmd
	stdin  io.Closer
	stderr *tailBuffer

	startedAt time.Time
	mu        sync.Mutex
	lastUsed  time.Time

	// readerDone closes once stdout reached EOF (output fully drained);
	// exited closes once the child has been waited for and reaped.
	readerDone chan struct{}
	exited     chan struct{}
	closeOnce  sync.Once
	closeErr   error
}

type remoteTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// NewStdioClient spawns an MCP server as a subprocess, performs the MCP
// handshake, and returns a connected Client. The server runs in its own process
// group; Close terminates the whole group. env is applied on top of the parent
// environment.
func NewStdioClient(ctx context.Context, server, command string, env map[string]string, args ...string) (*Client, error) {
	if command == "" {
		return nil, fmt.Errorf("stdio 传输缺少命令")
	}
	cmd := exec.Command(command, args...)
	if len(env) > 0 {
		cmd.Env = os.Environ()
		for k, v := range env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr := &tailBuffer{max: 16 << 10}
	cmd.Stderr = stderr
	// Give the child its own process group so Close can signal the descendants
	// (npm → node → Chromium) that would otherwise be orphaned by a plain Kill.
	configureProcess(cmd)

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &Client{
		server:     server,
		conn:       newConn(stdout, stdin),
		cmd:        cmd,
		stdin:      stdin,
		stderr:     stderr,
		startedAt:  time.Now(),
		lastUsed:   time.Now(),
		readerDone: make(chan struct{}),
		exited:     make(chan struct{}),
	}
	// Reap the child as soon as its output has been fully drained. Waiting here
	// (rather than never) is what keeps short-lived/leaked servers from turning
	// into zombies; waiting *after* the reader is done avoids losing buffered
	// output that exec.Cmd.Wait would otherwise discard.
	go func() {
		<-c.readerDone
		_ = cmd.Wait()
		close(c.exited)
	}()
	// readLoop owns stdout; tell the waiter when EOF is reached.
	go func() {
		<-c.conn.closeCh
		close(c.readerDone)
	}()

	register(c)
	if err := c.initialize(ctx); err != nil {
		c.Close()
		return nil, fmt.Errorf("mcp %s: %w%s", server, err, stderr.suffix())
	}
	log.Printf("[mcp] %s 已启动 (pid=%d, cmd=%s %v)", server, c.PID(), command, args)
	return c, nil
}

func (c *Client) initialize(ctx context.Context) error {
	_, err := c.conn.call(ctx, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "artex", "version": "1"},
	})
	if err != nil {
		return err
	}
	return c.conn.notify("notifications/initialized", map[string]any{})
}

// PID returns the server process id (also its process-group id).
func (c *Client) PID() int {
	if c == nil || c.cmd == nil || c.cmd.Process == nil {
		return 0
	}
	return c.cmd.Process.Pid
}

// Server is the configured MCP server name.
func (c *Client) Server() string { return c.server }

// Alive reports whether the server process is still running. The memory
// watchdog may reap an idle server mid-run; callers re-dial on the next call.
func (c *Client) Alive() bool {
	if c == nil {
		return false
	}
	select {
	case <-c.exited:
		return false
	default:
		return true
	}
}

// Tools lists the server's tools and adapts them to CoreTools.
func (c *Client) Tools(ctx context.Context) ([]actool.CoreTool, error) {
	c.touch()
	raw, err := c.conn.call(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var res struct {
		Tools []remoteTool `json:"tools"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	out := make([]actool.CoreTool, 0, len(res.Tools))
	for _, rt := range res.Tools {
		out = append(out, c.wrap(rt))
	}
	return out, nil
}

func (c *Client) wrap(rt remoteTool) actool.CoreTool {
	schema := rt.InputSchema
	if schema == nil {
		schema = map[string]any{"type": "object"}
	}
	full := ToolName(c.server, rt.Name)
	return actool.Build(actool.Spec{
		Name:        full,
		Description: rt.Description,
		Schema:      schema,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.AskUser("call MCP tool " + full + "?")
		},
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			c.touch()
			var args any
			if len(in) > 0 {
				_ = json.Unmarshal(in, &args)
			}
			raw, err := c.conn.call(ctx, "tools/call", map[string]any{"name": rt.Name, "arguments": args})
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			var res struct {
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
				IsError bool `json:"isError"`
			}
			if err := json.Unmarshal(raw, &res); err != nil {
				return actool.Errorf("Error: bad MCP response: " + err.Error()), nil
			}
			var text string
			for _, blk := range res.Content {
				text += blk.Text
			}
			return actool.Result{Content: []llm.ContentBlock{llm.TextBlock(actool.Capture(tc, text))}, IsError: res.IsError}, nil
		},
	})
}

// Close shuts down the server and every process it spawned. It is idempotent
// and safe to call from the memory watchdog while a call is in flight.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		unregister(c)
		if c.stdin != nil {
			_ = c.stdin.Close()
		}
		pid := c.PID()
		if pid <= 0 {
			return
		}
		// Politeness first: the server may flush state on SIGTERM. Then make
		// sure nothing in the group survives, including Chromium.
		terminateGroup(pid)
		select {
		case <-c.exited:
			return
		case <-time.After(1500 * time.Millisecond):
		}
		forceKillGroup(pid)
		select {
		case <-c.exited:
		case <-time.After(2 * time.Second):
			log.Printf("[mcp] %s (pid=%d) 关闭超时，进程组可能仍存活", c.server, pid)
		}
	})
	return c.closeErr
}

func (c *Client) touch() {
	c.mu.Lock()
	c.lastUsed = time.Now()
	c.mu.Unlock()
}

func (c *Client) lastUsedAt() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastUsed
}

// tailBuffer keeps the last max bytes written to it (child stderr).
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = b.buf[len(b.buf)-b.max:]
	}
	return len(p), nil
}

func (b *tailBuffer) suffix() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buf) == 0 {
		return ""
	}
	return "(stderr: " + string(b.buf) + ")"
}
