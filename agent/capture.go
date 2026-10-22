package agent

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/sidequestion"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// captureRun drives one agent turn-to-completion over Session.Prompt and emits a
// coalesced ActivityRecord per execution step (tool_use / tool_result / text /
// thinking / result). It is shared by every LLM agent in the system (worker,
// planner, …) so their execution is visible instead of a black box — the old
// agentcore.Run discarded every event. The emitted records carry only
// Kind/Tool/ToolUseID/IsError/Summary/Detail; the caller's emit fills in
// IntentID/Worker. Returns the final assistant text + terminal error.
//
// KindText/KindThinking arrive as streaming deltas (one event per fragment); a
// contiguous run is coalesced into a single record so the trace shows whole
// messages, not dozens of fragments.
func captureRun(ctx context.Context, opts agentcore.Options, input string, emit func(db.Activity)) (string, harness.TerminalReason, error) {
	s := agentcore.NewSession(opts)
	defer s.Close() // release the session's background-task manager (temp dir + processes)
	return captureRunSession(ctx, s, input, emit)
}

// captureRunSession is captureRun over an existing session, so a caller can run
// multiple prompts on the SAME conversation (e.g. a settlement round that reuses
// the worker's accumulated context after the main run hit max_turns).
func captureRunSession(ctx context.Context, s *agentcore.Session, input string, emit func(db.Activity)) (string, harness.TerminalReason, error) {
	ctx, auditTrace := intercept.WithTrace(ctx, input, approvalHistory(s.Messages()))
	defer auditTrace.Finish()

	// Shared no-progress watchdog: a provider that sends headers and then stops
	// streaming is not caught by MaxDuration (turn-boundary) or HTTP header
	// timeouts. Cancelling the run ctx is enough for the SDK's request body read
	// to unwind. The event loop below refreshes lastEvent on every event.
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	var lastEvent atomic.Int64
	lastEvent.Store(time.Now().UnixNano())
	var toolsInFlight atomic.Int64
	var idleFired atomic.Bool
	watchdogDone := make(chan struct{})
	defer close(watchdogDone)
	go func() {
		interval := runIdleTimeout / 4
		if interval > 30*time.Second {
			interval = 30 * time.Second
		}
		if interval < 50*time.Millisecond {
			interval = 50 * time.Millisecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-watchdogDone:
				return
			case <-runCtx.Done():
				return
			case <-ticker.C:
				// A long-running tool (nmap/sqlmap/brute force) produces no model
				// events for minutes but is not a stalled stream. The hard run ctx
				// is the backstop for a tool that hangs; only cut truly idle model
				// streams here.
				if toolsInFlight.Load() > 0 {
					continue
				}
				if time.Since(time.Unix(0, lastEvent.Load())) >= runIdleTimeout {
					idleFired.Store(true)
					cancelRun()
					return
				}
			}
		}
	}()

	var reason harness.TerminalReason
	rec := func(r db.Activity) {
		if r.Kind == "text" || r.Kind == "tool_result" {
			auditTrace.Append(db.InterceptContextEntry{Kind: r.Kind, Tool: r.Tool, ToolUseID: r.ToolUseID, Text: r.Detail, IsError: r.IsError})
		}
		if emit != nil {
			emit(r)
		}
	}
	toolNames := map[string]string{} // tool_use id -> name, to label results

	// A single thinking/text run is coalesced for display, but an unbounded run
	// (a model stuck "thinking" for tens of minutes) must not grow the in-memory
	// buffer forever. Flush a chunk when it gets large; the next delta starts a
	// new activity with the same kind, so nothing is lost.
	const maxDeltaBuf = 512 << 10
	// Cap the total text persisted as activity/audit detail. The transcript still
	// has the full conversation; this only prevents a runaway text/thinking stream
	// from growing the activity table and in-memory audit trace without bound.
	const maxRunTextBytes = 4 << 20
	var tbuf strings.Builder
	var tkind string
	var textBytes int
	var textCapped bool
	flush := func() {
		if tbuf.Len() == 0 {
			return
		}
		s := strings.TrimSpace(tbuf.String())
		k := tkind
		tbuf.Reset()
		tkind = ""
		if s == "" || textCapped {
			return
		}
		if textBytes+len(s) > maxRunTextBytes {
			if remaining := maxRunTextBytes - textBytes; remaining > 0 {
				s = safePrefixBytes(s, remaining)
			} else {
				s = ""
			}
			s += "\n…（本轮输出过长，后续文本已省略）"
			textCapped = true
		}
		textBytes += len(s)
		rec(db.Activity{Kind: k, Summary: firstLine(s, 200), Detail: s})
	}
	addDelta := func(kind, text string) {
		if text == "" {
			return
		}
		if tkind != "" && tkind != kind {
			flush()
		}
		tkind = kind
		tbuf.WriteString(text)
		if tbuf.Len() >= maxDeltaBuf {
			flush()
		}
	}
	lastTool := &runTrace{startedAt: time.Now()}
	var lastUsage *llm.Usage
	var loop toolLoopGuard
	pendingCalls := map[string]toolCallSig{} // tool_use id -> name + input signature
	var loopErr error

	var finalText string
	var rerr error
stream:
	for ev, err := range s.Prompt(runCtx, input) {
		lastEvent.Store(time.Now().UnixNano())
		if err != nil {
			flush()
			if idleFired.Load() {
				msg := fmt.Sprintf("模型流超过 %s 没有任何输出，已中止本轮以避免挂死（通常是 provider/网络卡住）", runIdleTimeout)
				rec(activityWithUsage(db.Activity{Kind: "result", IsError: true, Summary: msg, Detail: msg}, lastUsage))
				return finalText, reason, ErrRunIdle
			}
			if ctx.Err() != nil { // engine/user cancellation, not a provider failure
				sum, detail := terminalText(ctx, &harness.Terminal{Reason: reason, Err: ctx.Err()}, lastTool)
				rec(activityWithUsage(db.Activity{Kind: "result", Summary: firstLine(sum, 400), Detail: detail}, lastUsage))
				return finalText, reason, ctx.Err()
			}
			rec(activityWithUsage(db.Activity{Kind: "result", IsError: true, Summary: "执行出错: " + err.Error(), Detail: err.Error()}, lastUsage))
			return finalText, reason, err
		}
		switch ev.Kind {
		case harness.KindToolUse:
			if ev.ToolUse == nil {
				continue
			}
			flush()
			toolNames[ev.ToolUse.ID] = ev.ToolUse.Name
			inputSig := loop.remember(ev.ToolUse.Name, ev.ToolUse.Input)
			pendingCalls[ev.ToolUse.ID] = toolCallSig{name: ev.ToolUse.Name, input: inputSig}
			toolsInFlight.Add(1)
			in := string(ev.ToolUse.Input)
			lastTool.start(ev.ToolUse.ID, ev.ToolUse.Name, in)
			auditTrace.Start(ev.ToolUse.ID, ev.ToolUse.Name, ev.ToolUse.Input)
			rec(db.Activity{Kind: "tool_use", Tool: ev.ToolUse.Name, ToolUseID: ev.ToolUse.ID,
				Summary: ev.ToolUse.Name + " " + firstLine(in, 200), Detail: in})
		case harness.KindToolResult:
			if ev.ToolResult == nil {
				continue
			}
			flush()
			out := blocksText(ev.ToolResult.Content)
			lastTool.done(ev.ToolResult.ToolUseID)
			if _, ok := pendingCalls[ev.ToolResult.ToolUseID]; ok {
				toolsInFlight.Add(-1)
			}
			auditTrace.Complete(ev.ToolResult.ToolUseID, out, ev.ToolResult.IsError)
			rec(db.Activity{Kind: "tool_result", Tool: toolNames[ev.ToolResult.ToolUseID], ToolUseID: ev.ToolResult.ToolUseID,
				IsError: ev.ToolResult.IsError, Summary: firstLine(out, 200), Detail: out})
			// Decide loop state only after seeing the result: identical command
			// with a changing result is a legitimate poll/retry, not a loop.
			if call, ok := pendingCalls[ev.ToolResult.ToolUseID]; ok {
				delete(pendingCalls, ev.ToolResult.ToolUseID)
				if loop.observeResult(call.name, call.input, []byte(out)) {
					flush()
					loopErr = ErrToolLoop
					msg := fmt.Sprintf("检测到连续/周期性重复的 %s 工具调用（输入与结果相同），已中止本轮以防死循环（通常是模型在原地打转；下一轮会重新规划）", call.name)
					rec(activityWithUsage(db.Activity{Kind: "result", IsError: true, Summary: msg, Detail: msg}, lastUsage))
					break stream
				}
			}
		case harness.KindText:
			addDelta("text", ev.Text)
		case harness.KindThinking:
			addDelta("thinking", ev.Text)
		case harness.KindUsage:
			// live cumulative token usage (per model turn). Emitted as a non-rendered
			// "usage" activity carrying only the token fields; the UI uses the latest
			// one for a running session's live token count. Don't flush() here — the
			// buffered final-answer text must stay for the KindResult de-dup.
			if ev.Usage != nil {
				u := *ev.Usage
				lastUsage = &u
				rec(db.Activity{Kind: "usage",
					InputTokens: &u.InputTokens, OutputTokens: &u.OutputTokens,
					CacheReadTokens: &u.CacheReadTokens, CacheWriteTokens: &u.CacheWriteTokens})
			}
		case harness.KindResult:
			if ev.Terminal != nil {
				if ev.Terminal.Reason != harness.ReasonAbortedStreaming {
					sidequestion.Finish(ctx, ev.Terminal.Messages)
				}
				finalText = ev.Terminal.Text
				reason = ev.Terminal.Reason
				// the buffered tail text usually equals Terminal.Text (final answer);
				// drop it to avoid a duplicate record, the result row carries it.
				if tkind == "text" && strings.TrimSpace(tbuf.String()) == strings.TrimSpace(ev.Terminal.Text) {
					tbuf.Reset()
					tkind = ""
				}
				flush() // flush any trailing thinking / non-final text
				sum, detail := ev.Terminal.Text, ev.Terminal.Text
				if sum == "" || ev.Terminal.Reason == harness.ReasonAbortedTools || ev.Terminal.Reason == harness.ReasonAbortedStreaming {
					sum, detail = terminalText(ctx, ev.Terminal, lastTool)
				}
				if len(detail) > maxRunTextBytes {
					detail = safePrefixBytes(detail, maxRunTextBytes) + "\n…（已截断，完整内容见 transcript）"
				}
				u := ev.Terminal.Usage // cumulative token usage for this session
				rec(db.Activity{Kind: "result", IsError: ev.Terminal.Err != nil,
					Summary: firstLine(sum, 400), Detail: detail,
					InputTokens: &u.InputTokens, OutputTokens: &u.OutputTokens,
					CacheReadTokens: &u.CacheReadTokens, CacheWriteTokens: &u.CacheWriteTokens})
				if ev.Terminal.Err != nil {
					rerr = ev.Terminal.Err
				}
			}
		}
	}
	flush() // safety: any unflushed text if the stream ended without KindResult
	if loopErr != nil {
		return finalText, reason, loopErr
	}
	if idleFired.Load() {
		return finalText, reason, ErrRunIdle
	}
	return finalText, reason, rerr
}

func activityWithUsage(activity db.Activity, usage *llm.Usage) db.Activity {
	if usage == nil {
		return activity
	}
	u := *usage
	activity.InputTokens = &u.InputTokens
	activity.OutputTokens = &u.OutputTokens
	activity.CacheReadTokens = &u.CacheReadTokens
	activity.CacheWriteTokens = &u.CacheWriteTokens
	return activity
}

// blocksText concatenates the text of a tool-result's content blocks.
func blocksText(blocks []llm.ContentBlock) string {
	var b strings.Builder
	for _, bl := range blocks {
		if bl.Type == llm.BlockText && bl.Text != "" {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(bl.Text)
		}
	}
	return b.String()
}

// firstLine returns a single-line, rune-capped preview for the summary column.
func firstLine(s string, max int) string {
	s = strings.TrimSpace(s)
	if before, _, found := strings.Cut(s, "\n"); found {
		s = before
	}
	return truncateRunes(s, max, "…")
}

// safePrefixBytes returns at most n bytes of s without splitting a UTF-8 rune.
func safePrefixBytes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}

// Preserve the recorded session's visible messages, excluding thinking blocks.
// This is audit context; the judge receives only bounded, paired execution
// evidence selected from it, never assistant prose or thinking blocks.
func approvalHistory(messages []llm.Message) []db.InterceptContextEntry {
	var entries []db.InterceptContextEntry
	for _, message := range messages {
		for _, block := range message.Content {
			entry := db.InterceptContextEntry{Kind: string(message.Role)}
			switch block.Type {
			case llm.BlockText:
				entry.Text = block.Text
			case llm.BlockToolUse:
				entry.Kind, entry.Tool, entry.ToolUseID, entry.Text = "tool_use", block.Name, block.ID, string(block.Input)
			case llm.BlockToolResult:
				entry.Kind, entry.ToolUseID, entry.Text, entry.IsError = "tool_result", block.ToolUseID, blocksText(block.Content), block.IsError
			default:
				continue
			}
			entries = append(entries, entry)
		}
	}
	return entries
}
