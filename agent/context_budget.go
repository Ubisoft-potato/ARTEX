package agent

import (
	"context"

	"github.com/Autumn-27/norma/compaction"
	"github.com/Autumn-27/norma/llm"
)

// budgetCompactor wraps the SDK compactor with a deterministic last-resort
// budget. The SDK's AutoCompact is model-based: if the summary request keeps
// returning an empty body (common with unstable gateways), its breaker trips and
// the original oversized prompt is sent unchanged. The harness then reports
// prompt_too_long and the run dies. This wrapper keeps a hard prompt budget:
// after the SDK's compaction attempt it estimates the API view and, if prompt +
// output still exceeds the window, trims old tool results / old turns locally.
type budgetCompactor struct {
	inner      *compaction.Compactor
	window     int
	maxOutput  int
	keepRecent int
}

const (
	budgetKeepRecent = 8
	budgetMinSafety  = 2048
	budgetMaxSafety  = 8192
	budgetTrimMarker = "[Earlier conversation was truncated locally to fit the model context window.]"
	budgetToolMarker = "[Old tool result trimmed to fit the model context window.]"
)

func newBudgetCompactor(prov llm.Provider, window, maxOutput int, nonStreaming bool) *budgetCompactor {
	if prov == nil {
		return nil
	}
	if window <= 0 {
		window = defaultWindowK * 1000
	}
	if maxOutput <= 0 {
		maxOutput = 8192
	}
	cfg := compaction.Config{
		ContextWindow:   window,
		MaxOutputTokens: maxOutput,
		KeepRecent:      budgetKeepRecent,
	}
	inner := compaction.New(cfg, compaction.ProviderSummarizer(prov, maxOutput, nonStreaming))
	return &budgetCompactor{
		inner:      inner,
		window:     window,
		maxOutput:  maxOutput,
		keepRecent: budgetKeepRecent,
	}
}

func (c *budgetCompactor) Pre(ctx context.Context, msgs []llm.Message, lastInputTokens int) []llm.Message {
	if c == nil {
		return msgs
	}
	return c.fit(c.inner.Pre(ctx, msgs, lastInputTokens))
}

func (c *budgetCompactor) Reactive(ctx context.Context, msgs []llm.Message) ([]llm.Message, bool) {
	if c == nil {
		return msgs, false
	}
	out, ok := c.inner.Reactive(ctx, msgs)
	if ok {
		return c.fit(out), true
	}
	return c.hardTrim(msgs)
}

func (c *budgetCompactor) IsOverflow(err error) bool {
	return c != nil && c.inner.IsOverflow(err)
}

func (c *budgetCompactor) fit(msgs []llm.Message) []llm.Message {
	if c == nil || c.withinBudget(msgs) {
		return msgs
	}
	out, _ := c.hardTrim(msgs)
	return out
}

func (c *budgetCompactor) safety() int {
	s := c.window / 100
	if s < budgetMinSafety {
		s = budgetMinSafety
	}
	if s > budgetMaxSafety {
		s = budgetMaxSafety
	}
	return s
}

func (c *budgetCompactor) budget() int {
	target := c.window - c.maxOutput - c.safety()
	if target < c.window/2 {
		target = c.window / 2
	}
	if target < 1 {
		target = 1
	}
	return target
}

func (c *budgetCompactor) withinBudget(msgs []llm.Message) bool {
	return contextEstimateTokens(msgs) <= c.budget()
}

func contextEstimateTokens(msgs []llm.Message) int {
	return compaction.EstimateTokens(llm.MessagesForAPI(msgs)) * 4 / 3
}

// hardTrim first clears old compactable tool-result bodies (keeping tool_use /
// tool_result pairing intact), then drops whole oldest turns until the API view
// fits the budget. It keeps at least the newest message; a single oversized turn
// still needs the caller's output cap to leave room.
func (c *budgetCompactor) hardTrim(msgs []llm.Message) ([]llm.Message, bool) {
	if c == nil || len(msgs) == 0 {
		return msgs, false
	}
	changed := false

	// Clear old tool results first: this preserves message/block structure and is
	// much cheaper than dropping the surrounding turns.
	out := append([]llm.Message(nil), msgs...)
	clearBefore := len(out) - 2
	if clearBefore < 0 {
		clearBefore = 0
	}
	for i := 0; i < clearBefore; i++ {
		for j, b := range out[i].Content {
			if b.Type != llm.BlockToolResult || isBudgetToolMarker(b.Content) {
				continue
			}
			nc := append([]llm.ContentBlock(nil), out[i].Content...)
			nc[j].Content = []llm.ContentBlock{llm.TextBlock(budgetToolMarker)}
			out[i].Content = nc
			changed = true
		}
	}
	if c.withinBudget(out) {
		return out, changed
	}

	// Drop oldest whole turns. MessagesForAPI/PairToolBlocks will drop any orphan
	// tool block introduced by the cut, so the request remains syntactically valid.
	start := 0
	for start < len(out)-1 && !c.withinBudget(out[start:]) {
		start++
	}
	if start == 0 {
		return out, changed
	}
	trimmed := make([]llm.Message, 0, len(out)-start+1)
	trimmed = append(trimmed, llm.UserText(budgetTrimMarker))
	trimmed = append(trimmed, out[start:]...)
	return trimmed, true
}

func isBudgetToolMarker(blocks []llm.ContentBlock) bool {
	return len(blocks) == 1 && blocks[0].Type == llm.BlockText && blocks[0].Text == budgetToolMarker
}
