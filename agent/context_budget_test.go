package agent

import (
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestSafeMaxTokensLeavesPromptHeadroom(t *testing.T) {
	cases := []struct {
		window int
		want   int
	}{
		{0, 16384},
		{200000, 16384},
		{262144, 16384},
		{32768, 4096},
		{8192, 1024},
	}
	for _, tc := range cases {
		if got := SafeMaxTokens(tc.window); got != tc.want {
			t.Fatalf("SafeMaxTokens(%d)=%d, want %d", tc.window, got, tc.want)
		}
	}
}

func TestBudgetCompactorHardTrimFitsAndKeepsMarker(t *testing.T) {
	c := &budgetCompactor{window: 12000, maxOutput: 1000, keepRecent: budgetKeepRecent}
	msgs := make([]llm.Message, 0, 40)
	for i := 0; i < 40; i++ {
		msgs = append(msgs, llm.Message{
			Role:    llm.RoleUser,
			Content: []llm.ContentBlock{llm.TextBlock(strings.Repeat("x", 2000))},
		})
	}
	if c.withinBudget(msgs) {
		t.Fatal("test fixture should exceed the budget")
	}
	out, changed := c.hardTrim(msgs)
	if !changed {
		t.Fatal("hardTrim did not report a change")
	}
	if !c.withinBudget(out) {
		t.Fatalf("trimmed context still over budget: %d > %d", contextEstimateTokens(out), c.budget())
	}
	if len(out) >= len(msgs) {
		t.Fatalf("hardTrim kept all %d messages", len(msgs))
	}
	if len(out) == 0 || !strings.Contains(out[0].Content[0].Text, "truncated locally") {
		t.Fatalf("trimmed context missing local-truncation marker: %+v", out)
	}
}

func TestBudgetCompactorClearsOldToolResults(t *testing.T) {
	c := &budgetCompactor{window: 12000, maxOutput: 1000, keepRecent: budgetKeepRecent}
	msgs := []llm.Message{
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
			{Type: llm.BlockToolUse, ID: "t1", Name: "Bash", Input: []byte(`{}`)},
		}},
		{Role: llm.RoleUser, Content: []llm.ContentBlock{
			{Type: llm.BlockToolResult, ToolUseID: "t1", Content: []llm.ContentBlock{llm.TextBlock(strings.Repeat("r", 40000))}},
		}},
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("done")}},
		{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock("continue")}},
	}
	if c.withinBudget(msgs) {
		t.Fatal("test fixture should exceed the budget")
	}
	out, changed := c.hardTrim(msgs)
	if !changed {
		t.Fatal("hardTrim did not clear the old tool result")
	}
	if got := out[1].Content[0].Content[0].Text; got != budgetToolMarker {
		t.Fatalf("tool result marker=%q, want %q", got, budgetToolMarker)
	}
}
