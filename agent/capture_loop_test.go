package agent

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
)

// loopProvider is a non-streaming provider that always asks for the same
// (unknown) tool. The harness turns each call into an identical error result,
// which is exactly the shape the result-aware loop guard must catch.
type loopProvider struct {
	calls int
}

func (p *loopProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {}
}

func (p *loopProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.calls++
	return llm.Message{
		Role: llm.RoleAssistant,
		Content: []llm.ContentBlock{{
			Type:  llm.BlockToolUse,
			ID:    "tool-" + string(rune('0'+p.calls)),
			Name:  "NoSuchTool",
			Input: json.RawMessage(`{"x":1}`),
		}},
	}, "tool_use", llm.Usage{}, nil
}

func TestCaptureRunAbortsOnRepeatedToolLoop(t *testing.T) {
	provider := &loopProvider{}
	var activities []db.Activity
	_, _, err := captureRun(context.Background(), agentcore.Options{
		Provider:     provider,
		MaxTurns:     10,
		NonStreaming: true,
	}, "test", func(a db.Activity) {
		activities = append(activities, a)
	})
	if !errors.Is(err, ErrToolLoop) {
		t.Fatalf("captureRun error=%v, want ErrToolLoop", err)
	}
	if provider.calls != maxIdenticalToolCalls {
		t.Fatalf("provider calls=%d, want %d before the guard trips", provider.calls, maxIdenticalToolCalls)
	}
}

func TestCaptureRunAbortsOnIdleStream(t *testing.T) {
	old := runIdleTimeout
	runIdleTimeout = 200 * time.Millisecond
	defer func() { runIdleTimeout = old }()

	provider := captureUsageProvider{stream: func(ctx context.Context, yield func(llm.StreamEvent, error) bool) {
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil) {
			return
		}
		<-ctx.Done()
		yield(llm.StreamEvent{}, ctx.Err())
	}}

	done := make(chan error, 1)
	go func() {
		_, _, err := captureRun(context.Background(), agentcore.Options{Provider: provider, MaxTurns: 1}, "test", nil)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrRunIdle) {
			t.Fatalf("captureRun error=%v, want ErrRunIdle", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("captureRun did not abort an idle stream")
	}
}
