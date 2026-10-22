package agent

import (
	"context"
	"time"
)

// "0 = unlimited" is a useful escape hatch for long interactive sessions, but it
// must not mean "can hang forever". If a caller passes 0 these generous ceilings
// still apply so a stalled provider/tool cannot pin a goroutine for days.
const (
	defaultWorkerRunCeiling = 2 * time.Hour
	defaultChatRunCeiling   = time.Hour
	defaultMainRunCeiling   = time.Hour
)

// runIdleTimeout is a no-progress watchdog shared by every agent. A model stream
// may be slow, but ten minutes without a single event is a hang, not useful work
// (the provider header timeout is already ten minutes). Variable so tests can
// shrink it; production never changes it.
var runIdleTimeout = 10 * time.Minute

func effectiveRunBudget(budget, fallback time.Duration) time.Duration {
	if budget > 0 {
		return budget
	}
	return fallback
}

// withHardRunTimeout adds a hard wall-clock bound for the whole run. The SDK's
// MaxDuration only bounds toolCtx and is checked at turn boundaries, so this is
// what actually interrupts a model stream that stalls mid-flight. The extra
// grace lets the SDK's settlement round checkpoint partial results first.
func withHardRunTimeout(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	if budget <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, budget+runSettleGrace)
}
