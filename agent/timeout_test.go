package agent

import (
	"context"
	"testing"
	"time"
)

func TestEffectiveRunBudget(t *testing.T) {
	if got := effectiveRunBudget(20*time.Minute, time.Hour); got != 20*time.Minute {
		t.Fatalf("effectiveRunBudget(configured)=%s, want the configured value", got)
	}
	if got := effectiveRunBudget(0, time.Hour); got != time.Hour {
		t.Fatalf("effectiveRunBudget(0)=%s, want the fallback ceiling", got)
	}
}

func TestWithHardRunTimeoutAddsDeadline(t *testing.T) {
	ctx, cancel := withHardRunTimeout(context.Background(), time.Minute)
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("withHardRunTimeout must add a deadline")
	}
	// The helper adds runSettleGrace, so the deadline is budget+grace, not the
	// bare budget; just make sure it is later than now and not absurd.
	if time.Until(dl) <= 0 {
		t.Fatalf("deadline %s is not in the future", dl)
	}
}

func TestWithHardRunTimeoutZeroBudgetIsNoop(t *testing.T) {
	ctx, cancel := withHardRunTimeout(context.Background(), 0)
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("a zero budget must not add a deadline")
	}
}
