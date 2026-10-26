package server

import (
	"testing"
	"time"
)

func TestJitterRetryDelayBounds(t *testing.T) {
	for _, base := range []time.Duration{time.Second, 5 * time.Second, 2 * time.Minute} {
		low, high := base-base/5, base+base/5
		for i := 0; i < 100; i++ {
			got := jitterRetryDelay(base)
			if got < low || got > high {
				t.Fatalf("jitterRetryDelay(%s)=%s, want [%s,%s]", base, got, low, high)
			}
		}
	}
	if got := jitterRetryDelay(0); got != 0 {
		t.Fatalf("jitterRetryDelay(0)=%s, want 0", got)
	}
}

func TestPlannerRetryDelay(t *testing.T) {
	want := []time.Duration{
		5 * time.Second,
		15 * time.Second,
		45 * time.Second,
		2 * time.Minute,
		2 * time.Minute,
	}
	for i, w := range want {
		if got := plannerRetryDelay(i + 1); got != w {
			t.Fatalf("plannerRetryDelay(%d)=%s want %s", i+1, got, w)
		}
	}
	if got := plannerRetryDelay(0); got != 5*time.Second {
		t.Fatalf("plannerRetryDelay(0)=%s want 5s", got)
	}
	if !plannerRetryAllowed(plannerMaxConsecutiveFailures) {
		t.Fatalf("plannerRetryAllowed(%d) should allow the last fast retry", plannerMaxConsecutiveFailures)
	}
	if plannerRetryAllowed(plannerMaxConsecutiveFailures + 1) {
		t.Fatalf("plannerRetryAllowed(%d) must suspend fast retries", plannerMaxConsecutiveFailures+1)
	}
}
