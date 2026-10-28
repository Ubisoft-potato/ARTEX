package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestPlannerRunBudget(t *testing.T) {
	p := &Planner{}
	if got := p.runBudget(); got != defaultPlannerRun {
		t.Fatalf("default run budget=%s want %s", got, defaultPlannerRun)
	}
	p.SetRunTimeout(2 * time.Minute)
	if got := p.runBudget(); got != 2*time.Minute {
		t.Fatalf("configured run budget=%s want 2m", got)
	}
	// A too-large run_seconds (or the old unlimited default) must never restore
	// the multi-hour hang the 2026-10-22 incident exposed.
	p.SetRunTimeout(45 * time.Minute)
	if got := p.runBudget(); got != plannerRunCeiling {
		t.Fatalf("over-cap run budget=%s want %s", got, plannerRunCeiling)
	}
}

func TestPlannerLoopHintIsOneShot(t *testing.T) {
	p := &Planner{}
	if p.takeLoopHint() {
		t.Fatal("unexpected loop hint before NoteToolLoop")
	}
	store := p.todoFor(7)
	if _, err := store.Tool().Call(context.Background(), json.RawMessage(`{"todos":[{"content":"stale","status":"pending"}]}`), nil); err != nil {
		t.Fatalf("seed todos: %v", err)
	}
	if len(store.List()) != 1 {
		t.Fatalf("seed todos = %d, want 1", len(store.List()))
	}
	p.NoteToolLoop(7)
	if !p.takeLoopHint() {
		t.Fatal("loop hint was not observed")
	}
	if p.takeLoopHint() {
		t.Fatal("loop hint should be consumed by one round")
	}
	if got := p.todoFor(7).List(); len(got) != 0 {
		t.Fatalf("loop abort should reset the stale todo list, got %d items", len(got))
	}
}
