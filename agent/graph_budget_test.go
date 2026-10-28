package agent

import (
	"strings"
	"testing"
)

func TestGraphOverviewBudgetForWindow(t *testing.T) {
	cases := []struct {
		window int
		want   int
	}{
		{0, 150_000},
		{32_000, 24_000},
		{200_000, 150_000},
		{262_144, 160_000},
		{1_000_000, 160_000},
	}
	for _, tc := range cases {
		if got := graphOverviewBudgetForWindow(tc.window); got != tc.want {
			t.Fatalf("graphOverviewBudgetForWindow(%d)=%d, want %d", tc.window, got, tc.want)
		}
	}
}

func TestTrimGraphOverviewFitsBudgetAndKeepsCore(t *testing.T) {
	out := map[string]any{
		"task":          map[string]any{"description": "task", "goal": "goal"},
		"frontier_open": 2,
		"findings":      1,
		"facts":         100,
		"goals":         []map[string]any{{"id": 1, "text": "goal"}},
		"recent_done_intents": []map[string]any{
			{"id": 1, "state": "done", "summary": strings.Repeat("i", 1200), "parents": []int64{1, 2, 3}, "yields": []int64{4, 5, 6}},
		},
		"recent_facts": []map[string]any{
			{"id": 2, "state": "confirmed", "summary": strings.Repeat("f", 1200)},
		},
		"finding_list": []map[string]any{
			{"id": 3, "summary": strings.Repeat("v", 1200), "evidence": strings.Repeat("p", 1200)},
		},
	}
	for i := 0; i < 80; i++ {
		out["recent_done_intents"] = append(out["recent_done_intents"].([]map[string]any), map[string]any{
			"id": 100 + i, "state": "done", "summary": strings.Repeat("x", 2000),
			"parents": []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
			"yields":  []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
		})
		out["recent_facts"] = append(out["recent_facts"].([]map[string]any), map[string]any{
			"id": 200 + i, "state": "confirmed", "summary": strings.Repeat("y", 2000),
		})
		out["finding_list"] = append(out["finding_list"].([]map[string]any), map[string]any{
			"id": 300 + i, "summary": strings.Repeat("z", 2000), "evidence": strings.Repeat("e", 2000),
		})
	}
	const budget = 20_000
	trimmed := trimGraphOverview(out, budget)
	if n := overviewJSONBytes(trimmed); n > budget {
		t.Fatalf("trimmed overview is %d bytes, budget %d", n, budget)
	}
	if truncated, _ := trimmed["overview_truncated"].(bool); !truncated {
		t.Fatal("overview_truncated flag not set")
	}
	if _, ok := trimmed["task"].(map[string]any); !ok {
		t.Fatal("task core field was dropped")
	}
	if got := trimmed["frontier_open"]; got != 2 {
		t.Fatalf("frontier_open=%v, want 2", got)
	}
	if got := trimmed["findings"]; got != 1 {
		t.Fatalf("findings=%v, want 1", got)
	}
	// Entry-level compaction must run before we throw away all old work.
	if list, ok := trimmed["recent_done_intents"].([]map[string]any); !ok || len(list) == 0 {
		t.Fatal("recent_done_intents unexpectedly empty")
	}
}

func TestTrimGraphOverviewCapsCoverageAndRelated(t *testing.T) {
	out := map[string]any{
		"task": map[string]any{"goal": "g"},
		"coverage": map[string]any{
			"scope": []map[string]any{
				{"value": "a", "company_scope": []any{1, 2, 3, 4, 5, 6, 7, 8, 9}},
			},
		},
		"related_tasks": []map[string]any{{
			"source_task_id": 9,
			"recent_facts": []map[string]any{
				{"id": 1, "summary": strings.Repeat("r", 1000)},
			},
		}},
	}
	for i := 0; i < 40; i++ {
		out["coverage"].(map[string]any)["scope"] = append(out["coverage"].(map[string]any)["scope"].([]map[string]any), map[string]any{"value": strings.Repeat("s", 2000)})
		out["related_tasks"].([]map[string]any)[0]["recent_facts"] = append(out["related_tasks"].([]map[string]any)[0]["recent_facts"].([]map[string]any), map[string]any{"id": 100 + i, "summary": strings.Repeat("t", 2000)})
	}
	trimmed := trimGraphOverview(out, 8_000)
	if n := overviewJSONBytes(trimmed); n > 8_000 {
		t.Fatalf("trimmed overview is %d bytes, budget 8000", n)
	}
}
