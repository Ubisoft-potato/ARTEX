package agent

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

func TestOverviewTextBudgetIsFairAndUTF8Safe(t *testing.T) {
	if got := relatedOverviewBudgetForSources(1); got != relatedOverviewMaxTextPerSource {
		t.Fatalf("single source budget=%d want=%d", got, relatedOverviewMaxTextPerSource)
	}
	perSource := relatedOverviewBudgetForSources(db.MaxTaskSourceCount)
	if perSource*db.MaxTaskSourceCount > relatedOverviewTotalTextRunes {
		t.Fatalf("aggregate budget exceeded: per_source=%d", perSource)
	}

	budget := overviewTextBudget{remaining: 5}
	got := budget.take(strings.Repeat("中", 10), 20)
	if !utf8.ValidString(got) {
		t.Fatalf("budget truncation produced invalid UTF-8: %q", got)
	}
	if utf8.RuneCountInString(got) != 5 || !budget.truncated || budget.remaining != 0 {
		t.Fatalf("unexpected truncation: got=%q budget=%+v", got, budget)
	}
	if tail := budget.take("more", 20); tail != "" {
		t.Fatalf("exhausted budget returned more text: %q", tail)
	}
}

func TestTruncRunes(t *testing.T) {
	if got := truncRunes("short", 10); got != "short" {
		t.Fatalf("short string changed: %q", got)
	}
	got := truncRunes(strings.Repeat("中", findingPocRunes+10), findingPocRunes)
	if !utf8.ValidString(got) {
		t.Fatalf("truncation produced invalid UTF-8: %q", got)
	}
	if n := utf8.RuneCountInString(got); n > findingPocRunes+3 {
		t.Fatalf("truncated preview still too long: %d runes", n)
	}
}
