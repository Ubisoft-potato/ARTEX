package agent

import (
	"encoding/json"
)

const (
	// graph_overview is pre-injected into the planner/worker launch prompt and also
	// returned by the graph_overview tool. It must stay bounded: a large task graph
	// can otherwise consume most of the model window before the agent does any work.
	overviewToolBudgetBytes = 160_000
	overviewMinPromptBytes  = 24_000
	overviewMaxPromptBytes  = 160_000
	overviewTrimNote        = "态势概览已按上下文预算裁剪；未展开的旧方向/明细用 graph_overview、list_facts、list_findings、node_detail 或 expand_digest 按需读取。"
)

func graphOverviewBudgetForWindow(windowTokens int) int {
	if windowTokens <= 0 {
		windowTokens = defaultWindowK * 1000
	}
	budget := windowTokens * 3 / 4
	if budget < overviewMinPromptBytes {
		budget = overviewMinPromptBytes
	}
	if budget > overviewMaxPromptBytes {
		budget = overviewMaxPromptBytes
	}
	return budget
}

func overviewJSONBytes(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}

// trimGraphOverview applies a deterministic size budget after the snapshot is
// assembled. It keeps the decision-critical scalars and the newest/hot entries,
// then shortens summaries/lineage and finally drops optional blocks. All trimmed
// detail remains available through the on-demand tools.
func trimGraphOverview(out map[string]any, maxBytes int) map[string]any {
	if out == nil {
		return out
	}
	if maxBytes <= 0 {
		maxBytes = overviewToolBudgetBytes
	}
	if overviewJSONBytes(out) <= maxBytes {
		return out
	}

	changed := compactGraphOverviewEntries(out)
	if overviewJSONBytes(out) <= maxBytes {
		return markGraphOverviewTrimmed(out, changed)
	}

	// Hard caps first. Newest-first lists therefore retain the most recent items.
	for _, cap := range []struct {
		key string
		max int
	}{
		{"recent_done_intents", 48},
		{"recent_facts", 48},
		{"finding_list", 48},
		{"cold_digests", 20},
	} {
		if capGraphOverviewList(out, cap.key, cap.max) {
			changed = true
		}
		if overviewJSONBytes(out) <= maxBytes {
			return markGraphOverviewTrimmed(out, changed)
		}
	}

	// Related-task views are useful blackboard context, but they duplicate a lot
	// of text. Keep a very small slice before dropping the block entirely.
	trimRelatedOverview(out, 3, 3, 2)
	if overviewJSONBytes(out) <= maxBytes {
		return markGraphOverviewTrimmed(out, true)
	}

	// Coverage scope can be large for wide programs; counts and tested ratios are
	// the planning signal, the full scope stays in list_assets/task scope tools.
	trimCoverageOverview(out, 12, 6)
	if overviewJSONBytes(out) <= maxBytes {
		return markGraphOverviewTrimmed(out, true)
	}

	// Last resort: halve the high-volume lists until the payload fits. Keep at
	// least the newest few entries so the planner still sees recent work.
	for overviewJSONBytes(out) > maxBytes {
		progressed := false
		for _, key := range []string{"recent_done_intents", "recent_facts", "finding_list", "cold_digests"} {
			if capGraphOverviewList(out, key, maxOverviewListLen(out, key)/2) {
				progressed = true
			}
			if overviewJSONBytes(out) <= maxBytes {
				return markGraphOverviewTrimmed(out, true)
			}
		}
		if !progressed {
			break
		}
	}

	// Optional lineage/directory aids can be dropped before touching the core
	// task/goals/frontier/finding counts.
	for _, key := range []string{"related_tasks", "covered_members", "cold_index"} {
		if _, ok := out[key]; ok {
			delete(out, key)
			changed = true
		}
		if overviewJSONBytes(out) <= maxBytes {
			break
		}
	}
	if overviewJSONBytes(out) > maxBytes {
		// Scope is useful, but the coverage denominator/by_type totals carry the
		// planning signal and the full scope is available from the asset tools.
		if coverage, ok := out["coverage"].(map[string]any); ok {
			if _, exists := coverage["scope"]; exists {
				delete(coverage, "scope")
				changed = true
			}
		}
	}
	return markGraphOverviewTrimmed(out, changed)
}

func markGraphOverviewTrimmed(out map[string]any, changed bool) map[string]any {
	if !changed {
		return out
	}
	out["overview_truncated"] = true
	out["overview_note"] = overviewTrimNote
	return out
}

func compactGraphOverviewEntries(out map[string]any) bool {
	changed := false
	for _, key := range []string{"open_intents", "running_intents", "recent_done_intents", "recent_facts", "finding_list"} {
		list, ok := out[key].([]map[string]any)
		if !ok {
			continue
		}
		for _, m := range list {
			changed = truncOverviewString(m, "summary", 300) || changed
			changed = capOverviewField(m, "parents", 12) || changed
			changed = capOverviewField(m, "yields", 12) || changed
			changed = capOverviewField(m, "asset_ids", 12) || changed
			changed = capOverviewField(m, "categories", 6) || changed
			if key == "finding_list" {
				changed = truncOverviewString(m, "evidence", 240) || changed
				changed = capOverviewField(m, "assets", 10) || changed
			}
		}
	}
	if list, ok := out["cold_digests"].([]map[string]any); ok {
		for _, m := range list {
			changed = truncOverviewString(m, "body", 1000) || changed
		}
	}
	if related, ok := out["related_tasks"].([]map[string]any); ok {
		for _, source := range related {
			for _, key := range []string{"recent_intent_results", "recent_facts", "recent_findings", "cold_digests", "asset_scope"} {
				if capGraphOverviewMapList(source, key, 4) {
					changed = true
				}
			}
			for _, key := range []string{"recent_intent_results", "recent_facts", "recent_findings", "cold_digests"} {
				if list, ok := source[key].([]map[string]any); ok {
					for _, m := range list {
						changed = truncOverviewString(m, "summary", 240) || changed
						changed = truncOverviewString(m, "result_summary", 240) || changed
						changed = truncOverviewString(m, "body", 600) || changed
					}
				}
			}
		}
	}
	if coverage, ok := out["coverage"].(map[string]any); ok {
		changed = capCoverageScope(coverage, 20, 8) || changed
	}
	return changed
}

func truncOverviewString(m map[string]any, key string, limit int) bool {
	s, ok := m[key].(string)
	if !ok || len([]rune(s)) <= limit {
		return false
	}
	m[key] = truncRunes(s, limit)
	return true
}

func capOverviewField(m map[string]any, key string, limit int) bool {
	switch v := m[key].(type) {
	case []int64:
		if len(v) > limit {
			m[key] = v[:limit]
			return true
		}
	case []string:
		if len(v) > limit {
			m[key] = v[:limit]
			return true
		}
	case []any:
		if len(v) > limit {
			m[key] = v[:limit]
			return true
		}
	case []map[string]any:
		if len(v) > limit {
			m[key] = v[:limit]
			return true
		}
	}
	return false
}

func capGraphOverviewList(out map[string]any, key string, limit int) bool {
	if limit < 1 {
		limit = 1
	}
	list, ok := out[key].([]map[string]any)
	if !ok || len(list) <= limit {
		return false
	}
	out[key] = list[:limit]
	out[key+"_truncated"] = true
	return true
}

func maxOverviewListLen(out map[string]any, key string) int {
	if list, ok := out[key].([]map[string]any); ok {
		return len(list)
	}
	return 0
}

func capGraphOverviewMapList(m map[string]any, key string, limit int) bool {
	list, ok := m[key].([]map[string]any)
	if !ok || len(list) <= limit {
		return false
	}
	m[key] = list[:limit]
	m[key+"_truncated"] = true
	return true
}

func trimRelatedOverview(out map[string]any, maxIntents, maxFacts, maxFindings int) {
	related, ok := out["related_tasks"].([]map[string]any)
	if !ok {
		return
	}
	for _, source := range related {
		capGraphOverviewMapList(source, "recent_intent_results", maxIntents)
		capGraphOverviewMapList(source, "recent_facts", maxFacts)
		capGraphOverviewMapList(source, "recent_findings", maxFindings)
		capGraphOverviewMapList(source, "cold_digests", 2)
		capGraphOverviewMapList(source, "asset_scope", 6)
	}
}

func trimCoverageOverview(out map[string]any, maxScope, maxCompanyScope int) {
	coverage, ok := out["coverage"].(map[string]any)
	if !ok {
		return
	}
	capCoverageScope(coverage, maxScope, maxCompanyScope)
}

func capCoverageScope(coverage map[string]any, maxScope, maxCompanyScope int) bool {
	scope, ok := coverage["scope"].([]map[string]any)
	if !ok || len(scope) == 0 {
		return false
	}
	changed := false
	if len(scope) > maxScope {
		scope = scope[:maxScope]
		coverage["scope"] = scope
		coverage["scope_truncated"] = true
		changed = true
	}
	for _, entry := range scope {
		if truncOverviewString(entry, "value", 300) {
			changed = true
		}
		if truncOverviewString(entry, "source", 200) {
			changed = true
		}
		if capOverviewField(entry, "company_scope", maxCompanyScope) {
			changed = true
		}
		if capOverviewField(entry, "company_keywords", maxCompanyScope) {
			changed = true
		}
		if companyScope, ok := entry["company_scope"].([]map[string]any); ok {
			for _, rule := range companyScope {
				if truncOverviewString(rule, "value", 200) {
					changed = true
				}
				if truncOverviewString(rule, "reason", 200) {
					changed = true
				}
			}
		}
	}
	return changed
}
