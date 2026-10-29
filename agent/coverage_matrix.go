package agent

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// Coverage states describe individual asset/category cells. Covered requires an
// explicit verified check; intent completion alone leaves a cell pending review.
const (
	coverageStateUntested     = "untested"
	coverageStateInFlight     = "in_flight"
	coverageStateCovered      = "covered"
	coverageStateDebt         = "debt"
	coverageStateInconclusive = "inconclusive"
	coverageStateUnknown      = "unknown"
)

const (
	coveragePriorityNone = iota
	coveragePriorityDebt
	coveragePriorityInconclusive
	coveragePriorityPlanned
	coveragePriorityRunning
	coveragePriorityCovered
)

type coverageCell struct {
	state    string
	priority int
}

type coverageCategoryCount struct {
	applicable   int
	covered      int
	inFlight     int
	debt         int
	inconclusive int
	unknown      int
	untested     int
}

type coverageGap struct {
	AssetID      int64    `json:"asset_id"`
	Type         string   `json:"type"`
	Label        string   `json:"label"`
	Service      string   `json:"service,omitempty"`
	Port         int      `json:"port,omitempty"`
	Covered      []string `json:"covered"`
	Missing      []string `json:"missing"`
	MissingCount int      `json:"missing_count"`
	State        string   `json:"state"`
	Risk         int      `json:"risk"`
}

// buildCoverageMatrix joins explicit verification results to their actual cells.
// Intent categories only describe plans, including legacy keyword directions.
const coverageMaxTopN = 50

func (t *ToolSet) buildCoverageMatrix(topN int) (map[string]any, error) {
	if topN <= 0 {
		topN = 8
	}
	if topN > coverageMaxTopN {
		topN = coverageMaxTopN
	}
	return t.buildCoverageMatrixUncached(topN)
}

func (t *ToolSet) buildCoverageMatrixUncached(topN int) (map[string]any, error) {
	if t.ts == nil {
		return nil, fmt.Errorf("coverage_matrix 需要任务上下文")
	}
	if t.as == nil || t.taskID <= 0 {
		return nil, fmt.Errorf("coverage_matrix 需要任务资产上下文")
	}
	if topN <= 0 {
		topN = 8
	}
	if topN > 50 {
		topN = 50
	}

	graph, err := t.ts.CoverageEvidenceWithSources(t.taskID, 5000, 20000)
	if err != nil {
		return nil, fmt.Errorf("读取覆盖证据失败: %w", err)
	}
	assets, err := t.as.ListCoverageAssetsWithSources(t.taskID)
	if err != nil {
		return nil, fmt.Errorf("读取范围资产失败: %w", err)
	}
	return coverageMatrixFromEvidence(graph, assets, topN)
}

func coverageMatrixFromEvidence(graph *db.CoverageEvidence, assets []*db.Asset, topN int) (map[string]any, error) {
	intents := graph.Intents
	assetByID := make(map[int64]*db.Asset, len(assets))
	for _, a := range assets {
		if a != nil {
			assetByID[a.ID] = a
		}
	}

	cells := make(map[int64]map[string]coverageCell)
	targeted := make(map[int64]bool)
	globalCats := make(map[string]bool)
	intentStateCounts := make(map[string]int)
	unclassified := 0

	for _, n := range intents {
		if n == nil {
			continue
		}
		intentStateCounts[n.State]++

		var p map[string]any
		if len(n.Payload) > 0 {
			_ = json.Unmarshal(n.Payload, &p)
		}
		summary, _ := p["summary"].(string)
		cats := coverageIntentCategories(p)
		if len(cats) == 0 {
			// Backward compatibility: intents created before the structured
			// categories field still classify by their summary keywords.
			cats = classifyCategories(summary)
		}
		assetIDs := coverageNodeAssets(n, p)

		// Target accounting is independent of category classification: an intent
		// may be intentionally broad and not match a keyword. Stopped/deleted
		// work no longer counts: otherwise an abandoned direction makes its assets
		// disappear from zero_targeted even though nothing is actively covering it.
		if coverageIntentTargets(n.State) {
			for _, aid := range assetIDs {
				if assetByID[aid] != nil {
					targeted[aid] = true
				}
			}
		}

		if len(cats) == 0 {
			unclassified++
			continue
		}
		if len(assetIDs) == 0 {
			for _, cat := range cats {
				globalCats[cat] = true
			}
			continue
		}

		cellState, priority := coverageIntentState(n.State)
		if cellState == "" {
			continue // stopped/deleted (and unknown states) do not claim coverage
		}

		for _, aid := range assetIDs {
			a := assetByID[aid]
			if a == nil {
				continue // outside this task's scope
			}
			for _, cat := range cats {
				if !coverageCategoryApplies(a, cat) {
					continue // e.g. XSS on an SSH service
				}
				if cells[aid] == nil {
					cells[aid] = make(map[string]coverageCell)
				}
				mergeCoverageCell(cells[aid], cat, coverageCell{
					state:    cellState,
					priority: priority,
				})
			}
		}
	}

	// Intent categories describe plans only. Results close their own explicit cells.
	for _, intent := range intents {
		if intent.State != "done" {
			continue
		}
		for _, result := range graph.Results[intent.ID] {
			for _, check := range coverageResultChecks(result) {
				a := assetByID[check.AssetID]
				if a == nil || !coverageCategoryApplies(a, check.Category) {
					continue
				}
				if cells[a.ID] == nil {
					cells[a.ID] = map[string]coverageCell{}
				}
				mergeCoverageCell(cells[a.ID], check.Category, coverageCell{state: coverageStateCovered, priority: coveragePriorityCovered})
			}
		}
	}

	pendingResultIDs := map[int64]bool{}
	unattributedIntents := []int64{}
	for _, intent := range intents {
		if intent.State != "done" {
			continue
		}
		var payload map[string]any
		_ = json.Unmarshal(intent.Payload, &payload)
		cats := coverageIntentCategories(payload)
		summary, _ := payload["summary"].(string)
		if len(cats) == 0 {
			cats = classifyCategories(summary)
		}
		if len(cats) == 0 || len(coverageNodeAssets(intent, payload)) == 0 {
			unattributedIntents = append(unattributedIntents, intent.ID)
		}
		for _, result := range graph.Results[intent.ID] {
			if result != nil && len(coverageResultChecks(result)) == 0 {
				pendingResultIDs[result.ID] = true
			}
		}
	}

	categoryCounts := make(map[string]*coverageCategoryCount, len(attackCategories))
	stateCounts := make(map[string]int)
	var coveredAssets, inFlightAssets, debtAssets, inconclusiveAssets, untestedAssets int
	gaps := make([]coverageGap, 0)
	inFlightItems := []map[string]any{}
	reviewItems := []map[string]any{}
	unknownItems := []map[string]any{}

	for _, a := range assets {
		if a == nil {
			continue
		}
		gap := coverageGap{
			AssetID: a.ID,
			Type:    a.Type,
			Label:   coverageAssetLabel(a),
			Service: coverageAssetService(a),
			Port:    coverageAssetPort(a),
			Risk:    coverageAssetRisk(a),
			Covered: []string{},
			Missing: []string{},
		}
		hasInFlight, hasDebt, hasInconclusive, hasCovered, hasUntested := false, false, false, false, false

		for _, cat := range attackCategories {
			if !coverageCategoryApplies(a, cat.Key) {
				continue
			}
			if categoryCounts[cat.Key] == nil {
				categoryCounts[cat.Key] = &coverageCategoryCount{}
			}
			cc := categoryCounts[cat.Key]
			cc.applicable++

			state := coverageStateUntested
			if byCat := cells[a.ID]; byCat != nil {
				if c, ok := byCat[cat.Key]; ok {
					state = c.state
				}
			}
			// A bounded read cannot prove absence of other results or intents.
			if graph.Truncated && state != coverageStateCovered && state != coverageStateInFlight {
				state = coverageStateUnknown
			}
			stateCounts[state]++

			switch state {
			case coverageStateUnknown:
				cc.unknown++
				unknownItems = append(unknownItems, map[string]any{"asset_id": a.ID, "category": cat.Key})
			case coverageStateCovered:
				cc.covered++
				hasCovered = true
				gap.Covered = append(gap.Covered, cat.Key)
			case coverageStateInFlight:
				cc.inFlight++
				hasInFlight = true
				inFlightItems = append(inFlightItems, map[string]any{"asset_id": a.ID, "category": cat.Key})
			case coverageStateDebt:
				cc.debt++
				hasDebt = true
				gap.Missing = append(gap.Missing, cat.Key)
			case coverageStateInconclusive:
				cc.inconclusive++
				hasInconclusive = true
				reviewItems = append(reviewItems, map[string]any{"asset_id": a.ID, "category": cat.Key})
			default:
				cc.untested++
				hasUntested = true
				gap.Missing = append(gap.Missing, cat.Key)
			}
		}

		if hasCovered {
			coveredAssets++
		}
		if hasInFlight {
			inFlightAssets++
		}
		if hasDebt {
			debtAssets++
		}
		if hasInconclusive {
			inconclusiveAssets++
		}
		if hasUntested {
			untestedAssets++
		}

		if len(gap.Missing) == 0 {
			continue
		}
		switch {
		case hasInFlight:
			gap.State = coverageStateInFlight
		case hasDebt:
			gap.State = coverageStateDebt
		case hasInconclusive:
			gap.State = coverageStateInconclusive
		case hasCovered:
			gap.State = "partial"
		default:
			gap.State = coverageStateUntested
		}
		gap.MissingCount = len(gap.Missing)
		gaps = append(gaps, gap)
	}

	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].MissingCount != gaps[j].MissingCount {
			return gaps[i].MissingCount > gaps[j].MissingCount
		}
		if gaps[i].Risk != gaps[j].Risk {
			return gaps[i].Risk > gaps[j].Risk
		}
		return gaps[i].AssetID < gaps[j].AssetID
	})
	topGaps := gaps
	if len(topGaps) > topN {
		topGaps = topGaps[:topN]
	}

	categoryStats := make([]map[string]any, 0, len(attackCategories))
	for _, cat := range attackCategories {
		count := categoryCounts[cat.Key]
		if count == nil {
			count = &coverageCategoryCount{}
		}
		categoryStats = append(categoryStats, map[string]any{
			"key":                 cat.Key,
			"name":                cat.Name,
			"applicable_assets":   count.applicable,
			"assets_covered":      count.covered, // backwards-compatible field (cells for this category)
			"assets_in_flight":    count.inFlight,
			"assets_debt":         count.debt,
			"assets_inconclusive": count.inconclusive,
			"assets_untested":     count.untested,
			// Explicit cell aliases: summing assets_* across categories counts
			// cells, not unique assets. These names make that contract obvious.
			"covered_cells":      count.covered,
			"in_flight_cells":    count.inFlight,
			"debt_cells":         count.debt,
			"inconclusive_cells": count.inconclusive,
			"untested_cells":     count.untested,
			"unknown_cells":      count.unknown,
		})
	}

	zeroTargeted := make([]map[string]any, 0, 20)
	zeroTargetedCount := 0
	for _, a := range assets {
		if a == nil || targeted[a.ID] || graph.Truncated {
			continue
		}
		zeroTargetedCount++
		if len(zeroTargeted) < 20 {
			zeroTargeted = append(zeroTargeted, map[string]any{
				"asset_id": a.ID,
				"type":     a.Type,
				"label":    coverageAssetLabel(a),
			})
		}
	}

	totalApplicable := 0
	for _, count := range stateCounts {
		totalApplicable += count
	}
	coveredCells := stateCounts[coverageStateCovered]
	pct := 0
	if totalApplicable > 0 {
		pct = coveredCells * 100 / totalApplicable
	}

	summary := fmt.Sprintf(
		"%d 个范围内资产（%d 个被意图关联）；%d 个适用覆盖格：已验证 %d（%d%%）、在途 %d、债务 %d、待核实 %d、未测 %d、未知 %d；全局意图类别：%v",
		len(assets), len(targeted), totalApplicable, coveredCells, pct,
		stateCounts[coverageStateInFlight], stateCounts[coverageStateDebt],
		stateCounts[coverageStateInconclusive], stateCounts[coverageStateUntested], stateCounts[coverageStateUnknown],
		sortedCoverageKeys(globalCats),
	)

	return map[string]any{
		"summary":                             summary,
		"total_intents":                       len(intents),
		"assets_in_scope":                     len(assets),
		"assets_targeted":                     len(targeted),
		"coverage_pct":                        pct,
		"total_applicable_cells":              totalApplicable,
		"assets_with_covered_cells":           coveredAssets,
		"assets_with_in_flight_cells":         inFlightAssets,
		"assets_with_debt_cells":              debtAssets,
		"assets_with_inconclusive_cells":      inconclusiveAssets,
		"assets_with_untested_cells":          untestedAssets,
		"covered_cells":                       coveredCells,
		"in_flight_cells":                     stateCounts[coverageStateInFlight],
		"debt_cells":                          stateCounts[coverageStateDebt],
		"inconclusive_cells":                  stateCounts[coverageStateInconclusive],
		"untested_cells":                      stateCounts[coverageStateUntested],
		"category_coverage":                   categoryStats,
		"top_gaps":                            topGaps,
		"zero_targeted_assets":                zeroTargeted,
		"zero_targeted_complete":              !graph.Truncated,
		"zero_targeted_count":                 zeroTargetedCount,
		"global_categories":                   sortedCoverageKeys(globalCats),
		"unclassified_intents":                unclassified,
		"intent_state_counts":                 intentStateCounts,
		"truncated":                           graph.Truncated,
		"truncation_note":                     "只使用已读取且正确关联的结果；截断未读取项保持未知，不能据此认定已覆盖或批量派工。",
		"coverage_basis":                      "coverage_pct = 有明确资产+类别+非空证据的已验证格子 / 适用格子；仅 done 意图的 confirmed 结果可关闭格子，事实另须 observed。资产有验证记录不代表所有类别完成。",
		"unknown_cells":                       stateCounts[coverageStateUnknown],
		"unknown":                             unknownItems,
		"pending_review_results":              len(pendingResultIDs),
		"pending_review_unattributed_intents": unattributedIntents,
		"pending_review_cells":                stateCounts[coverageStateInconclusive],
		"pending_review":                      reviewItems,
		"pending_review_note":                 "完成意图的方向缺少明确有效检查项时待核实；保留历史结果，不猜测归属，不因覆盖率下降批量重新探索。",
		"in_flight":                           inFlightItems,
	}, nil
}

func coverageFactObserved(n *db.Node) bool {
	if n == nil || len(n.Payload) == 0 {
		return false
	}
	var p map[string]any
	if err := json.Unmarshal(n.Payload, &p); err != nil {
		return false
	}
	confidence, _ := p["confidence"].(string)
	confidence = strings.ToLower(strings.TrimSpace(confidence))
	evidence, _ := p["evidence"].(string)
	return confidence == "observed" && strings.TrimSpace(evidence) != ""
}

// coverageIntentTargets reports whether an intent should mark its payload
// assets as targeted. Stopped/deleted work is deliberately excluded; exhausted
// and blocked still count because they represent debt the planner should see.
func coverageIntentTargets(state string) bool {
	return state != "stopped" && state != "deleted"
}

// Plans never establish coverage. Explicit verified checks are overlaid separately.
func coverageIntentState(state string) (string, int) {
	switch state {
	case "open", "paused":
		return coverageStateInFlight, coveragePriorityPlanned
	case "running":
		return coverageStateInFlight, coveragePriorityRunning
	case "done":
		return coverageStateInconclusive, coveragePriorityInconclusive
	case "exhausted", "blocked":
		return coverageStateDebt, coveragePriorityDebt
	default:
		return "", coveragePriorityNone
	}
}

func mergeCoverageCell(byCat map[string]coverageCell, cat string, incoming coverageCell) {
	current, ok := byCat[cat]
	if !ok {
		byCat[cat] = incoming
		return
	}
	if incoming.priority > current.priority {
		byCat[cat] = incoming
		return
	}
	byCat[cat] = current
}

// coverageIntentCategories reads the structured categories added by add_intent.
// Unknown/empty values are ignored here (legacy or externally-created rows may
// carry stale values); add_intent validates new writes. If no valid category is
// present, the caller falls back to the legacy keyword classifier.
func coverageIntentCategories(p map[string]any) []string {
	raw, ok := p["categories"]
	if !ok || raw == nil {
		return nil
	}
	valid := make(map[string]bool, len(attackCategories))
	for _, cat := range attackCategories {
		valid[cat.Key] = true
	}
	seen := make(map[string]bool)
	out := make([]string, 0, len(attackCategories))
	add := func(v any) {
		key := strings.ToLower(strings.TrimSpace(fmt.Sprint(v)))
		if key == "" || seen[key] || !valid[key] {
			return
		}
		seen[key] = true
		out = append(out, key)
	}
	switch v := raw.(type) {
	case []any:
		for _, item := range v {
			add(item)
		}
	case []string:
		for _, item := range v {
			add(item)
		}
	case string:
		add(v)
	}
	return out
}

func coveragePayloadAssetIDs(p map[string]any) []int64 {
	raw, ok := p["asset_ids"]
	if !ok || raw == nil {
		raw, ok = p["target_ids"]
	}
	if !ok || raw == nil {
		if single, ok := p["target_id"]; ok && single != nil {
			raw = []any{single}
		}
	}
	if raw == nil {
		return nil
	}

	seen := make(map[int64]bool)
	out := make([]int64, 0)
	add := func(id int64) {
		if id > 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	switch v := raw.(type) {
	case []any:
		for _, item := range v {
			add(coverageInt64(item))
		}
	case []int64:
		for _, id := range v {
			add(id)
		}
	case float64:
		add(int64(v))
	case int64:
		add(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			add(n)
		}
	case string:
		var n int64
		if _, err := fmt.Sscan(v, &n); err == nil {
			add(n)
		}
	}
	return out
}

func coverageInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case string:
		var i int64
		_, _ = fmt.Sscan(n, &i)
		return i
	default:
		return 0
	}
}

func coverageCategoryApplies(a *db.Asset, cat string) bool {
	if a == nil {
		return false
	}
	web := coverageIsWebAsset(a)
	switch cat {
	case "recon":
		return a.Type == "root_domain" || a.Type == "subdomain" || a.Type == "ip" ||
			a.Type == "service" || a.Type == "app"
	case "auth":
		return coverageIsAuthAsset(a, web)
	case "authz":
		return a.Type == "app" || a.Type == "endpoint"
	case "injection":
		if a.Type == "app" || (a.Type == "service" && web) {
			return true
		}
		return a.Type == "endpoint" && coverageEndpointHasInput(a)
	case "xss":
		if a.Type == "app" || (a.Type == "service" && web) {
			return true
		}
		// A bare GET endpoint (health check, static JSON, robots.txt) is not an
		// XSS surface. Require actual input or a login-like path; otherwise every
		// static GET inflates the denominator by one cell.
		return a.Type == "endpoint" && (coverageEndpointHasInput(a) || coverageEndpointLooksLikeLogin(a))
	case "ssrf":
		if a.Type == "app" || (a.Type == "service" && web) {
			return true
		}
		return a.Type == "endpoint" && coverageEndpointHasURLParam(a)
	case "file":
		if a.Type == "app" || (a.Type == "service" && web) {
			return true
		}
		return a.Type == "endpoint" && (coverageEndpointHasInput(a) || coverageEndpointLooksLikeFile(a))
	case "logic":
		return a.Type == "app" || (a.Type == "endpoint" && (coverageEndpointHasInput(a) || coverageEndpointLooksLikeBusiness(a)))
	case "config":
		return web || a.Type == "service" || a.Type == "app" || a.Type == "endpoint"
	case "infra":
		// Supply-chain/infrastructure applies to hosts, services and apps, not to
		// every individual HTTP endpoint. Counting each endpoint as an infra cell
		// made the denominator explode without adding a distinct test target.
		return a.Type == "ip" || a.Type == "service" || a.Type == "app"
	default:
		return false
	}
}

func coverageIsWebAsset(a *db.Asset) bool {
	if a == nil {
		return false
	}
	if a.Type == "app" || a.Type == "endpoint" {
		return true
	}
	if a.Type != "service" {
		return false
	}
	if parsed, err := url.Parse(a.URL); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
		return true
	}
	st := strings.ToLower(strings.TrimSpace(a.ServiceType))
	if strings.Contains(st, "http") || st == "web" {
		return true
	}
	name := strings.ToLower(strings.TrimSpace(a.ServiceName))
	for _, n := range []string{"http", "https", "nginx", "apache", "iis", "tomcat", "jetty", "caddy", "web"} {
		if name == n || strings.Contains(name, n) {
			return true
		}
	}
	if a.Port != nil {
		switch *a.Port {
		case 80, 81, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000:
			return true
		}
	}
	return false
}

func coverageIsAuthAsset(a *db.Asset, web bool) bool {
	if a == nil {
		return false
	}
	if web || a.Type == "app" || len(a.Auth) > 0 {
		return true
	}
	if a.Type == "endpoint" {
		return coverageEndpointHasInput(a) || coverageEndpointLooksLikeLogin(a)
	}
	if a.Type != "service" {
		return false
	}
	name := strings.ToLower(strings.TrimSpace(a.ServiceName))
	for _, n := range []string{"ssh", "ftp", "telnet", "smb", "rdp", "vnc", "ldap", "smtp", "imap", "pop3",
		"mysql", "mariadb", "mssql", "postgres", "postgresql", "oracle", "redis", "mongodb", "memcached", "elasticsearch", "snmp"} {
		if name == n || strings.Contains(name, n) {
			return true
		}
	}
	if a.Port != nil {
		switch *a.Port {
		case 21, 22, 23, 25, 110, 143, 389, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017:
			return true
		}
	}
	return false
}

func coverageEndpointHasInput(a *db.Asset) bool {
	if a == nil {
		return false
	}
	if parsed, err := url.Parse(a.URL); err == nil && (len(parsed.Query()) > 0 || coverageObjectPath.MatchString(parsed.Path)) {
		return true
	}
	if len(a.Params) > 0 {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(a.Method)) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	case "", "GET", "HEAD", "OPTIONS", "TRACE":
		// These methods have no request body. A login-like GET still counts
		// because it accepts credentials in the URL/query; a bare health check
		// does not.
		return coverageEndpointLooksLikeLogin(a)
	default:
		return false
	}
}

func coverageEndpointLooksLikeLogin(a *db.Asset) bool {
	if a == nil {
		return false
	}
	u := strings.ToLower(a.URL)
	for _, s := range []string{"login", "signin", "sign-in", "oauth", "token", "auth", "admin", "user", "account"} {
		if strings.Contains(u, s) {
			return true
		}
	}
	return false
}

func coverageEndpointLooksLikeFile(a *db.Asset) bool {
	if a == nil {
		return false
	}
	u := strings.ToLower(a.URL)
	for _, s := range []string{"upload", "download", "file", "import", "export", "attach", "avatar", "image"} {
		if strings.Contains(u, s) {
			return true
		}
	}
	return false
}

func coverageEndpointHasURLParam(a *db.Asset) bool {
	if a == nil {
		return false
	}
	params := append([]map[string]any(nil), a.Params...)
	if parsed, err := url.Parse(a.URL); err == nil {
		for key := range parsed.Query() {
			params = append(params, map[string]any{"name": key})
		}
	}
	for _, p := range params {
		name := ""
		if v, ok := p["name"]; ok {
			name = fmt.Sprint(v)
		}
		name = strings.ToLower(name)
		for _, s := range []string{"url", "uri", "link", "redirect", "callback", "next", "target", "host", "domain", "fetch", "webhook", "image", "file", "path"} {
			if strings.Contains(name, s) {
				return true
			}
		}
	}
	return false
}

func coverageAssetLabel(a *db.Asset) string {
	if a == nil {
		return ""
	}
	if a.URL != "" {
		return a.URL
	}
	if a.Domain != "" {
		if a.Port != nil && *a.Port > 0 {
			return fmt.Sprintf("%s:%d", a.Domain, *a.Port)
		}
		return a.Domain
	}
	if a.IP != "" {
		if a.Port != nil && *a.Port > 0 {
			return fmt.Sprintf("%s:%d", a.IP, *a.Port)
		}
		return a.IP
	}
	if a.AppName != "" {
		return a.AppName
	}
	if a.RootDomain != "" {
		return a.RootDomain
	}
	return fmt.Sprintf("#%d", a.ID)
}

func coverageAssetService(a *db.Asset) string {
	if a == nil {
		return ""
	}
	if a.ServiceName != "" {
		return a.ServiceName
	}
	return a.ServiceType
}

func coverageAssetPort(a *db.Asset) int {
	if a == nil || a.Port == nil {
		return 0
	}
	return *a.Port
}

func coverageAssetRisk(a *db.Asset) int {
	if a == nil {
		return 0
	}
	risk := 0
	switch a.Type {
	case "app":
		risk += 5
	case "endpoint":
		risk += 4
	case "service":
		risk += 3
	case "ip":
		risk += 2
	case "subdomain", "root_domain":
		risk++
	}
	if coverageIsWebAsset(a) {
		risk += 3
	}
	if coverageIsAuthAsset(a, coverageIsWebAsset(a)) {
		risk += 2
	}
	return risk
}

func sortedCoverageKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var coverageObjectPath = regexp.MustCompile(`(?i)/(?:[0-9]+|[0-9a-f]{8}-[0-9a-f-]{27,}|\{[^/]+\}|:[a-z_][a-z0-9_]*)(?:/|$)`)

func coverageEndpointLooksLikeBusiness(a *db.Asset) bool {
	if coverageEndpointLooksLikeLogin(a) {
		return true
	}
	for _, word := range []string{"order", "cart", "checkout", "payment", "purchase", "refund", "transfer", "balance", "coupon", "invoice", "booking"} {
		if strings.Contains(strings.ToLower(a.URL), word) {
			return true
		}
	}
	return false
}

func coverageChecksSchema() map[string]any {
	return map[string]any{"type": "array", "description": "可选：逐项登记实际验证的资产+类别+证据；只关闭明确登记的格子。asset_id 必须属于本结果 asset_ids，相同资产和类别不得重复。", "items": obj(map[string]any{"asset_id": idp("本结果关联资产 ID"), "category": map[string]any{"type": "string", "enum": db.CoverageCategoryKeys}, "evidence": str("本格实际验证的非空证据")}, "asset_id", "category", "evidence")}
}

func coverageNodeAssets(n *db.Node, p map[string]any) []int64 {
	if len(n.Anchors) > 0 {
		return n.Anchors
	}
	return coveragePayloadAssetIDs(p)
}

func coverageResultChecks(n *db.Node) []db.CoverageCheck {
	if n == nil || n.State != "confirmed" {
		return nil
	}
	if n.Kind != db.KindFinding && (n.Kind != db.KindFact || !coverageFactObserved(n)) {
		return nil
	}
	var p struct {
		Checks []db.CoverageCheck `json:"coverage_checks"`
	}
	if json.Unmarshal(n.Payload, &p) != nil {
		return nil
	}
	// Invalid historical entries never invent coverage. New writes validate the full list.
	checks, err := db.NormalizeCoverageChecks(p.Checks, n.Anchors)
	if err != nil {
		return nil
	}
	return checks
}
