package agent

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// Coverage states used by the matrix. "covered" means an intent produced
// observed evidence (or a finding); "in_flight" means open/running work exists;
// "debt" means the work was attempted but produced no usable conclusion.
const (
	coverageStateUntested     = "untested"
	coverageStateInFlight     = "in_flight"
	coverageStateCovered      = "covered"
	coverageStateDebt         = "debt"
	coverageStateInconclusive = "inconclusive"
)

const (
	coveragePriorityNone = iota
	coveragePriorityInconclusive
	coveragePriorityDebt
	coveragePriorityPlanned
	coveragePriorityRunning
	coveragePriorityCovered
)

type coverageCell struct {
	state     string
	priority  int
	intentIDs []int64
	positive  bool
	inFlight  bool
}

type coverageCategoryCount struct {
	applicable   int
	covered      int
	inFlight     int
	debt         int
	inconclusive int
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

// buildCoverageMatrix is the read model behind coverage_matrix. It deliberately
// keeps the existing 10-category keyword taxonomy (so current intents still
// classify) but fixes three defects in the old implementation:
//
//  1. open/running/done/exhausted are no longer all "covered": only observed
//     facts/findings count, open/running is in-flight, exhausted/blocked is debt.
//  2. the denominator is every in-scope asset x applicable category, not only
//     assets that happened to have an intent.
//  3. categories are filtered by asset type/service so an SSH host is not
//     reported as missing XSS/SSRF/business-logic coverage.
func (t *ToolSet) buildCoverageMatrix(topN int) (map[string]any, error) {
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

	intents, intentsTruncated, err := t.coverageListNodes(db.KindIntent, 5000)
	if err != nil {
		return nil, fmt.Errorf("读取意图失败: %w", err)
	}
	facts, factsTruncated, err := t.coverageListNodes(db.KindFact, 5000)
	if err != nil {
		return nil, fmt.Errorf("读取事实失败: %w", err)
	}
	findings, findingsTruncated, err := t.coverageListNodes(db.KindFinding, 2000)
	if err != nil {
		return nil, fmt.Errorf("读取漏洞失败: %w", err)
	}
	assets, err := t.as.ListCoverageAssetsWithSources(t.taskID)
	if err != nil {
		return nil, fmt.Errorf("读取范围资产失败: %w", err)
	}
	edges, err := t.ts.Edges(20000)
	if err != nil {
		return nil, fmt.Errorf("读取图谱关系失败: %w", err)
	}

	assetByID := make(map[int64]*db.Asset, len(assets))
	for _, a := range assets {
		if a != nil {
			assetByID[a.ID] = a
		}
	}

	factByID := make(map[int64]*db.Node, len(facts))
	for _, n := range facts {
		if n != nil {
			factByID[n.ID] = n
		}
	}
	findingByID := make(map[int64]*db.Node, len(findings))
	for _, n := range findings {
		if n != nil {
			findingByID[n.ID] = n
		}
	}

	yields := make(map[int64][]int64)
	for _, e := range edges {
		if e.Rel == db.RelYields {
			yields[e.From] = append(yields[e.From], e.To)
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
		cats := classifyCategories(summary)
		assetIDs := coveragePayloadAssetIDs(p)

		// Target accounting is independent of category classification: an intent
		// may be intentionally broad and not match a keyword.
		for _, aid := range assetIDs {
			if assetByID[aid] != nil {
				targeted[aid] = true
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

		hasEvidence, observed, finding := coverageIntentEvidence(n.ID, yields, factByID, findingByID)
		cellState, priority, positive := coverageIntentState(n.State, hasEvidence, observed, finding)
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
					state:     cellState,
					priority:  priority,
					intentIDs: []int64{n.ID},
					positive:  positive,
					inFlight:  cellState == coverageStateInFlight,
				})
			}
		}
	}

	categoryCounts := make(map[string]*coverageCategoryCount, len(attackCategories))
	stateCounts := make(map[string]int)
	gaps := make([]coverageGap, 0)

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
		hasInFlight, hasDebt, hasInconclusive, hasCovered := false, false, false, false

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
			stateCounts[state]++

			switch state {
			case coverageStateCovered:
				cc.covered++
				hasCovered = true
				gap.Covered = append(gap.Covered, cat.Key)
			case coverageStateInFlight:
				cc.inFlight++
				hasInFlight = true
				gap.Missing = append(gap.Missing, cat.Key)
			case coverageStateDebt:
				cc.debt++
				hasDebt = true
				gap.Missing = append(gap.Missing, cat.Key)
			case coverageStateInconclusive:
				cc.inconclusive++
				hasInconclusive = true
				gap.Missing = append(gap.Missing, cat.Key)
			default:
				cc.untested++
				gap.Missing = append(gap.Missing, cat.Key)
			}
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
			"assets_covered":      count.covered, // backwards-compatible field
			"assets_in_flight":    count.inFlight,
			"assets_debt":         count.debt,
			"assets_inconclusive": count.inconclusive,
			"assets_untested":     count.untested,
		})
	}

	zeroTargeted := make([]map[string]any, 0, 20)
	zeroTargetedCount := 0
	for _, a := range assets {
		if a == nil || targeted[a.ID] {
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
		"%d 个范围内资产（%d 个被意图关联）；%d 个适用覆盖格：已验证 %d（%d%%）、在途 %d、债务 %d、证据不足 %d、未测 %d；全局意图类别：%v",
		len(assets), len(targeted), totalApplicable, coveredCells, pct,
		stateCounts[coverageStateInFlight], stateCounts[coverageStateDebt],
		stateCounts[coverageStateInconclusive], stateCounts[coverageStateUntested],
		sortedCoverageKeys(globalCats),
	)

	return map[string]any{
		"summary":                summary,
		"total_intents":          len(intents),
		"assets_in_scope":        len(assets),
		"assets_targeted":        len(targeted),
		"coverage_pct":           pct,
		"total_applicable_cells": totalApplicable,
		"covered_cells":          coveredCells,
		"in_flight_cells":        stateCounts[coverageStateInFlight],
		"debt_cells":             stateCounts[coverageStateDebt],
		"inconclusive_cells":     stateCounts[coverageStateInconclusive],
		"untested_cells":         stateCounts[coverageStateUntested],
		"category_coverage":      categoryStats,
		"top_gaps":               topGaps,
		"zero_targeted_assets":   zeroTargeted,
		"zero_targeted_count":    zeroTargetedCount,
		"global_categories":      sortedCoverageKeys(globalCats),
		"unclassified_intents":   unclassified,
		"intent_state_counts":    intentStateCounts,
		"truncated":              intentsTruncated || factsTruncated || findingsTruncated || len(edges) >= 20000,
	}, nil
}

// coverageListNodes pages through a node kind instead of silently stopping at
// the old fixed 500-row cap. The cap keeps a pathological graph bounded while
// the truncated flag tells the caller the matrix is incomplete.
func (t *ToolSet) coverageListNodes(kind string, cap int) ([]*db.Node, bool, error) {
	if cap <= 0 {
		cap = 5000
	}
	out := make([]*db.Node, 0, cap)
	before := int64(0)
	for len(out) < cap {
		page, hasMore, err := t.ts.ListByKindPage(kind, before, 500)
		if err != nil {
			return nil, false, err
		}
		if len(page) == 0 {
			return out, false, nil
		}
		remaining := cap - len(out)
		if len(page) > remaining {
			out = append(out, page[:remaining]...)
			return out, true, nil
		}
		out = append(out, page...)
		if !hasMore {
			return out, false, nil
		}
		before = page[len(page)-1].ID
	}
	return out, true, nil
}

func coverageIntentEvidence(intentID int64, yields map[int64][]int64, facts, findings map[int64]*db.Node) (hasEvidence, observed, finding bool) {
	for _, id := range yields[intentID] {
		if _, ok := findings[id]; ok {
			finding = true
			hasEvidence = true
			continue
		}
		if f, ok := facts[id]; ok {
			hasEvidence = true
			if coverageFactObserved(f) {
				observed = true
			}
			continue
		}
		// The edge exists but the node fell outside the bounded load. Treat it as
		// evidence rather than inventing debt; truncated=true makes this explicit.
		hasEvidence = true
		observed = true
	}
	return hasEvidence, observed, finding
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
	if confidence == "inferred" {
		return false
	}
	if confidence == "observed" {
		return true
	}
	evidence, _ := p["evidence"].(string)
	return strings.TrimSpace(evidence) != ""
}

func coverageIntentState(state string, hasEvidence, observed, finding bool) (string, int, bool) {
	switch state {
	case "open", "paused":
		return coverageStateInFlight, coveragePriorityPlanned, false
	case "running":
		return coverageStateInFlight, coveragePriorityRunning, false
	case "done":
		if finding {
			return coverageStateCovered, coveragePriorityCovered, true
		}
		if hasEvidence && observed {
			return coverageStateCovered, coveragePriorityCovered, false
		}
		return coverageStateInconclusive, coveragePriorityInconclusive, false
	case "exhausted", "blocked":
		return coverageStateDebt, coveragePriorityDebt, false
	default:
		// stopped/deleted are explicitly not coverage and not debt.
		return "", coveragePriorityNone, false
	}
}

func mergeCoverageCell(byCat map[string]coverageCell, cat string, incoming coverageCell) {
	current, ok := byCat[cat]
	if !ok {
		byCat[cat] = incoming
		return
	}
	if incoming.priority > current.priority {
		incoming.inFlight = incoming.inFlight || current.inFlight
		incoming.positive = incoming.positive || current.positive
		byCat[cat] = incoming
		return
	}
	if incoming.priority == current.priority {
		current.intentIDs = append(current.intentIDs, incoming.intentIDs...)
	}
	current.inFlight = current.inFlight || incoming.inFlight
	current.positive = current.positive || incoming.positive
	byCat[cat] = current
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
		return a.Type == "app" || (a.Type == "endpoint" && coverageEndpointHasInput(a))
	case "injection":
		if a.Type == "app" || (a.Type == "service" && web) {
			return true
		}
		return a.Type == "endpoint" && coverageEndpointHasInput(a)
	case "xss":
		if a.Type == "app" || (a.Type == "service" && web) {
			return true
		}
		return a.Type == "endpoint" && (coverageEndpointHasInput(a) || strings.EqualFold(a.Method, "GET"))
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
		return a.Type == "app" || (a.Type == "endpoint" && coverageEndpointHasInput(a))
	case "config":
		return web || a.Type == "service" || a.Type == "app" || a.Type == "endpoint"
	case "infra":
		return a.Type == "ip" || a.Type == "service" || a.Type == "app" || a.Type == "endpoint"
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
	if a.URL != "" {
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
	if len(a.Params) > 0 {
		return true
	}
	if a.Method != "" && !strings.EqualFold(a.Method, "GET") {
		return true
	}
	return coverageEndpointLooksLikeLogin(a)
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
	for _, p := range a.Params {
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
