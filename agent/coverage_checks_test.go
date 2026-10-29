package agent

import (
	"encoding/json"
	"fmt"
	actool "github.com/Autumn-27/norma/tool"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestCoverageResultChecksRejectsUnverified(t *testing.T) {
	for _, tt := range []struct {
		name, kind, state, confidence, evidence string
		asset                                   int64
		want                                    int
	}{
		{"explicit observed", db.KindFact, "confirmed", "observed", "proof", 1, 1},
		{"empty observed", db.KindFact, "confirmed", "observed", " \n\t", 1, 0},
		{"inferred", db.KindFact, "confirmed", "inferred", "proof", 1, 0},
		{"missing confidence", db.KindFact, "confirmed", "", "proof", 1, 0},
		{"dismissed fact", db.KindFact, "dismissed", "observed", "proof", 1, 0},
		{"finding", db.KindFinding, "confirmed", "", "", 1, 1},
		{"dismissed finding", db.KindFinding, "dismissed", "", "proof", 1, 0},
		{"wrong asset", db.KindFact, "confirmed", "observed", "proof", 2, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			payload, _ := json.Marshal(map[string]any{"confidence": tt.confidence, "evidence": tt.evidence, "coverage_checks": []db.CoverageCheck{{AssetID: tt.asset, Category: "authz", Evidence: "cell proof"}}})
			n := &db.Node{Kind: tt.kind, State: tt.state, Payload: payload, Anchors: []int64{1}}
			if got := coverageResultChecks(n); len(got) != tt.want {
				t.Fatalf("got %v", got)
			}
		})
	}
	if got := coverageResultChecks(nil); len(got) != 0 {
		t.Fatal(got)
	}

}

func TestCoverageEndpointURLCandidates(t *testing.T) {
	for _, raw := range []string{"https://example.test/api/orders/123", "https://example.test/api/item?id=7", "https://example.test/orders", "https://example.test/login", "https://example.test/api/item/{id}", "https://example.test/api/item/123e4567-e89b-12d3-a456-426614174000"} {
		a := &db.Asset{Type: "endpoint", Method: "GET", URL: raw}
		for _, cat := range []string{"authz", "logic"} {
			if !coverageCategoryApplies(a, cat) {
				t.Fatalf("%s missing %s", raw, cat)
			}
		}
	}
	if !coverageCategoryApplies(&db.Asset{Type: "endpoint", Method: "GET", URL: "https://example.test/fetch?url=https%3A%2F%2Fexample.test"}, "ssrf") {
		t.Fatal("URL query not inspected for SSRF")
	}
}

func TestCoverageExplicitCellsAndFreshReads(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("explicit coverage", "test", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	as := d.Assets()
	ids := []int64{}
	for i := 0; i < 2; i++ {
		id, err := as.UpsertApp(db.UpsertAppReq{Name: fmt.Sprintf("coverage-%d-%d", task.ID, i), TaskID: task.ID})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	t.Cleanup(func() { _, _ = as.DeleteByIDs(ids) })
	tools := NewToolSet(d.Exploration(task.ExplorationID), "worker")
	tools.SetTaskID(task.ID)
	tools.SetAssetStore(as, d.Companies())
	assetRaws := []json.RawMessage{json.RawMessage(fmt.Sprint(ids[0])), json.RawMessage(fmt.Sprint(ids[1]))}
	intent, err := tools.addOneIntent(intentItem{Summary: "authz logic", Categories: []string{"authz", "logic"}, AssetIDs: assetRaws})
	if err != nil {
		t.Fatal(err)
	}
	read := func() map[string]any {
		t.Helper()
		out, err := tools.buildCoverageMatrix(50)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := read()
	if coverageInt64(before["covered_cells"]) != 0 {
		t.Fatal(before)
	}
	if _, err := tools.recordOneFact(factItem{Summary: "empty", Confidence: "observed", Evidence: " \n"}, intent); err == nil {
		t.Fatal("accepted empty observed")
	}
	_, err = tools.recordOneFact(factItem{Summary: "one check", Confidence: "observed", Evidence: "proof", AssetIDs: assetRaws, CoverageChecks: []db.CoverageCheck{{AssetID: ids[0], Category: "authz", Evidence: "object denied"}}}, intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := tools.ts.SetIntentState(intent, "done"); err != nil {
		t.Fatal(err)
	}
	after := read()
	if coverageInt64(after["covered_cells"]) != 1 || coverageInt64(after["pending_review_cells"]) != 3 {
		t.Fatalf("expected 1 covered and 3 review, got %v", after)
	}
	for _, gap := range after["top_gaps"].([]coverageGap) {
		for _, cat := range gap.Missing {
			if (gap.AssetID == ids[0] || gap.AssetID == ids[1]) && (cat == "authz" || cat == "logic") {
				t.Fatalf("review sent to gaps: %v", gap)
			}
		}
	}
	_, err = tools.addOneIntent(intentItem{Summary: "new config", Categories: []string{"config"}, AssetIDs: assetRaws})
	if err != nil {
		t.Fatal(err)
	}
	fresh := read()
	if coverageInt64(fresh["in_flight_cells"]) != 2 {
		t.Fatalf("stale read: %v", fresh)
	}
}

func TestCoverageMatrixUnloadedAndUnfinishedNeverCover(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"asset_ids": []int64{1}, "categories": []string{"authz"}})
	proof, _ := json.Marshal(map[string]any{"confidence": "observed", "evidence": "proof", "coverage_checks": []db.CoverageCheck{{AssetID: 1, Category: "authz", Evidence: "proof"}}})
	for _, tt := range []struct {
		name, state             string
		result                  *db.Node
		truncated               bool
		wantCovered, wantReview int
	}{
		{"legacy without explicit checks", "done", &db.Node{Kind: db.KindFact, State: "confirmed", Payload: json.RawMessage(`{"confidence":"observed","evidence":"proof"}`), Anchors: []int64{1}}, false, 0, 1},
		{"missing result", "done", nil, false, 0, 1},
		{"truncated missing result", "done", nil, true, 0, 0},
		{"open with evidence", "open", &db.Node{Kind: db.KindFact, State: "confirmed", Payload: proof, Anchors: []int64{1}}, false, 0, 0},
		{"done with evidence", "done", &db.Node{Kind: db.KindFact, State: "confirmed", Payload: proof, Anchors: []int64{1}}, false, 1, 0},
		{"dismissed", "done", &db.Node{Kind: db.KindFact, State: "dismissed", Payload: proof, Anchors: []int64{1}}, false, 0, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			graph := &db.CoverageEvidence{Intents: []*db.Node{{ID: 10, Kind: db.KindIntent, State: tt.state, Payload: payload, Anchors: []int64{1}}}, Results: map[int64][]*db.Node{10: {tt.result}}, Truncated: tt.truncated}
			out, err := coverageMatrixFromEvidence(graph, []*db.Asset{{ID: 1, Type: "endpoint", Method: "GET", URL: "https://example.test/health"}}, 50)
			if err != nil || coverageInt64(out["covered_cells"]) != int64(tt.wantCovered) || coverageInt64(out["pending_review_cells"]) != int64(tt.wantReview) {
				t.Fatalf("%v %v", out, err)
			}
			if tt.truncated && (len(out["top_gaps"].([]coverageGap)) != 0 || coverageInt64(out["unknown_cells"]) == 0) {
				t.Fatalf("truncated data created dispatchable gaps: %v", out)
			}
		})
	}
}

func TestCoverageMatrixSourceEvidenceOnlyClosesActualCell(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	source, err := d.CreateTask("matrix source", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	child, err := d.CreateTaskWithOptions("matrix child", "fixture", db.TaskCreateOptions{SourceTaskIDs: []int64{source.ID}})
	if err != nil {
		t.Fatal(err)
	}
	grandchild, err := d.CreateTaskWithOptions("matrix indirect", "fixture", db.TaskCreateOptions{SourceTaskIDs: []int64{child.ID}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(grandchild.ID); _ = d.DeleteTask(child.ID); _ = d.DeleteTask(source.ID) })
	as := d.Assets()
	ids := []int64{}
	for i := 0; i < 2; i++ {
		aid, err := as.UpsertApp(db.UpsertAppReq{Name: fmt.Sprintf("matrix-source-%d-%d", source.ID, i)})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, aid)
	}
	t.Cleanup(func() { _, _ = as.DeleteByIDs(ids) })
	sourceStore := d.Exploration(source.ExplorationID)
	iid, err := sourceStore.AddNode(db.KindIntent, map[string]any{"asset_ids": ids, "categories": []string{"authz", "logic"}}, 5, "done", "test", ids)
	if err != nil {
		t.Fatal(err)
	}
	fid, err := sourceStore.AddNode(db.KindFact, map[string]any{"confidence": "observed", "evidence": "proof", "coverage_checks": []db.CoverageCheck{{AssetID: ids[0], Category: "authz", Evidence: "denied"}}}, 5, "confirmed", "test", ids[:1])
	if err != nil {
		t.Fatal(err)
	}
	if err := sourceStore.Link(iid, db.RelYields, fid); err != nil {
		t.Fatal(err)
	}
	tools := NewToolSet(d.Exploration(child.ExplorationID), "planner")
	tools.SetTaskID(child.ID)
	tools.SetAssetStore(as, d.Companies())
	out, err := tools.buildCoverageMatrix(50)
	if err != nil {
		t.Fatal(err)
	}
	if coverageInt64(out["covered_cells"]) != 1 || coverageInt64(out["pending_review_cells"]) != 3 || coverageInt64(out["assets_in_scope"]) != 2 {
		t.Fatalf("source cells spread: %v", out)
	}
	indirect := NewToolSet(d.Exploration(grandchild.ExplorationID), "planner")
	indirect.SetTaskID(grandchild.ID)
	indirect.SetAssetStore(as, d.Companies())
	out, err = indirect.buildCoverageMatrix(50)
	if err != nil {
		t.Fatal(err)
	}
	if coverageInt64(out["covered_cells"]) != 0 || coverageInt64(out["assets_in_scope"]) != 0 {
		t.Fatal("indirect source counted")
	}
	if err := d.DeleteTask(source.ID); err != nil {
		t.Fatal(err)
	}
	out, err = tools.buildCoverageMatrix(50)
	if err != nil {
		t.Fatal(err)
	}
	if coverageInt64(out["covered_cells"]) != 0 || coverageInt64(out["assets_in_scope"]) != 0 {
		t.Fatal("deleted source counted or stale cached result")
	}
}

func TestCoverageReviewSuppressesDebtDispatch(t *testing.T) {
	payload := json.RawMessage(`{"asset_ids":[1],"categories":["authz"]}`)
	graph := &db.CoverageEvidence{Intents: []*db.Node{{ID: 1, State: "done", Payload: payload}, {ID: 2, State: "blocked", Payload: payload}}, Results: map[int64][]*db.Node{}}
	out, err := coverageMatrixFromEvidence(graph, []*db.Asset{{ID: 1, Type: "endpoint", URL: "https://example.test/health", Method: "GET"}}, 50)
	if err != nil {
		t.Fatal(err)
	}
	if coverageInt64(out["pending_review_cells"]) != 1 {
		t.Fatal("review lost to debt")
	}
	for _, gap := range out["top_gaps"].([]coverageGap) {
		for _, cat := range gap.Missing {
			if cat == "authz" {
				t.Fatal("historical review dispatched as debt")
			}
		}
	}
}

func TestCoverageWorkflowPreservesCustomGuidance(t *testing.T) {
	tools := NewToolSet(nil, "")
	custom := DecorateTool(tools.coverageMatrix(), "CUSTOM MATRIX", tools.coverageMatrix().InputSchema())
	out, guidance := coverageWorkflowTools([]actool.CoreTool{custom, tools.recordFact(), tools.addFinding()})
	if len(out) != 3 || !strings.HasPrefix(out[0].Description(), "CUSTOM MATRIX") || !strings.Contains(guidance, "待核实") || !strings.Contains(guidance, "coverage_checks") {
		t.Fatal("coverage contract missing or replaced custom description")
	}
	oldResolve, oldAugment := ToolResolve, ToolAugment
	ToolResolve, ToolAugment = nil, nil
	defer func() { ToolResolve, ToolAugment = oldResolve, oldAugment }()
	_, def, cleanup := AugmentTools(t.Context(), "planner", []actool.CoreTool{custom})
	defer cleanup()
	system, _ := deferredSystem("USER PROMPT", def)
	if def.CoverageGuidance == "" || !strings.Contains(system[0], "待核实") || !strings.HasPrefix(system[0], "USER PROMPT") {
		t.Fatal("coverage guidance missing from persisted prompt assembly")
	}

	if out, guidance := coverageWorkflowTools(nil); len(out) != 0 || guidance != "" {
		t.Fatal("reintroduced disabled tools")
	}
}
