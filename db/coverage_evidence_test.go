package db

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestCoverageEvidenceDirectSourcesAndLimits(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	grand, err := d.CreateTask("coverage grand", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	source, err := d.CreateTaskWithOptions("coverage source", "fixture", TaskCreateOptions{SourceTaskIDs: []int64{grand.ID}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := d.CreateTaskWithOptions("coverage current", "fixture", TaskCreateOptions{SourceTaskIDs: []int64{source.ID}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(current.ID); _ = d.DeleteTask(source.ID); _ = d.DeleteTask(grand.ID) })
	as := d.Assets()
	aid, err := as.UpsertApp(UpsertAppReq{Name: fmt.Sprintf("coverage-source-%d", source.ID)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = as.DeleteByIDs([]int64{aid}) })
	makeProof := func(task *Task) (int64, int64) {
		t.Helper()
		store := d.Exploration(task.ExplorationID)
		iid, err := store.AddNode(KindIntent, map[string]any{"categories": []string{"authz", "logic"}, "asset_ids": []int64{aid}}, 5, "done", "test", []int64{aid})
		if err != nil {
			t.Fatal(err)
		}
		fid, err := store.AddNode(KindFact, map[string]any{"confidence": "observed", "evidence": "proof", "coverage_checks": []CoverageCheck{{AssetID: aid, Category: "authz", Evidence: "proof"}}}, 5, "confirmed", "test", []int64{aid})
		if err != nil {
			t.Fatal(err)
		}
		if err = store.Link(iid, RelYields, fid); err != nil {
			t.Fatal(err)
		}
		return iid, fid
	}
	grandIntent, grandFact := makeProof(grand)
	sourceIntent, sourceFact := makeProof(source)
	currentIntent, _ := makeProof(current)
	// A local edge pointing into an indirect exploration must not smuggle evidence.
	if err := d.Exploration(current.ExplorationID).Link(currentIntent, RelYields, grandFact); err != nil {
		t.Fatal(err)
	}
	// Newer unrelated facts must not crowd out evidence linked to selected intents.
	for i := 0; i < 3; i++ {
		if _, err := d.Exploration(current.ExplorationID).AddNode(KindFact, map[string]any{"confidence": "observed", "evidence": "unrelated"}, 5, "confirmed", "test", nil); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := d.Exploration(current.ExplorationID).CoverageEvidenceWithSources(current.ID, 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	if graph.Truncated || len(graph.Intents) != 2 || len(graph.Results[sourceIntent]) != 1 || len(graph.Results[grandIntent]) != 0 {
		t.Fatalf("unexpected graph: %+v", graph)
	}
	if graph.Results[sourceIntent][0].ID != sourceFact || !graph.Results[sourceIntent][0].Inherited {
		t.Fatal("lost source provenance")
	}
	for _, result := range graph.Results[currentIntent] {
		if result.ID == grandFact {
			t.Fatal("cross-exploration evidence leaked")
		}
	}
	// Result caps expose unknown state rather than guessing at missing nodes.
	limited, err := d.Exploration(current.ExplorationID).CoverageEvidenceWithSources(current.ID, 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !limited.Truncated {
		t.Fatal("missing result truncation flag")
	}
	limited, err = d.Exploration(current.ExplorationID).CoverageEvidenceWithSources(current.ID, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !limited.Truncated || len(limited.Intents) != 1 {
		t.Fatal("missing intent truncation flag")
	}
	exact, err := d.Exploration(current.ExplorationID).CoverageEvidenceWithSources(current.ID, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if exact.Truncated {
		t.Fatal("exactly full read falsely truncated")
	}
	// The matrix uses only the actual source cell and deduplicates shared assets.
	assets, err := as.ListCoverageAssetsWithSources(current.ID)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, a := range assets {
		if a.ID == aid {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("shared asset count=%d", count)
	}
	if err := d.DeleteTask(source.ID); err != nil {
		t.Fatal(err)
	}
	graph, err = d.Exploration(current.ExplorationID).CoverageEvidenceWithSources(current.ID, 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Intents) != 1 || len(graph.Results[sourceIntent]) != 0 {
		t.Fatal("deleted source still visible")
	}
}

func TestCoverageFindingChecksAtomicValidation(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	task, err := d.CreateTask("finding checks", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	aid, err := d.Assets().UpsertApp(UpsertAppReq{Name: fmt.Sprintf("finding-checks-%d", task.ID)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Assets().DeleteByIDs([]int64{aid}) })
	store := d.Exploration(task.ExplorationID)
	input := RecordFindingInput{TaskID: task.ID, ExplorationID: task.ExplorationID, Summary: "verified", Severity: "low", Evidence: "proof", AssetIDs: []int64{aid}, CoverageChecks: []CoverageCheck{{AssetID: aid, Category: "authz", Evidence: "denied"}}}
	saved, err := store.RecordFinding(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.GetNode(saved.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Checks []CoverageCheck `json:"coverage_checks"`
	}
	if err := json.Unmarshal(node.Payload, &p); err != nil || len(p.Checks) != 1 {
		t.Fatalf("checks lost: %s %v", node.Payload, err)
	}
	input.CoverageChecks[0].Category = "invalid"
	if _, err := store.RecordFinding(t.Context(), input); err == nil {
		t.Fatal("accepted invalid finding check")
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, task.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("non-atomic validation: count=%d err=%v", count, err)
	}
}

func TestCoverageAssetVerificationMetricsAgree(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	source, err := d.CreateTask("metric source", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	current, err := d.CreateTaskWithOptions("metric current", "fixture", TaskCreateOptions{SourceTaskIDs: []int64{source.ID}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(current.ID); _ = d.DeleteTask(source.ID) })
	as := d.Assets()
	ids := []int64{}
	t.Cleanup(func() { _, _ = as.DeleteByIDs(ids) })
	store := d.Exploration(source.ExplorationID)
	for i, tt := range []struct {
		kind, state string
		payload     map[string]any
	}{
		{KindFinding, "confirmed", map[string]any{"evidence": map[string]any{"poc": "verified command"}}},
		{KindFact, "confirmed", map[string]any{"confidence": "observed", "evidence": "proof"}},
		{KindFact, "confirmed", map[string]any{"confidence": "observed", "evidence": " \n\t\r"}},
		{KindFact, "confirmed", map[string]any{"confidence": "inferred", "evidence": "proof"}},
		{KindFact, "dismissed", map[string]any{"confidence": "observed", "evidence": "proof"}},
		{KindFinding, "dismissed", map[string]any{"evidence": "proof"}},
		{KindFinding, "confirmed", map[string]any{"evidence": map[string]any{"poc": " \n\t"}}},
		{KindFact, "confirmed", map[string]any{"evidence": "legacy unlabelled proof"}},
		{KindFinding, "confirmed", map[string]any{"evidence": "legacy finding proof"}},
		{KindFact, "confirmed", map[string]any{"confidence": "observed", "evidence": "\u3000\u00a0\t\n"}},
		{KindFinding, "confirmed", map[string]any{"evidence": map[string]any{"poc": "\u3000\u00a0"}}},
		{KindFact, "confirmed", map[string]any{"confidence": "\tOBSERVED\n", "evidence": "proof"}},
	} {
		id, err := as.UpsertApp(UpsertAppReq{Name: fmt.Sprintf("metric-%d-%d", source.ID, i)})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		if _, err := store.AddNode(tt.kind, tt.payload, 5, tt.state, "test", []int64{id}); err != nil {
			t.Fatal(err)
		}
	}
	// The same validated asset in both tasks remains one asset in the numerator.
	if _, err := d.Exploration(current.ExplorationID).AddNode(KindFact, map[string]any{"confidence": "observed", "evidence": "same asset"}, 5, "confirmed", "test", ids[:1]); err != nil {
		t.Fatal(err)
	}
	cov, err := as.TaskCoverageWithSources(current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Denominator != 12 || cov.Tested != 4 {
		t.Fatalf("wrong asset metric: %+v", cov)
	}
	backlog, total, err := as.ListUntestedAssetsWithSources(current.ID, "", 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 8 || len(backlog) != 8 {
		t.Fatalf("wrong backlog: %d %v", total, backlog)
	}
	tested := map[int64]bool{ids[0]: true, ids[1]: true, ids[8]: true, ids[11]: true}
	for _, a := range backlog {
		if tested[a.ID] {
			t.Fatal("verified asset still in backlog")
		}
	}
	graph, err := as.BuildCoverageGraph(current.ID, current.ExplorationID)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, node := range graph.Nodes {
		if node.AssetID > 0 && node.InScope {
			count++
			if node.Tested != tested[node.AssetID] {
				t.Fatalf("graph disagrees on %d", node.AssetID)
			}
		}
	}
	if count != 12 {
		t.Fatalf("graph denominator=%d", count)
	}
	legacy, err := as.TaskCoverage(source.ID, source.ExplorationID)
	if err != nil {
		t.Fatal(err)
	}
	// Legacy APIs still share the same verification predicate (their denominator is scope-only).
	if legacy.Tested != 0 {
		t.Fatalf("unexpected scoped assets: %+v", legacy)
	}
}
