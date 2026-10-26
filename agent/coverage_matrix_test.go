package agent

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestCoverageCategoryApplicability(t *testing.T) {
	sshPort := 22
	ssh := &db.Asset{Type: "service", ServiceName: "ssh", Port: &sshPort}
	if !coverageCategoryApplies(ssh, "auth") {
		t.Fatal("SSH service should be applicable to auth")
	}
	if coverageCategoryApplies(ssh, "xss") {
		t.Fatal("SSH service must not be applicable to XSS")
	}
	if coverageCategoryApplies(ssh, "ssrf") {
		t.Fatal("SSH service must not be applicable to SSRF")
	}
	if coverageCategoryApplies(ssh, "logic") {
		t.Fatal("SSH service must not be applicable to business logic")
	}

	httpPort := 443
	http := &db.Asset{Type: "service", ServiceType: "http", ServiceName: "nginx", URL: "https://example.test/", Port: &httpPort}
	for _, cat := range []string{"auth", "injection", "xss", "ssrf", "file", "config"} {
		if !coverageCategoryApplies(http, cat) {
			t.Fatalf("HTTP service should be applicable to %s", cat)
		}
	}
	if coverageCategoryApplies(http, "logic") {
		t.Fatal("a bare HTTP service should not be treated as a business-logic app")
	}

	app := &db.Asset{Type: "app", AppName: "portal"}
	for _, cat := range []string{"auth", "authz", "injection", "xss", "ssrf", "file", "logic", "config", "infra"} {
		if !coverageCategoryApplies(app, cat) {
			t.Fatalf("app should be applicable to %s", cat)
		}
	}

	root := &db.Asset{Type: "root_domain", RootDomain: "example.test"}
	if !coverageCategoryApplies(root, "recon") {
		t.Fatal("root domain should be applicable to recon")
	}
	if coverageCategoryApplies(root, "xss") || coverageCategoryApplies(root, "authz") {
		t.Fatal("root domain must not be applicable to web/authorization categories")
	}

	health := &db.Asset{Type: "endpoint", URL: "https://example.test/health", Method: "GET"}
	if coverageCategoryApplies(health, "ssrf") {
		t.Fatal("static GET endpoint without URL params should not be applicable to SSRF")
	}
	if coverageCategoryApplies(health, "authz") {
		t.Fatal("static GET endpoint without input should not be applicable to authz")
	}
	if coverageCategoryApplies(health, "xss") {
		t.Fatal("static GET endpoint without input should not be applicable to XSS")
	}
	if coverageCategoryApplies(health, "infra") {
		t.Fatal("individual endpoints should not be reported as infra/supply-chain cells")
	}
	for _, method := range []string{"HEAD", "OPTIONS"} {
		ep := &db.Asset{Type: "endpoint", URL: "https://example.test/status", Method: method}
		if coverageEndpointHasInput(ep) {
			t.Fatalf("%s without params must not count as input", method)
		}
		if coverageCategoryApplies(ep, "authz") {
			t.Fatalf("%s without params must not be applicable to authz", method)
		}
	}

	search := &db.Asset{
		Type:   "endpoint",
		URL:    "https://example.test/fetch",
		Method: "POST",
		Params: []map[string]any{{"name": "url", "location": "body"}},
	}
	for _, cat := range []string{"injection", "xss", "ssrf", "file", "logic", "authz"} {
		if !coverageCategoryApplies(search, cat) {
			t.Fatalf("parameterized endpoint should be applicable to %s", cat)
		}
	}
}

func TestCoverageIntentState(t *testing.T) {
	tests := []struct {
		name         string
		state        string
		hasEvidence  bool
		observed     bool
		finding      bool
		wantState    string
		wantPositive bool
	}{
		{name: "open is in flight", state: "open", wantState: coverageStateInFlight},
		{name: "running is in flight", state: "running", wantState: coverageStateInFlight},
		{name: "observed fact covers", state: "done", hasEvidence: true, observed: true, wantState: coverageStateCovered},
		{name: "finding covers positively", state: "done", hasEvidence: true, finding: true, wantState: coverageStateCovered, wantPositive: true},
		{name: "inferred fact is inconclusive", state: "done", hasEvidence: true, wantState: coverageStateInconclusive},
		{name: "done without evidence is inconclusive", state: "done", wantState: coverageStateInconclusive},
		{name: "exhausted is debt", state: "exhausted", wantState: coverageStateDebt},
		{name: "blocked is debt", state: "blocked", wantState: coverageStateDebt},
		{name: "deleted is excluded", state: "deleted", wantState: ""},
		{name: "stopped is excluded", state: "stopped", wantState: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, _, positive := coverageIntentState(tt.state, tt.hasEvidence, tt.observed, tt.finding)
			if state != tt.wantState || positive != tt.wantPositive {
				t.Fatalf("state=%q positive=%v, want state=%q positive=%v", state, positive, tt.wantState, tt.wantPositive)
			}
		})
	}
}

func TestCoverageIntentEvidenceRequiresConfirmedNodes(t *testing.T) {
	payload := func(confidence, evidence string) json.RawMessage {
		raw, err := json.Marshal(map[string]any{"confidence": confidence, "evidence": evidence})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	facts := map[int64]*db.Node{
		1: {ID: 1, Kind: db.KindFact, State: "confirmed", Payload: payload("observed", "saw it")},
		2: {ID: 2, Kind: db.KindFact, State: "dismissed", Payload: payload("observed", "saw it")},
		3: {ID: 3, Kind: db.KindFact, State: "confirmed", Payload: payload("inferred", "looks like it")},
	}
	findings := map[int64]*db.Node{
		4: {ID: 4, Kind: db.KindFinding, State: "confirmed"},
		5: {ID: 5, Kind: db.KindFinding, State: "dismissed"},
	}
	yields := map[int64][]int64{10: {1, 2, 3, 4, 5}}

	has, observed, finding := coverageIntentEvidence(10, yields, facts, findings)
	if !has || !observed || !finding {
		t.Fatalf("confirmed evidence: has=%v observed=%v finding=%v, want true/true/true", has, observed, finding)
	}

	// Dismissed children are not evidence at all.
	has, observed, finding = coverageIntentEvidence(10, map[int64][]int64{10: {2, 5}}, facts, findings)
	if has || observed || finding {
		t.Fatalf("dismissed evidence: has=%v observed=%v finding=%v, want all false", has, observed, finding)
	}
	// An inferred fact is evidence for "tried", but not observed coverage.
	has, observed, finding = coverageIntentEvidence(10, map[int64][]int64{10: {3}}, facts, findings)
	if !has || observed || finding {
		t.Fatalf("inferred evidence: has=%v observed=%v finding=%v, want true/false/false", has, observed, finding)
	}
}

func TestCoverageIntentTargetsExcludesStoppedAndDeleted(t *testing.T) {
	for _, state := range []string{"stopped", "deleted"} {
		if coverageIntentTargets(state) {
			t.Fatalf("state %q must not mark assets as targeted", state)
		}
	}
	for _, state := range []string{"open", "running", "done", "exhausted", "blocked", "paused"} {
		if !coverageIntentTargets(state) {
			t.Fatalf("state %q should mark assets as targeted", state)
		}
	}
}

func TestCoverageIntentCategoriesUsesStructuredField(t *testing.T) {
	p := map[string]any{"categories": []any{"authz", "LOGIC", "bogus", "authz", ""}}
	got := coverageIntentCategories(p)
	if fmt.Sprint(got) != "[authz logic]" {
		t.Fatalf("categories=%v, want [authz logic]", got)
	}
	if _, err := normalizeCoverageCategories([]string{"authz", "typo"}); err == nil {
		t.Fatal("unknown category must be rejected on write")
	}
}

func TestCoverageMatrixForTopNSlicesWithoutMutatingBase(t *testing.T) {
	base := map[string]any{
		"top_gaps": []coverageGap{{AssetID: 1}, {AssetID: 2}, {AssetID: 3}},
		"summary":  "x",
	}
	out := coverageMatrixForTopN(base, 2)
	gaps, _ := out["top_gaps"].([]coverageGap)
	if len(gaps) != 2 || gaps[1].AssetID != 2 {
		t.Fatalf("top_n slice = %+v, want first two gaps", gaps)
	}
	baseGaps, _ := base["top_gaps"].([]coverageGap)
	if len(baseGaps) != 3 {
		t.Fatalf("base cache mutated: %+v", baseGaps)
	}
}

func TestCoveragePayloadAssetIDs(t *testing.T) {
	p := map[string]any{"asset_ids": []any{float64(3), float64(3), float64(7)}}
	got := coveragePayloadAssetIDs(p)
	if fmt.Sprint(got) != "[3 7]" {
		t.Fatalf("asset ids=%v, want [3 7]", got)
	}
	if got := coveragePayloadAssetIDs(map[string]any{"target_id": float64(9)}); fmt.Sprint(got) != "[9]" {
		t.Fatalf("legacy target_id=%v, want [9]", got)
	}
}

func TestCoverageMatrixCountsUntestedAndExcludesExhausted(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTask("coverage matrix test", "test coverage", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	suffix := time.Now().UnixNano()
	root := fmt.Sprintf("coverage-%d.test", suffix)
	httpHost := "http." + root
	sshHost := "ssh." + root
	debtHost := "debt." + root
	untestedHost := "untested." + root
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM assets WHERE root_domain=$1 OR domain=$1 OR domain LIKE $2 OR domain LIKE $3 OR domain LIKE $4 OR domain LIKE $5 OR domain LIKE $6`,
			root, "%."+root, "%."+root, "%."+root, "%."+root, "%."+root)
	})

	assets := d.Assets()
	httpID, err := assets.UpsertHTTPService(db.UpsertHTTPServiceReq{URL: "https://" + httpHost + "/", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	sshID, err := assets.UpsertOtherService(db.UpsertOtherServiceReq{
		Domain: sshHost, IP: "192.0.2.41", Port: 22, ServiceName: "ssh", TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	debtID, err := assets.UpsertOtherService(db.UpsertOtherServiceReq{
		Domain: debtHost, IP: "192.0.2.42", Port: 22, ServiceName: "ssh", TaskID: task.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assets.UpsertHTTPService(db.UpsertHTTPServiceReq{URL: "https://" + untestedHost + "/", TaskID: task.ID}); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{httpHost, sshHost, debtHost, untestedHost} {
		if _, err := assets.AddAgentScope(task.ID, "subdomain", host, "coverage test", "manual"); err != nil {
			t.Fatal(err)
		}
	}

	tools := NewToolSet(d.Exploration(task.ExplorationID), "planner")
	tools.SetTaskID(task.ID)
	tools.SetAssetStore(assets, d.Companies())

	intentFor := func(summary string, assetID int64) int64 {
		raw, _ := json.Marshal(assetID)
		id, err := tools.addOneIntent(intentItem{Summary: summary, AssetIDs: []json.RawMessage{raw}})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	// HTTP XSS exploration is in flight, not covered.
	intentFor("测试 XSS 与 SQL 注入", httpID)

	// SSH auth was attempted with an observed negative fact => covered.
	sshIntent := intentFor("测试 SSH 默认口令", sshID)
	rawSSH, _ := json.Marshal(sshID)
	rawSSHIntent, _ := json.Marshal(sshIntent)
	if _, err := tools.recordOneFact(factItem{
		Summary:    "SSH 默认口令不存在",
		Evidence:   "ssh login with root/root failed",
		Confidence: "observed",
		IntentID:   rawSSHIntent,
		AssetIDs:   []json.RawMessage{rawSSH},
	}, sshIntent); err != nil {
		t.Fatal(err)
	}
	if err := d.Exploration(task.ExplorationID).SetIntentState(sshIntent, "done"); err != nil {
		t.Fatal(err)
	}

	// Exhausted SSH work is debt, not coverage.
	debtIntent := intentFor("测试 SSH 默认口令", debtID)
	if err := d.Exploration(task.ExplorationID).SetIntentState(debtIntent, "exhausted"); err != nil {
		t.Fatal(err)
	}

	out := callReadJSON(t, tools.coverageMatrix(), `{"top_n":20}`).(map[string]any)
	if got := coverageInt64(out["assets_in_scope"]); got < 4 {
		t.Fatalf("assets_in_scope=%d, want >=4", got)
	}
	if got := coverageInt64(out["zero_targeted_count"]); got < 1 {
		t.Fatalf("zero_targeted_count=%d, want >=1", got)
	}
	if pct := coverageInt64(out["coverage_pct"]); pct >= 100 {
		t.Fatalf("coverage_pct=%d, should not be 100%% when most cells are untested", pct)
	}

	sshGap := coverageGapForAsset(t, out, sshID)
	if sshGap == nil {
		t.Fatal("expected SSH asset in top_gaps")
	}
	if coverageStrings(sshGap["missing"])["xss"] {
		t.Fatal("SSH asset must not be reported as missing XSS")
	}
	if coverageStrings(sshGap["covered"])["auth"] != true {
		t.Fatalf("SSH auth should be covered, got covered=%v missing=%v", sshGap["covered"], sshGap["missing"])
	}

	debtGap := coverageGapForAsset(t, out, debtID)
	if debtGap == nil {
		t.Fatal("expected exhausted SSH asset in top_gaps")
	}
	if fmt.Sprint(debtGap["state"]) != coverageStateDebt {
		t.Fatalf("exhausted asset state=%v, want %q", debtGap["state"], coverageStateDebt)
	}
	if !coverageStrings(debtGap["missing"])["auth"] {
		t.Fatalf("exhausted SSH auth should remain missing, got %v", debtGap["missing"])
	}

	httpGap := coverageGapForAsset(t, out, httpID)
	if httpGap == nil {
		t.Fatal("expected HTTP asset in top_gaps")
	}
	if fmt.Sprint(httpGap["state"]) != coverageStateInFlight {
		t.Fatalf("open HTTP intent should be in_flight, got %v", httpGap["state"])
	}
}

func coverageGapForAsset(t *testing.T, out map[string]any, assetID int64) map[string]any {
	t.Helper()
	gaps, _ := out["top_gaps"].([]any)
	for _, raw := range gaps {
		gap, ok := raw.(map[string]any)
		if ok && coverageInt64(gap["asset_id"]) == assetID {
			return gap
		}
	}
	return nil
}

func coverageStrings(v any) map[string]bool {
	out := map[string]bool{}
	list, _ := v.([]any)
	for _, item := range list {
		out[fmt.Sprint(item)] = true
	}
	return out
}
