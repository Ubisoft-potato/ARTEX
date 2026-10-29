package server

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCoverageToolsUpgradePreservesCustomization(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	for _, key := range []string{"record_fact", "report_finding"} {
		old, err := pg.GetTool(key)
		if err != nil || old == nil {
			t.Fatal("missing tool", key, err)
		}
		t.Cleanup(func() {
			bindings, _ := json.Marshal(old.Agents)
			_ = pg.UpdateTool(old.Key, old.Description, old.Schema, bindings, old.Enabled)
		})
		schema := json.RawMessage(`{"type":"object","properties":{"summary":{"type":"string","description":"USER SUMMARY","default":"custom default"},"facts":{"type":"array","items":{"type":"object","description":"USER ITEM"}}}}`)
		if err := pg.UpdateTool(key, "USER DESCRIPTION", schema, json.RawMessage(`["custom-agent"]`), false); err != nil {
			t.Fatal(err)
		}
	}
	if err := pg.SetSetting("coverage_checks_tools_v1", "false"); err != nil {
		t.Fatal(err)
	}
	s.seedCoverageTools()
	for _, key := range []string{"record_fact", "report_finding"} {
		row, err := pg.GetTool(key)
		if err != nil {
			t.Fatal(err)
		}
		if row.Enabled || row.Description != "USER DESCRIPTION" || len(row.Agents) != 1 || row.Agents[0] != "custom-agent" {
			t.Fatal("changed user configuration")
		}
		for _, term := range []string{"USER SUMMARY", "custom default", "USER ITEM", "coverage_checks"} {
			if !strings.Contains(string(row.Schema), term) {
				t.Fatalf("lost %s from %s", term, key)
			}
		}
		var schema map[string]any
		if err := json.Unmarshal(row.Schema, &schema); err != nil {
			t.Fatal(err)
		}
		props := schema["properties"].(map[string]any)
		if key == "record_fact" {
			nested := props["facts"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
			if nested["coverage_checks"] == nil {
				t.Fatal("missing batch check schema")
			}
		}
	}
}
