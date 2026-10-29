package server

import (
	"encoding/json"
	"log"

	"github.com/Autumn-27/artex/agent"
)

// Upgrade optional schema properties only. Existing descriptions, defaults,
// binding choices and disabled tools remain under the user's control.
func (s *Server) seedCoverageTools() {
	const flag = "coverage_checks_tools_v1"
	if value, _, _ := s.m.pg.GetSetting(flag); value == "true" {
		return
	}
	for _, seed := range agent.BuiltinToolSeeds() {
		if seed.Key != "record_fact" && seed.Key != "report_finding" {
			continue
		}
		row, err := s.m.pg.GetTool(seed.Key)
		if err != nil {
			log.Printf("[coverage] load %s: %v", seed.Key, err)
			return
		}
		if row == nil || !row.System {
			continue
		}
		var schema map[string]any
		if err := json.Unmarshal(row.Schema, &schema); err != nil || schema == nil {
			log.Printf("[coverage] invalid schema for %s", seed.Key)
			return
		}
		props := objectProperty(schema, "properties")
		property := seed.Schema["properties"].(map[string]any)["coverage_checks"]
		if _, exists := props["coverage_checks"]; !exists {
			props["coverage_checks"] = property
		}
		if seed.Key == "record_fact" {
			facts := objectProperty(props, "facts")
			if _, exists := facts["type"]; !exists {
				facts["type"] = "array"
			}
			items := objectProperty(facts, "items")
			if _, exists := items["type"]; !exists {
				items["type"] = "object"
			}
			itemProps := objectProperty(items, "properties")
			if _, exists := itemProps["coverage_checks"]; !exists {
				itemProps["coverage_checks"] = property
			}
		}
		raw, err := json.Marshal(schema)
		if err != nil {
			return
		}
		if _, err := s.m.pg.Exec(`UPDATE tools SET schema=$2::jsonb,updated_at=now() WHERE key=$1 AND system`, seed.Key, string(raw)); err != nil {
			log.Printf("[coverage] upgrade %s: %v", seed.Key, err)
			return
		}
	}
	_ = s.m.pg.SetSetting(flag, "true")
}
