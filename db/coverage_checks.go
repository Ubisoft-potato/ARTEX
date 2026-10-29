package db

import (
	"fmt"
	"strings"
)

// CoverageCheck records only the asset and category actually verified by a result.
type CoverageCheck struct {
	AssetID  int64  `json:"asset_id"`
	Category string `json:"category"`
	Evidence string `json:"evidence"`
}

func NormalizeCoverageChecks(checks []CoverageCheck, assets []int64) ([]CoverageCheck, error) {
	allowed := map[int64]bool{}
	for _, id := range assets {
		allowed[id] = id > 0
	}
	categories := map[string]bool{}
	for _, cat := range CoverageCategoryKeys {
		categories[cat] = true
	}
	seen := map[CoverageCheck]bool{}
	out := make([]CoverageCheck, 0, len(checks))
	for _, check := range checks {
		check.Category = strings.ToLower(strings.TrimSpace(check.Category))
		check.Evidence = strings.TrimSpace(check.Evidence)
		if !allowed[check.AssetID] {
			return nil, fmt.Errorf("coverage_checks.asset_id 必须属于本结果的关联资产")
		}
		if !categories[check.Category] {
			return nil, fmt.Errorf("coverage_checks.category 必须属于现有十类")
		}
		if check.Evidence == "" {
			return nil, fmt.Errorf("coverage_checks.evidence 不能为空")
		}
		key := CoverageCheck{AssetID: check.AssetID, Category: check.Category}
		if seen[key] {
			return nil, fmt.Errorf("coverage_checks 不能重复登记相同资产和类别")
		}
		seen[key] = true
		out = append(out, check)
	}
	return out, nil
}

var CoverageCategoryKeys = []string{"recon", "auth", "authz", "injection", "xss", "ssrf", "file", "logic", "config", "infra"}
