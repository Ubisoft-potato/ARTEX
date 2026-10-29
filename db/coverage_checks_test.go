package db

import "testing"

func TestNormalizeCoverageChecks(t *testing.T) {
	valid := CoverageCheck{AssetID: 7, Category: " AUTHZ ", Evidence: " proof \n"}
	got, err := NormalizeCoverageChecks([]CoverageCheck{valid}, []int64{7, 8})
	if err != nil || len(got) != 1 || got[0].Category != "authz" || got[0].Evidence != "proof" {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, checks := range [][]CoverageCheck{
		{{AssetID: 8, Category: "authz", Evidence: "proof"}},
		{{AssetID: 7, Category: "unknown", Evidence: "proof"}},
		{{AssetID: 7, Category: "authz", Evidence: " \t\n"}},
		{valid, valid},
	} {
		if _, err := NormalizeCoverageChecks(checks, []int64{7}); err == nil {
			t.Fatalf("accepted invalid checks: %v", checks)
		}
	}
}
