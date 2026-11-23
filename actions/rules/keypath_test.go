package rules

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// TestKeyPathsParse: every key path the engine writes for an inconclusive
// place of the end-to-end report reads back with lint.ParseKeyPath, so that
// an acceptance made from the report loads.
func TestKeyPathsParse(t *testing.T) {
	b, err := os.ReadFile("testdata/e2e.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Findings []struct {
			Certainty string `json:"certainty"`
			KeyPath   string `json:"key_path"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	inconclusive := 0
	for _, g := range rep.Findings {
		if g.Certainty == "inconclusive" {
			inconclusive++
		}
	}
	if inconclusive == 0 {
		t.Fatal("no inconclusive finding in the end-to-end report")
	}
	for _, g := range rep.Findings {
		if k, err := lint.ParseKeyPath(g.KeyPath); err != nil || k.String() != g.KeyPath {
			t.Errorf("ParseKeyPath(%q) = %v, %v", g.KeyPath, k, err)
		}
	}
}
