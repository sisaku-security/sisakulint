package rules

import "testing"

// TestExpressionIfText: an if of text and ${{ }} is cond's; expression
// reports nothing of the object in it, and reports the object in the run.
func TestExpressionIfText(t *testing.T) {
	src := "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - if: ${{ github.event }} == x\n        run: echo ${{ github.event }}\n"
	var kinds []string
	for _, f := range qualityReport(t, ExpressionRuleID, src, nil).QualityFindings {
		kinds = append(kinds, f.Args.KindID().String())
	}
	if len(kinds) != 1 || kinds[0] != "expression.embedded-object" {
		t.Fatalf("quality findings %v", kinds)
	}
}

// TestExpressionAnchor: the same expression at two places has the anchor
// of its place, so that removing one leaves the fingerprint of the other.
func TestExpressionAnchor(t *testing.T) {
	two := "on: push\njobs:\n  a:\n    runs-on: x\n    timeout-minutes: ${{ vars.T }}\n    steps: [{run: a}]\n  b:\n    runs-on: x\n    timeout-minutes: ${{ vars.T }}\n    steps: [{run: a}]\n"
	one := "on: push\njobs:\n  b:\n    runs-on: x\n    timeout-minutes: ${{ vars.T }}\n    steps: [{run: a}]\n"
	fs := qualityReport(t, ExpressionRuleID, two, nil).QualityFindings
	g := qualityReport(t, ExpressionRuleID, one, nil).QualityFindings
	if len(fs) != 2 || len(g) != 1 || fs[1].Fingerprint != g[0].Fingerprint {
		t.Fatalf("fingerprints %d %d: %v %v", len(fs), len(g), fs, g)
	}
}
