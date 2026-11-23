package reportview

import (
	"context"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/rules"
)

// TestBuildAddedAttackers: a finding that only an added attacker gives
// carries its mark to the page.
func TestBuildAddedAttackers(t *testing.T) {
	src := "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  test:\n    if: github.event.label.name == 'safe to test'\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: make test\n"
	in, err := lint.Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte(src)}})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := lint.NewRegistry(rules.All())
	if err != nil {
		t.Fatal(err)
	}
	rep := lint.RunAdded(context.Background(), in, reg, facts.Assume(offline{}), []lint.AddedAttacker{lint.AddedAttackerTriageAccount})
	p, err := Build(rep, in, reg)
	if err != nil {
		t.Fatal(err)
	}
	marked := 0
	for _, f := range p.Findings {
		if f.Rule.String() == "untrusted-checkout" && slices.Equal(f.AddedAttackers, []lint.AddedAttacker{lint.AddedAttackerTriageAccount}) {
			marked++
		}
	}
	if marked != 1 {
		t.Errorf("%d marked findings of untrusted-checkout, want 1", marked)
	}
}
