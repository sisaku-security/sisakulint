package reportview

import (
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

const runsOnInput = `on:
  workflow_dispatch:
    inputs:
      runner:
        type: string
permissions: {}
jobs:
  a:
    runs-on: ${{ inputs.runner }}
    steps:
      - run: echo hi
  b:
    runs-on: ${{ inputs.runner }}
    steps:
      - run: echo hi
`

// TestBuildAcceptance: an accepted inconclusive place has the reason of its
// acceptance; one not accepted has none.
func TestBuildAcceptance(t *testing.T) {
	rep, in := runOn(t, map[string]string{".github/workflows/w.yml": runsOnInput})
	if len(rep.FindingsWith(lint.CertaintyInconclusive)) != 2 {
		t.Fatalf("inconclusive %+v", rep.FindingsWith(lint.CertaintyInconclusive))
	}
	g := rep.FindingsWith(lint.CertaintyInconclusive)[0]
	rep, _ = lint.Accept(rep, []lint.Acceptance{{Rule: g.Rule, KindID: g.InconclusiveKind, Input: g.Location.File.Input, KeyPath: g.KeyPath,
		SpanText: g.SpanText, SpanLines: g.SpanLines, Reason: "the runner is chosen from our own list"}})
	p, err := Build(rep, in, testRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	var inconclusive []Finding
	for _, x := range p.Findings {
		if x.Certainty == lint.CertaintyInconclusive {
			inconclusive = append(inconclusive, x)
		}
	}
	if len(inconclusive) != 2 || inconclusive[0].Acceptance != "the runner is chosen from our own list" || inconclusive[1].Acceptance != "" {
		t.Errorf("inconclusive %+v", inconclusive)
	}
	// each inconclusive finding has the text of its kind, which the page
	// shows with it
	m, _ := testRegistry(t).Meta(g.Rule)
	for _, x := range inconclusive {
		if i := slices.IndexFunc(m.InconclusiveKinds, func(k lint.InconclusiveKind) bool { return g.Rule.String()+"."+k.ID.String() == x.KindID }); i < 0 || x.KindText == "" || x.KindText != m.InconclusiveKinds[i].Text {
			t.Errorf("%s: kind text %q", x.KindID, x.KindText)
		}
	}
}
