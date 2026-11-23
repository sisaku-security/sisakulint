package ir

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/prcode"
)

const checkoutWorkflow = `on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4.2.2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
  label:
    if: github.event.action == 'labeled'
    environment: prod
    steps:
      - uses: actions/checkout@v1
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: ${{ github.head_ref }}
`

// TestCheckoutSitesAreTheProjection: each summary has what prcode.Analyze
// gives of its site, without positions and pointers.
func TestCheckoutSitesAreTheProjection(t *testing.T) {
	tree, w := parse(t, checkoutWorkflow)
	var want []prcode.CheckoutSite
	for _, s := range prcode.Analyze(w, nil) {
		if len(s.PRCodeOn) > 0 {
			want = append(want, s)
		}
	}
	got := New(".github/workflows/w.yml", tree, w, nil).allCheckoutSites()
	if len(got) != len(want) || len(got) == 0 {
		t.Fatalf("got %d, want %d", len(got), len(want))
	}
	for i, s := range want {
		g := got[i]
		if g.checkoutCode != s.CheckoutCode || g.guard != s.Guard || g.approval != s.Approval || g.fork != s.Fork || g.noRef != s.NoRef || g.sha != s.SHA || g.environment != s.Environment || g.mutable != s.Mutable() || g.stepPath != s.Path {
			t.Errorf("%d: %+v", i, g)
		}
		if len(g.refs) != len(s.Refs) || len(g.codeRunSteps) != len(s.CodeRunSteps) || len(g.prCodeOn) != len(s.PRCodeOn) {
			t.Errorf("%d: refs %d, runs %d, events %d", i, len(g.refs), len(g.codeRunSteps), len(g.prCodeOn))
		}
		for j, r := range s.Refs {
			if g.refs[j].Text != r.Text || g.refs[j].Input != r.Input || g.refs[j].Mutable != r.Mutable {
				t.Errorf("%d: ref %d: %+v", i, j, g.refs[j])
			}
		}
	}
}

// TestCheckoutOfCompositeAction: a composite action.yml has summaries too.
func TestCheckoutOfCompositeAction(t *testing.T) {
	tree, a := parseAction(t, "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v1\n      with:\n        ref: ${{ github.event.pull_request.head.sha }}\n")
	if got := New("action.yml", tree, nil, a).allCheckoutSites(); len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
}
