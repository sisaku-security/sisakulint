package prcode

import (
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/composite"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// innerOf reads the steps of the composite action uses names from m: the
// steps of an action.yml, and for a key with a ! an answer of no one
// asked, for one with ? an unknown of --online.
func innerOf(t *testing.T, m map[string]string) Inner {
	t.Helper()
	return func(s *workflow.Step) composite.Expansion {
		u := s.Uses.Value.AsString()
		var e composite.Expansion
		if src, ok := m[u]; ok {
			a := mustAction(t, src)
			for i := range a.Runs.Value.Steps.Value.Items {
				e.Steps = append(e.Steps, composite.Step{Step: &a.Runs.Value.Steps.Value.Items[i], Action: a, Chain: []composite.Hop{{Uses: u}}, Substituted: strings.HasPrefix(u, "o/subst")})
			}
		}
		if r, ok := m["?"+u]; ok {
			e.Unanswered = append(e.Unanswered, composite.Unanswered{Chain: []composite.Hop{{Uses: u}}, Asked: true, Reason: r})
		}
		if _, ok := m["!"+u]; ok {
			e.Unanswered = append(e.Unanswered, composite.Unanswered{Chain: []composite.Hop{{Uses: u}}})
		}
		return e
	}
}

// TestCacheSavesInComposite: a step of a composite action a step runs
// saves the tree as a step of the job does, at the place of the step that
// runs it; the uses that --online could not answer, of the steps a save
// counts, are gaps of the site.
func TestCacheSavesInComposite(t *testing.T) {
	const co = "      - uses: actions/checkout@v4\n        with: {ref: \"${{ github.event.pull_request.head.sha }}\"}\n"
	saveDot := "runs:\n  using: composite\n  steps:\n    - uses: actions/cache/save@v4\n      with: {key: k, path: .}\n"
	cacheDist := "runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v4\n      with: {key: k, path: dist}\n"
	inner := innerOf(t, map[string]string{"o/save@v1": saveDot, "o/cache@v1": cacheDist, "o/subst@v1": saveDot, "?o/down@v1": "github: rate limited", "!o/none@v1": ""})
	for _, c := range []struct {
		name, steps string
		want        []string // the uses that runs the step, and the line
		gaps        []string
	}{
		{"save after the checkout", co + "      - uses: o/save@v1\n", []string{"o/save@v1 ."}, nil},
		{"save before the checkout", "      - uses: o/save@v1\n" + co, nil, nil},
		{"actions/cache before: its post saves at the end", "      - uses: o/cache@v1\n" + co, []string{"o/cache@v1 dist"}, nil},
		{"a clean checkout after", co + "      - uses: actions/checkout@v4\n      - uses: o/save@v1\n", nil, nil},
		{"substituted", co + "      - uses: o/subst@v1\n", []string{"o/subst@v1 . substituted"}, nil},
		{"unknown of --online", co + "      - uses: o/down@v1\n", nil, []string{"o/down@v1"}},
		{"no one asked", co + "      - uses: o/none@v1\n", nil, nil},
	} {
		src := "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" + c.steps
		var got, gaps []string
		for _, s := range AnalyzeComposite(nil, calls.Node{}, mustWorkflow(t, src), nil, nil, inner)[:1] { // the checkout of the pull request's code
			for _, x := range s.CacheSaves {
				if x.Via == nil {
					continue
				}
				g := x.Via.Uses.Value.AsString() + " " + x.Line
				if x.Substituted {
					g += " substituted"
				}
				got = append(got, g)
			}
			for _, g := range s.Unanswered {
				gaps = append(gaps, g.Via.Uses.Value.AsString())
			}
		}
		if !slices.Equal(got, c.want) || !slices.Equal(gaps, c.gaps) {
			t.Errorf("%s: saves %q gaps %q, want %q %q", c.name, got, gaps, c.want, c.gaps)
		}
	}
}
