package taint

import (
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// values reads src as a workflow and gives the references of the with
// input prompt and of the step's env, as lines as analyze gives them.
func values(t *testing.T, src string) []string {
	t.Helper()
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	pick := func(s workflow.Step) []Pick {
		var out []Pick
		if s.With.Status == workflow.Present {
			if e, ok := s.With.Value.Lookup("prompt"); ok && e.Value.Status == workflow.Present {
				out = append(out, Pick{Value: e.Value.Value})
			}
		}
		if s.Env.Status == workflow.Present {
			for _, e := range s.Env.Value.Entries {
				if e.Value.Status == workflow.Present {
					out = append(out, Pick{Value: e.Value.Value, InEnv: true})
				}
			}
		}
		return out
	}
	var out []string
	for _, v := range StepValues(nil, calls.Node{}, w, nil, pick) {
		text := v.Value.Text()
		for _, r := range v.Refs {
			line := text[r.Span.Start:r.Span.End] + " " + r.Verdict.String()
			if r.Verdict == analysis.Controlled {
				var names []string
				for _, e := range r.ControlledOn {
					if !slices.Contains(names, e.Name().String()) {
						names = append(names, e.Name().String())
					}
				}
				line += " " + strings.Join(names, ",")
			}
			if r.Verdict == analysis.Inconclusive {
				line += " " + r.InconclusiveKind.String()
			}
			out = append(out, line)
		}
	}
	return out
}

// TestStepValues: a value picked of a step is read as a sink's value is:
// the attacker's events, the env it goes through, the outputs of a step
// before; an env of the step's own reads env from the job's on.
func TestStepValues(t *testing.T) {
	src := `on:
  issues: {types: [opened]}
  issue_comment: {types: [created]}
env:
  W: ${{ github.event.comment.body }}
jobs:
  a:
    runs-on: x
    env:
      T: ${{ github.event.issue.title }}
    steps:
      - id: s
        run: echo
      - uses: o/agent@v1
        env:
          T: ${{ env.T }}
          N: ${{ github.event.issue.number }}
        with:
          prompt: "${{ env.T }} ${{ env.W }} ${{ steps.s.outputs.x }}"
`
	want := []string{
		"env.T Controlled issue_comment,issues",
		"env.W Controlled issue_comment",
		"steps.s.outputs.x Inconclusive step-output-run",
		"env.T Controlled issue_comment,issues",
		"github.event.issue.number NotControlled",
	}
	if got := values(t, src); !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestStepValuesSameAsSinks: the same value in a run and in a pick gives
// the same verdicts.
func TestStepValuesSameAsSinks(t *testing.T) {
	src := `on: issue_comment
jobs:
  a:
    runs-on: x
    steps:
      - run: echo "${{ github.event.comment.body }} ${{ github.sha }}"
        env:
          X: "${{ github.event.comment.body }} ${{ github.sha }}"
`
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	sink := Analyze(w, nil).Sinks[0]
	vals := StepValues(nil, calls.Node{}, w, nil, func(s workflow.Step) []Pick {
		return []Pick{{Value: s.Env.Value.Entries[0].Value.Value, InEnv: true}}
	})
	if len(vals) != 1 || len(vals[0].Refs) != len(sink.Refs) {
		t.Fatalf("%+v", vals)
	}
	for i, r := range vals[0].Refs {
		if r.Verdict != sink.Refs[i].Verdict || !slices.Equal(r.ControlledOn, sink.Refs[i].ControlledOn) {
			t.Errorf("%d: %+v, the sink's %+v", i, r, sink.Refs[i])
		}
	}
}
