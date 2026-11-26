package ir

import (
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/callerstest"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// passesIR is the IR of the workflow src at .github/workflows/w.yml, read
// with its callers in the attacker run table of the barriers p, as a run
// of the linter that adds an attacker reads it.
func passesIR(t *testing.T, src string, p analysis.BarrierPasses) *IR {
	t.Helper()
	g := callerstest.Graph(t, true, false, [2]string{".github/workflows/w.yml", src})
	c := taint.NewCallersIn(g, attacker.TableOf(p))
	f, ok := g.File(calls.InputNode(facts.MustCleanInputPath(".github/workflows/w.yml")))
	if !ok {
		t.Fatal("no w.yml")
	}
	return New(f.Name.String(), f.Tree, f.Workflow, f.Action).WithCallers(func() *taint.Callers { return c }).WithBarriers(p)
}

// eventNameSet are the names of the events of evs, once each, sorted.
func eventNameSet(evs []analysis.EventActivity) []string {
	var out []string
	for _, e := range evs {
		if n := e.Name().String(); !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

const everyRunWF = `on:
  issues: {types: [assigned]}
  schedule: [{cron: '0 0 * * *'}]
jobs:
  a:
    runs-on: x
    steps:
      - uses: anthropics/claude-code-action@v1
        env:
          GUIDE: ${{ vars.G }}
          B: ${{ env.FROM_VAR }}
        with:
          prompt: "Triage ${{ vars.P }}"
          claude_args: ${{ vars.A }}
    env:
      FROM_VAR: ${{ secrets.S }} ${{ vars.V }}
  b:
    runs-on: x
    steps:
      - id: s
        run: echo
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "Triage ${{ steps.s.outputs.x }}"
`

// TestAgentStepEveryRun: in a run that adds variables-writer, the
// references of vars that reach the agent are the attacker's in every run
// on the events of the step (EveryRunOn, EveryRunRefs), and the step's
// WrittenValueOn has those events, also for a step whose prompt has no
// reference of vars; the readings of the attacker's own runs and of the
// payload do not change. The run that adds no attacker has none.
func TestAgentStepEveryRun(t *testing.T) {
	both := []string{"issues", "schedule"}
	base := passesIR(t, everyRunWF, analysis.BarrierPasses{}).allAgentSteps()
	got := passesIR(t, everyRunWF, analysis.BarrierPasses{}.With(analysis.BarrierVariableValue)).allAgentSteps()
	if len(got) != 2 || len(base) != 2 {
		t.Fatalf("%d and %d steps", len(got), len(base))
	}
	for i := range base {
		b, g := base[i], got[i]
		if b.writtenValueOn != nil || b.everyRunRefs != nil {
			t.Errorf("step %d with no attacker added: written value on %v, every run refs %+v", i, b.writtenValueOn, b.everyRunRefs)
		}
		for _, p := range b.promptRefs {
			if p.EveryRunOn != nil {
				t.Errorf("step %d with no attacker added: %s every run on %v", i, p.Ref.Text, p.EveryRunOn)
			}
		}
		if !slices.Equal(eventNameSet(g.writtenValueOn), both) {
			t.Errorf("step %d: written value on %v, want %v", i, eventNameSet(g.writtenValueOn), both)
		}
		// the readings of the attacker's own runs and of the payload
		if !slices.Equal(b.attackerOn, g.attackerOn) && len(g.attackerOn) != 0 || !slices.Equal(b.othersOn, g.othersOn) && len(g.othersOn) != 0 {
			t.Errorf("step %d: attacker on %v others on %v, with no attacker added %v %v", i, g.attackerOn, g.othersOn, b.attackerOn, b.othersOn)
		}
	}
	a := got[0]
	type ref struct {
		route              analysis.AgentValueRoute
		name, text, source string
		direct             bool
	}
	var refs []ref
	for _, r := range a.everyRunRefs {
		name := r.Input.String()
		if r.Env != (workflow.EnvName{}) {
			name = r.Env.String()
		}
		refs = append(refs, ref{r.Route, name, r.Ref.Text, r.Source, r.Direct})
		if !slices.Equal(eventNameSet(r.EveryRunOn), both) {
			t.Errorf("%s: every run on %v, want %v", r.Ref.Text, eventNameSet(r.EveryRunOn), both)
		}
		if r.Source != "" && r.SourceName == "" {
			t.Errorf("%s: source %s has no name", r.Ref.Text, r.Source)
		}
	}
	want := []ref{
		{analysis.AgentValueRoutePromptInput, "prompt", "vars.P", "vars.P", true},
		{analysis.AgentValueRouteStepEnv, "GUIDE", "vars.G", "vars.G", true},
		{analysis.AgentValueRouteStepEnv, "B", "env.FROM_VAR", "vars.V", false},
		{analysis.AgentValueRouteJobEnv, "FROM_VAR", "vars.V", "vars.V", true},
		{analysis.AgentValueRouteSettingInput, "claude_args", "vars.A", "vars.A", true},
	}
	if !slices.Equal(refs, want) {
		t.Errorf("every run refs\n %+v\nwant\n %+v", refs, want)
	}
	for _, p := range a.promptRefs {
		if p.Ref.Text == "secrets.S" {
			continue // the job's env FROM_VAR: not the attacker's in a run that adds variables-writer
		}
		if !slices.Equal(eventNameSet(p.EveryRunOn), both) {
			t.Errorf("prompt ref %s: every run on %v, want %v", p.Ref.Text, eventNameSet(p.EveryRunOn), both)
		}
	}
	if len(a.settingRefs) != 1 || !slices.Equal(eventNameSet(a.settingRefs[0].EveryRunOn), both) {
		t.Errorf("setting refs %+v", a.settingRefs)
	}
	if got[1].everyRunRefs != nil {
		t.Errorf("a prompt of a step output: every run refs %+v", got[1].everyRunRefs)
	}
}

// TestAgentStepEveryRunEvents: a step on schedule alone, an event an
// attacker does not trigger, has the events of its references of vars in
// a run that adds variables-writer; claude-code-action, which fails on
// push, has none on push.
func TestAgentStepEveryRunEvents(t *testing.T) {
	p := analysis.BarrierPasses{}.With(analysis.BarrierVariableValue)
	for _, c := range []struct {
		name, on string
		want     []string
	}{
		{"schedule", "schedule: [{cron: '0 0 * * *'}]", []string{"schedule"}},
		{"push", "push", nil},
	} {
		src := "on: " + c.on + "\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: \"Triage ${{ vars.P }}\"\n"
		got := passesIR(t, src, p).allAgentSteps()
		if len(got) != 1 {
			t.Fatalf("%s: %d steps", c.name, len(got))
		}
		var refs []string
		for _, r := range got[0].everyRunRefs {
			refs = append(refs, eventNameSet(r.EveryRunOn)...)
		}
		if !slices.Equal(eventNameSet(got[0].writtenValueOn), c.want) || !slices.Equal(refs, c.want) {
			t.Errorf("%s: written value on %v, every run refs on %v, want %v", c.name, eventNameSet(got[0].writtenValueOn), refs, c.want)
		}
	}
}

// TestAgentStepEveryRunGrants: claude-code-action's tag mode, which
// track_progress starts on pull_request, gives its grants in a run that
// adds variables-writer, where a variable in the prompt reaches the agent
// on pull_request, a run of any branch of the repository; the later step
// counts pull_request. The run that adds no attacker, which does not read
// pull_request, has neither.
func TestAgentStepEveryRunGrants(t *testing.T) {
	src := "on: pull_request\njobs:\n  a:\n    if: github.event.pull_request.head.repo.full_name == github.repository\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          track_progress: true\n          prompt: \"Review ${{ vars.P }}\"\n      - run: npm test\n"
	base := passesIR(t, src, analysis.BarrierPasses{}).allAgentSteps()
	got := passesIR(t, src, analysis.BarrierPasses{}.With(analysis.BarrierVariableValue)).allAgentSteps()
	if len(base) != 1 || len(got) != 1 {
		t.Fatalf("%d and %d steps", len(base), len(got))
	}
	push := func(gs []CapabilityGrant) bool {
		return slices.ContainsFunc(gs, func(g CapabilityGrant) bool { return strings.Contains(g.Permission, "git-push.sh") })
	}
	if push(base[0].capabilityGrants) || !push(got[0].capabilityGrants) {
		t.Errorf("the grant of the tag mode's push: with no attacker added %v, with variables-writer %v", base[0].capabilityGrants, got[0].capabilityGrants)
	}
	laterOn := func(s *AgentStep) []string {
		var out []string
		for _, l := range s.laterSteps {
			out = append(out, eventNameSet(l.On)...)
		}
		return out
	}
	if b, g := laterOn(base[0]), laterOn(got[0]); len(b) != 0 || !slices.Equal(g, []string{"pull_request"}) {
		t.Errorf("later steps on: with no attacker added %v, with variables-writer %v", b, g)
	}
}
