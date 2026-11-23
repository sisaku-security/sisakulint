package taint

import (
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/internal/callerstest"
)

// refsIn are the references of the workflow files[0] read in the table
// tab, as lines: the reference and its verdict, and the events it is
// controlled on.
func refsIn(t *testing.T, tab attacker.Table, files ...[2]string) map[string][]string {
	t.Helper()
	g := callerstest.Graph(t, true, false, files...)
	cl := NewCallersIn(g, tab)
	f, _ := g.File(inputName(files[0][0]))
	out := map[string][]string{}
	for _, s := range AnalyzeIn(cl, calls.InputNode(f.Name), f.Workflow, nil, nil).Sinks {
		text := s.Value.Text()
		for _, r := range s.Refs {
			ref := text[r.Span.Start:r.Span.End]
			if r.Verdict == analysis.Controlled {
				out[ref] = eventNames(r.ControlledOn)
			} else {
				out[ref] = nil
			}
		}
	}
	return out
}

func barrierTable(bs ...analysis.Barrier) attacker.Table {
	return attacker.TableOf(analysis.BarrierPasses{}.With(bs...))
}

// TestValueBarriers: vars and secrets are the attacker's values in a run
// whose attacker writes them; secrets.GITHUB_TOKEN, a whole secrets and
// the other contexts are not.
func TestValueBarriers(t *testing.T) {
	src := "on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    if: vars.FLAG == 'x'\n    steps:\n      - run: |\n          echo ${{ vars.X }}\n          echo ${{ secrets.S }}\n          echo ${{ secrets.GITHUB_TOKEN }}\n          echo ${{ toJSON(secrets) }}\n          echo ${{ runner.os }}\n"
	file := [2]string{".github/workflows/w.yml", src}
	for _, c := range []struct {
		name          string
		tab           attacker.Table
		vars, secrets bool
	}{
		{"outsider", attacker.Outsider, false, false},
		{"variables", barrierTable(analysis.BarrierVariableValue), true, false},
		{"secrets", barrierTable(analysis.BarrierSecretValue), false, true},
	} {
		got := refsIn(t, c.tab, file)
		check := func(ref string, want bool) {
			if _, ok := got[ref]; !ok {
				t.Errorf("%s: no reference %s in %v", c.name, ref, got)
			}
			if (got[ref] != nil) != want {
				t.Errorf("%s: %s controlled on %v, want controlled %v", c.name, ref, got[ref], want)
			}
		}
		check("vars.X", c.vars)
		check("secrets.S", c.secrets)
		check("secrets.GITHUB_TOKEN", false)
		check("secrets", false)
		check("runner.os", false)
	}
}

// TestValueBarriersAnyRun: a variable is the attacker's on every event
// that runs the job, whoever starts the run: a
// schedule, a push, and an issue_comment whose if lets only members in;
// not an event that an if on github.event_name leaves out.
func TestValueBarriersAnyRun(t *testing.T) {
	tab := barrierTable(analysis.BarrierVariableValue)
	for _, c := range []struct {
		name, on, cond string
		want           []string
	}{
		{"schedule", "schedule: [{cron: '0 0 * * *'}]", "", []string{"schedule"}},
		{"push", "push", "", []string{"push"}},
		{"members only", "issue_comment", "github.event.comment.author_association == 'MEMBER'", []string{"issue_comment"}},
		{"event_name", "{pull_request_target: {}, push: {}}", "github.event_name == 'push'", []string{"push"}},
	} {
		src := "on: " + c.on + "\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
		if c.cond != "" {
			src += "    if: " + c.cond + "\n"
		}
		src += "    steps:\n      - run: echo ${{ vars.X }}\n"
		got := refsIn(t, tab, [2]string{".github/workflows/w.yml", src})["vars.X"]
		slices.Sort(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: controlled on %v, want %v", c.name, got, c.want)
		}
	}
}

// TestCalledValueAnyCaller: a variable in a called workflow is the
// attacker's on every event its callers run it on, the callers' ifs read
// by github.event_name and github.event.action alone.
func TestCalledValueAnyCaller(t *testing.T) {
	called := [2]string{".github/workflows/called.yml", "on: workflow_call\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ vars.X }}\n"}
	caller := [2]string{".github/workflows/caller.yml", "on: {issues: {types: [opened]}}\njobs:\n  c:\n    if: github.event.issue.author_association == 'OWNER'\n    uses: ./.github/workflows/called.yml\n"}
	for _, c := range []struct {
		name string
		tab  attacker.Table
		want []string
	}{
		{"outsider", attacker.Outsider, nil},
		{"variables", barrierTable(analysis.BarrierVariableValue), []string{"issues"}},
	} {
		got := refsIn(t, c.tab, called, caller)["vars.X"]
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: controlled on %v, want %v", c.name, got, c.want)
		}
	}
}

// TestCallerValueInWith: a variable that a caller passes through with is
// the attacker's in the called workflow and in the composite action, on
// every event the caller runs on.
func TestCallerValueInWith(t *testing.T) {
	tab := barrierTable(analysis.BarrierVariableValue)
	caller := [2]string{".github/workflows/caller.yml", "on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      x: ${{ vars.X }}\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./act\n        with:\n          x: ${{ vars.X }}\n"}
	called := [2]string{".github/workflows/called.yml", "on:\n  workflow_call:\n    inputs:\n      x: {type: string}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ inputs.x }}\n"}
	action := [2]string{"act/action.yml", "name: a\ninputs:\n  x: {}\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo ${{ inputs.x }}\n"}
	for _, f := range [][2]string{called, action} {
		got := refsInFile(t, tab, f[0], called, caller, action)["inputs.x"]
		if !slices.Equal(got, []string{"push"}) {
			t.Errorf("%s: inputs.x controlled on %v, want [push]", f[0], got)
		}
	}
}

// refsInFile is refsIn of the file name among files.
func refsInFile(t *testing.T, tab attacker.Table, name string, files ...[2]string) map[string][]string {
	t.Helper()
	g := callerstest.Graph(t, true, false, files...)
	cl := NewCallersIn(g, tab)
	f, _ := g.File(inputName(name))
	out := map[string][]string{}
	for _, s := range AnalyzeIn(cl, calls.InputNode(f.Name), f.Workflow, f.Action, nil).Sinks {
		text := s.Value.Text()
		for _, r := range s.Refs {
			ref := text[r.Span.Start:r.Span.End]
			if r.Verdict == analysis.Controlled {
				out[ref] = eventNames(r.ControlledOn)
			} else {
				out[ref] = nil
			}
		}
	}
	return out
}

// everyRunIn are the references of the sinks of the workflow src read in
// the table tab, each with the events of its EveryRunOn (nil for none),
// and whether every reference keeps EveryRunOn a part of ControlledOn.
func everyRunIn(t *testing.T, tab attacker.Table, src string) (map[string][]string, bool) {
	t.Helper()
	g := callerstest.Graph(t, true, false, [2]string{".github/workflows/w.yml", src})
	cl := NewCallersIn(g, tab)
	f, _ := g.File(inputName(".github/workflows/w.yml"))
	out := map[string][]string{}
	within := true
	for _, s := range AnalyzeIn(cl, calls.InputNode(f.Name), f.Workflow, nil, nil).Sinks {
		text := s.Value.Text()
		for _, r := range s.Refs {
			out[text[r.Span.Start:r.Span.End]] = eventNames(r.EveryRunOn)
			for _, e := range r.EveryRunOn {
				within = within && slices.Contains(r.ControlledOn, e)
			}
		}
	}
	return out, within
}

// TestEveryRunOn: in a run whose attacker writes vars or secrets, a
// reference of vars or of secrets (but secrets.GITHUB_TOKEN), and an env
// whose value has one, is the attacker's in every run: EveryRunOn holds
// the events of the step, a part of ControlledOn; in a run whose attacker
// writes neither, no reference has EveryRunOn.
func TestEveryRunOn(t *testing.T) {
	src := "on: {issues: {types: [assigned]}, schedule: [{cron: '0 0 * * *'}]}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n      A: ${{ vars.X }}\n    steps:\n      - run: |\n          echo ${{ vars.X }}\n          echo ${{ env.A }}\n          echo ${{ secrets.S }}\n          echo ${{ secrets.GITHUB_TOKEN }}\n"
	both := []string{"issues", "schedule"}
	for _, c := range []struct {
		name string
		tab  attacker.Table
		want map[string][]string
	}{
		{"outsider", attacker.Outsider, map[string][]string{"vars.X": nil, "env.A": nil, "secrets.S": nil, "secrets.GITHUB_TOKEN": nil}},
		{"variables", barrierTable(analysis.BarrierVariableValue), map[string][]string{"vars.X": both, "env.A": both, "secrets.S": nil, "secrets.GITHUB_TOKEN": nil}},
		{"secrets", barrierTable(analysis.BarrierSecretValue), map[string][]string{"vars.X": nil, "env.A": nil, "secrets.S": both, "secrets.GITHUB_TOKEN": nil}},
		{"member", barrierTable(analysis.BarrierAssociationMember), map[string][]string{"vars.X": nil, "env.A": nil, "secrets.S": nil, "secrets.GITHUB_TOKEN": nil}},
	} {
		got, within := everyRunIn(t, c.tab, src)
		for ref, want := range c.want {
			g, ok := got[ref]
			if !ok {
				t.Errorf("%s: no reference %s in %v", c.name, ref, got)
				continue
			}
			slices.Sort(g)
			if !slices.Equal(g, want) {
				t.Errorf("%s: %s EveryRunOn %v, want %v", c.name, ref, g, want)
			}
		}
		if !within {
			t.Errorf("%s: an EveryRunOn is not a part of its ControlledOn", c.name)
		}
	}
}

// everyRunInFile are the references of the sinks of the file name among
// files read in the table tab, each with the events of its ControlledOn
// and of its EveryRunOn (nil for none).
func everyRunInFile(t *testing.T, tab attacker.Table, name string, files ...[2]string) (controlled, everyRun map[string][]string) {
	t.Helper()
	g := callerstest.Graph(t, true, false, files...)
	cl := NewCallersIn(g, tab)
	f, _ := g.File(inputName(name))
	controlled, everyRun = map[string][]string{}, map[string][]string{}
	for _, s := range AnalyzeIn(cl, calls.InputNode(f.Name), f.Workflow, f.Action, nil).Sinks {
		text := s.Value.Text()
		for _, r := range s.Refs {
			ref := text[r.Span.Start:r.Span.End]
			controlled[ref], everyRun[ref] = eventNames(r.ControlledOn), eventNames(r.EveryRunOn)
			slices.Sort(controlled[ref])
			slices.Sort(everyRun[ref])
		}
	}
	return controlled, everyRun
}

// TestValueCallerInputs: a variable that a caller passes through with, on
// events whose runs the attacker of a run that adds variables-writer does
// not start (issues assigned, schedule), is the attacker's in the called
// workflow and in the composite action, in every run; a run that adds no
// attacker reads it as before.
func TestValueCallerInputs(t *testing.T) {
	caller := [2]string{".github/workflows/caller.yml", "on: {issues: {types: [assigned]}, schedule: [{cron: '0 0 * * *'}]}\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      x: ${{ vars.P }}\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./act\n        with:\n          x: ${{ vars.P }}\n"}
	called := [2]string{".github/workflows/called.yml", "on:\n  workflow_call:\n    inputs:\n      x: {type: string}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ inputs.x }}\n"}
	action := [2]string{"act/action.yml", "name: a\ninputs:\n  x: {}\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo ${{ inputs.x }}\n"}
	both := []string{"issues", "schedule"}
	for _, f := range [][2]string{called, action} {
		controlled, everyRun := everyRunInFile(t, barrierTable(analysis.BarrierVariableValue), f[0], caller, called, action)
		if !slices.Equal(controlled["inputs.x"], both) || !slices.Equal(everyRun["inputs.x"], both) {
			t.Errorf("%s: inputs.x controlled on %v, every run on %v, want %v", f[0], controlled["inputs.x"], everyRun["inputs.x"], both)
		}
		controlled, everyRun = everyRunInFile(t, attacker.Outsider, f[0], caller, called, action)
		if controlled["inputs.x"] != nil || everyRun["inputs.x"] != nil {
			t.Errorf("outsider %s: inputs.x controlled on %v, every run on %v, want none", f[0], controlled["inputs.x"], everyRun["inputs.x"])
		}
	}
}

// TestValueBarriersComposite: a step of a composite action has no vars
// and no secrets (the contexts of step-with, step-env and the strings of
// steps, and of the default of an input, in workflow-parser's
// action-v1.0.json), so a reference of vars there is not the attacker's
// in a run that adds variables-writer; a variable the workflow passes
// through with is (TestValueCallerInputs).
func TestValueBarriersComposite(t *testing.T) {
	caller := [2]string{".github/workflows/caller.yml", "on: {issues: {types: [assigned]}}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./act\n        with:\n          x: ${{ vars.P }}\n"}
	action := [2]string{"act/action.yml", "name: a\ninputs:\n  x: {}\n  y:\n    default: ${{ vars.D }}\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: |\n        echo ${{ vars.P }}\n        echo ${{ inputs.y }}\n        echo ${{ inputs.x }}\n"}
	controlled, _ := everyRunInFile(t, barrierTable(analysis.BarrierVariableValue), action[0], caller, action)
	for ref, want := range map[string][]string{"vars.P": nil, "inputs.y": nil, "inputs.x": {"issues"}} {
		if got, ok := controlled[ref]; !ok || !slices.Equal(got, want) {
			t.Errorf("%s: controlled on %v (read %v), want %v", ref, got, ok, want)
		}
	}
	// the default of an input of a called workflow may read vars
	// (on.workflow_call.inputs.<inputs_id>.default), which the attacker
	// writes in every run of the caller
	called := [2]string{".github/workflows/called.yml", "on:\n  workflow_call:\n    inputs:\n      y:\n        type: string\n        default: ${{ vars.D }}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ inputs.y }}\n"}
	callerOf := [2]string{".github/workflows/caller.yml", "on: {issues: {types: [assigned]}}\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n"}
	for _, c := range []struct {
		name string
		tab  attacker.Table
		want []string
	}{
		{"outsider", attacker.Outsider, nil},
		{"variables", barrierTable(analysis.BarrierVariableValue), []string{"issues"}},
	} {
		_, everyRun := everyRunInFile(t, c.tab, called[0], callerOf, called)
		if !slices.Equal(everyRun["inputs.y"], c.want) {
			t.Errorf("%s: the default of a called workflow: inputs.y every run on %v, want %v", c.name, everyRun["inputs.y"], c.want)
		}
	}
}

// TestValueCallerDispatchInput: in a run that adds variables-writer, a
// caller on workflow_dispatch gives the called workflow a variable as the
// attacker's, and an input of workflow_dispatch, which the one who
// dispatches chooses and the attacker does not write, as before: nothing
// on the events of vars and secrets.
func TestValueCallerDispatchInput(t *testing.T) {
	caller := [2]string{".github/workflows/caller.yml", "on:\n  workflow_dispatch:\n    inputs:\n      version: {type: string}\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      x: ${{ inputs.version }}\n      y: ${{ vars.P }}\n"}
	called := [2]string{".github/workflows/called.yml", "on:\n  workflow_call:\n    inputs:\n      x: {type: string}\n      y: {type: string}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ inputs.x }} ${{ inputs.y }}\n"}
	verdicts := func(tab attacker.Table) map[string]analysis.Verdict {
		g := callerstest.Graph(t, true, false, caller, called)
		cl := NewCallersIn(g, tab)
		f, _ := g.File(inputName(called[0]))
		out := map[string]analysis.Verdict{}
		for _, s := range AnalyzeIn(cl, calls.InputNode(f.Name), f.Workflow, nil, nil).Sinks {
			text := s.Value.Text()
			for _, r := range s.Refs {
				out[text[r.Span.Start:r.Span.End]] = r.Verdict
			}
		}
		return out
	}
	base, value := verdicts(attacker.Outsider), verdicts(barrierTable(analysis.BarrierVariableValue))
	if value["inputs.x"] != base["inputs.x"] {
		t.Errorf("the input of workflow_dispatch: %v, with no attacker added %v", value["inputs.x"], base["inputs.x"])
	}
	if value["inputs.y"] != analysis.Controlled {
		t.Errorf("the variable: %v, want Controlled", value["inputs.y"])
	}
}

// TestValueCallerJobOutput: in a run that adds variables-writer, a caller
// on schedule gives the called workflow the output of a job, which a
// variable may make: the input is not analyzed (job-output), as in the
// caller itself; the run that adds no attacker reads nothing on schedule.
func TestValueCallerJobOutput(t *testing.T) {
	caller := [2]string{".github/workflows/caller.yml", "on: {schedule: [{cron: '0 0 * * *'}]}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    outputs:\n      o: ${{ steps.s.outputs.o }}\n    steps:\n      - id: s\n        run: echo \"o=${{ vars.P }}\" >> \"$GITHUB_OUTPUT\"\n  b:\n    needs: a\n    uses: ./.github/workflows/called.yml\n    with:\n      x: ${{ needs.a.outputs.o }}\n"}
	called := [2]string{".github/workflows/called.yml", "on:\n  workflow_call:\n    inputs:\n      x: {type: string}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ inputs.x }}\n"}
	verdict := func(tab attacker.Table) analysis.Verdict {
		g := callerstest.Graph(t, true, false, caller, called)
		cl := NewCallersIn(g, tab)
		f, _ := g.File(inputName(called[0]))
		for _, s := range AnalyzeIn(cl, calls.InputNode(f.Name), f.Workflow, nil, nil).Sinks {
			for _, r := range s.Refs {
				return r.Verdict
			}
		}
		return analysis.Verdict(0)
	}
	if got := verdict(attacker.Outsider); got != analysis.NotControlled {
		t.Errorf("with no attacker added: %v, want NotControlled", got)
	}
	if got := verdict(barrierTable(analysis.BarrierVariableValue)); got != analysis.Inconclusive {
		t.Errorf("with variables-writer: %v, want Inconclusive", got)
	}
}
