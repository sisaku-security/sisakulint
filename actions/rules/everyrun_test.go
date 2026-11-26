package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// runAdded runs every rule on files with the attackers vs added
// (lint.RunAdded; none is the run that adds no attacker), with no facts,
// and gives the report and the inputs.
func runAdded(t *testing.T, files map[string]string, vs ...lint.AddedAttacker) (lint.Report, lint.Inputs) {
	t.Helper()
	return runAddedWith(t, files, noFacts{}, vs...)
}

// runAddedWith is runAdded with r answering the facts.
func runAddedWith(t *testing.T, files map[string]string, r facts.Resolver, vs ...lint.AddedAttacker) (lint.Report, lint.Inputs) {
	t.Helper()
	fsys := fstest.MapFS{}
	for n, s := range files {
		fsys[n] = &fstest.MapFile{Data: []byte(s)}
	}
	in, err := lint.Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := lint.NewRegistry(All())
	if err != nil {
		t.Fatal(err)
	}
	rep := lint.RunAdded(context.Background(), in, reg, r, vs)
	for _, e := range rep.Errors {
		t.Errorf("internal error: %+v", e)
	}
	return rep, in
}

// marked are the findings of the rule id in rep, each as <input> <kind>
// <the text it points at> [<the added attackers that mark it>], sorted.
func marked(t *testing.T, rep lint.Report, in lint.Inputs, id lint.RuleID) []string {
	t.Helper()
	var out []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Rule != id {
			continue
		}
		i, st := in.Lookup(f.Location.File.Input)
		if st != lint.LookupFound {
			t.Fatalf("no input %s", f.Location.File.Input)
		}
		var marks []string
		for _, v := range f.AddedAttackers {
			marks = append(marks, v.String())
		}
		out = append(out, f.Location.File.Input.String()+" "+f.Args.KindID().String()+" "+string(i.Tree.Bytes()[f.Location.Span.Start:f.Location.Span.End])+" ["+strings.Join(marks, ",")+"]")
	}
	slices.Sort(out)
	return out
}

// TestNotAttackerCallerInputs: a variable a caller passes through with,
// on events whose runs the attacker of a run that adds variables-writer
// does not start, is written into the run script of the called workflow
// and of the composite action: code-injection reports it there, marked;
// the run that adds no attacker does not.
func TestNotAttackerCallerInputs(t *testing.T) {
	files := map[string]string{
		".github/workflows/caller.yml": "on: {issues: {types: [assigned]}, schedule: [{cron: '0 0 * * *'}]}\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      x: ${{ vars.P }}\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./act\n        with:\n          x: ${{ vars.P }}\n",
		".github/workflows/called.yml": "on:\n  workflow_call:\n    inputs:\n      x: {type: string}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ inputs.x }}\n",
		"act/action.yml":               "name: a\ninputs:\n  x: {}\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo ${{ inputs.x }}\n",
	}
	rep, in := runAdded(t, files)
	if got := marked(t, rep, in, CodeInjectionID); len(got) != 0 {
		t.Errorf("the run that adds no attacker: %v", got)
	}
	rep, in = runAdded(t, files, lint.AddedAttackerVariablesWriter)
	got := marked(t, rep, in, CodeInjectionID)
	for _, want := range []string{
		".github/workflows/called.yml code-injection.controlled inputs.x [variables-writer]",
		"act/action.yml code-injection.controlled inputs.x [variables-writer]",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("no %q in %v", want, got)
		}
	}
}

// TestValueRunCompositeVars: a step of a composite action has no vars, so
// the run that adds variables-writer reports no code-injection on a
// reference of vars in the action.yml; a variable the workflow passes
// through with is reported (TestNotAttackerCallerInputs).
func TestValueRunCompositeVars(t *testing.T) {
	files := map[string]string{
		".github/workflows/w.yml": "on: {issues: {types: [assigned]}}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./act\n",
		"act/action.yml":          "name: a\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo ${{ vars.P }}\n",
	}
	rep, in := runAdded(t, files, lint.AddedAttackerVariablesWriter)
	for _, f := range marked(t, rep, in, CodeInjectionID) {
		if strings.HasPrefix(f, "act/action.yml ") {
			t.Errorf("a finding in the composite action: %s", f)
		}
	}
}

// TestRemoteCompositeWrittenValue: a step that uses a composite action of
// another repository gives a variable in its with to an input of the
// action, whose step puts the input into the prompt of the agent: in the
// run that adds variables-writer, the value of the input is not analyzed
// (the steps of the action are read without callers) and may be the
// attacker's, so ai-action-prompt-injection reports value-unknown, marked;
// the run that adds no attacker, on schedule alone, does not. So does a
// with of the output of a job, which the rule does not analyze and which
// a variable may reach; a with of no variable gives none.
func TestRemoteCompositeWrittenValue(t *testing.T) {
	b, err := os.ReadFile("examples/true-positive/ai-action-prompt-injection/prompt.remote-composite.facts.json")
	if err != nil {
		t.Fatal(err)
	}
	store := strings.ReplaceAll(strings.ReplaceAll(string(b), `Triage this issue: ${{ github.event.issue.title }}`, `Triage this issue: ${{ inputs.prompt }}`), "prompt.remote-composite.yml", "w.yml")
	r, err := facts.LoadStore([]byte(store))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, with string
		want       []string
	}{
		{"variable", "${{ vars.P }}", []string{"value-unknown [variables-writer]"}},
		{"output of a job", "${{ needs.a.outputs.o }}", []string{"value-unknown [variables-writer]"}},
		{"no variable", "fixed", nil},
	} {
		files := map[string]string{".github/workflows/w.yml": "on: {schedule: [{cron: '0 0 * * *'}]}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    outputs:\n      o: ${{ steps.s.outputs.x }}\n    steps:\n      - id: s\n        run: echo \"x=${{ vars.P }}\" >> \"$GITHUB_OUTPUT\"\n  triage:\n    needs: a\n    runs-on: ubuntu-latest\n    steps:\n      - uses: example-org/claude-prompt-composite@v1\n        with:\n          prompt: " + c.with + "\n"}
		var got []string
		for _, v := range [][]lint.AddedAttacker{nil, {lint.AddedAttackerVariablesWriter}} {
			rep, _ := runAddedWith(t, files, r, v...)
			for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
				if g.Rule != AIActionPromptInjectionID {
					continue
				}
				var marks []string
				for _, m := range g.AddedAttackers {
					marks = append(marks, m.String())
				}
				got = append(got, g.InconclusiveKind.String()+" ["+strings.Join(marks, ",")+"]")
			}
		}
		slices.Sort(got)
		got = slices.Compact(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// TestLocalCompositeWrittenValue: a step of the workflow, after the
// checkout of the repository, gives a value in its with to an input of a
// composite action of the repository, whose step
// puts the input into the prompt of the agent. In the run that adds
// variables-writer, a variable is the attacker's in every run, and
// ai-action-prompt-injection reports the input in the action.yml, marked;
// the output of a job, which the rule does not analyze and which a
// variable may reach, gives value-unknown there, marked, as it does in the
// prompt of an agent of the workflow. A with of no variable gives none, and
// the run that adds no attacker, on schedule alone, gives none.
func TestLocalCompositeWrittenValue(t *testing.T) {
	act := "name: a\ninputs:\n  p: {}\nruns:\n  using: composite\n  steps:\n    - uses: anthropics/claude-code-action@v1\n      with:\n        prompt: \"Triage ${{ inputs.p }}\"\n"
	for _, c := range []struct {
		name, with string
		want       []string
	}{
		{"variable", "${{ vars.P }}", []string{"F act/action.yml ai-action-prompt-injection.prompt inputs.p [variables-writer]"}},
		{"output of a job", "${{ needs.a.outputs.o }}", []string{"I act/action.yml value-unknown [variables-writer]"}},
		{"no variable", "fixed", nil},
	} {
		files := map[string]string{
			".github/workflows/w.yml": "on: {schedule: [{cron: '0 0 * * *'}]}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    outputs:\n      o: ${{ steps.s.outputs.x }}\n    steps:\n      - id: s\n        run: echo \"x=${{ vars.P }}\" >> \"$GITHUB_OUTPUT\"\n  triage:\n    needs: a\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./act\n        with:\n          p: " + c.with + "\n",
			"act/action.yml":          act,
		}
		for _, v := range [][]lint.AddedAttacker{nil, {lint.AddedAttackerVariablesWriter}} {
			rep, in := runAdded(t, files, v...)
			var got []string
			for _, f := range marked(t, rep, in, AIActionPromptInjectionID) {
				got = append(got, "F "+f)
			}
			for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
				if g.Rule != AIActionPromptInjectionID {
					continue
				}
				var marks []string
				for _, m := range g.AddedAttackers {
					marks = append(marks, m.String())
				}
				got = append(got, "I "+g.Location.File.Input.String()+" "+g.InconclusiveKind.String()+" ["+strings.Join(marks, ",")+"]")
			}
			slices.Sort(got)
			want := c.want
			if v == nil {
				want = nil
			}
			if !slices.Equal(got, want) {
				t.Errorf("%s, %v: %v, want %v", c.name, v, got, want)
			}
		}
	}
}

// promptGaps are the inconclusive places of ai-action-prompt-injection in
// rep, each as <input> <kind> [<the added attackers that mark it>], sorted.
func promptGaps(rep lint.Report) []string {
	var out []string
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		if g.Rule != AIActionPromptInjectionID {
			continue
		}
		var marks []string
		for _, m := range g.AddedAttackers {
			marks = append(marks, m.String())
		}
		out = append(out, g.Location.File.Input.String()+" "+g.InconclusiveKind.String()+" ["+strings.Join(marks, ",")+"]")
	}
	slices.Sort(out)
	return out
}

// TestCompositeWrittenValueDispatchCall: a called workflow that can also be
// dispatched gives an input, which its caller gives the output of a job,
// to a composite action whose step puts the input into the prompt of the
// agent. On the events of the caller the input is the caller's, which the
// rule does not analyze, so the run that adds variables-writer reports
// value-unknown, marked, in the composite action of the repository and at
// the uses of the composite action of another repository, as it does in
// the prompt of an agent of the called workflow. A workflow that cannot be
// called gives its own input of workflow_dispatch, which the one who
// dispatches chooses: none. The run that adds no attacker gives none.
func TestCompositeWrittenValueDispatchCall(t *testing.T) {
	b, err := os.ReadFile("examples/true-positive/ai-action-prompt-injection/prompt.remote-composite.facts.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := facts.LoadStore([]byte(strings.ReplaceAll(string(b), `Triage this issue: ${{ github.event.issue.title }}`, `Triage this issue: ${{ inputs.prompt }}`)))
	if err != nil {
		t.Fatal(err)
	}
	caller := "on: {schedule: [{cron: '0 0 * * *'}]}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    outputs:\n      o: ${{ steps.s.outputs.x }}\n    steps:\n      - id: s\n        run: echo \"x=${{ vars.P }}\" >> \"$GITHUB_OUTPUT\"\n  c:\n    needs: a\n    uses: ./.github/workflows/r.yml\n    with:\n      p: ${{ needs.a.outputs.o }}\n"
	called := func(on, uses string) string {
		return "on:\n" + on + "jobs:\n  t:\n    if: github.event_name != 'workflow_dispatch'\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n" + uses
	}
	both := "  workflow_call:\n    inputs:\n      p: {type: string}\n  workflow_dispatch:\n    inputs:\n      p: {type: string}\n"
	act := "name: a\ninputs:\n  p: {}\nruns:\n  using: composite\n  steps:\n    - uses: anthropics/claude-code-action@v1\n      with:\n        prompt: \"Triage ${{ inputs.p }}\"\n"
	local := "      - uses: ./act\n        with:\n          p: ${{ inputs.p }}\n"
	remote := "      - uses: example-org/claude-prompt-composite@v1\n        with:\n          prompt: ${{ inputs.p }}\n"
	for _, c := range []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"local", map[string]string{".github/workflows/w.yml": caller, ".github/workflows/r.yml": called(both, local), "act/action.yml": act},
			[]string{"act/action.yml value-unknown [variables-writer]"}},
		{"remote", map[string]string{".github/workflows/w.yml": caller, ".github/workflows/r.yml": called(both, remote)},
			[]string{".github/workflows/r.yml value-unknown [variables-writer]"}},
		{"not called", map[string]string{".github/workflows/r.yml": called("  schedule: [{cron: '0 0 * * *'}]\n  workflow_dispatch:\n    inputs:\n      p: {type: string}\n", local), "act/action.yml": act}, nil},
	} {
		for _, v := range [][]lint.AddedAttacker{nil, {lint.AddedAttackerVariablesWriter}} {
			rep, _ := runAddedWith(t, c.files, r, v...)
			want := c.want
			if v == nil {
				want = nil
			}
			if got := promptGaps(rep); !slices.Equal(got, want) {
				t.Errorf("%s, %v: %v, want %v", c.name, v, got, want)
			}
		}
	}
}

// TestRemoteCompositeWrittenValueIf: the if of the step of the agent in a
// composite action of another repository keeps the events on which the
// with of the step that uses the action gives the action a value: on
// schedule, a step that runs only on issues gives none in the run that adds
// variables-writer.
func TestRemoteCompositeWrittenValueIf(t *testing.T) {
	b, err := os.ReadFile("examples/true-positive/ai-action-prompt-injection/prompt.remote-composite.facts.json")
	if err != nil {
		t.Fatal(err)
	}
	store := strings.ReplaceAll(string(b), `Triage this issue: ${{ github.event.issue.title }}`, `Triage this issue: ${{ inputs.prompt }}`)
	store = strings.ReplaceAll(store, `- uses: anthropics/claude-code-action@v1\n      with:`, `- uses: anthropics/claude-code-action@v1\n      if: github.event_name == 'issues'\n      with:`)
	r, err := facts.LoadStore([]byte(store))
	if err != nil {
		t.Fatal(err)
	}
	for _, with := range []string{"${{ vars.P }}", "${{ needs.a.outputs.o }}"} {
		files := map[string]string{".github/workflows/w.yml": "on: {schedule: [{cron: '0 0 * * *'}]}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    outputs:\n      o: ${{ steps.s.outputs.x }}\n    steps:\n      - id: s\n        run: echo \"x=${{ vars.P }}\" >> \"$GITHUB_OUTPUT\"\n  triage:\n    needs: a\n    runs-on: ubuntu-latest\n    steps:\n      - uses: example-org/claude-prompt-composite@v1\n        with:\n          prompt: " + with + "\n"}
		rep, _ := runAddedWith(t, files, r, lint.AddedAttackerVariablesWriter)
		if got := promptGaps(rep); len(got) != 0 {
			t.Errorf("%s: %v, want none", with, got)
		}
	}
}

// TestRemoteCompositeWrittenValueInput: a step that uses a composite
// action of another repository gives, in its with, a secret to one input
// of the action and fixed text to another, and the step of the action
// puts only the second input into the prompt of the agent. In the run
// that adds secrets-writer, the secret reaches no value of the agent's
// step, so ai-action-prompt-injection reports no value-unknown; a secret
// given to the input that the prompt refers to, or a with that is one
// ${{ }} (which may give any input), gives value-unknown, marked. So does
// a secret given to another input when the prompt also has a value that
// the rule does not analyze and that is not an input (an output of a
// step of the action, which a step reading the other input may write).
func TestRemoteCompositeWrittenValueInput(t *testing.T) {
	b, err := os.ReadFile("examples/true-positive/ai-action-prompt-injection/prompt.remote-composite.facts.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, prompt, with string
		want               []string
	}{
		{"another input", "${{ inputs.prompt }}", "\n          prompt: fixed\n          anthropic-api-key: ${{ secrets.K }}", nil},
		{"the input of the prompt", "${{ inputs.prompt }}", "\n          prompt: ${{ secrets.K }}\n          anthropic-api-key: fixed", []string{".github/workflows/w.yml value-unknown [secrets-writer]"}},
		{"one ${{ }}", "${{ inputs.prompt }}", " ${{ fromJSON(secrets.K) }}", []string{".github/workflows/w.yml value-unknown [secrets-writer]"}},
		{"an output of a step", "${{ inputs.prompt }} ${{ steps.s.outputs.x }}", "\n          prompt: fixed\n          anthropic-api-key: ${{ secrets.K }}", []string{".github/workflows/w.yml value-unknown [secrets-writer]"}},
	} {
		store := strings.ReplaceAll(strings.ReplaceAll(string(b), `Triage this issue: ${{ github.event.issue.title }}`, `Triage this issue: `+c.prompt), "prompt.remote-composite.yml", "w.yml")
		store = strings.ReplaceAll(store, `steps:\n    - uses: anthropics/claude-code-action@v1`, `steps:\n    - id: s\n      shell: bash\n      run: echo \"x=${{ inputs.anthropic-api-key }}\" >> \"$GITHUB_OUTPUT\"\n    - uses: anthropics/claude-code-action@v1`)
		r, err := facts.LoadStore([]byte(store))
		if err != nil {
			t.Fatal(err)
		}
		files := map[string]string{".github/workflows/w.yml": "on: {schedule: [{cron: '0 0 * * *'}]}\njobs:\n  triage:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: example-org/claude-prompt-composite@v1\n        with:" + c.with + "\n"}
		rep, _ := runAddedWith(t, files, r, lint.AddedAttackerSecretsWriter)
		if got := slices.Compact(promptGaps(rep)); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// TestRemoteCompositeWrittenValueRoutes: a step that uses a composite
// action of another repository gives a secret to the input other and
// fixed text to the input prompt. In the run that adds secrets-writer,
// ai-action-prompt-injection reports value-unknown, marked, when a value
// of the secret may reach a reference of the prompt that the rule does
// not analyze: the prompt refers to every input (toJSON(inputs)); the
// agent is in an action that the action runs (which input reaches the
// agent is not read); and, for codex-action with the safety strategy
// unprivileged-user, which does not give the env of the step to the
// agent, the prompt refers to the input other through an env of the
// step, or to an env of the step that holds an output of a step of the
// action after the input prompt. It reports none when only a setting
// input of the agent (claude_args) refers to the input other.
func TestRemoteCompositeWrittenValueRoutes(t *testing.T) {
	b, err := os.ReadFile("examples/true-positive/ai-action-prompt-injection/prompt.remote-composite.facts.json")
	if err != nil {
		t.Fatal(err)
	}
	const orig = `"runs:\n  using: composite\n  steps:\n    - uses: anthropics/claude-code-action@v1\n      with:\n        anthropic_api_key: ${{ inputs.anthropic-api-key }}\n        prompt: \"Triage this issue: ${{ github.event.issue.title }}\"\n"`
	agentStep := func(before, prompt, with string) string {
		return "runs:\n  using: composite\n  steps:\n" + before + "    - uses: anthropics/claude-code-action@v1\n      with:\n        prompt: \"" + prompt + "\"\n" + with
	}
	output := "    - id: s\n      shell: bash\n      run: echo \"x=${{ inputs.other }}\" >> \"$GITHUB_OUTPUT\"\n"
	// codex-action with unprivileged-user does not give the env of the
	// step to the agent, so that the prompt alone refers to the env
	codexStep := func(before, prompt, env string) string {
		return "runs:\n  using: composite\n  steps:\n" + before + "    - uses: openai/codex-action@v1\n      with:\n        prompt: \"" + prompt + "\"\n        sandbox: read-only\n        safety-strategy: unprivileged-user\n      env:\n        " + env + "\n"
	}
	inner := func(content string) string {
		enc, err := json.Marshal(content)
		if err != nil {
			t.Fatal(err)
		}
		def := `"state":"found","value":{"commit":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","file":"action.yml","content":` + string(enc) + `,"archive_substituted":false}}`
		return `{"query":{"kind":"action.definition","repo":"example-org/inner","ref":"v1"},` + def + `,` +
			`{"query":{"kind":"git.ref-commit","repo":"example-org/inner","ref":"v1"},"state":"found","value":{"ref":"refs/tags/v1","sha":"21bd71901bbe5b1630ceea73d27597364c9af683"}},` +
			`{"query":{"kind":"action.definition","repo":"example-org/inner","ref":"21bd71901bbe5b1630ceea73d27597364c9af683"},` + def + `,`
	}
	marked := []string{".github/workflows/w.yml value-unknown [secrets-writer]"}
	for _, c := range []struct {
		name, action, facts string
		want                []string
	}{
		{"every input", agentStep("", "${{ toJSON(inputs) }}", ""), "", marked},
		{"env of the step", codexStep("", "${{ inputs.prompt }} ${{ env.P }}", "P: ${{ inputs.other }}"), "", marked},
		{"an output of a step in an env", codexStep(output, "${{ env.P }}", "P: ${{ inputs.prompt }} ${{ steps.s.outputs.x }}"), "", marked},
		{"an action that the action runs", "runs:\n  using: composite\n  steps:\n    - uses: example-org/inner@v1\n      with:\n        p: ${{ inputs.prompt }}\n", inner(agentStep("", "${{ inputs.p }}", "")), marked},
		{"a setting input", agentStep("", "${{ inputs.prompt }}", "        claude_args: ${{ inputs.other }}\n"), "", nil},
	} {
		enc, err := json.Marshal(c.action)
		if err != nil {
			t.Fatal(err)
		}
		store := strings.ReplaceAll(string(b), orig, string(enc))
		if store == string(b) {
			t.Fatal("the facts of the composite action changed")
		}
		store = strings.Replace(strings.ReplaceAll(store, "prompt.remote-composite.yml", "w.yml"), `"facts":[`, `"facts":[`+c.facts, 1)
		r, err := facts.LoadStore([]byte(store))
		if err != nil {
			t.Fatal(err)
		}
		files := map[string]string{".github/workflows/w.yml": "on: {schedule: [{cron: '0 0 * * *'}]}\njobs:\n  triage:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: example-org/claude-prompt-composite@v1\n        with:\n          prompt: fixed\n          other: ${{ secrets.K }}\n"}
		rep, _ := runAddedWith(t, files, r, lint.AddedAttackerSecretsWriter)
		if got := slices.Compact(promptGaps(rep)); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// TestRemoteCompositeEveryRunRules: a step that uses a composite action of
// another repository gives a variable, directly or through an env of the
// job, in its with to an input of the action, whose step runs the agent
// with Bash and with the permission checks off, on a self-hosted runner,
// and a later step of the job holds a secret. In the run that adds
// variables-writer, ai-action-excessive-tools, ai-action-execution-order
// and ai-action-unsafe-sandbox report the uses of the composite action,
// marked, as for an agent of the workflow, with the reference of the with
// in the evidence. The output of a job, which the rules do not analyze,
// gives no finding (reach-unknown, as for an agent of the workflow); nor
// does the run that adds no attacker.
func TestRemoteCompositeEveryRunRules(t *testing.T) {
	b, err := os.ReadFile("examples/true-positive/ai-action-prompt-injection/prompt.remote-composite.facts.json")
	if err != nil {
		t.Fatal(err)
	}
	store := strings.ReplaceAll(string(b), `prompt: \"Triage this issue: ${{ github.event.issue.title }}\"\n`, `prompt: \"Triage this issue: ${{ inputs.prompt }}\"\n        claude_args: --allowedTools Bash --dangerously-skip-permissions\n`)
	r, err := facts.LoadStore([]byte(store))
	if err != nil {
		t.Fatal(err)
	}
	const uses = "example-org/claude-prompt-composite@v1"
	src := func(with string) string {
		return "on: {schedule: [{cron: '0 0 * * *'}]}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    outputs:\n      o: ${{ steps.s.outputs.x }}\n    steps:\n      - id: s\n        run: echo \"x=${{ vars.P }}\" >> \"$GITHUB_OUTPUT\"\n  triage:\n    needs: a\n    runs-on: self-hosted\n    env:\n      NOTE: ${{ vars.NOTE }}\n    steps:\n      - uses: " + uses + "\n        with:\n          prompt: " + with + "\n      - run: ./deploy.sh\n        env:\n          TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n"
	}
	rules := []struct {
		id   lint.RuleID
		kind string
	}{
		{AIActionExcessiveToolsID, "ai-action-excessive-tools.run-code"},
		{AIActionExecutionOrderID, "ai-action-execution-order.later-secrets"},
		{AIActionUnsafeSandboxID, "ai-action-unsafe-sandbox.commands"},
	}
	for _, c := range []struct {
		name, with, ref string // ref: the reference of the with the evidence names, none for no finding
	}{
		{"variable", "${{ vars.P }}", "vars.P"},
		{"env of the job", "${{ env.NOTE }}", "env.NOTE"},
		{"output of a job", "${{ needs.a.outputs.o }}", ""},
	} {
		files := map[string]string{".github/workflows/w.yml": src(c.with)}
		base, baseIn := runAddedWith(t, files, r)
		rep, in := runAddedWith(t, files, r, lint.AddedAttackerVariablesWriter)
		for _, x := range rules {
			if got := marked(t, base, baseIn, x.id); len(got) != 0 {
				t.Errorf("%s, %s: the run that adds no attacker: %v", c.name, x.id, got)
			}
			var got []string
			for _, f := range marked(t, rep, in, x.id) {
				if strings.Contains(f, " "+x.kind+" ") {
					got = append(got, f)
				}
			}
			if c.ref == "" {
				if len(got) != 0 {
					t.Errorf("%s, %s: %v, want none", c.name, x.id, got)
				}
				continue
			}
			if want := []string{".github/workflows/w.yml " + x.kind + " " + uses + " [variables-writer]"}; !slices.Equal(got, want) {
				t.Errorf("%s, %s: %v, want %v", c.name, x.id, got, want)
			}
			route := c.ref + ": " + c.ref + " reaches the input prompt of the composite action " + uses + " through the with of the step that uses the composite action " + uses
			if notes := evidenceNotes(t, rep, in, x.id, x.kind); !slices.ContainsFunc(notes, func(n string) bool { return strings.HasPrefix(n, route) }) {
				t.Errorf("%s, %s: evidence %q, want one that starts with %q", c.name, x.id, notes, route)
			}
		}
	}
}

// TestRemoteCompositeEveryRunNarrow: the with of a step that uses a
// composite action of another repository counts in the three rules only
// for an input that a value of the step of the agent refers to, and only
// when the step of the agent is a step of that composite action. In the
// run that adds secrets-writer, the API key the with gives an input that
// only anthropic_api_key reads gives no finding, as for an agent of the
// workflow; an if of the step of the agent that the event fails gives
// none; a composite action of the repository that wraps the composite
// action reads its own with: a fixed note gives none, and a note that the
// wrapper gives on from its input is reported in the wrapper, not in the
// workflow.
func TestRemoteCompositeEveryRunNarrow(t *testing.T) {
	const composite = "example-org/claude-note-unsafe-composite"
	load := func(t *testing.T, edit func(string) string) facts.Resolver {
		t.Helper()
		b, err := os.ReadFile("examples/true-positive/ai-action-unsafe-sandbox/commands.remote-composite-value-run.facts.json")
		if err != nil {
			t.Fatal(err)
		}
		r, err := facts.LoadStore([]byte(edit(string(b))))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	same := func(s string) string { return s }
	innerIf := func(s string) string {
		return strings.ReplaceAll(s, `- uses: anthropics/claude-code-action@v1\n      with:`, `- uses: anthropics/claude-code-action@v1\n      if: github.event_name == 'issues'\n      with:`)
	}
	workflow := func(uses, note string) string {
		return "on: {schedule: [{cron: '0 0 * * *'}]}\njobs:\n  claude:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: " + uses + "\n        with:\n          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}\n          note: " + note + "\n"
	}
	wrap := func(note string) string {
		return "name: w\ninputs:\n  anthropic-api-key: {}\n  note: {}\nruns:\n  using: composite\n  steps:\n    - uses: " + composite + "@v1\n      with:\n        anthropic-api-key: ${{ inputs.anthropic-api-key }}\n        note: " + note + "\n"
	}
	for _, c := range []struct {
		name  string
		edit  func(string) string
		files map[string]string
		v     lint.AddedAttacker
		want  []string
	}{
		{"the API key", same, map[string]string{".github/workflows/w.yml": workflow(composite+"@v1", "fixed")}, lint.AddedAttackerSecretsWriter, nil},
		{"the note", same, map[string]string{".github/workflows/w.yml": workflow(composite+"@v1", "${{ vars.N }}")}, lint.AddedAttackerVariablesWriter,
			[]string{".github/workflows/w.yml ai-action-unsafe-sandbox.commands " + composite + "@v1 [variables-writer]"}},
		{"an if of the step of the agent", innerIf, map[string]string{".github/workflows/w.yml": workflow(composite+"@v1", "${{ vars.N }}")}, lint.AddedAttackerVariablesWriter, nil},
		{"a with that is one ${{ }}", same, map[string]string{".github/workflows/w.yml": "on: {schedule: [{cron: '0 0 * * *'}]}\njobs:\n  claude:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + composite + "@v1\n        with: ${{ fromJSON(format('{{\"anthropic-api-key\":\"{0}\",\"note\":\"fixed\"}}', secrets.KEY)) }}\n"}, lint.AddedAttackerSecretsWriter, nil},
		{"a wrapper with a fixed note", same, map[string]string{".github/workflows/w.yml": workflow("./wrap", "${{ vars.N }}"), "wrap/action.yml": wrap("fixed")}, lint.AddedAttackerVariablesWriter, nil},
		{"a wrapper that gives the note on", same, map[string]string{".github/workflows/w.yml": workflow("./wrap", "${{ vars.N }}"), "wrap/action.yml": wrap("${{ inputs.note }}")}, lint.AddedAttackerVariablesWriter,
			[]string{"wrap/action.yml ai-action-unsafe-sandbox.commands " + composite + "@v1 [variables-writer]"}},
	} {
		r := load(t, c.edit)
		rep, in := runAddedWith(t, c.files, r, c.v)
		if got := marked(t, rep, in, AIActionUnsafeSandboxID); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		if gaps := promptGaps(rep); slices.ContainsFunc(gaps, func(g string) bool {
			return strings.HasPrefix(g, ".github/workflows/w.yml ") && strings.Contains(c.name, "wrapper")
		}) {
			t.Errorf("%s: value-unknown in the workflow for the step of the wrapper: %v", c.name, gaps)
		}
	}
}

// TestRemoteCompositeEveryRunEnv: the step of codex-action in a composite
// action of another repository, whose safety-strategy unprivileged-user
// does not pass the env of the step to the agent, puts env.NOTE into the
// prompt, and the env NOTE of the step is the input note: in the run that
// adds variables-writer, the variable the with gives the input note is
// counted, as for the input in the prompt itself.
func TestRemoteCompositeEveryRunEnv(t *testing.T) {
	b, err := os.ReadFile("examples/true-positive/ai-action-unsafe-sandbox/commands.remote-composite.facts.json")
	if err != nil {
		t.Fatal(err)
	}
	store := strings.ReplaceAll(string(b), `prompt: \"Answer issue #${{ github.event.issue.number }}\"\n        sandbox: danger-full-access\n`, `prompt: \"Answer ${{ env.NOTE }}\"\n        sandbox: danger-full-access\n        safety-strategy: unprivileged-user\n      env:\n        NOTE: ${{ inputs.note }}\n`)
	if store == string(b) {
		t.Fatal("the facts do not have the step of codex-action")
	}
	r, err := facts.LoadStore([]byte(store))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{".github/workflows/w.yml": "on: {schedule: [{cron: '0 0 * * *'}]}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: example-org/codex-sandbox-composite@v1\n        with:\n          note: ${{ vars.N }}\n"}
	rep, in := runAddedWith(t, files, r, lint.AddedAttackerVariablesWriter)
	if got := marked(t, rep, in, AIActionUnsafeSandboxID); len(got) == 0 {
		t.Errorf("no marked finding of ai-action-unsafe-sandbox")
	}
}

// TestAIActionPromptInjectionEveryRun: in a run that adds variables-writer
// or secrets-writer, a variable or a secret that reaches the agent as text
// is the attacker's in every run, whoever starts the run: on an event the
// attacker does not trigger, past an if that only a maintainer passes, on
// gollum; the finding is marked, and the run that adds no attacker gives
// none. A value the rule does not analyze, such as the output of a step,
// gives value-unknown in such a run.
func TestAIActionPromptInjectionEveryRun(t *testing.T) {
	claude := func(on, cond, with string) string {
		src := "on: " + on + "\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
		if cond != "" {
			src += "    if: " + cond + "\n"
		}
		return src + "    steps:\n      - id: s\n        run: echo\n      - uses: anthropics/claude-code-action@v1\n" + with
	}
	owner := "github.event.issue.author_association == 'OWNER'"
	for _, c := range []struct {
		name, src string
		v         lint.AddedAttacker
		want      []string
	}{
		{"env, assigned", claude("{issues: {types: [assigned]}}", "", "        env:\n          TRIAGE_GUIDE: ${{ vars.TRIAGE_GUIDE }}\n        with:\n          prompt: Triage the issue by the guide in the env TRIAGE_GUIDE\n"), lint.AddedAttackerVariablesWriter,
			[]string{"ai-action-prompt-injection.env vars.TRIAGE_GUIDE [variables-writer]"}},
		{"prompt, owner only", claude("{issues: {types: [assigned]}}", owner, "        with:\n          prompt: \"Triage ${{ vars.P }}\"\n"), lint.AddedAttackerVariablesWriter,
			[]string{"ai-action-prompt-injection.prompt vars.P [variables-writer]"}},
		{"prompt, schedule", claude("{schedule: [{cron: '0 0 * * *'}]}", "", "        with:\n          prompt: \"Triage ${{ vars.P }}\"\n"), lint.AddedAttackerVariablesWriter,
			[]string{"ai-action-prompt-injection.prompt vars.P [variables-writer]"}},
		{"prompt, workflow_dispatch", claude("workflow_dispatch", "", "        with:\n          prompt: \"Triage ${{ vars.P }}\"\n"), lint.AddedAttackerVariablesWriter,
			[]string{"ai-action-prompt-injection.prompt vars.P [variables-writer]"}},
		{"gollum", "on: gollum\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/ai-inference@v1\n        with:\n          prompt: \"Summarize ${{ vars.P }}\"\n", lint.AddedAttackerVariablesWriter,
			[]string{"ai-action-prompt-injection.prompt vars.P [variables-writer]"}},
		{"secret", claude("{schedule: [{cron: '0 0 * * *'}]}", "", "        with:\n          prompt: \"Triage ${{ secrets.P }}\"\n"), lint.AddedAttackerSecretsWriter,
			[]string{"ai-action-prompt-injection.prompt secrets.P [secrets-writer]"}},
		{"GITHUB_TOKEN", claude("{schedule: [{cron: '0 0 * * *'}]}", "", "        with:\n          prompt: \"Triage ${{ secrets.GITHUB_TOKEN }}\"\n"), lint.AddedAttackerSecretsWriter, nil},
	} {
		files := map[string]string{".github/workflows/w.yml": c.src}
		rep, in := runAdded(t, files)
		if got := marked(t, rep, in, AIActionPromptInjectionID); len(got) != 0 {
			t.Errorf("%s: the run that adds no attacker: %v", c.name, got)
		}
		rep, in = runAdded(t, files, c.v)
		var got []string
		for _, f := range marked(t, rep, in, AIActionPromptInjectionID) {
			got = append(got, strings.TrimPrefix(f, ".github/workflows/w.yml "))
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	// the output of a step, which the rule does not analyze
	files := map[string]string{".github/workflows/w.yml": claude("{issues: {types: [assigned]}}", owner, "        with:\n          prompt: \"Triage ${{ steps.s.outputs.x }}\"\n")}
	gaps := func(rep lint.Report) []string {
		var out []string
		for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
			if g.Rule == AIActionPromptInjectionID {
				var marks []string
				for _, m := range g.AddedAttackers {
					marks = append(marks, m.String())
				}
				out = append(out, g.InconclusiveKind.String()+" ["+strings.Join(marks, ",")+"]")
			}
		}
		return out
	}
	rep, _ := runAdded(t, files)
	if got := gaps(rep); len(got) != 0 {
		t.Errorf("the output of a step, the run that adds no attacker: %v", got)
	}
	rep, _ = runAdded(t, files, lint.AddedAttackerVariablesWriter)
	if got, want := gaps(rep), []string{"value-unknown [variables-writer]"}; !slices.Equal(got, want) {
		t.Errorf("the output of a step: %v, want %v", got, want)
	}
}

// TestEveryRunNote: the note of the evidence of a reference that reaches
// the agent, by its route and where its value comes from.
func TestEveryRunNote(t *testing.T) {
	claude := analysis.AgentActionClaudeCode
	envA, _ := workflow.EnvNameOf("A")
	note, _ := workflow.InputNameOf("note")
	for _, c := range []struct {
		secret bool
		r      ir.EveryRunRef
		want   string
	}{
		{false, ir.EveryRunRef{Route: analysis.AgentValueRoutePromptInput, Input: analysis.AgentInputPrompt, Ref: ir.ExprRef{Text: "vars.P"}, Source: "vars.P", SourceName: "P", Direct: true},
			"vars.P reaches the agent through the input prompt of anthropics/claude-code-action, and an attacker who can write the variable P chooses the value of vars.P for every workflow run, whoever starts the workflow run"},
		{false, ir.EveryRunRef{Route: analysis.AgentValueRouteStepEnv, Env: envA, Ref: ir.ExprRef{Text: "env.A"}, Source: "vars.P", SourceName: "P"},
			"env.A reaches the agent through the env A of the step; the value of env.A comes from vars.P, and an attacker who can write the variable P chooses the value of vars.P for every workflow run, whoever starts the workflow run"},
		{false, ir.EveryRunRef{Route: analysis.AgentValueRouteJobEnv, Env: envA, Ref: ir.ExprRef{Text: "vars.P"}, Source: "vars.P", SourceName: "P", Direct: true},
			"vars.P reaches the agent through the variable A in the env of the job, and an attacker who can write the variable P chooses the value of vars.P for every workflow run, whoever starts the workflow run"},
		{true, ir.EveryRunRef{Route: analysis.AgentValueRouteWorkflowEnv, Env: envA, Ref: ir.ExprRef{Text: "secrets.S"}, Source: "secrets.S", SourceName: "S", Direct: true},
			"secrets.S reaches the agent through the variable A in the env of the workflow, and an attacker who can write the secret S chooses the value of secrets.S for every workflow run, whoever starts the workflow run"},
		{false, ir.EveryRunRef{Route: analysis.AgentValueRouteSettingInput, Input: analysis.AgentInputClaudeArgs, Ref: ir.ExprRef{Text: "vars.A"}, Source: "vars.A", SourceName: "A", Direct: true},
			"vars.A reaches the settings of the agent through the input claude_args of anthropics/claude-code-action, and an attacker who can write the variable A chooses the value of vars.A for every workflow run, whoever starts the workflow run"},
		{true, ir.EveryRunRef{Route: analysis.AgentValueRoutePromptInput, Input: analysis.AgentInputPrompt, Ref: ir.ExprRef{Text: "inputs.x"}},
			"inputs.x reaches the agent through the input prompt of anthropics/claude-code-action; the value of inputs.x comes from a secret, and an attacker who can write secrets chooses the value of the secret for every workflow run, whoever starts the workflow run"},
		{true, ir.EveryRunRef{Route: analysis.AgentValueRoutePromptInput, Input: analysis.AgentInputPrompt, Ref: ir.ExprRef{Text: "secrets.S"}, Source: "secrets.S", SourceName: "S", Direct: true},
			"secrets.S reaches the agent through the input prompt of anthropics/claude-code-action, and an attacker who can write the secret S chooses the value of secrets.S for every workflow run, whoever starts the workflow run"},
		{false, ir.EveryRunRef{Route: analysis.AgentValueRouteCompositeInput, CompositeInput: note, Composite: "o/c@v1", Ref: ir.ExprRef{Text: "vars.N"}, Source: "vars.N", SourceName: "N", Direct: true},
			"vars.N reaches the input note of the composite action o/c@v1 through the with of the step that uses the composite action o/c@v1, and an attacker who can write the variable N chooses the value of vars.N for every workflow run, whoever starts the workflow run. A ${{ }} in the with or the env of the step that runs the agent of anthropics/claude-code-action in the composite action o/c@v1 refers to the input note, so the rule counts the input note as a value that reaches the agent. The rule does not count an input of the composite action o/c@v1 that reaches the agent only through another step of the composite action o/c@v1"},
	} {
		if got := everyRunNote(c.secret, claude, c.r); got != c.want {
			t.Errorf("got  %q\nwant %q", got, c.want)
		}
	}
}

// evidenceNotes are the notes of the evidence of the findings of the
// rule id and the kind kind in rep, each as <the text it points at>: <note>,
// but the evidence in the answer of a fact (such as the file of a composite
// action of another repository), which no input holds.
func evidenceNotes(t *testing.T, rep lint.Report, in lint.Inputs, id lint.RuleID, kind string) []string {
	t.Helper()
	var out []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Rule != id || f.Args.KindID().String() != kind {
			continue
		}
		for _, e := range f.Evidence {
			if e.Location.File.Input == (facts.InputPath{}) {
				continue // a place in the answer of a fact, such as the file of a composite action of another repository
			}
			i, st := in.Lookup(e.Location.File.Input)
			if st != lint.LookupFound {
				t.Fatalf("no input %s", e.Location.File.Input)
			}
			out = append(out, string(i.Tree.Bytes()[e.Location.Span.Start:e.Location.Span.End])+": "+e.Note)
		}
	}
	return out
}

// claudeJob is a workflow of a job on on, past the if cond when it is not
// empty, on the runner runsOn, whose steps are a claude-code-action with
// the with with, and then the steps after.
func claudeJob(on, cond, runsOn, with, after string) string {
	src := "on: " + on + "\njobs:\n  a:\n    runs-on: " + runsOn + "\n"
	if cond != "" {
		src += "    if: " + cond + "\n"
	}
	return src + "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n" + with + after
}

const ownerIf = "github.event.issue.author_association == 'OWNER'"

// TestAIActionExcessiveToolsEveryRun: in a run that adds variables-writer,
// a variable in a setting input is the attacker's (setting-value), and a
// variable in the prompt steers an agent whose permissions let it run any
// code or start in auto mode (run-code, auto-mode), with the variable in
// the evidence; the run that adds no attacker gives none of them.
func TestAIActionExcessiveToolsEveryRun(t *testing.T) {
	assigned := "{issues: {types: [assigned]}}"
	for _, c := range []struct {
		name, src, kind string
		want            []string
		evidence        string
	}{
		{"setting", claudeJob(assigned, "", "ubuntu-latest", "          prompt: Triage the issue\n          claude_args: ${{ vars.CLAUDE_ARGS }}\n", ""), "ai-action-excessive-tools.setting-value",
			[]string{"ai-action-excessive-tools.setting-value vars.CLAUDE_ARGS [variables-writer]"}, ""},
		{"run code", claudeJob(assigned, ownerIf, "ubuntu-latest", "          prompt: \"Triage ${{ vars.P }}\"\n          claude_args: --allowedTools Bash\n", ""), "ai-action-excessive-tools.run-code",
			[]string{"ai-action-excessive-tools.run-code Bash [variables-writer]"}, "vars.P: vars.P reaches the agent through the input prompt of anthropics/claude-code-action, and an attacker who can write the variable P chooses the value of vars.P for every workflow run, whoever starts the workflow run"},
		{"auto mode", claudeJob(assigned, ownerIf, "ubuntu-latest", "          prompt: \"Triage ${{ vars.P }}\"\n          claude_args: --permission-mode auto\n", ""), "ai-action-excessive-tools.auto-mode",
			[]string{"ai-action-excessive-tools.auto-mode --permission-mode auto [variables-writer]"}, "vars.P: vars.P reaches the agent through the input prompt of anthropics/claude-code-action, and an attacker who can write the variable P chooses the value of vars.P for every workflow run, whoever starts the workflow run"},
	} {
		files := map[string]string{".github/workflows/w.yml": c.src}
		rep, in := runAdded(t, files)
		if got := marked(t, rep, in, AIActionExcessiveToolsID); len(got) != 0 {
			t.Errorf("%s: the run that adds no attacker: %v", c.name, got)
		}
		rep, in = runAdded(t, files, lint.AddedAttackerVariablesWriter)
		var got []string
		for _, f := range marked(t, rep, in, AIActionExcessiveToolsID) {
			if strings.Contains(f, " "+c.kind+" ") {
				got = append(got, strings.TrimPrefix(f, ".github/workflows/w.yml "))
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		if notes := evidenceNotes(t, rep, in, AIActionExcessiveToolsID, c.kind); c.evidence != "" && !slices.Contains(notes, c.evidence) {
			t.Errorf("%s: evidence %q, want %q", c.name, notes, c.evidence)
		}
	}
}

// TestAIActionExecutionOrderEveryRun: in a run that adds variables-writer,
// a variable in the prompt steers an agent that runs any code, and a later
// step holds a secret the agent does not: later-secrets, marked, with the
// variable in the evidence; a later step whose if leaves out the events of
// the variable does not count. The run that adds no attacker gives none.
func TestAIActionExecutionOrderEveryRun(t *testing.T) {
	with := "          prompt: \"Triage ${{ vars.P }}\"\n          claude_args: --allowedTools Bash\n"
	deploy := func(cond string) string {
		s := "      - run: ./deploy.sh\n"
		if cond != "" {
			s = "      - if: " + cond + "\n        run: ./deploy.sh\n"
		}
		return s + "        env:\n          TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n"
	}
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"later secret", claudeJob("{issues: {types: [assigned]}}", ownerIf, "self-hosted", with, deploy("")), []string{"ai-action-execution-order.later-secrets anthropics/claude-code-action@v1 [variables-writer]"}},
		{"later step not on schedule", claudeJob("{schedule: [{cron: '0 0 * * *'}]}", "", "self-hosted", with, deploy("github.event_name == 'issues'")), nil},
	} {
		files := map[string]string{".github/workflows/w.yml": c.src}
		rep, in := runAdded(t, files)
		if got := marked(t, rep, in, AIActionExecutionOrderID); len(got) != 0 {
			t.Errorf("%s: the run that adds no attacker: %v", c.name, got)
		}
		rep, in = runAdded(t, files, lint.AddedAttackerVariablesWriter)
		var got []string
		for _, f := range marked(t, rep, in, AIActionExecutionOrderID) {
			got = append(got, strings.TrimPrefix(f, ".github/workflows/w.yml "))
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		if c.want != nil && !slices.ContainsFunc(evidenceNotes(t, rep, in, AIActionExecutionOrderID, "ai-action-execution-order.later-secrets"), func(n string) bool { return strings.HasPrefix(n, "vars.P: vars.P reaches the agent") }) {
			t.Errorf("%s: no evidence of vars.P", c.name)
		}
	}
}

// TestAIActionUnsafeSandboxEveryRun: in a run that adds variables-writer,
// a variable in the prompt steers an agent whose sandbox is off: the
// finding of the setting, marked, with the variable in the evidence; the
// run that adds no attacker gives none.
func TestAIActionUnsafeSandboxEveryRun(t *testing.T) {
	files := map[string]string{".github/workflows/w.yml": claudeJob("{issues: {types: [assigned]}}", ownerIf, "ubuntu-latest", "          prompt: \"Triage ${{ vars.P }}\"\n          claude_args: --dangerously-skip-permissions\n", "")}
	rep, in := runAdded(t, files)
	if got := marked(t, rep, in, AIActionUnsafeSandboxID); len(got) != 0 {
		t.Errorf("the run that adds no attacker: %v", got)
	}
	rep, in = runAdded(t, files, lint.AddedAttackerVariablesWriter)
	got := marked(t, rep, in, AIActionUnsafeSandboxID)
	if want := []string{".github/workflows/w.yml ai-action-unsafe-sandbox.commands --dangerously-skip-permissions [variables-writer]"}; !slices.Equal(got, want) {
		t.Errorf("%v, want %v", got, want)
	}
	if !slices.ContainsFunc(evidenceNotes(t, rep, in, AIActionUnsafeSandboxID, "ai-action-unsafe-sandbox.commands"), func(n string) bool { return strings.HasPrefix(n, "vars.P: vars.P reaches the agent") }) {
		t.Error("no evidence of vars.P")
	}
}

// TestJobEnvEveryRun: in a run that adds variables-writer, a variable in
// an env of the job reaches the process of the agent, and the rules of the
// steps count it as one in the prompt: the step kind of
// ai-action-excessive-tools, ai-action-execution-order and
// ai-action-unsafe-sandbox (TestAIActionExcessiveToolsEveryRun and the
// others).
func TestJobEnvEveryRun(t *testing.T) {
	jobEnv := func(runsOn, with, after string) string {
		return "on: {issues: {types: [assigned]}}\njobs:\n  a:\n    runs-on: " + runsOn + "\n    if: " + ownerIf + "\n    env:\n      GUIDE: ${{ vars.GUIDE }}\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: Triage the issue by the guide in the env GUIDE\n" + with + after
	}
	for _, c := range []struct {
		id   lint.RuleID
		src  string
		want string
	}{
		{AIActionExcessiveToolsID, jobEnv("ubuntu-latest", "          claude_args: --allowedTools Bash\n", ""), ".github/workflows/w.yml ai-action-excessive-tools.run-code Bash [variables-writer]"},
		{AIActionExecutionOrderID, jobEnv("self-hosted", "          claude_args: --allowedTools Bash\n", "      - run: ./deploy.sh\n        env:\n          TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n"), ".github/workflows/w.yml ai-action-execution-order.later-secrets anthropics/claude-code-action@v1 [variables-writer]"},
		{AIActionUnsafeSandboxID, jobEnv("ubuntu-latest", "          claude_args: --dangerously-skip-permissions\n", ""), ".github/workflows/w.yml ai-action-unsafe-sandbox.commands --dangerously-skip-permissions [variables-writer]"},
	} {
		rep, in := runAdded(t, map[string]string{".github/workflows/w.yml": c.src}, lint.AddedAttackerVariablesWriter)
		if got := marked(t, rep, in, c.id); !slices.Equal(got, []string{c.want}) {
			t.Errorf("%s: %v, want %s", c.id, got, c.want)
		}
	}
}

// TestAgentPlaceInconclusiveRelated: an inconclusive place in a composite
// action of another repository is at the uses of the step of the input
// that runs the action, with the place in the file of the action in
// Related, as a finding has it in Evidence, and a detected text of the
// rule alone.
func TestAgentPlaceInconclusiveRelated(t *testing.T) {
	b, err := os.ReadFile("examples/true-positive/ai-action-prompt-injection/prompt.remote-composite.facts.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := facts.LoadStore([]byte(strings.ReplaceAll(string(b), `Triage this issue: ${{ github.event.issue.title }}`, `Triage this issue: ${{ inputs.prompt }}`)))
	if err != nil {
		t.Fatal(err)
	}
	caller := "on: {schedule: [{cron: '0 0 * * *'}]}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    outputs:\n      o: ${{ steps.s.outputs.x }}\n    steps:\n      - id: s\n        run: echo \"x=${{ vars.P }}\" >> \"$GITHUB_OUTPUT\"\n  c:\n    needs: a\n    uses: ./.github/workflows/r.yml\n    with:\n      p: ${{ needs.a.outputs.o }}\n"
	called := "on:\n  workflow_call:\n    inputs:\n      p: {type: string}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: example-org/claude-prompt-composite@v1\n        with:\n          prompt: ${{ inputs.p }}\n"
	rep, _ := runAddedWith(t, map[string]string{".github/workflows/w.yml": caller, ".github/workflows/r.yml": called}, r, lint.AddedAttackerVariablesWriter)
	var got []lint.Finding
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		if g.Rule == AIActionPromptInjectionID {
			got = append(got, g)
		}
	}
	if len(got) != 1 {
		t.Fatalf("%d inconclusive findings of ai-action-prompt-injection, want 1", len(got))
	}
	g := got[0]
	if g.Location.File.Input.String() != ".github/workflows/r.yml" || strings.HasPrefix(g.Detected(), "in the composite action") {
		t.Errorf("at %v, detected %q: want the uses of r.yml and the note of the rule", g.Location.File, g.Detected())
	}
	if len(g.Related) == 0 || g.Related[0].Location.File.Query == nil || g.Related[0].Note != "in the composite action example-org/claude-prompt-composite@v1" {
		t.Errorf("related %+v, want first the place in the file of the action", g.Related)
	}
	if len(g.Evidence) != 0 {
		t.Errorf("evidence %+v, want none", g.Evidence)
	}
}

// injectionLines are the places of ai-action-prompt-injection in rep, each
// as <kind> <certainty> <line> <the text it points at>, sorted; with the
// action of the arguments of a finding when action is set.
func injectionLines(rep lint.Report, action bool) []string {
	var out []string
	for _, f := range rep.Findings {
		if f.Rule != AIActionPromptInjectionID {
			continue
		}
		kind := f.InconclusiveKind.String()
		if f.Certainty != lint.CertaintyInconclusive {
			kind = f.Args.KindID().String()
		}
		l := fmt.Sprintf("%s %s %d %s", kind, f.Certainty, f.Location.Position().Line, f.SpanText)
		if a, ok := f.Args.(AIActionPromptInjectionEnv); ok && action {
			l += " " + a.Action.String()
		}
		out = append(out, l)
	}
	slices.Sort(out)
	return out
}

// TestJobEnvTwoAgentSteps: a value of the env of the job or of the
// workflow that reaches several agent steps is one place, at the env,
// whatever the order of the steps: a finding with no condition when one
// step gives one, else one with the condition, else each kind of
// inconclusive place once; and no error of a finding reported twice
// (runAdded fails on one). An env of a step whose name differs only in
// case replaces it only where runs-on decides Windows, whose runner folds
// the names.
func TestJobEnvTwoAgentSteps(t *testing.T) {
	const prompt = "Label the issue whose body is in the env BODY"
	const anyUser, anyBot, users = `allowed_non_write_users: "*"`, `allowed_bots: "*"`, `allowed_non_write_users: ${{ vars.USERS }}`
	claude := func(gate, prompt, env string) string {
		return "      - uses: anthropics/claude-code-action@v1\n" + env + "        with:\n          " + gate + "\n          github_token: t\n          prompt: \"" + prompt + "\"\n          claude_args: --allowedTools Bash\n"
	}
	// gemini-cli passes ISSUE_BODY to its tools, not BODY, with no settings
	gemini := "      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          prompt: Label the issue whose body is in ISSUE_BODY\n"
	job := func(runsOn, body string) string {
		return "on: {issues: {types: [opened]}}\njobs:\n  a:\n    runs-on: " + runsOn + "\n    env:\n      BODY: " + body + "\n    steps:\n"
	}
	const body = "${{ github.event.issue.body }}"
	const env, envPublic = "ai-action-prompt-injection.env confirmed 6 github.event.issue.body", "ai-action-prompt-injection.env conditional 6 github.event.issue.body"
	for _, c := range []struct {
		name, src string
		action    bool
		want      []string
	}{
		{"two steps", job("ubuntu-latest", body) + claude(anyUser, prompt, "") + claude(anyUser, prompt, ""), false, []string{env}},
		{"the first step has the value in its prompt too", job("ubuntu-latest", body) + claude(anyUser, "Label this issue: "+body, "") + claude(anyUser, prompt, ""), false,
			[]string{env, "ai-action-prompt-injection.prompt confirmed 12 github.event.issue.body"}},
		{"a bot's gate, then anyone's", job("ubuntu-latest", body) + claude(anyBot, prompt, "") + claude(anyUser, prompt, ""), false, []string{env}},
		{"anyone's gate, then a bot's", job("ubuntu-latest", body) + claude(anyUser, prompt, "") + claude(anyBot, prompt, ""), false, []string{env}},
		{"two bots' gates", job("ubuntu-latest", body) + claude(anyBot, prompt, "") + claude(anyBot, prompt, ""), false, []string{envPublic}},
		{"an undecided gate, then anyone's", job("ubuntu-latest", body) + claude(users, prompt, "") + claude(anyUser, prompt, ""), false, []string{env}},
		{"an undecided gate alone", job("ubuntu-latest", body) + claude(users, prompt, "") + claude(users, prompt, ""), false,
			[]string{"gate-expr inconclusive 6 github.event.issue.body"}},
		{"the action of the strongest step", strings.Replace(job("ubuntu-latest", body), "BODY:", "ISSUE_BODY:", 1) + claude(anyBot, prompt, "") + gemini, true,
			[]string{env + " run-gemini-cli"}},
		{"one text twice in the value", job("ubuntu-latest", `"`+body+` `+body+`"`) + claude(anyUser, prompt, "") + claude(anyUser, prompt, ""), false,
			[]string{env, env}},
		{"a case-only name on Linux", job("ubuntu-latest", body) + claude(anyUser, prompt, "        env:\n          body: fixed text\n"), false, []string{env}},
		{"a case-only name on Windows", job("windows-latest", body) + claude(anyUser, prompt, "        env:\n          body: fixed text\n"), false, nil},
		{"a case-only name where runs-on does not decide the OS (unknown-os-case)", strings.Replace(job("${{ matrix.os }}", body), "    runs-on:", "    strategy: {matrix: {os: [ubuntu-latest, windows-latest]}}\n    runs-on:", 1) + claude(anyUser, prompt, "        env:\n          body: fixed text\n"), false,
			[]string{"ai-action-prompt-injection.env confirmed 7 github.event.issue.body"}},
		{"a step before writes the name to $GITHUB_ENV (github-env-write)", job("ubuntu-latest", body) + "      - run: echo \"BODY=fixed\" >> \"$GITHUB_ENV\"\n" + claude(anyUser, prompt, ""), false, []string{env}},
		{"a step before with an if writes the name to $GITHUB_ENV", job("ubuntu-latest", body) + "      - if: github.event_name == 'push'\n        run: echo \"BODY=fixed\" >> \"$GITHUB_ENV\"\n" + claude(anyUser, prompt, ""), false, []string{env}},
		{"a step before writes the value back to $GITHUB_ENV", job("ubuntu-latest", body) + "      - run: echo \"BODY=${BODY}\" >> \"$GITHUB_ENV\"\n" + claude(anyUser, prompt, ""), false, []string{env}},
		{"a step before writes the value back in a heredoc", job("ubuntu-latest", body) + "      - run: |\n          {\n            echo \"BODY<<EOF\"\n            echo \"$BODY\"\n            echo EOF\n          } >> \"$GITHUB_ENV\"\n" + claude(anyUser, prompt, ""), false, []string{env}},
		{"a step before writes the name in a branch", job("ubuntu-latest", body) + "      - run: |\n          if [ -z \"$BODY\" ]; then echo \"BODY=none\" >> \"$GITHUB_ENV\"; fi\n" + claude(anyUser, prompt, ""), false, []string{env}},
		{"a step before writes the name after &&", job("ubuntu-latest", body) + "      - run: test -z \"$BODY\" && echo \"BODY=none\" >> \"$GITHUB_ENV\"\n" + claude(anyUser, prompt, ""), false, []string{env}},
		{"a step before writes the name in another case to $GITHUB_ENV on Linux", job("ubuntu-latest", body) + "      - run: echo \"body=fixed\" >> \"$GITHUB_ENV\"\n" + claude(anyUser, prompt, ""), false, []string{env}},
		{"a step before writes the name in another case to $GITHUB_ENV on Windows (github-env-write)", job("windows-latest", body) + "      - run: echo \"body=fixed\" >> \"$GITHUB_ENV\"\n        shell: bash\n" + claude(anyUser, prompt, ""), false, []string{env}},
		{"a step after writes the name to $GITHUB_ENV", job("ubuntu-latest", body) + claude(anyUser, prompt, "") + "      - run: echo \"BODY=fixed\" >> \"$GITHUB_ENV\"\n", false, []string{env}},
		{"a step env that is one whole ${{ }} (whole-with)", job("ubuntu-latest", body) + claude(anyUser, prompt, "        env: ${{ fromJSON(vars.STEP_ENV) }}\n"), false, nil},
		{"an undecided gate, then a bot's", job("ubuntu-latest", body) + claude(users, prompt, "") + claude(anyBot, prompt, ""), false,
			[]string{envPublic, "gate-expr inconclusive 6 github.event.issue.body"}},
	} {
		rep, _ := runAdded(t, map[string]string{".github/workflows/w.yml": c.src})
		if got := injectionLines(rep, c.action); !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	// an input of workflow_dispatch in the env of the job: the dispatcher's
	// for a step that runs on workflow_dispatch, not analyzed for a step
	// that runs on issues only
	dispatch := "on:\n  workflow_dispatch:\n    inputs:\n      x: {type: string}\n  issues:\n    types: [opened]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n      X: ${{ inputs.x }}\n    steps:\n" + claude(anyUser, prompt, "") + strings.Replace(claude(anyUser, prompt, ""), "      - uses:", "      - if: github.event_name == 'issues'\n        uses:", 1)
	rep0, _ := runAdded(t, map[string]string{".github/workflows/w.yml": dispatch})
	if got, want := injectionLines(rep0, false), []string{"input-dispatch inconclusive 11 inputs.x", "value-unknown inconclusive 11 inputs.x"}; !slices.Equal(got, want) {
		t.Errorf("an input of workflow_dispatch in the env of the job: %q, want %q", got, want)
	}
	// a value of the env of the workflow that reaches the agent steps of two jobs
	wf := "on: {issues: {types: [opened]}}\nenv:\n  BODY: " + body + "\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" + claude(anyUser, prompt, "") + "  b:\n    runs-on: ubuntu-latest\n    steps:\n" + claude(anyUser, prompt, "")
	rep, _ := runAdded(t, map[string]string{".github/workflows/w.yml": wf})
	if got, want := injectionLines(rep, false), []string{"ai-action-prompt-injection.env confirmed 3 github.event.issue.body"}; !slices.Equal(got, want) {
		t.Errorf("the env of the workflow: %q, want %q", got, want)
	}
}
