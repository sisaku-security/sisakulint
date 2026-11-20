package attackrun

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// example is a workflow example whose notes put value into carrier.
func example(t *testing.T, carrier, quoted, workflow string, others ...lint.ExampleFile) lint.Example {
	t.Helper()
	text := "# attack-value: " + carrier + " = " + quoted + "\n" + workflow
	n, err := lint.ParseExampleNotes(text)
	if err != nil {
		t.Fatal(err)
	}
	return lint.Example{InputKind: lint.InputKindWorkflow, Name: facts.MustCleanInputPath("w.yml"), Text: text, Others: others, Notes: n}
}

func TestSubstitute(t *testing.T) {
	for _, c := range []struct {
		name, carrier, quoted, workflow string
		want                            []Substitution
	}{
		{"run", "github.event.issue.title", `"a\"b"`, "on: issues\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n",
			[]Substitution{{fp("w.yml"), "jobs.a.steps[0].run", `echo "a"b"`}}},
		{"spaces and case in the expression", "github.event.issue.title", `"v"`, "on: issues\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo ${{github.event.issue.Title}} ${{ github.sha }}\n",
			[]Substitution{{fp("w.yml"), "jobs.a.steps[0].run", "echo v ${{ github.sha }}"}}},
		{"env and with", "github.event.issue.body", `"x\ny"`, "on: issues\njobs:\n  a:\n    runs-on: x\n    env:\n      B: pre-${{ github.event.issue.body }}\n    steps:\n      - uses: o/a@v1\n        with:\n          prompt: ${{ github.event.issue.body }}\n",
			[]Substitution{{fp("w.yml"), "jobs.a.env.B", "pre-x\ny"}, {fp("w.yml"), "jobs.a.steps[0].with.prompt", "x\ny"}}},
		{"wrapped is not put in", "github.event.issue.title", `"v"`, "on: issues\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo ${{ format('{0}', github.event.issue.title) }}\n", nil},
		{"words", "the file in the artifact", `"v"`, "on: issues\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo\n", nil},
	} {
		got := Substitute(example(t, c.carrier, c.quoted, c.workflow))
		if len(got) != len(c.want) {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: %+v, want %+v", c.name, got[i], c.want[i])
			}
		}
	}
}

func TestSubstituteSeveralFiles(t *testing.T) {
	caller := lint.ExampleFile{InputKind: lint.InputKindWorkflow, Name: facts.MustCleanInputPath(".github/workflows/caller.yml"), Text: "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ github.event.issue.title }}\n"}
	e := example(t, "github.event.issue.title", `"v"`, "on: workflow_call\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo ${{ inputs.t }}\n", caller)
	got := Substitute(e)
	if len(got) != 1 || got[0] != (Substitution{fp(".github/workflows/caller.yml"), "jobs.c.with.t", "v"}) {
		t.Errorf("%+v", got)
	}
}

// actionExample is an action metadata example whose notes put value into carrier.
func actionExample(t *testing.T, carrier, quoted, action string) lint.Example {
	t.Helper()
	text := "# attack-value: " + carrier + " = " + quoted + "\n" + action
	n, err := lint.ParseExampleNotes(text)
	if err != nil {
		t.Fatal(err)
	}
	return lint.Example{InputKind: lint.InputKindActionMetadata, Name: facts.MustCleanInputPath("action.yml"), Text: text, Notes: n}
}

func fp(s string) facts.InputPath { return facts.MustCleanInputPath(s) }

func TestSubstituteWithOnly(t *testing.T) {
	e := example(t, "github.event.issue.body", `"v"`, "on: issues\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: o/a@v1\n        with:\n          prompt: ${{ github.event.issue.body }}\n")
	if got := Substitute(e); len(got) != 1 {
		t.Errorf("%+v", got)
	}
	p, err := Prepare(e)
	if err != nil || p.Unrun != UnrunCarrierNotInRun {
		t.Errorf("a value only in with: %+v %v", p, err)
	}
}
