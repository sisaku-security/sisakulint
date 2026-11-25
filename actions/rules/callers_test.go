package rules

import (
	"slices"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// repoOf is the inputs of files as the whole repository.
func repoOf(t *testing.T, files map[string]string) lint.Inputs {
	t.Helper()
	fsys := fstest.MapFS{}
	for n, s := range files {
		fsys[n] = &fstest.MapFile{Data: []byte(s)}
	}
	in, err := lint.Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

const calledEcho = "on:\n  workflow_call:\n    inputs:\n      t: {type: string}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.t }}\"\n"

// TestCallerEvidence: a finding on a called workflow's input has the
// caller's with as its evidence, and the other caller's with as related.
func TestCallerEvidence(t *testing.T) {
	in := repoOf(t, map[string]string{
		".github/workflows/called.yml": calledEcho,
		".github/workflows/a.yml":      "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ github.event.issue.title }}\n",
		".github/workflows/b.yml":      "on: issue_comment\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ github.event.comment.body }}\n",
	})
	rep := runAlone(t, CodeInjection, in)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("findings %+v, errors %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.Errors)
	}
	f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
	inputs := func(rs []lint.Related) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.Location.File.Input.String())
		}
		return out
	}
	if f.Location.File.Input.String() != ".github/workflows/called.yml" || !slices.Equal(inputs(f.Evidence), []string{".github/workflows/a.yml"}) || !slices.Equal(inputs(f.Related), []string{".github/workflows/b.yml"}) {
		t.Fatalf("finding at %s, evidence %v, related %v", f.Location.File.Input, inputs(f.Evidence), inputs(f.Related))
	}
}

// TestCallersPerRule: a called workflow is reported when its caller in
// the repository runs on an attacker's event, and not when its one caller
// runs on push; read alone, as before callers were read.
func TestCallersPerRule(t *testing.T) {
	for _, tc := range []struct {
		rule  lint.Rule
		on    string // the attacker's event of the caller
		alone bool   // whether the rule reports the called workflow read alone
		// whether the rule reports the called workflow when the caller names
		// it by owner/repo/path@ref of the repository (--repo): the caller is
		// not resolved to the file, so a rule that reads the events of the
		// callers reads the called workflow on every event, and a rule that
		// reads its ifs reads them on every event too (the undetected form
		// caller-by-repository-name of unsound-contains)
		named bool
	}{
		{CodeInjection, "issues", true, true},
		{EnvvarInjection, "issues", true, true},
		{OutputClobbering, "issues", true, true},
		{EnvpathInjection, "issues", true, true},
		{UntrustedCheckout, "pull_request_target", true, true},
		// on every event, the checkout is untrusted-checkout's .executed
		{UntrustedCheckoutToctou, "pull_request_target:\n    types: [labeled]", false, false},
		{ArtifactPoisoning, "workflow_run:\n    workflows: [ci]", true, true},
		// the ifs of a called workflow whose callers are not all known are
		// read on every event, as the taint rules read its steps
		{BotConditions, "pull_request_target", true, true},
		// on every event, the login is not the attacker's in every run that
		// the if lets in (the push of a writer: an empty login)
		{UnsoundContains, "issue_comment", false, false},
	} {
		id := tc.rule.Meta().ID.String()
		t.Run(id, func(t *testing.T) {
			b, err := examples.ReadFile("examples/undetected/" + id + "/outside-caller/.github/workflows/called.yml")
			if err != nil {
				t.Fatal(err)
			}
			called := string(b)
			alone := runAlone(t, tc.rule, inputOf(t, lint.Example{InputKind: lint.InputKindWorkflow, Name: facts.MustCleanInputPath(".github/workflows/called.yml"), Text: called}))
			if got := len(alone.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) > 0; got != tc.alone {
				t.Fatalf("alone: findings %v, errors %+v", kindsOf(alone), alone.Errors)
			}
			caller := func(on string) string {
				return "on:\n  " + on + "\njobs:\n  call:\n    uses: ./.github/workflows/called.yml\n"
			}
			attacked := runAlone(t, tc.rule, repoOf(t, map[string]string{".github/workflows/called.yml": called, ".github/workflows/ci.yml": caller(tc.on)}))
			if len(attacked.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) == 0 || len(attacked.Errors) != 0 {
				t.Errorf("caller on %s: findings %v, errors %+v", tc.on, kindsOf(attacked), attacked.Errors)
			}
			pushed := runAlone(t, tc.rule, repoOf(t, map[string]string{".github/workflows/called.yml": called, ".github/workflows/ci.yml": caller("push")}))
			if len(pushed.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 || len(pushed.Errors) != 0 {
				t.Errorf("caller on push: findings %v, errors %+v", kindsOf(pushed), pushed.Errors)
			}
			in := repoOf(t, map[string]string{".github/workflows/called.yml": called, ".github/workflows/ci.yml": "on:\n  " + tc.on + "\njobs:\n  call:\n    uses: o/r/.github/workflows/called.yml@main\n"})
			in.Repo, _ = facts.ParseRepo("o/r")
			named := runAlone(t, tc.rule, in)
			if got := len(named.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) > 0; got != tc.named || len(named.Errors) != 0 {
				t.Errorf("caller by name on %s: findings %v, errors %+v", tc.on, kindsOf(named), named.Errors)
			}
		})
	}
}

// TestCallersInputPerRule: what a caller on an attacker's event gives
// inputs.t is reported where the called workflow writes it, by each rule
// of injection; a fixed value is not.
func TestCallersInputPerRule(t *testing.T) {
	for _, tc := range []struct {
		rule lint.Rule
		run  string
	}{
		{CodeInjection, `echo "${{ inputs.t }}"`},
		{EnvvarInjection, `echo "B=${{ inputs.t }}" >> "$GITHUB_ENV"`},
		{OutputClobbering, `echo "b=${{ inputs.t }}" >> "$GITHUB_OUTPUT"`},
		{EnvpathInjection, `echo "${{ inputs.t }}" >> "$GITHUB_PATH"`},
	} {
		id := tc.rule.Meta().ID.String()
		t.Run(id, func(t *testing.T) {
			called := "on:\n  workflow_call:\n    inputs:\n      t: {type: string}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - id: s\n        run: " + tc.run + "\n"
			for _, c := range []struct {
				value string
				want  bool
			}{{"${{ github.event.issue.body }}", true}, {"fixed", false}} {
				ci := "on: issues\njobs:\n  call:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: " + c.value + "\n"
				rep := runAlone(t, tc.rule, repoOf(t, map[string]string{".github/workflows/called.yml": called, ".github/workflows/ci.yml": ci}))
				if got := len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) > 0; got != c.want || len(rep.Errors) != 0 {
					t.Errorf("%s: findings %v, errors %+v", c.value, kindsOf(rep), rep.Errors)
				}
			}
		})
	}
}

// TestCallerRemoteFormOfTheRepository: a caller that names the workflow by
// owner/repo/path@ref, of the repository, leaves the called workflow read
// in the worst case, and what it gives is reported.
func TestCallerRemoteFormOfTheRepository(t *testing.T) {
	called := "on:\n  workflow_call:\n    inputs:\n      t: {type: string}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.t }}\"\n      - run: echo \"${{ github.head_ref }}\"\n"
	in := repoOf(t, map[string]string{
		".github/workflows/called.yml": called,
		".github/workflows/ci.yml":     "on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: hello\n",
		".github/workflows/prt.yml":    "on: pull_request_target\njobs:\n  c:\n    uses: me/repo/.github/workflows/called.yml@main\n    with:\n      t: ${{ github.event.pull_request.title }}\n",
	})
	rep := runAlone(t, CodeInjection, in)
	var at []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Location.File.Input.String() == ".github/workflows/called.yml" {
			at = append(at, f.Args.Detected())
		}
	}
	if len(at) != 2 {
		t.Fatalf("findings in called.yml: %v, errors %+v", at, rep.Errors)
	}
}

// TestCallerEvidenceOfDefault: the evidence of a value from an input's
// default says so.
func TestCallerEvidenceOfDefault(t *testing.T) {
	called := "on:\n  workflow_call:\n    inputs:\n      t: {type: string, default: \"${{ github.event.issue.title }}\"}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.t }}\"\n"
	in := repoOf(t, map[string]string{".github/workflows/called.yml": called, ".github/workflows/ci.yml": "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n"})
	rep := runAlone(t, CodeInjection, in)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Evidence) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Evidence[0].Note != "the input's default gives inputs.t here" {
		t.Fatalf("findings %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}
