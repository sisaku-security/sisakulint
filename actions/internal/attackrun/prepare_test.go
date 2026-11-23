package attackrun

import (
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

func TestPrepare(t *testing.T) {
	const job = "on:\n  issues:\n    types: [opened]\njobs:\n  a:\n    runs-on: x\n"
	for _, c := range []struct {
		name, carrier, quoted, workflow string
		unrun                           UnrunReason
		steps                           []ScriptStep
	}{
		{"run", "github.event.issue.title", `"v"`, job + "    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n",
			UnrunNone, []ScriptStep{{File: fp("w.yml"), Where: "jobs.a.steps[0]", Script: `echo "v"`, OptionWords: []string{"-e"}}}},
		{"env", "github.event.issue.title", `"v"`, job + "    env:\n      W: ${{ secrets.X }}\n      K: k\n    steps:\n      - env:\n          T: ${{ github.event.issue.title }}\n        shell: bash\n        run: echo \"$T\"\n",
			UnrunNone, []ScriptStep{{File: fp("w.yml"), Where: "jobs.a.steps[0]", Script: `echo "$T"`, OptionWords: []string{"--noprofile", "--norc", "-e", "-o", "pipefail"}, Env: []string{"K=k", "T=v"}}}},
		{"a step the value does not reach", "github.event.issue.title", `"v"`, job + "    steps:\n      - run: echo hi\n      - run: echo ${{ github.event.issue.title }}\n",
			UnrunNone, []ScriptStep{{File: fp("w.yml"), Where: "jobs.a.steps[1]", Script: "echo v", OptionWords: []string{"-e"}}}},
		{"if keeps the attacker out", "github.event.issue.title", `"v"`, job + "    steps:\n      - if: github.event.issue.author_association == 'OWNER'\n        run: echo \"${{ github.event.issue.title }}\"\n", UnrunSkippedByIf, nil},
		{"an if that compares the value", "github.event.issue.title", `"v"`, job + "    steps:\n      - if: github.event.issue.title == 'deploy'\n        run: echo \"${{ github.event.issue.title }}\"\n", UnrunSkippedByIf, nil},
		{"an if the value passes", "github.event.issue.title", `"Deploy"`, job + "    steps:\n      - if: github.event.issue.title == 'deploy'\n        run: echo \"${{ github.event.issue.title }}\"\n",
			UnrunNone, []ScriptStep{{File: fp("w.yml"), Where: "jobs.a.steps[0]", Script: `echo "Deploy"`, OptionWords: []string{"-e"}}}},
		{"no attacker event", "github.event.schedule", `"v"`, "on:\n  schedule:\n    - cron: '0 0 * * *'\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo \"${{ github.event.schedule }}\"\n", UnrunNoAttackerEvent, nil},
		{"words", "the file pr.txt in the artifact", `"v"`, job + "    steps:\n      - run: echo\n", UnrunCarrierNotExpression, nil},
		{"wrapped", "github.event.issue.title", `"v"`, job + "    steps:\n      - run: echo ${{ format('{0}', github.event.issue.title) }}\n", UnrunCarrierWrapped, nil},
		{"another expression in the script", "github.event.issue.title", `"v"`, job + "    steps:\n      - run: echo ${{ github.event.issue.title }} ${{ github.sha }}\n", UnrunOtherExpression, nil},
		{"pwsh", "github.event.issue.title", `"v"`, job + "    steps:\n      - shell: pwsh\n        run: echo ${{ github.event.issue.title }}\n", UnrunShellNotBash, nil},
		{"the job's default shell", "github.event.issue.title", `"v"`, job + "    defaults:\n      run:\n        shell: sh\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n", UnrunShellNotBash, nil},
		// custom shells
		{"bash -e {0}", "github.event.issue.title", `"v"`, job + "    steps:\n      - shell: bash -e {0}\n        run: echo ${{ github.event.issue.title }}\n",
			UnrunNone, []ScriptStep{{File: fp("w.yml"), Where: "jobs.a.steps[0]", Script: "echo v", OptionWords: []string{"-e"}}}},
		{"the job's default custom shell", "github.event.issue.title", `"v"`, job + "    defaults:\n      run:\n        shell: bash -x {0} a\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n",
			UnrunNone, []ScriptStep{{File: fp("w.yml"), Where: "jobs.a.steps[0]", Script: "echo v", OptionWords: []string{"-x"}, PositionalWords: []string{"a"}}}},
		{"/bin/bash on ubuntu", "github.event.issue.title", `"v"`, "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - shell: /bin/bash -x {0}\n        run: echo ${{ github.event.issue.title }}\n",
			UnrunNone, []ScriptStep{{File: fp("w.yml"), Where: "jobs.a.steps[0]", Script: "echo v", OptionWords: []string{"-x"}}}},
		{"bash -c", "github.event.issue.title", `"v"`, job + "    steps:\n      - shell: bash -c x {0}\n        run: echo ${{ github.event.issue.title }}\n", UnrunShellNotBash, nil},
		{"sh -e {0}", "github.event.issue.title", `"v"`, job + "    steps:\n      - shell: sh -e {0}\n        run: echo ${{ github.event.issue.title }}\n", UnrunShellNotBash, nil},
		{"an absolute path", "github.event.issue.title", `"v"`, job + "    steps:\n      - run: /usr/bin/curl ${{ github.event.issue.title }}\n", UnrunAbsolutePathCommand, nil},
		{"a path relative to the root", "github.event.issue.title", `"v"`, job + "    steps:\n      - run: cd / && usr/bin/id ${{ github.event.issue.title }}\n", UnrunAbsolutePathCommand, nil},
		{"an env of the carrier and another expression", "github.event.issue.title", `"v"`, job + "    steps:\n      - env:\n          T: ${{ github.event.issue.title }}-${{ github.run_id }}\n        run: echo \"$T\"\n", UnrunOtherExpression, nil},
		{"after a failure", "github.event.issue.title", `"v"`, job + "    steps:\n      - if: always()\n        run: echo ${{ github.event.issue.title }}\n",
			UnrunNone, []ScriptStep{{File: fp("w.yml"), Where: "jobs.a.steps[0]", Script: "echo v", OptionWords: []string{"-e"}, AfterFailure: true}}},
		// the payload of issues field_added has no label: GitHub writes it empty
		{"a carrier no payload of the events has", "github.event.label.name", `"v"`, "on:\n  issues:\n    types: [field_added]\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo \"${{ github.event.label.name }}\"\n",
			UnrunNone, []ScriptStep{{File: fp("w.yml"), Where: "jobs.a.steps[0]", Script: `echo ""`, OptionWords: []string{"-e"}}}},
		// the runner writes an array and an object as Array and Object
		{"a carrier through a star", "github.event.issue.labels.*.name", `"v"`, job + "    steps:\n      - run: echo \"${{ github.event.issue.labels.*.name }}\"\n",
			UnrunNone, []ScriptStep{{File: fp("w.yml"), Where: "jobs.a.steps[0]", Script: `echo "Array"`, OptionWords: []string{"-e"}}}},
		{"an object carrier", "github.event.issue", `"v"`, job + "    steps:\n      - run: echo \"${{ github.event.issue }}\"\n",
			UnrunNone, []ScriptStep{{File: fp("w.yml"), Where: "jobs.a.steps[0]", Script: `echo "Object"`, OptionWords: []string{"-e"}}}},
		{"an item of the labels, an object", "github.event.issue.labels[0]", `"v"`, job + "    steps:\n      - run: echo \"${{ github.event.issue.labels[0] }}\"\n",
			UnrunNone, []ScriptStep{{File: fp("w.yml"), Where: "jobs.a.steps[0]", Script: `echo "Object"`, OptionWords: []string{"-e"}}}},
		// edited has changes, an object; labeled has none
		{"an object carrier of one payload", "github.event.changes", `"v"`, "on:\n  issues:\n    types: [edited, labeled]\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo \"${{ github.event.changes }}\"\n",
			UnrunNone, []ScriptStep{{File: fp("w.yml"), Where: "jobs.a.steps[0]", Script: `echo "Object"`, OptionWords: []string{"-e"}}}},
		// labeled has a label: the value goes in
		{"a carrier one payload has", "github.event.label.name", `"v"`, "on:\n  issues:\n    types: [field_added, labeled]\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo \"${{ github.event.label.name }}\"\n",
			UnrunNone, []ScriptStep{{File: fp("w.yml"), Where: "jobs.a.steps[0]", Script: `echo "v"`, OptionWords: []string{"-e"}}}},
		// the runner writes GITHUB_HEAD_REF in every step, after env
		{"a variable the runner writes", "github.head_ref", `"v"`, "on: pull_request_target\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: tar -xf a.tar \"$GITHUB_HEAD_REF\"\n",
			UnrunNone, []ScriptStep{{File: fp("w.yml"), Where: "jobs.a.steps[0]", Script: `tar -xf a.tar "$GITHUB_HEAD_REF"`, OptionWords: []string{"-e"}, Env: []string{"GITHUB_HEAD_REF=v"}}}},
		{"an env of a variable the runner writes", "github.head_ref", `"v"`, "on: pull_request_target\njobs:\n  a:\n    runs-on: x\n    steps:\n      - env:\n          GITHUB_HEAD_REF: mine\n        run: echo \"${GITHUB_HEAD_REF}\"\n",
			UnrunNone, []ScriptStep{{File: fp("w.yml"), Where: "jobs.a.steps[0]", Script: `echo "${GITHUB_HEAD_REF}"`, OptionWords: []string{"-e"}, Env: []string{"GITHUB_HEAD_REF=v"}}}},
		// an env the runner writes over does not take the value, and a
		// longer name is another variable
		{"an env the runner writes over", "github.event.issue.title", `"v"`, job + "    steps:\n      - env:\n          GITHUB_SHA: ${{ github.event.issue.title }}\n        run: echo \"$GITHUB_SHA\"\n", UnrunCarrierNotInRun, nil},
		{"a longer name", "github.head_ref", `"v"`, "on: pull_request_target\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo \"$GITHUB_HEAD_REF_X\"\n", UnrunCarrierAbsent, nil},
	} {
		p, err := Prepare(example(t, c.carrier, c.quoted, c.workflow))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if p.Unrun != c.unrun {
			t.Errorf("%s: unrun %v, want %v", c.name, p.Unrun, c.unrun)
		}
		if c.unrun == UnrunNone && !equalSteps(p.Steps, c.steps) {
			t.Errorf("%s: steps %+v, want %+v", c.name, p.Steps, c.steps)
		}
	}
}

func equalSteps(a, b []ScriptStep) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].File != b[i].File || a[i].Where != b[i].Where || a[i].Script != b[i].Script || !slices.Equal(a[i].OptionWords, b[i].OptionWords) || !slices.Equal(a[i].PositionalWords, b[i].PositionalWords) || a[i].AfterFailure != b[i].AfterFailure || strings.Join(a[i].Env, "\x00") != strings.Join(b[i].Env, "\x00") {
			return false
		}
	}
	return true
}

func TestPrepareAction(t *testing.T) {
	e := actionExample(t, "inputs.t", `"v"`, "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo ${{ inputs.t }}\n")
	p, err := Prepare(e)
	if err != nil || p.Unrun != UnrunNone || len(p.Steps) != 1 || p.Steps[0].Script != "echo v" || !slices.Equal(p.Steps[0].OptionWords, []string{"--noprofile", "--norc", "-e", "-o", "pipefail"}) {
		t.Errorf("%+v %v", p, err)
	}
	// a composite step names bash by a path on a runner the rules do not
	// know: not run, rather than run as bash -e
	e = actionExample(t, "inputs.t", `"v"`, "runs:\n  using: composite\n  steps:\n    - shell: /bin/bash -e {0}\n      run: echo ${{ inputs.t }}\n")
	if p, err := Prepare(e); err != nil || p.Unrun != UnrunShellNotBash {
		t.Errorf("/bin/bash in a composite step: %+v %v", p, err)
	}
}

func TestUnrunReasonString(t *testing.T) {
	for r, s := range map[UnrunReason]string{UnrunSkippedByIf: "skipped-by-if", UnrunCarrierNotInRun: "carrier-not-in-run", UnrunCarrierAbsent: "carrier-absent", UnrunNoAttackerEvent: "no-attacker-event", UnrunStubbedCommandFailed: "stubbed-command-failed", UnrunNone: "", UnrunCarrierNotExpression: "carrier-not-expression", UnrunCarrierWrapped: "carrier-wrapped", UnrunOtherExpression: "other-expression", UnrunShellNotBash: "shell-not-bash", UnrunAbsolutePathCommand: "absolute-path-command"} {
		if r.String() != s {
			t.Errorf("%d: %q, want %q", r, r.String(), s)
		}
	}
}

func TestCheck(t *testing.T) {
	const job = "on:\n  issues:\n    types: [opened]\njobs:\n  a:\n    runs-on: x\n    steps:\n"
	run := example(t, "github.event.issue.title", `"v"`, job+"      - run: echo ${{ github.event.issue.title }}\n")
	pwsh := example(t, "github.event.issue.title", `"v"`, job+"      - shell: pwsh\n        run: echo ${{ github.event.issue.title }}\n")
	for _, c := range []struct {
		e    lint.Example
		m    Marker
		want string
	}{
		{run, MarkerStdout, "run by a test"},
		{pwsh, MarkerStdout, "not run: shell-not-bash"},
		{run, MarkerNone, ""},
		{lint.Example{}, MarkerStdout, ""},
	} {
		if got := Check(c.e, c.m); got != c.want {
			t.Errorf("%q, want %q", got, c.want)
		}
	}
}

// TestPrepareCarrierNowhere: a carrier that is in no ${{ }} of an example
// that has some is an error, not a value that does not reach; one with no
// ${{ }} at all reaches nothing.
func TestPrepareCarrierNowhere(t *testing.T) {
	const job = "on:\n  issues:\n    types: [opened]\njobs:\n  a:\n    runs-on: x\n    steps:\n"
	if _, err := Prepare(example(t, "github.event.issue.titel", `"v"`, job+"      - run: echo \"${{ github.event.issue.title }}\"\n")); err == nil {
		t.Error("a misspelt carrier is no error")
	}
	p, err := Prepare(example(t, "github.event.issue.title", `"v"`, job+"      - run: echo \"$HOME/.local/bin\" >> \"$GITHUB_PATH\"\n"))
	if err != nil || p.Unrun != UnrunCarrierAbsent {
		t.Errorf("an example with no ${{ }}: %+v %v", p, err)
	}
	p, err = Prepare(example(t, "github.event.issue.title", `"v"`, job+"      - if: github.event.issue.author_association == 'OWNER'\n        run: echo \"${{ github.event.issue.title }}\"\n"))
	if err != nil || p.Unrun != UnrunSkippedByIf {
		t.Errorf("a step the if skips: %+v %v", p, err)
	}
}
