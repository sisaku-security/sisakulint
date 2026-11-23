package taint

import (
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// invocationOf is the ShellInvocation of the first step of the first job
// of src, or of the first step of the composite action src.
func invocationOf(t *testing.T, src string, action bool) ShellInvocation {
	t.Helper()
	tr := cst.ParseMode([]byte(src), cst.ModeGitHub)
	if action {
		am, _ := workflow.ParseActionMetadata(tr)
		if am == nil || am.Runs.Status != workflow.Present || am.Runs.Value.Steps.Status != workflow.Present {
			t.Fatalf("no steps in %q", src)
		}
		return ShellInvocationOf(nil, nil, am.Runs.Value.Steps.Value.Items[0])
	}
	w, _ := workflow.Parse(tr)
	if w == nil || w.Jobs.Status != workflow.Present || len(w.Jobs.Value.Entries) == 0 {
		t.Fatalf("no jobs in %q", src)
	}
	j := w.Jobs.Value.Entries[0].Value.Value
	return ShellInvocationOf(w, &j, j.Steps.Value.Items[0])
}

// shellJob is a workflow whose job runs on label with defaults (the
// lines under the job, if any) and one step with the shell line shell
// (a YAML scalar; none if empty).
func shellJob(label, defaults, shell string) string {
	src := "on: push\njobs:\n  a:\n    runs-on: " + label + "\n" + defaults + "    steps:\n      - run: echo x\n"
	if shell != "" {
		src += "        shell: " + shell + "\n"
	}
	return src
}

func TestShellInvocationOf(t *testing.T) {
	builtinBash := []string{"--noprofile", "--norc", "-e", "-o", "pipefail"}
	read := []struct {
		name, src string
		action    bool
		want      ShellInvocation
	}{
		{"bash -e", shellJob("ubuntu-latest", "", "bash -e {0}"), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"-e"}}},
		{"the options of shell: bash", shellJob("ubuntu-latest", "", "bash --noprofile --norc -euo pipefail {0}"), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"--noprofile", "--norc", "-euo", "pipefail"}}},
		{"-x", shellJob("ubuntu-latest", "", "bash -x {0}"), false, ShellInvocation{Shell: ShellBash, XTrace: true, OptionWords: []string{"-x"}}},
		{"-x +x", shellJob("ubuntu-latest", "", "bash -x +x {0}"), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"-x", "+x"}}},
		{"+x -x", shellJob("ubuntu-latest", "", "bash +x -x {0}"), false, ShellInvocation{Shell: ShellBash, XTrace: true, OptionWords: []string{"+x", "-x"}}},
		{"-o xtrace", shellJob("ubuntu-latest", "", "bash -o xtrace {0}"), false, ShellInvocation{Shell: ShellBash, XTrace: true, OptionWords: []string{"-o", "xtrace"}}},
		{"-ex", shellJob("ubuntu-latest", "", "bash -ex {0}"), false, ShellInvocation{Shell: ShellBash, XTrace: true, OptionWords: []string{"-ex"}}},
		{"-ox xtrace", shellJob("ubuntu-latest", "", "bash -ox xtrace {0}"), false, ShellInvocation{Shell: ShellBash, XTrace: true, OptionWords: []string{"-ox", "xtrace"}}},
		{"--", shellJob("ubuntu-latest", "", "bash -e -- {0}"), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"-e", "--"}}},
		{"-", shellJob("ubuntu-latest", "", "bash -e - {0}"), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"-e", "-"}}},
		{"-l", shellJob("ubuntu-latest", "", "bash -l {0}"), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"-l"}}},
		{"+l", shellJob("ubuntu-latest", "", "bash +l {0}"), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"+l"}}},
		{"--login before -e", shellJob("ubuntu-latest", "", "bash --login -e {0}"), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"--login", "-e"}}},
		{"-E -T", shellJob("ubuntu-latest", "", "bash -E -T {0}"), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"-E", "-T"}}},
		{"words after {0}", shellJob("ubuntu-latest", "", "bash -e {0} a {0}"), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"-e"}, PositionalWords: []string{"a", "{0}"}}},
		{"blanks around", shellJob("ubuntu-latest", "", `"  bash -e {0}  "`), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"-e"}}},
		{"blanks between", shellJob("ubuntu-latest", "", `"bash  -e	{0}"`), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"-e"}}},
		{"sh -eux", shellJob("ubuntu-latest", "", "sh -eux {0}"), false, ShellInvocation{Shell: ShellSh, XTrace: true, OptionWords: []string{"-eux"}}},
		{"sh -o nounset", shellJob("ubuntu-latest", "", "sh -o nounset {0}"), false, ShellInvocation{Shell: ShellSh, OptionWords: []string{"-o", "nounset"}}},
		{"/bin/bash on ubuntu", shellJob("ubuntu-latest", "", "/bin/bash -e {0}"), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"-e"}}},
		{"/bin/bash on macos", shellJob("macos-14", "", "/bin/bash -e {0}"), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"-e"}}},
		{"/usr/bin/sh on ubuntu", shellJob("ubuntu-22.04", "", "/usr/bin/sh -e {0}"), false, ShellInvocation{Shell: ShellSh, OptionWords: []string{"-e"}}},
		{"/usr/bin/bash on ubuntu", shellJob("ubuntu-latest", "", "/usr/bin/bash {0}"), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{}}},
		{"the job's defaults", shellJob("ubuntu-latest", "    defaults:\n      run:\n        shell: bash -e {0}\n", ""), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"-e"}}},
		{"the workflow's defaults", "on: push\ndefaults:\n  run:\n    shell: bash -x {0}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo x\n", false, ShellInvocation{Shell: ShellBash, XTrace: true, OptionWords: []string{"-x"}}},
		{"the step's shell before the defaults", shellJob("ubuntu-latest", "    defaults:\n      run:\n        shell: python {0}\n", "bash"), false, ShellInvocation{Shell: ShellBash, OptionWords: builtinBash}},
		{"a composite step", "runs:\n  using: composite\n  steps:\n    - run: echo x\n      shell: bash -e {0}\n", true, ShellInvocation{Shell: ShellBash, OptionWords: []string{"-e"}}},
		{"shell: bash", shellJob("windows-latest", "", "bash"), false, ShellInvocation{Shell: ShellBash, OptionWords: builtinBash}},
		{"shell: sh", shellJob("ubuntu-latest", "", "sh"), false, ShellInvocation{Shell: ShellSh, OptionWords: []string{"-e"}}},
		{"shell: pwsh", shellJob("ubuntu-latest", "", "pwsh"), false, ShellInvocation{Shell: ShellPwsh}},
		{"shell: powershell", shellJob("windows-latest", "", "powershell"), false, ShellInvocation{Shell: ShellPwsh}},
		{"no shell on ubuntu", shellJob("ubuntu-latest", "", ""), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"-e"}}},
		{"no shell on macos", shellJob("macos-latest", "", ""), false, ShellInvocation{Shell: ShellBash, OptionWords: []string{"-e"}}},
		{"no shell on windows", shellJob("windows-latest", "", ""), false, ShellInvocation{Shell: ShellPwsh}},
	}
	for _, c := range read {
		t.Run(c.name, func(t *testing.T) {
			got := invocationOf(t, c.src, c.action)
			if got.Shell != c.want.Shell || got.XTrace != c.want.XTrace || !slices.Equal(got.OptionWords, c.want.OptionWords) || !slices.Equal(got.PositionalWords, c.want.PositionalWords) {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
	unknown := []struct{ name, src string }{
		{"-c", shellJob("ubuntu-latest", "", "bash -c x {0}")},
		{"-s", shellJob("ubuntu-latest", "", "bash -s {0}")},
		{"-n", shellJob("ubuntu-latest", "", "bash -n {0}")},
		{"-r", shellJob("ubuntu-latest", "", "bash -r {0}")},
		{"-i", shellJob("ubuntu-latest", "", "bash -i {0}")},
		{"-v", shellJob("ubuntu-latest", "", "bash -v {0}")},
		{"-o verbose", shellJob("ubuntu-latest", "", "bash -o verbose {0}")},
		{"--verbose", shellJob("ubuntu-latest", "", "bash --verbose {0}")},
		{"-ec", shellJob("ubuntu-latest", "", "bash -ec {0}")},
		{"-xv", shellJob("ubuntu-latest", "", "bash -xv {0}")},
		{"-O extglob", shellJob("ubuntu-latest", "", "bash -O extglob {0}")},
		{"--posix", shellJob("ubuntu-latest", "", "bash --posix {0}")},
		{"a long option after -e", shellJob("ubuntu-latest", "", "bash -e --noprofile {0}")},
		{"-- -x", shellJob("ubuntu-latest", "", "bash -- -x {0}")},
		{"-o without a value", shellJob("ubuntu-latest", "", "bash -o {0}")},
		{"two o in a word", shellJob("ubuntu-latest", "", "bash -oo pipefail xtrace {0}")},
		{"double quotes", shellJob("ubuntu-latest", "", `'bash "{0}"'`)},
		{"single quotes", shellJob("ubuntu-latest", "", `"bash '{0}'"`)},
		{"a backslash", shellJob("ubuntu-latest", "", `'bash -e\ {0}'`)},
		{"{1}", shellJob("ubuntu-latest", "", "bash {1}")},
		{"{0}x", shellJob("ubuntu-latest", "", "bash {0}x")},
		{"no {0}", shellJob("ubuntu-latest", "", "bash -e")},
		{"an operand before {0}", shellJob("ubuntu-latest", "", "bash x {0}")},
		{"another path", shellJob("ubuntu-latest", "", "/usr/local/bin/bash -e {0}")},
		{"Bash", shellJob("ubuntu-latest", "", "Bash -e {0}")},
		{"a tab after the command", shellJob("ubuntu-latest", "", `"bash\t-e {0}"`)},
		{"an expression", shellJob("ubuntu-latest", "", "${{ 'bash -e {0}' }}")},
		{"pwsh -File", shellJob("ubuntu-latest", "", "pwsh -File {0}")},
		{"python", shellJob("ubuntu-latest", "", "python {0}")},
		{"sh -o pipefail", shellJob("ubuntu-latest", "", "sh -o pipefail {0}")},
		{"sh -l", shellJob("ubuntu-latest", "", "sh -l {0}")},
		{"sh -E", shellJob("ubuntu-latest", "", "sh -E {0}")},
		{"sh --noprofile", shellJob("ubuntu-latest", "", "sh --noprofile {0}")},
		{"/usr/bin/bash on macos", shellJob("macos-latest", "", "/usr/bin/bash -e {0}")},
		{"/bin/bash on windows", shellJob("windows-latest", "", "/bin/bash -e {0}")},
		{"/bin/bash on self-hosted", shellJob("self-hosted", "", "/bin/bash -e {0}")},
		{"/bin/bash on an expression", shellJob("${{ matrix.os }}", "", "/bin/bash -e {0}")},
		{"/bin/bash on two labels", shellJob("[self-hosted, ubuntu-latest]", "", "/bin/bash -e {0}")},
		{"a quote after {0}", shellJob("ubuntu-latest", "", `"bash -e {0} '$x'"`)},
		{"{1} after {0}", shellJob("ubuntu-latest", "", "bash -e {0} {1}")},
		{"a brace after {0}", shellJob("ubuntu-latest", "", "bash -e {0} }")},
		{"python", shellJob("ubuntu-latest", "", "python")},
		{"cmd", shellJob("windows-latest", "", "cmd")},
		{"no shell on self-hosted", shellJob("self-hosted", "", "")},
	}
	for _, c := range unknown {
		t.Run(c.name, func(t *testing.T) {
			if got := invocationOf(t, c.src, false); got.Shell != ShellUnknown || got.XTrace || got.OptionWords != nil || got.PositionalWords != nil {
				t.Errorf("got %+v, want ShellUnknown with no words", got)
			}
		})
	}
	t.Run("a composite step without shell", func(t *testing.T) {
		if got := invocationOf(t, "runs:\n  using: composite\n  steps:\n    - run: echo x\n", true); got.Shell != ShellUnknown {
			t.Errorf("got %+v, want ShellUnknown", got)
		}
	})
	t.Run("a composite step with /bin/bash", func(t *testing.T) {
		if got := invocationOf(t, "runs:\n  using: composite\n  steps:\n    - run: echo x\n      shell: /bin/bash -e {0}\n", true); got.Shell != ShellUnknown {
			t.Errorf("got %+v, want ShellUnknown", got)
		}
	})
	t.Run("ShellOf", func(t *testing.T) {
		tr := cst.ParseMode([]byte(shellJob("ubuntu-latest", "", "bash -x {0}")), cst.ModeGitHub)
		w, _ := workflow.Parse(tr)
		j := w.Jobs.Value.Entries[0].Value.Value
		if got := ShellOf(w, &j, j.Steps.Value.Items[0]); got != ShellBash {
			t.Errorf("got %v, want ShellBash", got)
		}
	})
}
