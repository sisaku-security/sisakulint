package taint

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// arguments are the CommandArguments of the runs of src, as lines:
// command, word, role, the text in the run, the path, head, quoted.
func arguments(t *testing.T, src string, action bool) []string {
	t.Helper()
	tr := cst.ParseMode([]byte(src), cst.ModeGitHub)
	var a Analysis
	if action {
		act, _ := workflow.ParseActionMetadata(tr)
		a = Analyze(nil, act)
	} else {
		w, _ := workflow.Parse(tr)
		a = Analyze(w, nil)
	}
	var out []string
	for _, s := range a.Sinks {
		text := s.Value.Text()
		for _, x := range s.Arguments {
			line := fmt.Sprintf("%s %d %s %s %s", x.Command, x.Word, strings.TrimPrefix(x.Role.String(), "ArgumentRole"), text[x.Span.Start:x.Span.End], expr.PathString(x.Path))
			if x.Head {
				line += " head"
			}
			if x.Quoted {
				line += " quoted"
			}
			if x.Ref.Verdict == analysis.Inconclusive {
				line += " " + x.Ref.InconclusiveKind.String()
			}
			if x.Remote != shell.RemoteKindUnknown {
				line += " " + x.Remote.String()
			}
			out = append(out, line)
		}
	}
	return out
}

func TestArguments(t *testing.T) {
	wf := func(env, run string) string {
		return "on:\n  pull_request_target:\nenv:\n  W: ${{ github.event.pull_request.body }}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      T: ${{ github.event.pull_request.title }}\n    steps:\n      - id: x\n        run: echo\n      - env:\n" + env + "        run: " + run + "\n"
	}
	h := "          H: ${{ github.head_ref }}\n          P: refs/heads/${{ github.head_ref }}\n          S: ${{ github.sha }}\n"
	for _, c := range []struct {
		name, run string
		want      []string
	}{
		{"${{ }} after an operand", `tar -xf a.tar f "${{ github.head_ref }}"`, []string{`tar 4 Option ${{ github.head_ref }} github.head_ref head quoted`}},
		{"a variable of env", `tar -xf a.tar f "$H"`, []string{`tar 4 Option $H github.head_ref head quoted`}},
		{"a variable with a default", `tar -xf a.tar f "${H:-main}"`, []string{`tar 4 Option ${H:-main} github.head_ref head quoted`}},
		// the word of :- is the value when the variable is empty
		{"a variable as the default", `tar -xf a.tar f "${X:-$H}"`, []string{`tar 4 Option $H github.head_ref head quoted`}},
		{"a variable as the string of /#", `tar -xf a.tar f "${X/#a/$H}"`, []string{`tar 4 Option $H github.head_ref head quoted`}},
		{"a variable as the string of /", `tar -xf a.tar f "${X/a/$H}"`, []string{`tar 4 Option $H github.head_ref quoted`}},
		{"an operator that changes the value", `tar -xf a.tar f "${H#x}"`, nil},
		{"inside a word", `tar -xf a.tar f "x$H"`, []string{`tar 4 Option $H github.head_ref quoted`}},
		{"after a literal in env", `tar -xf a.tar f "$P"`, []string{`tar 4 Option $P github.head_ref quoted`}},
		{"outside quotes, job env", `tar -xf a.tar f $T`, []string{`tar 4 Option $T github.event.pull_request.title head`}},
		{"workflow env", `make all "$W"`, []string{`make 2 Option $W github.event.pull_request.body head quoted`}},
		{"inside $( )", `out=$(tar -xf a.tar f "$H")`, []string{`tar 4 Option $H github.head_ref head quoted`}},
		{"compound and pipeline", `if true; then make all "$H"; fi | cat`, []string{`make 2 Option $H github.head_ref head quoted`}},
		{"a command that reads no option", `echo "$H"`, []string{`echo 1 Option $H github.head_ref head quoted`}},
		{"an assignment", `X="$H"`, nil},
		{"the command word", `"$H" -x`, nil},
		{"a variable env does not set", `echo "$GITHUB_SHA"`, nil},
		{"a value no attacker controls", `tar -xf a.tar f "$S"`, nil},
		{"an output of a step", `tar -xf a.tar f "${{ steps.x.outputs.y }}"`, []string{`tar 4 Option ${{ steps.x.outputs.y }} steps.x.outputs.y head quoted step-output-run`}},
		{"after --", `tar -xf a.tar -- "$H"`, []string{`tar 4 Operand $H github.head_ref head quoted`}},
		// the repository git names
		{"git fetch, a local path", `git fetch /tmp/r "$H"`, []string{`git fetch 3 Option $H github.head_ref head quoted RemoteKindLocal`}},
		{"git fetch, HTTPS", `git fetch https://github.com/a/b "$H"`, []string{`git fetch 3 Option $H github.head_ref head quoted RemoteKindHTTPS`}},
		{"git clone, SSH", `git clone git@github.com:a/b c "$H"`, []string{`git clone 4 Option $H github.head_ref head quoted RemoteKindSSH`}},
		{"git fetch, no repository", `git fetch "$H"`, []string{`git fetch 2 Option $H github.head_ref head quoted`}},
		{"tar has no remote", `tar -xf /tmp/a.tar f "$H"`, []string{`tar 4 Option $H github.head_ref head quoted`}},
		// a value in one word before the repository is
		// an option word; a value that splits into words writes the repository
		{"git ls-remote, the value before a local path", `git ls-remote "$H" /tmp/r`, []string{`git ls-remote 2 Option $H github.head_ref head quoted RemoteKindLocal`}},
		{"git fetch, a title outside quotes", `git fetch $T`, []string{`git fetch 2 Option $T github.event.pull_request.title head RemoteKindLocal`}},
		{"git fetch, a title outside quotes after HTTPS", `git fetch https://github.com/a/b $T`, []string{`git fetch 3 Option $T github.event.pull_request.title head RemoteKindHTTPS`}},
		{"git fetch, a variable repository before the value", `git fetch "$S" "$H"`, []string{`git fetch 3 Option $H github.head_ref head quoted`}},
	} {
		got := arguments(t, wf(h, c.run), false)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got\n%s\nwant\n%s", c.name, strings.Join(got, "\n"), strings.Join(c.want, "\n"))
		}
	}
	action := "runs:\n  using: composite\n  steps:\n    - shell: bash\n      env:\n        H: ${{ inputs.ref }}\n      run: tar -xf a.tar f \"$H\"\n"
	if got := arguments(t, action, true); len(got) != 1 || !strings.HasPrefix(got[0], "tar 4 Option $H") {
		t.Errorf("composite action: %v", got)
	}
}

// TestArgumentsHead: the value starts the word only when nothing comes
// before it: in the word, in the expression, and in each env value it went
// through.
func TestArgumentsHead(t *testing.T) {
	src := func(run string) string {
		return `on: pull_request_target
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      G: x${{ github.head_ref }}
      H: ${{ github.head_ref }}
    steps:
      - env:
          R: ${{ github.repository }}/${{ github.event.pull_request.title }}
          N: ${{ env.G }}
          M: ${{ env.H }}
        run: ` + run + "\n"
	}
	for _, c := range []struct {
		run  string
		want []string
	}{
		{`tar -xf a.tar f "$R"`, []string{`tar 4 Option $R github.event.pull_request.title quoted`}},
		{`tar -xf a.tar f "${{ format('x{0}', github.head_ref) }}"`, []string{`tar 4 Option ${{ format('x{0}', github.head_ref) }} github.head_ref quoted`}},
		{`tar -xf a.tar f "${{ toJSON(github.event.pull_request.title) }}"`, []string{`tar 4 Option ${{ toJSON(github.event.pull_request.title) }} github.event.pull_request.title quoted`}},
		{`tar -xf a.tar f "$N"`, []string{`tar 4 Option $N github.head_ref quoted`}},
		{`tar -xf a.tar f "$M"`, []string{`tar 4 Option $M github.head_ref head quoted`}},
		{`tar -xf a.tar f "${{ env.M }}"`, []string{`tar 4 Option ${{ env.M }} github.head_ref head quoted`}},
		{`tar -xf a.tar f "${{ github.event.pull_request.title || 'x' }}"`, []string{`tar 4 Option ${{ github.event.pull_request.title || 'x' }} github.event.pull_request.title head quoted`}},
		// the value starts with the reference's through format with {N} first,
		// case, and a part taken of an operand
		{`tar -xf a.tar f "${{ format('{0}', github.head_ref) }}"`, []string{`tar 4 Option ${{ format('{0}', github.head_ref) }} github.head_ref head quoted`}},
		{`tar -xf a.tar f "${{ case(true, github.head_ref, 'x') }}"`, []string{`tar 4 Option ${{ case(true, github.head_ref, 'x') }} github.head_ref head quoted`}},
		{`tar -xf a.tar f "${{ (github.event.pull_request || github.event.issue).head.ref }}"`, []string{`tar 4 Option ${{ (github.event.pull_request || github.event.issue).head.ref }} github.event.pull_request head quoted`}},
	} {
		if got := arguments(t, src(c.run), false); !slices.Equal(got, c.want) {
			t.Errorf("%s: got\n%s\nwant\n%s", c.run, strings.Join(got, "\n"), strings.Join(c.want, "\n"))
		}
	}
}
