package rules

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/attackrun"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/shell"
)

// safeFixTemplate is a script of a run step with one ${{ }} (the carrier
// below), where the shell reads the ${{ }} at quoting, and the fix of
// code-injection it gets: EnvVarID, EnvVarReviewID, or none.
type safeFixTemplate struct {
	name    string
	run     string
	quoting shell.Quoting
	fix     lint.FixKindID // noFix: none
	// sigpipe is whether a command of the pipeline may get SIGPIPE, as a
	// reader of the pipe exits without reading all of the pipe: under
	// pipefail the exit of the script is then 141 or 0 by the timing, before
	// and after the fix alike, and an exit of 141 is compared as 0 (bash
	// 5.3.15: bash -o pipefail on echo "a b" | bash < /dev/null exited 141
	// in 9 runs of 200; go test -count=30 -run
	// TestSafeFixWithBash/pipe-digest saw 141 before or after the fix of
	// pipe-digest under pipefail, where the exits were compared as they are)
	sigpipe bool
}

// noFix is no fix kind.
var noFix lint.FixKindID

const safeFixCarrier = "${{ github.event.issue.title }}"

// safeFixTemplates are one template or more for each Quoting (not
// QuotingUnknown), and one for each rule of the classifier that makes a
// place DoubleQuoted, Heredoc or Comment.
var safeFixTemplates = []safeFixTemplate{
	{"unquoted", "echo " + safeFixCarrier, shell.Unquoted, EnvVarReviewID, false},
	{"double-quoted", "echo \"" + safeFixCarrier + "\"", shell.DoubleQuoted, EnvVarID, false},
	{"single-quoted", "echo '" + safeFixCarrier + "'", shell.SingleQuoted, noFix, false},
	{"heredoc", "cat <<EOF\n" + safeFixCarrier + "\nEOF", shell.Heredoc, EnvVarID, false},
	{"quoted-heredoc", "cat <<'EOF'\n" + safeFixCarrier + "\nEOF", shell.QuotedHeredoc, noFix, false},
	{"comment", "echo a # " + safeFixCarrier, shell.Comment, EnvVarID, false},
	{"command-string", "bash -c \"" + safeFixCarrier + "\"", shell.CommandString, noFix, false},
	{"cond-operand", "[[ \"" + safeFixCarrier + "\" == a ]] || echo b", shell.DoubleQuoted, EnvVarID, false},
	{"continued-comment", "echo a \\\n# " + safeFixCarrier, shell.Comment, EnvVarID, false},
	{"redirect-target", "echo a > \"" + safeFixCarrier + "\"; cat ./*", shell.DoubleQuoted, EnvVarID, false},
	// what the pipe carries reaches no reader of code (the owner's decision
	// of 2026-11-14: env-var only where the comparison in bash passes)
	{"pipe-to-file", "echo \"" + safeFixCarrier + "\" > f | bash; cat f", shell.DoubleQuoted, EnvVarID, false},
	{"pipe-digest", "echo \"" + safeFixCarrier + "\" | sha256sum | bash", shell.DoubleQuoted, EnvVarID, true},
	{"pipe-reader-stdin", "echo \"" + safeFixCarrier + "\" | bash < /dev/null", shell.DoubleQuoted, EnvVarID, true},
	{"pipe-compound", "echo \"" + safeFixCarrier + "\" | { echo hi; }", shell.CommandString, noFix, false}, // a compound in which a command reads the pipe is taken as a reader
	{"pipe-compound-inner-pipe", "echo \"" + safeFixCarrier + "\" | { cat | bash; }", shell.CommandString, noFix, false},
	{"pipe-while-read", "echo \"" + safeFixCarrier + "\" | while read -r l; do echo \"$l\" | bash; done", shell.CommandString, noFix, false},
	// a reader in a substitution reads the pipe
	{"pipe-substitution", "echo \"" + safeFixCarrier + "\" | y=$(bash)", shell.CommandString, noFix, false},
	// $(( )) and ` ` in a command of the pipeline are read as $( ) is (the
	// owner's decision of 2026-11-15: env-var only where the comparison in
	// bash passes); echo does not read the pipe
	{"pipe-arithmetic", "echo \"" + safeFixCarrier + "\" | echo $((1))", shell.DoubleQuoted, EnvVarID, true},
	{"pipe-backquote", "echo \"" + safeFixCarrier + "\" | echo `echo hi`", shell.DoubleQuoted, EnvVarID, true},
	// a reader of code takes the place as code, whatever the quotes inside
	// say: no fix
	{"eval-substitution", "eval \"$(echo \"" + safeFixCarrier + "\")\"", shell.CommandString, noFix, false},
	{"bash-process-substitution", "bash <(echo \"" + safeFixCarrier + "\")", shell.CommandString, noFix, false},
	{"exec-process-substitution", "exec < <(echo \"" + safeFixCarrier + "\"); bash", shell.CommandString, noFix, false},
	{"arithmetic-substitution", "echo $(( $(echo \"" + safeFixCarrier + "\") ))", shell.CommandString, noFix, false},
	// places the old reading gave no fix, which bash reads as data
	{"assignment-substitution", "X=\"$(echo a)" + safeFixCarrier + "\"; echo \"$X\"", shell.DoubleQuoted, EnvVarID, false},
	{"assignment-substitution-unquoted", "X=$(echo a)" + safeFixCarrier + "; echo \"$X\"", shell.Unquoted, EnvVarReviewID, false},
	{"append-assignment", "X=a; X+=\"" + safeFixCarrier + "\"; echo \"$X\"", shell.DoubleQuoted, EnvVarID, false},
	{"clobber-target", "echo \"" + safeFixCarrier + "\" >| bash; cat bash", shell.DoubleQuoted, EnvVarID, false},
	{"quoted-assignment-word", "\"Y=1\" eval \"" + safeFixCarrier + "\" || echo b", shell.DoubleQuoted, EnvVarID, false},
	{"substitution-double-quoted", "echo \"$(echo \"" + safeFixCarrier + "\")\"", shell.DoubleQuoted, EnvVarID, false},
	{"substitution-unquoted", "echo \"$(echo " + safeFixCarrier + ")\"", shell.Unquoted, EnvVarReviewID, false},
	{"parameter-default", "echo \"${x:-" + safeFixCarrier + "}\"", shell.DoubleQuoted, EnvVarID, false},
	{"backquote-unquoted", "echo \"`echo " + safeFixCarrier + "`\"", shell.Unquoted, EnvVarReviewID, false},
	{"for-word", "for i in a \"" + safeFixCarrier + "\"; do echo \"$i\"; done", shell.DoubleQuoted, EnvVarID, false},
	{"backquote-in-double-quotes", "echo \"`echo \"" + safeFixCarrier + "\"`\"", shell.DoubleQuoted, EnvVarID, false},
	{"here-string-other-fd", "{ bash 0<&3; } 3<<< \"" + safeFixCarrier + "\"", shell.CommandString, noFix, false},
	{"integer-default-assign", "declare -i n; : \"${n:=" + safeFixCarrier + "}\"", shell.CommandString, noFix, false},
	{"brace-command-word", "{bash,-c} \"" + safeFixCarrier + "\"", shell.CommandString, noFix, false},
	{"function-reader", "f() { bash; }; echo \"" + safeFixCarrier + "\" | f", shell.CommandString, noFix, false},
	{"function-reader-here-string", "f() { read -r l; eval \"$l\"; }; f <<< \"" + safeFixCarrier + "\"", shell.CommandString, noFix, false},
	{"function-writer", "f() { echo \"" + safeFixCarrier + "\"; }; f | bash", shell.CommandString, noFix, false},
	{"function-writer-to-cat", "f() { echo \"" + safeFixCarrier + "\"; }; f | cat", shell.DoubleQuoted, EnvVarID, false},
	{"function-argument", "f() { eval \"$1\"; }; f \"" + safeFixCarrier + "\"", shell.CommandString, noFix, false},
	{"function-argument-data", "f() { echo \"$1\"; }; f \"" + safeFixCarrier + "\"", shell.DoubleQuoted, EnvVarID, false},
	{"coproc-input", "coproc bash; echo \"" + safeFixCarrier + "\" >&${COPROC[1]}", shell.CommandString, noFix, false},
	{"bash-c-joined", "bash -c\"" + safeFixCarrier + "\" || true", shell.DoubleQuoted, EnvVarID, false},
	{"brace-option", "bash {-c,} \"" + safeFixCarrier + "\"", shell.CommandString, noFix, false},
	{"time-p", "time -p eval \"" + safeFixCarrier + "\"", shell.CommandString, noFix, false},
	{"time-p-dashes", "time -p -- eval \"" + safeFixCarrier + "\"", shell.CommandString, noFix, false},
	{"integer-export-quoted", "declare -i n; export \"n=" + safeFixCarrier + "\"", shell.CommandString, noFix, false},
	{"here-string-large-fd", "1000<<<\"" + safeFixCarrier + "\" . /dev/fd/1000", shell.CommandString, noFix, false},
	{"heredoc-line-substitution", "cat <<EOF\n$(echo a) " + safeFixCarrier + "\nEOF", shell.Heredoc, EnvVarID, false},
	{"element-value", "a[0]=\"" + safeFixCarrier + "\"; echo \"${a[0]}\"", shell.DoubleQuoted, EnvVarID, false},
	{"arithmetic-hash", "echo $(( 16#ff)) \"" + safeFixCarrier + "\"", shell.DoubleQuoted, EnvVarID, false},
	{"command-word-not-literal", "C=echo; \"$C\" \"" + safeFixCarrier + "\"", shell.CommandString, noFix, false},
	{"loop-heredoc-read-eval", "while read -r l; do eval \"$l\"; done <<EOF\n" + safeFixCarrier + "\nEOF", shell.CommandString, noFix, false},
	{"compound-heredoc-read-eval", "{ read -r l; eval \"$l\"; } <<EOF\n" + safeFixCarrier + "\nEOF", shell.CommandString, noFix, false},
}

// safeFixValues are five harmless values: empty, a blank, a parenthesis,
// a glob and a line break.
var safeFixValues = []string{"", "a b", "(", "*", "a\ny"}

// safeFixAttacks are the attack values: $(echo PWNED), which runs where bash
// expands the value, and one that runs where a program reads the value as
// code (a reader of a pipe), where the first writes only an error.
var safeFixAttacks = []string{"$(echo PWNED)", "echo PWNED"}

// safeFixShells are the shell: values a template's script runs with: none
// (bash -e), and custom shells with the options the rules read
// (taint.ShellInvocationOf), so that a safe fix is safe under each of the
// options too.
var safeFixShells = []string{"", "bash -e {0}", "bash +e {0}", "bash -u {0}", "bash -x {0}", "bash -o pipefail {0}", "bash -E -T {0}", "bash --noprofile --norc -euo pipefail {0}"}

// safeFixExample is the example of the template's script with the value v,
// in a step whose shell: is sh (none if empty).
func safeFixExample(t *testing.T, sh, run, v string) lint.Example {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "# attack-value: github.event.issue.title = %s\n", strconv.Quote(v))
	b.WriteString("on:\n  issues:\n    types: [opened]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n")
	if sh != "" {
		b.WriteString("      - shell: " + sh + "\n        run: |\n")
	} else {
		b.WriteString("      - run: |\n")
	}
	for _, l := range strings.Split(run, "\n") {
		b.WriteString("          " + l + "\n")
	}
	notes, err := lint.ParseExampleNotes(b.String())
	if err != nil {
		t.Fatal(err)
	}
	name, err := facts.ParseInputPath(".github/workflows/t.yml")
	if err != nil {
		t.Fatal(err)
	}
	return lint.Example{InputKind: lint.InputKindWorkflow, Name: name, Text: b.String(), Notes: notes}
}

// runExample runs e with its attack value.
func runExample(t *testing.T, e lint.Example) attackrun.Seen {
	t.Helper()
	p, err := attackrun.Prepare(e)
	if err != nil {
		t.Fatal(err)
	}
	if p.Unrun != attackrun.UnrunNone {
		t.Fatalf("not run: %s", p.Unrun)
	}
	seen, err := attackrun.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	return seen
}

// codeInjectionFix is the fix of code-injection on e, and e with all the fixes of
// that rule applied (the review ones too).
func codeInjectionFix(t *testing.T, reg *lint.Registry, e lint.Example) (lint.FixKindID, lint.Example) {
	t.Helper()
	in, err := e.Inputs()
	if err != nil {
		t.Fatal(err)
	}
	r := exampleStore(t, e)
	rep := lint.Run(context.Background(), in, reg, r)
	var kind lint.FixKindID
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Rule == CodeInjectionID && f.Fix != nil {
			kind = f.Fix.KindID
		}
	}
	if kind == noFix {
		return noFix, e
	}
	applied, err := lint.ApplyFixes(context.Background(), in, reg, r, rep, lint.SafetyReview)
	if err != nil {
		t.Fatal(err)
	}
	return kind, fixedExample(t, e, applied.Files)
}

// TestSafeFixWithBash runs the script of each template before and after
// the fix of code-injection in bash, as the runner does (attackrun), with
// safeFixValues and safeFixAttacks: with a fix of EnvVarID, the
// harmless values give the same standard output and exit codes before and
// after, and the attack does not run after. EnvVarID is to review, as every
// fix that moves a value is (value-not-read-as-script: a workflow may rely
// on the shell reading the characters of the value); the comparison checks
// the quality of the fix before a person reviews the fix, not that the fix
// may be applied without a person looking. A Comment template is compared with
// its script before the fix with the empty value, which is the script with
// nothing in the comment: before the fix, a line break in the value ends
// the comment and runs the rest, which is the injection the fix takes away.
// With a review fix (EnvVarReviewID), the attack does not run after.
func TestSafeFixWithBash(t *testing.T) {
	if testing.Short() {
		t.Skip("runs bash")
	}
	reg, err := lint.NewRegistry(All())
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []shell.Quoting{shell.Unquoted, shell.DoubleQuoted, shell.SingleQuoted, shell.Heredoc, shell.QuotedHeredoc, shell.Comment, shell.CommandString} {
		if !slices.ContainsFunc(safeFixTemplates, func(x safeFixTemplate) bool { return x.quoting == q }) {
			t.Errorf("no template reads the ${{ }} as %v", q)
		}
	}
	for _, tc := range safeFixTemplates {
		t.Run(tc.name, func(t *testing.T) {
			at := strings.Index(tc.run, safeFixCarrier)
			plain := strings.Replace(tc.run, safeFixCarrier, "x", 1)
			if got := shell.Quotings(plain, []int{at})[0]; got != tc.quoting {
				t.Errorf("the ${{ }} is read as %v, want %v", got, tc.quoting)
			}
			for _, sh := range safeFixShells {
				t.Run("shell "+sh, func(t *testing.T) {
					kind, _ := codeInjectionFix(t, reg, safeFixExample(t, sh, tc.run, safeFixAttacks[0]))
					if kind != tc.fix {
						t.Fatalf("the fix is %q, want %q", kind, tc.fix)
					}
					if kind == noFix {
						return
					}
					values := append(slices.Clone(safeFixValues), safeFixAttacks...)
					if kind != EnvVarID {
						values = safeFixAttacks
					}
					for _, v := range values {
						before := safeFixExample(t, sh, tc.run, v)
						_, after := codeInjectionFix(t, reg, before)
						got := runExample(t, after)
						if slices.Contains(safeFixAttacks, v) {
							if got.Shows(attackrun.MarkerStdout) {
								t.Errorf("the attack runs after the fix: stdout %q", got.Stdout)
							}
							continue
						}
						if tc.quoting == shell.Comment {
							before = safeFixExample(t, sh, tc.run, "")
						}
						want := runExample(t, before)
						gotExits, wantExits := got.Exits, want.Exits
						if tc.sigpipe {
							gotExits, wantExits = withoutSigpipe(gotExits), withoutSigpipe(wantExits)
						}
						if got.Stdout != want.Stdout || !slices.Equal(gotExits, wantExits) {
							t.Errorf("value %q: after the fix, stdout %q and exits %v; before, %q and %v", v, got.Stdout, got.Exits, want.Stdout, want.Exits)
						}
					}
				})
			}
		})
	}
}

// withoutSigpipe are the exits with 141 (SIGPIPE) put as 0.
func withoutSigpipe(exits []int) []int {
	out := slices.Clone(exits)
	for i, e := range out {
		if e == 141 {
			out[i] = 0
		}
	}
	return out
}
