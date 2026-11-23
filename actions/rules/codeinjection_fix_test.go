package rules

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"
)

// injFixed runs code-injection on the workflow src, applies its fixes of
// safety, and gives the workflow after them; notes are the notes of the
// findings without a fix.
func injFixed(t *testing.T, src string, safety lint.Safety) (out string, notes []string) {
	t.Helper()
	rep, in, reg := checkRules(t, []lint.Rule{CodeInjection}, wfFile(src), nil)
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.NoFix != nil {
			notes = append(notes, f.NoFix.Reason.String()+": "+f.NoFix.Note)
		} else if f.Fix == nil {
			t.Errorf("a finding with no fix and no reason")
		}
	}
	applied, err := lint.ApplyFixes(context.Background(), in, reg, &refs{}, rep, safety)
	if err != nil {
		t.Fatalf("ApplyFixes: %v", err)
	}
	files := applied.Files
	b, ok := files[facts.MustCleanInputPath(".github/workflows/w.yml")]
	if !ok {
		return src, notes
	}
	return string(b), notes
}

func injStep(run string) string {
	return "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: " + run + "\n"
}

func TestInjectionFix(t *testing.T) {
	for _, c := range []struct {
		name, src, want string
	}{
		{"outside quotes", injStep(`echo ${{ github.event.issue.title }}`),
			injStep(`echo "${ISSUE_TITLE}"`) + "        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n"},
		{"inside double quotes", injStep(`echo "Title - ${{ github.event.issue.title }}!"`),
			injStep(`echo "Title - ${ISSUE_TITLE}!"`) + "        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n"},
		// a comment ends at a line break the value may hold
		{"in a comment", injStep("|\n          echo hi # ${{ github.event.issue.title }}"),
			injStep("|\n          echo hi # ${ISSUE_TITLE}") + "        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n"},
		{"the same expression twice, and another", injStep(`echo ${{ github.event.issue.title }} "${{github.event.issue.title}}" ${{ github.event.issue.body }}`),
			injStep(`echo "${ISSUE_TITLE}" "${ISSUE_TITLE}" "${ISSUE_BODY}"`) +
				"        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n          ISSUE_BODY: ${{ github.event.issue.body }}\n"},
		{"a whole expression", injStep(`echo ${{ github.event.issue.title || 'none' }}`),
			injStep(`echo "${ISSUE_TITLE}"`) + "        env:\n          ISSUE_TITLE: ${{ github.event.issue.title || 'none' }}\n"},
		{"the env of the step", "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n        env:\n          A: b\n",
			"on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${ISSUE_TITLE}\"\n        env:\n          A: b\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n"},
		// a name taken, whatever its case
		{"a name taken", "on: issues\nenv:\n  issue_title: x\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n",
			"on: issues\nenv:\n  issue_title: x\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${ISSUE_TITLE_2}\"\n        env:\n          ISSUE_TITLE_2: ${{ github.event.issue.title }}\n"},
		// the variable is there already
		{"env", "on: issues\nenv:\n  Title: ${{ github.event.issue.title }}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ env.title }}\n",
			"on: issues\nenv:\n  Title: ${{ github.event.issue.title }}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${Title}\"\n"},
		// only the expression changes in a script of many lines
		{"a literal block", "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo one\n          echo \"${{ github.event.issue.title }}\"\n\n          echo three\n",
			"on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo one\n          echo \"${ISSUE_TITLE}\"\n\n          echo three\n        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n"},
		// a string compared inside [[ ]]
		{"inside [[ ]]", injStep(`if [[ "${{ github.event.issue.title }}" == /deploy ]]; then echo a; fi`),
			injStep(`if [[ "${ISSUE_TITLE}" == /deploy ]]; then echo a; fi`) + "        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n"},
		{"a heredoc", "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          cat <<EOF\n          ${{ github.event.issue.title }}\n          EOF\n",
			"on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          cat <<EOF\n          ${ISSUE_TITLE}\n          EOF\n        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, notes := injFixed(t, c.src, lint.SafetyReview)
			if got != c.want {
				t.Errorf("got\n%s\nwant\n%s", got, c.want)
			}
			if len(notes) != 0 {
				t.Errorf("findings without a fix: %v", notes)
			}
		})
	}
}

func TestInjectionFixReview(t *testing.T) {
	for _, c := range []struct {
		name, src, want string
	}{
		{"pwsh", "on: issues\njobs:\n  j:\n    runs-on: windows-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n",
			"on: issues\njobs:\n  j:\n    runs-on: windows-latest\n    steps:\n      - run: echo $env:ISSUE_TITLE\n        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n"},
		{"pwsh by the workflow's defaults", "on: issues\ndefaults:\n  run:\n    shell: pwsh\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n",
			"on: issues\ndefaults:\n  run:\n    shell: pwsh\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo $env:ISSUE_TITLE\n        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n"},
		{"a list of one label", "on: issues\njobs:\n  j:\n    runs-on: [windows-latest]\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n",
			"on: issues\njobs:\n  j:\n    runs-on: [windows-latest]\n    steps:\n      - run: echo $env:ISSUE_TITLE\n        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n"},
		// the pattern becomes a string
		{"a pattern of [[ ]]", injStep(`if [[ x == ${{ github.event.issue.title }} ]]; then echo a; fi`),
			injStep(`if [[ x == "${ISSUE_TITLE}" ]]; then echo a; fi`) + "        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n"},
		{"github-script", "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/github-script@v7\n        with:\n          script: console.log('${{ github.event.issue.title }}')\n",
			"on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/github-script@v7\n        with:\n          script: console.log(process.env.ISSUE_TITLE)\n        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got, _ := injFixed(t, c.src, lint.SafetySafe); got != c.src {
				t.Errorf("a fix to review is applied as safe:\n%s", got)
			}
			got, notes := injFixed(t, c.src, lint.SafetyReview)
			if got != c.want || len(notes) != 0 {
				t.Errorf("got\n%s\nwant\n%s\nnotes %v", got, c.want, notes)
			}
		})
	}
}

func TestInjectionNoFix(t *testing.T) {
	for _, c := range []struct {
		name, src, reason, note string
	}{
		{"inside single quotes", injStep(`echo '${{ github.event.issue.title }}'`), "manual", "not expanded"},
		{"eval", injStep(`eval "echo ${{ github.event.issue.title }}"`), "manual", "code"},
		{"inside single quotes in [[ ]]", injStep(`if [[ '${{ github.event.issue.title }}' =~ ^v0\.1 ]]; then echo a; fi`), "manual", "not expanded"},
		{"arithmetic in [[ ]]", injStep(`if [[ "${{ github.event.issue.title }}" -eq 1 ]]; then echo a; fi`), "manual", "code"},
		{"the operator of [[ ]]", injStep(`if [[ x ${{ github.event.issue.title }} y ]]; then echo a; fi`), "manual", "cannot tell"},
		{"python -c", injStep(`python3 -c "print('${{ github.event.issue.title }}')"`), "manual", "code"},
		{"a pattern of ${ }", injStep(`echo "${X/${{ github.event.issue.title }}/b}"`), "manual", "cannot tell"},
		{"inside <( )", injStep(`diff <(echo "${{ github.event.issue.title }}") f`), "manual", "cannot tell"},
		{"inside $( ) read as code", injStep(`eval "$(echo "${{ github.event.issue.title }}")"`), "manual", "code"},
		{"python", "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: print('${{ github.event.issue.title }}')\n        shell: python\n", "manual", "shell"},
		// a custom shell with an option the rules do not read
		{"a shell of its own", "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n        shell: bash -c x {0}\n", "manual", "shell"},
		{"the job's defaults", "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    defaults:\n      run:\n        shell: python\n    steps:\n      - run: print('${{ github.event.issue.title }}')\n", "manual", "shell"},
		{"a runner not known", "on: issues\njobs:\n  j:\n    runs-on: self-hosted\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n", "manual", "shell"},
		{"a step through an alias", "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - &s\n        run: echo ${{ github.event.issue.title }}\n  k:\n    runs-on: ubuntu-latest\n    steps:\n      - *s\n", "form", "alias"},
		// env takes an object or an array as a mapping or a sequence, and fails the step
		{"a value that may be an array", injStep(`echo "${{ github.event.issue.title || github.event.issue.labels }}"`), "manual", "object or an array"},
		{"fromJSON", injStep(`echo "${{ fromJSON(github.event.issue.title) }}"`), "manual", "object or an array"},
		{"inside a JavaScript string", "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/github-script@v7\n        with:\n          script: console.log('x ${{ github.event.issue.title }}')\n", "manual", "JavaScript"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, notes := injFixed(t, c.src, lint.SafetyReview)
			if got != c.src {
				t.Errorf("changed:\n%s", got)
			}
			if len(notes) == 0 || !strings.HasPrefix(notes[0], c.reason+": ") || !strings.Contains(notes[0], c.note) {
				t.Errorf("notes %v, want %s mentioning %q", notes, c.reason, c.note)
			}
		})
	}
}

// TestInjectionFixPart: a fixable and an unfixable expression in one step;
// the fix moves the one and leaves the other with its reason.
func TestInjectionFixPart(t *testing.T) {
	got, notes := injFixed(t, injStep(`echo ${{ github.event.issue.body }} '${{ github.event.issue.title }}'`), lint.SafetyReview)
	want := injStep(`echo "${ISSUE_BODY}" '${{ github.event.issue.title }}'`) + "        env:\n          ISSUE_BODY: ${{ github.event.issue.body }}\n"
	if got != want || len(notes) != 1 {
		t.Errorf("got\n%s\nwant\n%s\nnotes %v", got, want, notes)
	}
}

// A value that may be an array stays, and another expression of the step
// is moved.
func TestInjectionFixCollectionPart(t *testing.T) {
	got, notes := injFixed(t, injStep(`echo "${{ github.event.issue.title || github.event.issue.labels }}" "${{ github.event.issue.body }}"`), lint.SafetyReview)
	want := injStep(`echo "${{ github.event.issue.title || github.event.issue.labels }}" "${ISSUE_BODY}"`) + "        env:\n          ISSUE_BODY: ${{ github.event.issue.body }}\n"
	if got != want || len(notes) != 1 || !strings.Contains(notes[0], "object or an array") {
		t.Errorf("got\n%s\nwant\n%s\nnotes %v", got, want, notes)
	}
}

// TestInjectionFixShared: findings of one step give one fix, which the
// engine checks once.
func TestInjectionFixShared(t *testing.T) {
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection}, wfFile(injStep(`echo ${{ github.event.issue.title }} ${{ github.event.issue.body }}`)), nil)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 2 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix == nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[1].Fix == nil {
		t.Fatalf("findings: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	a, b := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[1].Fix
	if len(a.Edits) != len(b.Edits) || len(a.Edits) != 3 {
		t.Errorf("edits %d and %d, want the same 3: two replacements and the env", len(a.Edits), len(b.Edits))
	}
}

// TestInjectionFixSameExpression: the same expression twice, the second inside
// '...': the fix moves the first, and the second keeps its finding.
func TestInjectionFixSameExpression(t *testing.T) {
	src := injStep("|\n          echo \"${{ github.event.issue.title }}\"\n          echo '${{ github.event.issue.title }}'")
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection}, wfFile(src), nil)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 2 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix == nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[1].NoFix == nil {
		t.Errorf("findings: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestInjectionFixStepEnvInExpression: a whole expression with an env of the
// step itself, which the env of the step cannot see.
func TestInjectionFixStepEnvInExpression(t *testing.T) {
	src := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ env.T || 'none' }}\"\n        env:\n          T: ${{ github.event.issue.title }}\n"
	got, notes := injFixed(t, src, lint.SafetyReview)
	if got != src || len(notes) != 1 || !strings.Contains(notes[0], "env of the step") {
		t.Errorf("got\n%s\nnotes %v", got, notes)
	}
}

// TestInjectionFixScriptVariable: a name the script uses already.
func TestInjectionFixScriptVariable(t *testing.T) {
	got, _ := injFixed(t, injStep("|\n          ISSUE_TITLE=default\n          echo \"${{ github.event.issue.title }}\""), lint.SafetyReview)
	if !strings.Contains(got, `echo "${ISSUE_TITLE_2}"`) || !strings.Contains(got, "ISSUE_TITLE_2: ${{ github.event.issue.title }}") {
		t.Errorf("got\n%s", got)
	}
}

// TestInjectionFixLargeScript: each expression of a large script has a
// finding with a fix. The format() expression of the 180 lines is about
// 16,600 long, below the 21,000 that a workflow allows (a script of 700
// lines made the workflow invalid, and the rule read nothing). The findings
// are checked in every run. The time is compared with ACTIONS_SCALE=1
// only, as the time depends on the machine; the time limit does not find a
// reading of the script again for each expression, which adds about a
// second at this size.
func TestInjectionFixLargeScript(t *testing.T) {
	const lines = 180
	var b strings.Builder
	b.WriteString("|\n")
	for range lines {
		b.WriteString("          echo \"${{ github.event.issue.title }} ${{ github.event.issue.body }}\" # padding padding padding\n")
	}
	start := time.Now()
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection}, wfFile(injStep(strings.TrimSuffix(b.String(), "\n"))), nil)
	if d := time.Since(start); os.Getenv("ACTIONS_SCALE") == "1" && d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	fs := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)
	if len(fs) != 2*lines {
		t.Fatalf("%d findings, want %d", len(fs), 2*lines)
	}
	for _, f := range fs {
		if f.Fix == nil {
			t.Fatalf("a finding with no fix: %+v", f.NoFix)
		}
	}
}

// TestInjectionFixUnquotedIsReview: outside quotes, the variable is one word
// where the value was split and globbed: a person looks.
func TestInjectionFixUnquotedIsReview(t *testing.T) {
	src := injStep(`echo ${{ github.event.issue.title }}`)
	if got, _ := injFixed(t, src, lint.SafetySafe); got != src {
		t.Errorf("applied as safe:\n%s", got)
	}
}

// The fix of code-injection in a step that writes to a file command: the
// plan of the step knows the value's line breaks there (stepfix).
func TestInjectionFixFileCommand(t *testing.T) {
	for _, c := range []struct {
		name, run, want string
		notes           int
	}{
		{"the value of a line", `echo "t=${{ github.event.issue.title }}" >> "$GITHUB_OUTPUT"`,
			injStep(`echo "t=$(printf '%s' "${ISSUE_TITLE}" | tr -d '\n')" >> "$GITHUB_OUTPUT"`) + "        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n", 0},
		{"outside quotes", `echo t=${{ github.event.issue.title }} >> "$GITHUB_OUTPUT"`,
			injStep(`echo t="$(printf '%s' "${ISSUE_TITLE}" | tr -d '\n')" >> "$GITHUB_OUTPUT"`) + "        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n", 0},
		{"the key", `echo "${{ github.event.issue.title }}=1" >> "$GITHUB_ENV"`, "", 1},
		{"a heredoc whose delimiter the fix makes random", `'{ echo "t<<EOF"; echo "${{ github.event.issue.title }}"; echo EOF; } >> "$GITHUB_OUTPUT"'`,
			injStep(`'GHA_DELIM="ghadelimiter_$(od -An -N16 -tx1 /dev/urandom | tr -d '' \n'')"; { echo "t<<${GHA_DELIM}"; echo "${ISSUE_TITLE}"; echo "${GHA_DELIM}"; } >> "$GITHUB_OUTPUT"'`) + "        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n", 0},
		{"a heredoc of another form", `'{ printf "t<<EOF\n"; echo "${{ github.event.issue.title }}"; echo EOF; } >> "$GITHUB_OUTPUT"'`, "", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, notes := injFixed(t, injStep(c.run), lint.SafetyReview)
			if c.want == "" {
				c.want = injStep(c.run)
			}
			if got != c.want {
				t.Errorf("got\n%s\nwant\n%s", got, c.want)
			}
			if len(notes) != c.notes {
				t.Errorf("findings without a fix: %v", notes)
			}
		})
	}
}

// With safe fixes only, a step whose fix takes line breaks out is left.
func TestInjectionFixFileCommandSafe(t *testing.T) {
	src := injStep(`echo "t=${{ github.event.issue.title }}" >> "$GITHUB_OUTPUT"`)
	if got, _ := injFixed(t, src, lint.SafetySafe); got != src {
		t.Errorf("a fix to review was applied:\n%s", got)
	}
}

// A branch name cannot hold a line break: where it is written to
// $GITHUB_OUTPUT, the fix of code-injection takes no line break out and is
// env-var. env-var is to review like every fix that moves a value: with safe
// fixes only, the step is left.
func TestInjectionFixFileCommandBranch(t *testing.T) {
	src := "on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"h=${{ github.head_ref }}\" >> \"$GITHUB_OUTPUT\"\n"
	want := "on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"h=${HEAD_REF}\" >> \"$GITHUB_OUTPUT\"\n        env:\n          HEAD_REF: ${{ github.head_ref }}\n"
	if got, _ := injFixed(t, src, lint.SafetyReview); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	if got, _ := injFixed(t, src, lint.SafetySafe); got != src {
		t.Errorf("applied as safe:\n%s", got)
	}
}

// commit-sha and code-injection in one step of actions/github-script, the
// one step where both give a fix: with `with` before `uses` the env goes
// right after the uses that commit-sha rewrites, and in a flow mapping both
// edit one line. The fixes apply together, and nothing is found after them;
// as safe, only commit-sha's.
func TestInjectionFixWithCommitSHA(t *testing.T) {
	const head = "on: issues\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" // no token to write: dangerous-triggers has nothing to report
	const script = `console.log("${{ github.event.issue.title }}")`
	const fixedScript = "console.log(process.env.ISSUE_TITLE)"
	const env = "        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n"
	for _, c := range []struct{ name, src, review, safe string }{
		{"uses first",
			head + "      - uses: actions/github-script@v7\n        with:\n          script: " + script + "\n",
			head + "      - uses: actions/github-script@" + sha + " # v7\n        with:\n          script: " + fixedScript + "\n" + env,
			head + "      - uses: actions/github-script@" + sha + " # v7\n        with:\n          script: " + script + "\n"},
		{"with first: the env right after the uses",
			head + "      - with:\n          script: " + script + "\n        uses: actions/github-script@v7\n",
			head + "      - with:\n          script: " + fixedScript + "\n        uses: actions/github-script@" + sha + " # v7\n" + env,
			head + "      - with:\n          script: " + script + "\n        uses: actions/github-script@" + sha + " # v7\n"},
		{"a flow mapping: one line",
			head + "      - {uses: actions/github-script@v7, with: {script: '" + script + "'}}\n",
			head + "      - {uses: actions/github-script@" + sha + ", with: {script: '" + fixedScript + "'}, env: {ISSUE_TITLE: \"${{ github.event.issue.title }}\"}}\n",
			head + "      - {uses: actions/github-script@" + sha + ", with: {script: '" + script + "'}}\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := &refs{answer: map[string]facts.RawAnswer{"actions/github-script@v7": resolved(sha)}}
			rep, in, reg := checkRules(t, All(), wfFile(c.src), r)
			var rules []string
			for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
				rules = append(rules, f.Rule.String())
			}
			slices.Sort(rules)
			if !slices.Equal(rules, []string{"code-injection", "commit-sha"}) {
				t.Fatalf("findings of %v, want one of code-injection and one of commit-sha: the test proves nothing", rules)
			}
			for safety, want := range map[lint.Safety]string{lint.SafetyReview: c.review, lint.SafetySafe: c.safe} {
				applied, err := lint.ApplyFixes(context.Background(), in, reg, r, rep, safety)
				if err != nil {
					t.Fatalf("%v: ApplyFixes: %v", safety, err)
				}
				files := applied.Files
				if got := string(files[facts.MustCleanInputPath(".github/workflows/w.yml")]); got != want {
					t.Errorf("%v: got\n%s\nwant\n%s", safety, got, want)
				}
			}
		})
	}
}

// TestInjectionFixSideEffects: the side effects of the fix of a step are
// those of the replacements it writes, each once, in the order of the
// values, and value-not-read-as-script, which every fix that moves a value
// has; a step without one of the replacements gets env-var, which is also
// to review.
func TestInjectionFixSideEffects(t *testing.T) {
	gh := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/github-script@v7\n        with:\n          script: console.log('${{ github.event.issue.title }}')\n"
	pwsh := "on: issues\njobs:\n  j:\n    runs-on: windows-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n"
	for _, c := range []struct {
		name, src string
		want      []ir.SideEffect
	}{
		{"quoted", injStep(`echo "${{ github.event.issue.title }}"`), nil},
		{"unquoted", injStep(`echo ${{ github.event.issue.title }}`), []ir.SideEffect{ir.SideEffectUnquotedOneWord}},
		{"a pattern of [[ ]]", injStep(`if [[ x == ${{ github.event.issue.title }} ]]; then echo a; fi`), []ir.SideEffect{ir.SideEffectUnquotedOneWord, ir.SideEffectPatternLiteral}},
		{"the left of [[ ]]", injStep(`if [[ ${{ github.event.issue.title }} == x ]]; then echo a; fi`), []ir.SideEffect{ir.SideEffectUnquotedOneWord}},
		{"pwsh", pwsh, []ir.SideEffect{ir.SideEffectPwshUnchecked}},
		{"github-script", gh, []ir.SideEffect{ir.SideEffectGitHubScriptUnchecked}},
		{"the value of a line", injStep(`echo "t=${{ github.event.issue.title }}" >> "$GITHUB_OUTPUT"`), []ir.SideEffect{ir.SideEffectLineBreaksRemoved}},
		{"a heredoc whose delimiter is literal", injStep(`'{ echo "t<<EOF"; echo "${{ github.event.issue.title }}"; echo EOF; } >> "$GITHUB_OUTPUT"'`), []ir.SideEffect{ir.SideEffectRandomDelimiter}},
		{"two of them", injStep(`echo ${{ github.event.issue.body }}; [[ x == ${{ github.event.issue.title }} ]]`), []ir.SideEffect{ir.SideEffectUnquotedOneWord, ir.SideEffectPatternLiteral}},
		// a place without a fix adds no side effect
		{"a place without a fix", injStep(`echo "${{ github.event.issue.body }}"; eval ${{ github.event.issue.title }}`), nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep, _, _ := checkRules(t, []lint.Rule{CodeInjection}, wfFile(c.src), nil)
			fixed := 0
			for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
				if f.Fix == nil {
					continue
				}
				fixed++
				kind := EnvVarID
				if len(c.want) > 0 {
					kind = EnvVarReviewID
				}
				want := append(slices.Clone(c.want), ir.SideEffectValueNotReadAsScript)
				slices.Sort(want)
				if f.Fix.KindID != kind || !slices.Equal(f.Fix.SideEffects, want) {
					t.Errorf("%s with %v, want %s with %v", f.Fix.KindID, f.Fix.SideEffects, kind, want)
				}
			}
			if fixed == 0 {
				t.Errorf("no fix in %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			}
		})
	}
}

// ${{ }} is put in before bash reads the script: on the left of [[ ]], a
// value with blanks was several words (bash refuses the expression), and
// "${NAME}" is one. A person looks.
func TestInjectionFixCondLeftIsReview(t *testing.T) {
	src := injStep(`if [[ ${{ github.event.issue.title }} == x ]]; then echo a; fi`)
	if got, _ := injFixed(t, src, lint.SafetySafe); got != src {
		t.Errorf("applied as safe:\n%s", got)
	}
}

// A ${{ }} written before the = of a line of $GITHUB_ENV takes the fix of
// its step away from code-injection too: the fix of a step is one plan for
// every rule (actions/ir, the plan of the step), and moving the expression
// into env would leave the name of the line to the attacker. The same
// expression written only where bash reads it gets the fix.
func TestInjectionFixKeyTakesTheStepFix(t *testing.T) {
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection, EnvvarInjection}, wfFile(injStep(`echo "${{ github.event.issue.title }}=1" >> "$GITHUB_ENV"`)), nil)
	rules := map[lint.RuleID]bool{}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		rules[f.Rule] = true
		if f.Fix != nil || f.NoFix == nil || f.NoFix.Reason != ir.NoFixReasonManual || !strings.Contains(f.NoFix.Note, "before the = or <<") {
			t.Errorf("%s: fix %v, no fix %+v; want no fix, the reason manual, for the name of the line", f.Rule, f.Fix, f.NoFix)
		}
	}
	if !rules[CodeInjectionID] || !rules[EnvvarInjectionID] {
		t.Fatalf("findings of %v, want code-injection and envvar-injection", rules)
	}
	plain, _, _ := checkRules(t, []lint.Rule{CodeInjection}, wfFile(injStep(`echo "${{ github.event.issue.title }}"`)), nil)
	if len(plain.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || plain.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix == nil {
		t.Errorf("without $GITHUB_ENV: %+v, want one finding with a fix", plain.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// One ${{ }} written where bash reads it and also to $GITHUB_ENV: the plan
// of the step gives code-injection and envvar-injection one fix, the same
// edits, with one variable of env read in two ways: as it is where bash
// reads it, and with its line breaks taken out where the step writes it to
// $GITHUB_ENV. ApplyFixes applies the edits once.
func TestInjectionFixSharedAcrossRules(t *testing.T) {
	src := injStep("|\n          echo \"${{ github.event.issue.title }}\"\n          echo \"title=${{ github.event.issue.title }}\" >> \"$GITHUB_ENV\"")
	rep, in, reg := checkRules(t, []lint.Rule{CodeInjection, EnvvarInjection}, wfFile(src), nil)
	var fixes []*lint.Fix
	rules := map[lint.RuleID]bool{}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		rules[f.Rule] = true
		if f.Fix == nil {
			t.Fatalf("%s: no fix (%+v)", f.Rule, f.NoFix)
		}
		fixes = append(fixes, f.Fix)
	}
	if !rules[CodeInjectionID] || !rules[EnvvarInjectionID] {
		t.Fatalf("findings of %v, want code-injection and envvar-injection", rules)
	}
	for _, x := range fixes[1:] {
		if !slices.EqualFunc(x.Edits, fixes[0].Edits, func(a, b edit.Edit) bool { return a.Span == b.Span && string(a.New) == string(b.New) }) {
			t.Errorf("the fixes differ: %+v and %+v", fixes[0].Edits, x.Edits)
		}
	}
	a, err := lint.ApplyFixes(context.Background(), in, reg, nil, rep, lint.SafetyReview)
	if err != nil {
		t.Fatal(err)
	}
	got := string(a.Files[facts.MustCleanInputPath(".github/workflows/w.yml")])
	for _, want := range []string{
		`echo "${ISSUE_TITLE}"`,
		`echo "title=$(printf '%s' "${ISSUE_TITLE}" | tr -d '\n')" >> "$GITHUB_ENV"`,
		"ISSUE_TITLE: ${{ github.event.issue.title }}",
	} {
		if strings.Count(got, want) != 1 {
			t.Errorf("want %q once in\n%s", want, got)
		}
	}
}
