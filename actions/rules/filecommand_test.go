package rules

import (
	"context"
	"github.com/gh-intel/sisakulint/actions/facts"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

func fileRules(t *testing.T, src string) (lint.Report, lint.Inputs) {
	t.Helper()
	rep, in, _ := checkRules(t, []lint.Rule{EnvvarInjection, OutputClobbering}, wfFile(src), nil)
	return rep, in
}

// fcStep is a job on issues of one step with the env T (a title) and B (a
// body), and run.
func fcStep(run string) string {
	return "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          T: ${{ github.event.issue.title }}\n          B: ${{ github.event.issue.body }}\n        run: " + run + "\n"
}

func TestFileCommandDetection(t *testing.T) {
	for _, c := range []struct{ run, want string }{
		{`echo "t=$T" >> "$GITHUB_OUTPUT"`, "output-clobbering $T"},
		{`echo "t=$T" >> "$GITHUB_ENV"`, "envvar-injection $T"},
		{`echo "t=${{ github.event.issue.title }}" >> "$GITHUB_ENV"`, "envvar-injection github.event.issue.title"},
		{`'{ echo "t=$T"; echo "b=${B}"; } >> "$GITHUB_OUTPUT"'`, "output-clobbering $T; output-clobbering ${B}"},
		// one place for each file: the order is the report's (by place, then rule)
		{`echo "t=$T" | tee -a "$GITHUB_ENV" "$GITHUB_OUTPUT"`, "envvar-injection $T; output-clobbering $T"},
		{`printf 'b=%s\n' "$B" >> "$GITHUB_OUTPUT"`, "output-clobbering $B"},
		{"|\n          cat <<EOF >> \"$GITHUB_ENV\"\n          b=$B\n          EOF", "envvar-injection $B"},
		{`echo "t=$(echo "$T" | tr -d '\n')" >> "$GITHUB_OUTPUT"`, ""},
		{`echo "t=$T"`, ""},
	} {
		rep, _ := fileRules(t, fcStep(c.run))
		var got []string
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			got = append(got, f.Rule.String()+" "+strings.SplitN(f.Detected(), " ", 2)[0])
		}
		if s := strings.Join(got, "; "); s != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.run, s, c.want)
		}
	}
}

func TestFileCommandFinding(t *testing.T) {
	rep, _ := fileRules(t, fcStep(`echo "t=$T" >> "$GITHUB_ENV"`))
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("findings %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
	if f.Certainty != lint.CertaintyConfirmed || !f.Location.Exact || len(f.Evidence) == 0 {
		t.Errorf("%+v: a confirmed, exact finding with the env it comes from", f)
	}
	if !strings.Contains(f.Detected(), "issues") {
		t.Errorf("what is detected says the events: %s", f.Detected())
	}
}

// TestFileCommandSh: dash's echo turns \n in a value into a line break.
func TestFileCommandSh(t *testing.T) {
	src := strings.Replace(fcStep(`echo "t=$T" >> "$GITHUB_ENV"`), "        run:", "        shell: sh\n        run:", 1)
	rep, _ := fileRules(t, src)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 || len(rep.FindingsWith(lint.CertaintyInconclusive)) != 1 || rep.FindingsWith(lint.CertaintyInconclusive)[0].InconclusiveKind.String() != "writer-unknown" {
		t.Errorf("findings %+v, not examined %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
	}
}

// fcFixed applies the fixes of code-injection and the three rules of file
// commands to src, as review, and gives the workflow after them.
func fcFixed(t *testing.T, src string, safety lint.Safety) (string, []string) {
	t.Helper()
	rep, in, reg := checkRules(t, []lint.Rule{CodeInjection, EnvpathInjection, EnvvarInjection, OutputClobbering}, wfFile(src), nil)
	var notes []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.NoFix != nil {
			notes = append(notes, f.Rule.String()+": "+f.NoFix.Note)
		}
	}
	applied, err := lint.ApplyFixes(context.Background(), in, reg, &refs{}, rep, safety)
	if err != nil {
		t.Fatalf("ApplyFixes: %v", err)
	}
	files := applied.Files
	if b, ok := files[facts.MustCleanInputPath(".github/workflows/w.yml")]; ok {
		return string(b), notes
	}
	return src, notes
}

// TestFileCommandFix: what the fix writes is not reported again (ApplyFixes
// runs again and fails on a finding left).
func TestFileCommandFix(t *testing.T) {
	for _, c := range []struct{ run, want string }{
		{`echo "t=$T" >> "$GITHUB_OUTPUT"`, `echo "t=$(printf '%s' "${T}" | tr -d '\n')" >> "$GITHUB_OUTPUT"`},
		{`echo t=$T >> "$GITHUB_OUTPUT"`, `echo t="$(printf '%s' "${T}" | tr -d '\n')" >> "$GITHUB_OUTPUT"`},
		{`echo "t=${T}" && echo done`, `echo "t=${T}" && echo done`},
		{`echo "t=${T}" >> "$GITHUB_ENV" && echo done`, `echo "t=$(printf '%s' "${T}" | tr -d '\n')" >> "$GITHUB_ENV" && echo done`},
		{"|\n          cat <<EOF >> \"$GITHUB_ENV\"\n          b=$B\n          EOF", "|\n          cat <<EOF >> \"$GITHUB_ENV\"\n          b=$(printf '%s' \"${B}\" | tr -d '\\n')\n          EOF"},
		{`'{ echo "b<<EOF"; echo "$B"; echo "EOF"; } >> "$GITHUB_OUTPUT"'`,
			`'GHA_DELIM="ghadelimiter_$(od -An -N16 -tx1 /dev/urandom | tr -d '' \n'')"; { echo "b<<${GHA_DELIM}"; echo "$B"; echo "${GHA_DELIM}"; } >> "$GITHUB_OUTPUT"'`},
		{`'{ echo ''b<<EOF''; echo "$B"; echo EOF; } >> "$GITHUB_OUTPUT"'`,
			`'GHA_DELIM="ghadelimiter_$(od -An -N16 -tx1 /dev/urandom | tr -d '' \n'')"; { echo ''b<<''"${GHA_DELIM}"''''; echo "$B"; echo "${GHA_DELIM}"; } >> "$GITHUB_OUTPUT"'`},
	} {
		got, notes := fcFixed(t, fcStep(c.run), lint.SafetyReview)
		if want := fcStep(c.want); got != want {
			t.Errorf("%s:\n got %s\nwant %s", c.run, got, want)
		}
		if len(notes) != 0 {
			t.Errorf("%s: without a fix %v", c.run, notes)
		}
	}
}

func TestFileCommandNoFix(t *testing.T) {
	for _, run := range []string{
		`echo "$T=1" >> "$GITHUB_ENV"`,
		`echo "t=${T:-x}" >> "$GITHUB_OUTPUT"`,
		`'{ printf "b<<EOF\n"; echo "$B"; echo EOF; } >> "$GITHUB_OUTPUT"'`,
	} {
		got, notes := fcFixed(t, fcStep(run), lint.SafetyReview)
		if got != fcStep(run) || len(notes) == 0 {
			t.Errorf("%s: got\n%s\nnotes %v", run, got, notes)
		}
	}
}

// TestFileCommandFixWithCodeInjection: code-injection and the two rules in one step fix
// together, as review, and nothing is applied as safe.
func TestFileCommandFixWithCodeInjection(t *testing.T) {
	src := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo \"t=${{ github.event.issue.title }}\" >> \"$GITHUB_OUTPUT\"\n          echo \"${{ github.event.issue.title }}\"\n"
	want := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo \"t=$(printf '%s' \"${ISSUE_TITLE}\" | tr -d '\\n')\" >> \"$GITHUB_OUTPUT\"\n          echo \"${ISSUE_TITLE}\"\n        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n"
	if got, _ := fcFixed(t, src, lint.SafetyReview); got != want {
		t.Errorf("review: got\n%s\nwant\n%s", got, want)
	}
	if got, _ := fcFixed(t, src, lint.SafetySafe); got != src {
		t.Errorf("safe: got\n%s", got)
	}
}

// TestFileCommandFixWithPath: code-injection and the three rules of file commands in
// one step: the fixes apply, $GITHUB_PATH's value is left, with
// code-injection's reason, and ApplyFixes does not stop on it.
func TestFileCommandFixWithPath(t *testing.T) {
	src := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo \"${{ github.event.issue.title }}\" >> \"$GITHUB_PATH\"\n          echo \"t=${{ github.event.issue.body }}\" >> \"$GITHUB_OUTPUT\"\n"
	want := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo \"${{ github.event.issue.title }}\" >> \"$GITHUB_PATH\"\n          echo \"t=$(printf '%s' \"${ISSUE_BODY}\" | tr -d '\\n')\" >> \"$GITHUB_OUTPUT\"\n        env:\n          ISSUE_BODY: ${{ github.event.issue.body }}\n"
	got, notes := fcFixed(t, src, lint.SafetyReview)
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	if len(notes) != 1 || !strings.HasPrefix(notes[0], "code-injection: ") || !strings.Contains(notes[0], "$GITHUB_PATH") {
		t.Errorf("code-injection gives its reason for the value of $GITHUB_PATH: %v", notes)
	}
}

// readPairs reads a file of file commands as the runner does
// (FileCommandManager.cs of actions/runner v2.337.0, 382 to 495): lines at
// \n, name=value, and name<<DELIM up to the line that is DELIM.
func readPairs(b string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(strings.TrimSuffix(b, "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		e, h := strings.Index(l, "="), strings.Index(l, "<<")
		switch {
		case l == "":
		case e >= 0 && (h < 0 || e < h):
			out[l[:e]] = l[e+1:]
		case h >= 0:
			var v []string
			for i++; i < len(lines) && lines[i] != l[h+2:]; i++ {
				v = append(v, lines[i])
			}
			out[l[:h]] = strings.Join(v, "\n")
		}
	}
	return out
}

// TestFileCommandBash runs scripts the test writes, before and after the
// fix, in bash with the attacker's value and with a plain
// one, and reads $GITHUB_OUTPUT as the runner does: a plain value gives the
// same pairs, and after the fix the attacker's value adds no name.
func TestFileCommandBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	const attack = "hello\nEOF\napproved=true\nx<<EOF"
	for _, run := range []string{
		`echo "t=$B" >> "$GITHUB_OUTPUT"`,
		`printf 't=%s\n' "$B" >> "$GITHUB_OUTPUT"`,
		`'{ echo "t<<EOF"; echo "$B"; echo "EOF"; } >> "$GITHUB_OUTPUT"'`,
	} {
		fixed, _ := fcFixed(t, fcStep(run), lint.SafetyReview)
		script := func(src string) string {
			for _, s := range runScripts([]byte(src), lint.InputKindWorkflow) {
				return s
			}
			t.Fatalf("no run in %s", src)
			return ""
		}
		exec1 := func(s, v string) map[string]string {
			f := filepath.Join(t.TempDir(), "out")
			cmd := exec.Command(bash, "-e", "-c", s)
			cmd.Env = append(os.Environ(), "B="+v, "GITHUB_OUTPUT="+f)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s: %v %s", s, err, out)
			}
			b, _ := os.ReadFile(f)
			return readPairs(string(b))
		}
		before, after := script(fcStep(run)), script(fixed)
		if b, a := exec1(before, "plain"), exec1(after, "plain"); !mapsEqual(b, a) {
			t.Errorf("%s: a plain value: before %v, after %v", run, b, a)
		}
		if _, ok := exec1(before, attack)["approved"]; !ok {
			t.Errorf("%s: the attack does not add a name before the fix: the test proves nothing", run)
		}
		if got := exec1(after, attack); len(got) != 1 {
			t.Errorf("%s: after the fix the attack gives %v", run, got)
		}
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Dash's echo cannot write the fix's delimiter as the reading knows it, so
// the fix with a random delimiter is not given on sh; the run has no error.
func TestFileCommandShNoDelimFix(t *testing.T) {
	src := strings.Replace(fcStep(`'{ echo "b<<EOF"; printf ''%s\n'' "$B"; echo EOF; } >> "$GITHUB_OUTPUT"'`), "        run:", "        shell: sh\n        run:", 1)
	rep, _ := fileRules(t, src)
	if len(rep.Errors) != 0 || len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].NoFix == nil {
		t.Fatalf("errors %+v, findings %+v", rep.Errors, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// Before the = of a line, a value needs no line break to
// name another variable: a branch name is enough, and no fix is given.
func TestFileCommandKeyStructured(t *testing.T) {
	src := "on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.head_ref }}=1\" >> \"$GITHUB_ENV\"\n"
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection, EnvvarInjection}, wfFile(src), nil)
	var rules []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		rules = append(rules, f.Rule.String())
		if f.NoFix == nil {
			t.Errorf("%s: a fix %+v", f.Rule, f.Fix)
		}
	}
	if strings.Join(rules, " ") != "code-injection envvar-injection" {
		t.Errorf("findings of %v", rules)
	}
}

// The plan of a step (stepfix), through the three rules: the Safety of a
// fix is the least of what it does; D where the shell reads a heredoc's
// body; none inside '...'; a name of the delimiter's variable taken.
func TestStepFixPlan(t *testing.T) {
	t.Run("the least safety", func(t *testing.T) {
		src := fcStep("|\n          echo \"${{ github.event.issue.title }}\"\n          echo \"b=$B\" >> \"$GITHUB_OUTPUT\"")
		rep, _, _ := checkRules(t, []lint.Rule{CodeInjection, OutputClobbering}, wfFile(src), nil)
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			if f.Fix == nil || f.Fix.KindID != EnvVarReviewID {
				t.Errorf("%s: fix %+v", f.Rule, f.Fix)
			}
		}
		if got, _ := fcFixed(t, src, lint.SafetySafe); got != src {
			t.Errorf("a fix to review applied as safe:\n%s", got)
		}
	})
	for _, c := range []struct{ name, run, want string }{
		{"a heredoc's body", "|\n          cat <<EOF >> \"$GITHUB_OUTPUT\"\n          t=${{ github.event.issue.title }}\n          EOF",
			"|\n          cat <<EOF >> \"$GITHUB_OUTPUT\"\n          t=$(printf '%s' \"${ISSUE_TITLE}\" | tr -d '\\n')\n          EOF"},
		{"inside '...'", `echo 't=${{ github.event.issue.title }}' >> "$GITHUB_OUTPUT"`, ""},
		{"the name taken", `'echo "$GHA_DELIM"; { echo "b<<EOF"; echo "$B"; echo EOF; } >> "$GITHUB_OUTPUT"'`,
			`'echo "$GHA_DELIM"; GHA_DELIM_2="ghadelimiter_$(od -An -N16 -tx1 /dev/urandom | tr -d '' \n'')"; { echo "b<<${GHA_DELIM_2}"; echo "$B"; echo "${GHA_DELIM_2}"; } >> "$GITHUB_OUTPUT"'`},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := fcStep(c.run)
			got, notes := fcFixed(t, src, lint.SafetyReview)
			want := src
			if c.want != "" {
				want = fcStep(c.want)
				if strings.Contains(c.run, "${{") {
					want = strings.Replace(want, "        run:", "          ISSUE_TITLE: ${{ github.event.issue.title }}\n        run:", 1)
				}
			} else if len(notes) == 0 {
				t.Errorf("no reason for no fix")
			}
			if got != want {
				t.Errorf("got\n%s\nwant\n%s", got, want)
			}
		})
	}
}

// TestStepFixPath: a ${{ }} written to $GITHUB_PATH gets no fix, since
// moving it to env leaves the directory the attacker's; the other
// expressions of the step keep theirs, and the fixes apply.
func TestStepFixPath(t *testing.T) {
	src := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo \"${{ github.event.issue.title }}\" >> \"$GITHUB_PATH\"\n          echo \"${{ github.event.issue.body }}\"\n"
	want := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo \"${{ github.event.issue.title }}\" >> \"$GITHUB_PATH\"\n          echo \"${ISSUE_BODY}\"\n        env:\n          ISSUE_BODY: ${{ github.event.issue.body }}\n"
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection}, wfFile(src), nil)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 2 {
		t.Fatalf("findings %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		path := strings.Contains(f.Detected(), "title")
		if path && (f.NoFix == nil || !strings.Contains(f.NoFix.Note, "$GITHUB_PATH")) {
			t.Errorf("%s: fix %+v, no fix %+v", f.Detected(), f.Fix, f.NoFix)
		}
		if !path && f.Fix == nil {
			t.Errorf("%s: no fix %+v", f.Detected(), f.NoFix)
		}
	}
	if got, _ := fcFixed(t, src, lint.SafetyReview); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	// one value to $GITHUB_ENV and $GITHUB_PATH
	src2 := fcStep(`echo "t=$T" | tee -a "$GITHUB_ENV" "$GITHUB_PATH"`)
	rep2, _, _ := checkRules(t, []lint.Rule{EnvvarInjection}, wfFile(src2), nil)
	if len(rep2.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep2.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].NoFix == nil {
		t.Errorf("findings %+v", rep2.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}
