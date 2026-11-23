package rules

import (
	"context"
	"maps"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

func injection(t *testing.T, files map[string]string) (lint.Report, lint.Inputs) {
	t.Helper()
	rep, in, _ := checkRules(t, []lint.Rule{CodeInjection}, files, nil)
	return rep, in
}

func wfFile(src string) map[string]string { return map[string]string{".github/workflows/w.yml": src} }

func TestInjectionDetection(t *testing.T) {
	rep, in := injection(t, wfFile(`on: [issues, pull_request_target]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }} ${{ github.event.issue.number }}"
      - uses: actions/github-script@v7
        with:
          script: console.log('${{ github.event.pull_request.head.ref }}')
`))
	want := []string{
		".github/workflows/w.yml github.event.issue.title",
		".github/workflows/w.yml github.event.pull_request.head.ref",
	}
	if got := at(t, rep, in); !slices.Equal(got, want) {
		t.Fatalf("findings at\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Rule != CodeInjectionID || f.Severity != lint.SeverityCritical || f.Certainty != lint.CertaintyConfirmed || !f.Location.Exact {
			t.Errorf("%+v: want a confirmed, exact finding of critical severity", f)
		}
		if f.Fix == nil || f.NoFix != nil {
			t.Errorf("%+v: want a fix", f)
		}
	}
	if m := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Detected(); !strings.Contains(m, "run") || !strings.Contains(m, "issues") || strings.Contains(m, "pull_request_target") {
		t.Errorf("what is detected says where and on which events: %s", m)
	}
	if m := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[1].Detected(); !strings.Contains(m, "github-script") || !strings.Contains(m, "pull_request_target") {
		t.Errorf("what is detected says where and on which events: %s", m)
	}
}

// TestInjectionPusher: on push, the rule reports nothing on the name, the
// email and the username of the pusher, the account that pushed or merged,
// which holds a credential that can push; the rule still reports the name
// of the author of the head commit, which the author of a pull request
// writes.
func TestInjectionPusher(t *testing.T) {
	rep, in := injection(t, wfFile(`on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pusher.name }} ${{ github.event.pusher.email }} ${{ github.event.pusher.username }} ${{ github.event.head_commit.author.name }}"
`))
	want := []string{".github/workflows/w.yml github.event.head_commit.author.name"}
	if got := at(t, rep, in); !slices.Equal(got, want) {
		t.Errorf("findings at\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(rep.FindingsWith(lint.CertaintyInconclusive)) != 0 {
		t.Errorf("inconclusive places %+v, want none", rep.FindingsWith(lint.CertaintyInconclusive))
	}
}

// TestInjectionPositions: where the expression is, in each style of scalar. The
// place is in the input's bytes: an escape in the reference is there as it
// is written (a span that holds a whole escape is exact; a reference, whose
// names cannot hold more than one character of an escape, never cuts one).
func TestInjectionPositions(t *testing.T) {
	const ref = "github.event.issue.title"
	for _, c := range []struct{ name, run, at string }{
		{"plain", `echo ${{ github.event.issue.title }}`, ref},
		{"double-quoted", `"echo \"${{ github.event.issue.title }}\""`, ref},
		{"single-quoted", `'echo "${{ github.event.issue.title }}"'`, ref},
		{"literal", "|\n          echo one\n          echo \"${{ github.event.issue.title }}\"", ref},
		{"folded", ">\n          echo\n          ${{ github.event.issue.title }}", ref},
		{"crlf", "|\r\n          echo \"${{ github.event.issue.title }}\"\r\n", ref},
		{"escaped dollar", `"echo \x24{{ github.event.issue.title }}"`, ref},
		{"escaped reference", `"echo ${{ \x67ithub.event.issue.title }}"`, `\x67ithub.event.issue.title`},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: " + c.run + "\n"
			if c.name == "crlf" {
				src = strings.ReplaceAll(src, "\n", "\r\n")
				src = strings.ReplaceAll(src, "\r\r\n", "\r\n")
			}
			rep, in := injection(t, wfFile(src))
			if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
				t.Fatalf("findings: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			}
			if !rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Location.Exact {
				t.Error("not exact")
			}
			if got := at(t, rep, in)[0]; got != ".github/workflows/w.yml "+c.at {
				t.Errorf("at %q", got)
			}
		})
	}
}

func TestInjectionTwoInOneScript(t *testing.T) {
	rep, _ := injection(t, wfFile(`on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ github.event.issue.title }}"
          echo "${{ github.event.issue.title }}" "${{ github.event.issue.body }}"
`))
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 3 {
		t.Fatalf("findings: %d", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	fps := map[string]bool{}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		fps[f.Fingerprint.String()] = true
	}
	if len(fps) != 3 {
		t.Errorf("fingerprints are not distinct: %v", fps)
	}
}

func TestInjectionEnv(t *testing.T) {
	rep, in := injection(t, wfFile(`on: issues
env:
  TITLE: ${{ github.event.issue.title }}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ env.TITLE }}"
`))
	if got := at(t, rep, in); !slices.Equal(got, []string{".github/workflows/w.yml env.TITLE"}) {
		t.Fatalf("findings at %v", got)
	}
	ev := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Evidence
	if len(ev) != 1 {
		t.Fatalf("evidence: %+v", ev)
	}
	i, _ := in.Lookup(ev[0].Location.File.Input)
	if got := string(i.Tree.Bytes()[ev[0].Location.Span.Start:ev[0].Location.Span.End]); got != "${{ github.event.issue.title }}" {
		t.Errorf("the evidence is at %q, want the env value", got)
	}
}

func TestInjectionUnexamined(t *testing.T) {
	rep, in := injection(t, wfFile(`on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo
  j:
    needs: a
    runs-on: ubuntu-latest
    steps:
      - id: s
        run: echo
      - run: echo "${{ steps.s.outputs.o }} ${{ needs.a.outputs.o }} ${{ env.NOWHERE }}"
`))
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
		t.Errorf("findings: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	var got []string
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		i, _ := in.Lookup(g.Location.File.Input)
		got = append(got, g.InconclusiveKind.String()+" "+string(i.Tree.Bytes()[g.Location.Span.Start:g.Location.Span.End]))
		if g.Rule != CodeInjectionID || g.Note == "" {
			t.Errorf("%+v", g)
		}
	}
	want := []string{"step-output-run steps.s.outputs.o", "job-output needs.a.outputs.o", "env-unset env.NOWHERE"}
	if !slices.Equal(got, want) {
		t.Errorf("unexamined %v, want %v", got, want)
	}
}

func TestInjectionComposite(t *testing.T) {
	rep, in := injection(t, map[string]string{"act/action.yml": `runs:
  using: composite
  steps:
    - run: echo "${{ github.event.pull_request.title }}"
      shell: bash
`})
	if got := at(t, rep, in); !slices.Equal(got, []string{"act/action.yml github.event.pull_request.title"}) {
		t.Errorf("findings at %v", got)
	}
}

func TestInjectionRegistry(t *testing.T) {
	reg, err := lint.NewRegistry(All())
	if err != nil {
		t.Fatal(err)
	}
	m, ok := reg.Meta(CodeInjectionID)
	if !ok || m.Severity() != lint.SeverityCritical {
		t.Errorf("Meta = %+v, %v", m, ok)
	}
}

// wikiFact answers repo.wiki-open with a value, and every other fact Unknown.
type wikiFact bool

func (w wikiFact) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	if _, ok := q.(facts.RepoWikiOpen); ok {
		if w {
			return facts.RawAnswer{State: facts.StateFound, Value: []byte("true")}
		}
		return facts.RawAnswer{State: facts.StateFound, Value: []byte("false")}
	}
	return facts.RawAnswer{State: facts.StateUnknown, Reason: "not asked"}
}

func TestInjectionGollum(t *testing.T) {
	const gollum = `on: gollum
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ github.event.pages[0].title }}"
          echo "${{ github.event.pages[0].page_name }}"
          echo "${{ github.event.pages[0].sha }} ${{ github.event.pages[0].action }}"
`
	want := []string{
		".github/workflows/w.yml github.event.pages[0].page_name",
		".github/workflows/w.yml github.event.pages[0].title",
	}
	for _, c := range []struct {
		name      string
		r         facts.Resolver
		certainty lint.Certainty
		assumed   bool
		none      bool
	}{
		{"assumed", facts.Assumptions(), lint.CertaintyConfirmed, true, false},
		{"not known", nil, lint.CertaintyConditional, false, false},
		{"open", wikiFact(true), lint.CertaintyConfirmed, false, false},
		{"closed", wikiFact(false), 0, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep, in, _ := checkRules(t, []lint.Rule{CodeInjection}, wfFile(gollum), c.r)
			if c.none {
				if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
					t.Fatalf("findings where no one but collaborators edits the wiki: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
				}
				return
			}
			if got := at(t, rep, in); !slices.Equal(got, want) {
				t.Fatalf("findings at\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
			for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
				if f.Certainty != c.certainty || f.Condition == nil || !strings.Contains(f.Detected(), "gollum") || f.Args.KindID() != (CodeInjectionWiki{}).KindID() {
					t.Errorf("%+v: want %v, with the condition of repo.wiki-open, and of the kind code-injection.wiki", f, c.certainty)
				}
			}
			if len(rep.Facts) != 1 || rep.Facts[0].RawAnswer.Assumed() != c.assumed {
				t.Errorf("facts %+v, want repo.wiki-open, assumed %v", rep.Facts, c.assumed)
			}
			// the report with an assumed fact is what report-v0.json says
			b, err := rep.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			if err := schemaSet(t).Validate("report-v0.json", "#", b); err != nil {
				t.Errorf("the report does not fit report-v0.json: %v\n%s", err, b)
			}
		})
	}
	// another attacker's event keeps a finding whole
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection}, wfFile(`on: [gollum, issues]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
`), nil)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Condition != nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Certainty != lint.CertaintyConfirmed {
		t.Errorf("issue.title on gollum and issues: %+v, want one finding with no condition", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	// the job does not run on gollum
	rep, _, _ = checkRules(t, []lint.Rule{CodeInjection}, wfFile(`on: [gollum, issues]
jobs:
  j:
    if: github.event_name != 'gollum'
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pages[0].title }}"
`), facts.Assumptions())
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
		t.Errorf("a job that is not run on gollum: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	// a reusable workflow runs on whatever calls it, gollum too
	rep, _, _ = checkRules(t, []lint.Rule{CodeInjection}, wfFile(`on: workflow_call
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pages[0].title }} ${{ github.event.issue.title }}"
`), nil)
	var conds []bool
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		conds = append(conds, f.Condition != nil)
	}
	if !slices.Equal(conds, []bool{true, false}) {
		t.Errorf("workflow_call: conditions %v, want pages conditional and issue.title not", conds)
	}
}

// In one step, what
// only gollum controls is code-injection.wiki, and what issues controls
// is code-injection.controlled.
func TestInjectionKinds(t *testing.T) {
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection}, wfFile(`on: [gollum, issues]
jobs:
  w:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pages[0].title }}" "${{ github.event.issue.title }}"
`), facts.Assumptions())
	got := map[string]lint.FindingKindID{}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		switch a := f.Args.(type) {
		case CodeInjectionWiki:
			got[a.ExprRef] = a.KindID()
		case CodeInjectionControlled:
			got[a.ExprRef] = a.KindID()
		}
	}
	want := map[string]lint.FindingKindID{
		"github.event.pages[0].title": kindCodeInjectionWiki,
		"github.event.issue.title":    kindCodeInjectionControlled,
	}
	if !maps.Equal(got, want) {
		t.Errorf("kinds %v, want %v", got, want)
	}
}

// The incident code-injection cites (GHSA-7x29-qqmq-v6qc): the composite
// action ultralytics/actions af42cbd wrote github.head_ref and
// github.event.pull_request.head.ref into run. The rule reports them, and its
// fix keeps what a plain branch name prints and stops a command in one (the
// form is written out here, not copied). The form is also the example
// examples/true-positive/code-injection/controlled.ghsa-7x29-qqmq-v6qc.action.yml;
// this test holds the fix.
func TestInjectionUltralytics(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	const src = `name: actions
description: the form of ultralytics/actions af42cbd
runs:
  using: composite
  steps:
    - name: Print
      run: |
        echo "github.event.pull_request.head.ref: ${{ github.event.pull_request.head.ref }}"
        echo "github.head_ref: ${{ github.head_ref }}"
      shell: bash
`
	files := map[string]string{"action.yml": src}
	rep, in, reg := checkRules(t, []lint.Rule{CodeInjection}, files, nil)
	var refs []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		refs = append(refs, strings.SplitN(f.Detected(), " ", 2)[0])
		if f.Certainty != lint.CertaintyConfirmed || f.Fix == nil {
			t.Errorf("%s: want a confirmed finding with a fix", f.Detected())
		}
	}
	if want := []string{"github.event.pull_request.head.ref", "github.head_ref"}; !slices.Equal(refs, want) {
		t.Fatalf("findings %v, want %v", refs, want)
	}
	applied, err := lint.ApplyFixes(context.Background(), in, reg, nil, rep, lint.SafetyReview)
	if err != nil {
		t.Fatal(err)
	}
	out := applied.Files
	fixed := string(out[facts.MustCleanInputPath("action.yml")])
	env := map[string]string{} // the new variables of the step: their expressions
	for _, m := range regexp.MustCompile(`(?m)^\s+([A-Z_0-9]+): \$\{\{ (.*) \}\}$`).FindAllStringSubmatch(fixed, -1) {
		env[m[1]] = m[2]
	}
	run := func(script string, vals, vars map[string]string) string {
		script = regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`).ReplaceAllStringFunc(script, func(e string) string {
			return vals[strings.TrimSpace(e[3:len(e)-2])]
		})
		cmd := exec.Command(bash, "-e", "-c", script)
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		for k, v := range vars {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		b, _ := cmd.Output()
		return string(b)
	}
	before, after := runScripts([]byte(src), lint.InputKindActionMetadata)["runs step 0"], runScripts([]byte(fixed), lint.InputKindActionMetadata)["runs step 0"]
	for _, c := range []struct {
		v      string
		attack bool
	}{{"feature-x", false}, {`x";echo INJECTED;#`, true}} {
		vals := map[string]string{"github.event.pull_request.head.ref": c.v, "github.head_ref": c.v}
		vars := map[string]string{}
		for k, e := range env {
			vars[k] = vals[e]
		}
		b, a := run(before, vals, nil), run(after, vals, vars)
		switch {
		case !c.attack && a != b:
			t.Errorf("a plain branch name: before %q, after %q", b, a)
		case c.attack && (!strings.Contains(b, "INJECTED\n") || strings.Contains(a, "INJECTED\n")):
			t.Errorf("an attack: before %q, after %q", b, a)
		}
	}
}

// TestInjectionActivityTypes: the activity types of types are read as
// GitHub reads them.
func TestInjectionActivityTypes(t *testing.T) {
	for _, c := range []struct {
		on   string
		want int
	}{
		{"{issues: {types: [field_added]}}", 1},
		{"{issues: {types: [opened, foo]}}", 1},
		{"{issues: {types: [foo]}}", 0},
		{"{issues: {types: [Opened]}}", 0},
		{"{pull_request_target: {types: [stacked]}}", 0},
		{"{pull_request_target: {types: [opened, stacked]}}", 1},
		{"issues", 1},
	} {
		rep, _ := injection(t, wfFile("on: "+c.on+"\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.issue.title }}${{ github.event.pull_request.title }}\"\n"))
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != c.want {
			t.Errorf("on %s: %d findings, want %d: %+v", c.on, len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), c.want, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			continue
		}
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			if m := f.Detected(); strings.Contains(m, "pull_request_target") && strings.Contains(c.on, "issues") {
				t.Errorf("on %s: %s", c.on, m)
			}
		}
	}
}

// TestCodeInjectionEnvVariable: a variable of env that a run of bash reads
// as code, with no fix; on gollum alone, the kind of the wiki and its
// condition; a variable read as data, none; a value of env the rule does
// not analyze, inconclusive.
func TestCodeInjectionEnvVariable(t *testing.T) {
	step := func(on, env, run string) string {
		return "on: " + on + "\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - id: s\n        run: echo\n      - env:\n          ISSUE_TITLE: " + env + "\n        run: " + run + "\n"
	}
	rep, in := injection(t, wfFile(step("issues", "${{ github.event.issue.title }}", `eval "echo $ISSUE_TITLE"`)))
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("findings: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
	a, ok := f.Args.(CodeInjectionEnvVariable)
	if !ok || a.Variable != "$ISSUE_TITLE" || a.ExprRef != "github.event.issue.title" || a.CodeReading.Arg() != "code-argument" || !slices.Contains(a.ControlledOn, workflow.EventNameIssues) {
		t.Errorf("args %#v", f.Args)
	}
	i, _ := in.Lookup(f.Location.File.Input)
	if got := string(i.Tree.Bytes()[f.Location.Span.Start:f.Location.Span.End]); got != "$ISSUE_TITLE" || f.Fix != nil || f.NoFix != nil || len(f.Evidence) == 0 {
		t.Errorf("at %q, fix %v, no fix %v, evidence %v", got, f.Fix, f.NoFix, f.Evidence)
	}

	rep, _ = injection(t, wfFile(step("gollum", "${{ github.event.pages[0].title }}", `eval "echo $ISSUE_TITLE"`)))
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID() != (CodeInjectionEnvVariableWiki{}).KindID() || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Condition == nil {
		t.Errorf("gollum: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}

	rep, _ = injection(t, wfFile(step("issues", "${{ github.event.issue.title }}", `echo "$ISSUE_TITLE"`)))
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 || len(rep.FindingsWith(lint.CertaintyInconclusive)) != 0 {
		t.Errorf("data: %+v %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
	}

	rep, _ = injection(t, wfFile(step("issues", "${{ steps.s.outputs.y }}", `eval "$ISSUE_TITLE"`)))
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 || len(rep.FindingsWith(lint.CertaintyInconclusive)) != 1 || rep.FindingsWith(lint.CertaintyInconclusive)[0].InconclusiveKind.String() != "step-output-run" || !strings.Contains(rep.FindingsWith(lint.CertaintyInconclusive)[0].Note, "$ISSUE_TITLE") {
		t.Errorf("inconclusive: %+v %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
	}
}

// TestRadwareCases are the two workflows that Radware's report of 2026-10
// ("Inside a GitHub Supply Chain Attack Campaign") shows a title ran a
// command in, reduced. Snouzy/workout-cool writes the issue's title into run
// by ${{ }} on issues (also the example controlled.workout-cool);
// PX4/PX4-Autopilot writes the pull request's title into run on
// pull_request, the undetected form pull-request
// (https://github.com/PX4/PX4-Autopilot/blob/da414713fc7da42796bf1e767f44f6de8122cc67/.github/workflows/commit_checks.yml,
// line 34).
func TestRadwareCases(t *testing.T) {
	rep, _ := injection(t, wfFile(`on:
  issues:
    types: [opened, reopened, closed]
jobs:
  Discord:
    runs-on: ubuntu-latest
    steps:
      - run: |
          ISSUE_TITLE="${{ github.event.issue.title }}"
          echo "$ISSUE_TITLE"
`))
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID() != (CodeInjectionControlled{}).KindID() {
		t.Errorf("workout-cool: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	rep, _ = injection(t, wfFile(`on:
  pull_request:
    types: [opened, edited, synchronize, reopened]
jobs:
  pr-title:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - run: |
          python3 Tools/ci/check_pr_title.py "${{ github.event.pull_request.title }}" --markdown-file comment.md && rc=0 || rc=$?
`))
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
		t.Errorf("PX4: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestInjectionCoproc: coproc runs the command after it, and after its name;
// moving the expression to env does not stop the value from naming what runs.
func TestInjectionCoproc(t *testing.T) {
	for _, run := range []string{
		`coproc ${{ github.event.issue.title }}`,
		`coproc N { ${{ github.event.issue.title }}; }`,
	} {
		rep, _ := injection(t, wfFile("on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: "+run+"\n"))
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
			t.Fatalf("%s: findings %+v", run, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
		}
		f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
		if f.Fix != nil || f.NoFix == nil || !strings.Contains(f.NoFix.Note, "the command word") {
			t.Errorf("%s: fix %+v, no fix %+v; want no fix, as at the command word", run, f.Fix, f.NoFix)
		}
	}
}
