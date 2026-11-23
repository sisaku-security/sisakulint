package rules

import (
	"context"
	"encoding/json"
	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/ir"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

const (
	sha   = "11bd71901bbe5b1630ceea73d27597364c9af683"
	sha64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// refs answers git.ref-commit from a table by repo@ref, as the runner
// resolves refs, and counts what it is asked. A SHA in
// the table is found as the tag of the ref's name.
type refs struct {
	mu     sync.Mutex
	answer map[string]facts.RawAnswer
	asked  map[string]int
}

func (r *refs) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	g, ok := q.(facts.GitRefCommit)
	if !ok {
		return facts.RawAnswer{State: facts.StateUnknown, Reason: "not a ref"}
	}
	k := g.Repo.String() + "@" + g.Ref
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.asked == nil {
		r.asked = map[string]int{}
	}
	r.asked[k]++
	a, ok := r.answer[k]
	if !ok {
		return facts.RawAnswer{State: facts.StateUnknown, Reason: "not in the table"}
	}
	var sha string
	if a.State == facts.StateFound && json.Unmarshal(a.Value, &sha) == nil {
		b, _ := json.Marshal(map[string]string{"sha": sha, "ref": "refs/tags/" + g.Ref})
		a.Value = b
	}
	return a
}

func resolved(s string) facts.RawAnswer {
	b, _ := json.Marshal(s)
	return facts.RawAnswer{State: facts.StateFound, Value: b}
}

// check runs commit-sha on files and gives the report and the inputs.
func check(t *testing.T, files map[string]string, r facts.Resolver) (lint.Report, lint.Inputs, *lint.Registry) {
	t.Helper()
	return checkRules(t, []lint.Rule{CommitSHA}, files, r)
}

// checkRules runs rules on files.
func checkRules(t *testing.T, rules []lint.Rule, files map[string]string, r facts.Resolver) (lint.Report, lint.Inputs, *lint.Registry) {
	t.Helper()
	fsys := fstest.MapFS{}
	for n, s := range files {
		fsys[n] = &fstest.MapFile{Data: []byte(s)}
	}
	in, err := lint.Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := lint.NewRegistry(rules)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		r = &refs{}
	}
	rep := lint.Run(context.Background(), in, reg, r)
	for _, e := range rep.Errors {
		t.Errorf("internal error: %+v", e)
	}
	return rep, in, reg
}

// at is what each finding points at: input, then the bytes of At.
func at(t *testing.T, rep lint.Report, in lint.Inputs) []string {
	t.Helper()
	var out []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		i, st := in.Lookup(f.Location.File.Input)
		if st != lint.LookupFound {
			t.Fatalf("no input %s", f.Location.File.Input)
		}
		out = append(out, f.Location.File.Input.String()+" "+string(i.Tree.Bytes()[f.Location.Span.Start:f.Location.Span.End]))
	}
	slices.Sort(out)
	return out
}

const detection = `on: push
jobs:
  steps:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@` + sha + `
      - uses: actions/checkout@11BD71901BBE5B1630CEEA73D27597364C9AF683
      - uses: actions/checkout@11bd719
      - uses: owner/repo/sub/dir@v1
      - uses: owner/repo@` + sha64 + `
      - uses: ./local
      - uses: docker://alpine:3
      - uses: docker://alpine@sha256:` + sha64 + `
      - uses: ${{ 'folded/action@v2' }}
      - uses: ${{ 'folded/action@` + sha + `' }}
  call:
    uses: owner/repo/.github/workflows/r.yml@main
  pinned-call:
    uses: owner/repo/.github/workflows/r.yml@` + sha + `
  local-call:
    uses: ./.github/workflows/r.yml
`

const compositeAction = `runs:
  using: composite
  steps:
    - uses: inner/action@v2
    - uses: $/self
    - uses: ./workspace
`

func TestDetection(t *testing.T) {
	rep, in, _ := check(t, map[string]string{".github/workflows/w.yml": detection, "act/action.yml": compositeAction}, nil)
	want := []string{
		".github/workflows/w.yml " + sha64,
		".github/workflows/w.yml 11bd719",
		".github/workflows/w.yml main",
		".github/workflows/w.yml v1",
		".github/workflows/w.yml v2", // the folded string's ref, in the literal
		".github/workflows/w.yml v4",
		"act/action.yml v2",
	}
	if got := at(t, rep, in); !slices.Equal(got, want) {
		t.Errorf("findings at\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Severity != lint.SeverityHigh || f.Certainty != lint.CertaintyConfirmed || f.Condition != nil {
			t.Errorf("%+v: want a confirmed finding of high severity", f)
		}
	}
}

func TestDetectionThroughAnAlias(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: &u actions/checkout@v4\n      - uses: *u\n"
	rep, _, _ := check(t, map[string]string{".github/workflows/w.yml": src}, nil)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 2 || len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Location.Via)+len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[1].Location.Via) != 1 {
		t.Errorf("findings %+v; want the anchor's and the alias's, one through the alias", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// fixed applies the fixes of rep and gives the new bytes of w.yml.
func fixed(t *testing.T, src string, r facts.Resolver) (lint.Report, string) {
	t.Helper()
	rep, in, reg := check(t, map[string]string{".github/workflows/w.yml": src}, r)
	applied, err := lint.ApplyFixes(context.Background(), in, reg, r, rep, lint.SafetySafe)
	if err != nil {
		t.Fatal(err)
	}
	out := applied.Files
	return rep, string(out[facts.MustCleanInputPath(".github/workflows/w.yml")])
}

func step(uses string) string {
	return "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: " + uses + "\n"
}

func TestFix(t *testing.T) {
	r := &refs{answer: map[string]facts.RawAnswer{
		"actions/checkout@v4":  resolved(sha),
		"actions/checkout@V4":  resolved(sha),
		"owner/repo@v1":        resolved(sha),
		"owner/repo@main":      resolved(sha),
		"actions/checkout@abc": resolved(sha),
		"folded/action@v2":     resolved(sha),
	}}
	for _, c := range []struct{ name, src, want string }{
		{"a tag, with its name as a comment", step("actions/checkout@v4"), step("actions/checkout@" + sha + " # v4")},
		{"a subdirectory (#18)", step("owner/repo/sub@v1"), step("owner/repo/sub@" + sha + " # v1")},
		{"a comment there is kept", step("actions/checkout@v4 # keep me"), step("actions/checkout@" + sha + " # keep me")},
		{"quoted", step(`"actions/checkout@v4"`), step(`"actions/checkout@` + sha + `" # v4`)},
		// the escape is a whole character of the ref, so its bytes are the ref's
		{"an escape in the ref", step(`"actions/checkout@v\x34"`), step(`"actions/checkout@` + sha + `" # v4`)},
		{"a flow mapping: no room for a comment", "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - {uses: actions/checkout@v4, with: {a: 1}}\n",
			"on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - {uses: actions/checkout@" + sha + ", with: {a: 1}}\n"},
		{"CRLF", strings.ReplaceAll(step("actions/checkout@v4"), "\n", "\r\n"), strings.ReplaceAll(step("actions/checkout@"+sha+" # v4"), "\n", "\r\n")},
		{"a reusable workflow", "on: push\njobs:\n  a:\n    uses: owner/repo/.github/workflows/r.yml@main\n",
			"on: push\njobs:\n  a:\n    uses: owner/repo/.github/workflows/r.yml@" + sha + " # main\n"},
		{"folded: the ref in the literal", step("${{ 'folded/action@v2' }}"), step("${{ 'folded/action@" + sha + "' }} # v2")},
		{"through an alias, fixed once", "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: &u actions/checkout@v4\n      - uses: *u\n",
			"on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: &u actions/checkout@" + sha + " # v4\n      - uses: *u\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep, got := fixed(t, c.src, r)
			for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
				if f.Fix == nil || f.Fix.KindID != PinSHAID {
					t.Errorf("fix %+v", f.Fix)
				}
			}
			if got != c.want {
				t.Errorf("fixed =\n%q\nwant\n%q", got, c.want)
			}
		})
	}
}

func TestNoFix(t *testing.T) {
	r := &refs{answer: map[string]facts.RawAnswer{
		"gone/repo@v1":             {State: facts.StateAbsent},
		"actions/checkout@abc1234": {State: facts.StateAbsent},
	}}
	for _, c := range []struct {
		name, uses string
		reason     ir.NoFixReason
		note       string
	}{
		{"the ref is not there", "gone/repo@v1", ir.NoFixReasonManual, "not in the repository"},
		{"a shortened SHA", "actions/checkout@abc1234", ir.NoFixReasonManual, "shortened"},
		{"not known", "unknown/repo@v1", ir.NoFixReasonFact, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep, _, _ := check(t, map[string]string{".github/workflows/w.yml": step(c.uses)}, r)
			if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
				t.Fatalf("findings %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			}
			f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
			if f.NoFix == nil || f.NoFix.Reason != c.reason || !strings.Contains(f.NoFix.Note, c.note) || f.Fix != nil {
				t.Errorf("no fix %+v, fix %+v; want %v with a note of %q", f.NoFix, f.Fix, c.reason, c.note)
			}
			if c.reason == ir.NoFixReasonFact && (len(f.NoFix.Queries) != 1 || f.NoFix.Queries[0].Kind() != facts.KindGitRefCommit) {
				t.Errorf("facts %v", f.NoFix.Queries)
			}
			// what to do is the resolver's to say, in its reason: the rule
			// does not know the flags of the command
			if c.reason == ir.NoFixReasonFact && (!strings.HasPrefix(f.NoFix.Note, "the commit of the ref is not known (") || !strings.HasSuffix(f.NoFix.Note, ")")) {
				t.Errorf("note %q, want the reason of the resolver and no more", f.NoFix.Note)
			}
		})
	}
}

// TestHexRefHasNoComment: a shortened SHA that is a tag's name is fixed
// without a comment, since the hex digits say nothing of a version.
func TestHexRefHasNoComment(t *testing.T) {
	r := &refs{answer: map[string]facts.RawAnswer{"actions/checkout@abc1234": resolved(sha)}}
	_, got := fixed(t, step("actions/checkout@abc1234"), r)
	if want := step("actions/checkout@" + sha); got != want {
		t.Errorf("fixed = %q, want %q", got, want)
	}
}

// TestOneQuestionPerFact: one fact is asked once; the
// case of a repository does not make another fact, the case of a ref does.
func TestOneQuestionPerFact(t *testing.T) {
	r := &refs{answer: map[string]facts.RawAnswer{"actions/checkout@v4": resolved(sha), "actions/checkout@V4": resolved(sha)}}
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n" +
		"      - uses: actions/checkout@v4\n      - uses: Actions/Checkout@v4\n      - uses: actions/checkout/sub@v4\n      - uses: actions/checkout@V4\n"
	check(t, map[string]string{".github/workflows/w.yml": src}, r)
	if r.asked["actions/checkout@v4"] != 1 || r.asked["actions/checkout@V4"] != 1 || len(r.asked) != 2 {
		t.Errorf("asked %v", r.asked)
	}
}

func TestRegistry(t *testing.T) {
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := reg.Meta(CommitSHAID)
	if !ok || m.Severity() != lint.SeverityHigh {
		t.Errorf("Meta = %+v, %v", m, ok)
	}
	if got := m.FindingKinds[0].CVSS.Vector(); got != "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:L/SC:H/SI:H/SA:N" {
		t.Errorf("vector %s", got)
	}
	b, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"docs/research", "docs/superpowers", "docs/backlog"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("the registry refers to %s, which is not there when the package is taken out", bad)
		}
	}
}

// TestFoldedWithAnEscapedQuote: a literal with a doubled single quote is not the value's bytes
// one for one, so the model gives no pieces and the rule says nothing: a
// false negative, of a ref with a quote in it only (a name of a GitHub
// owner or repository has none).
func TestFoldedWithAnEscapedQuote(t *testing.T) {
	rep, _, _ := check(t, map[string]string{".github/workflows/w.yml": step("${{ 'a/b@it''s' }}")}, nil)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
		t.Errorf("findings %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestDuplicateStepIDs: GitHub refuses two steps
// with one id, but the input is the attacker's, so the two findings must
// still be two, each with its fix, and no internal error.
func TestDuplicateStepIDs(t *testing.T) {
	r := &refs{answer: map[string]facts.RawAnswer{"a/b@v1": resolved(sha), "a/b@v2": resolved(sha)}}
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - id: s\n        uses: a/b@v1\n      - id: s\n        uses: a/b@v2\n"
	rep, _, _ := check(t, map[string]string{".github/workflows/w.yml": src}, r)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 2 {
		t.Fatalf("findings %d, want 2", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Fix == nil {
			t.Errorf("%s: fix %+v, no fix %+v", f.Detected(), f.Fix, f.NoFix)
		}
	}
}

// TestDetectedAsWritten: the args and what is detected, as written: capitals, and
// & with no escape.
func TestDetectedAsWritten(t *testing.T) {
	a := CommitSHAUnpinned{Uses: "Actions/Checkout@v1&2", Repo: "Actions/Checkout", Ref: "v1&2"}
	if got, want := a.Detected(), "Actions/Checkout@v1&2 is not pinned to a full commit SHA"; got != want {
		t.Errorf("Detected = %q, want %q", got, want)
	}
}

func TestArgsNoHTMLEscape(t *testing.T) {
	b, err := CommitSHAUnpinned{Uses: "a/b@v1&2", Repo: "a/b", Ref: "v1&2"}.MarshalJSON()
	if err != nil || string(b) != `{"kind_id":"commit-sha.unpinned","uses":"a/b@v1&2","repo":"a/b","ref":"v1&2"}` {
		t.Errorf("MarshalJSON = %s, %v", b, err)
	}
}

// An array argument left nil is written as [], as the schema says.
func TestArgsEmptyArray(t *testing.T) {
	b, err := CodeInjectionControlled{ExprRef: "r", SinkKind: analysis.SinkRun}.MarshalJSON()
	if err != nil || string(b) != `{"kind_id":"code-injection.controlled","expr_ref":"r","sink_kind":"run","controlled_on":[]}` {
		t.Errorf("MarshalJSON = %s, %v", b, err)
	}
}

// TestCommitSHAAgentkit: coinbase/agentkit
// 5e01c2d99b2077e6748342d0ca7a73ac198ce3ce .github/workflows/changelog.yml
// (lines 1-11 and 26-32), which ran the malicious commit a moved tag of
// tj-actions/changed-files pointed to on 2025-03-14 (Unit 42): commit-sha
// reports the ref, and its kind cites the incident.
func TestCommitSHAAgentkit(t *testing.T) {
	const src = `name: Changelog

on: [pull_request]

jobs:
  check-changelog-python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Check for modified Python files in coinbase-agentkit
        if: steps.check-label.outputs.skip != 'true'
        id: changed-agent-files
        uses: tj-actions/changed-files@v39
        with:
          files: |
            python/coinbase-agentkit/**/*.py
`
	rep, _, _ := check(t, wfFile(src), nil)
	var refs []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		refs = append(refs, f.Args.(CommitSHAUnpinned).Uses)
	}
	if !slices.Contains(refs, "tj-actions/changed-files@v39") {
		t.Errorf("no finding of tj-actions/changed-files@v39: %v", refs)
	}
	if !slices.Contains(commitSHAMeta.FindingKinds[0].Incidents, agentkit2025) {
		t.Errorf("the kind does not cite %s: %v", agentkit2025, commitSHAMeta.FindingKinds[0].Incidents)
	}
}

// TestCommitSHAOutside: a uses whose path goes above the root of its
// repository runs the action of the directory the path names: the rule
// reads the uses that downloads it, else the ref the path names.
func TestCommitSHAOutside(t *testing.T) {
	steps := func(uses ...string) map[string]string {
		src := "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
		for _, u := range uses {
			src += "      - uses: " + u + "\n"
		}
		return wfFile(src)
	}
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  []string // what each finding points at
		noFix bool
	}{
		{"s11", steps("o/r/acts/b@probe/obfuscation", "o/r/../probe/obfuscation/acts/b@"+sha), []string{".github/workflows/w.yml probe/obfuscation"}, false},
		{"e4", steps("o/r/acts/comp@"+sha, "o/r/../../../actions/github-script/v7@"+sha), []string{".github/workflows/w.yml ../../../actions/github-script/v7"}, true},
		{"pinned in the path", steps("o/r/acts/comp@"+sha, "o/r/../../../actions/github-script/"+sha+"@"+sha), nil, false},
		{"out of _actions", steps("o/r/../../../../x/y/z@" + sha), nil, false},
	} {
		rep, in, _ := check(t, tc.files, nil)
		if got := at(t, rep, in); !slices.Equal(got, tc.want) {
			t.Errorf("%s: findings at %q, want %q", tc.name, got, tc.want)
			continue
		}
		if tc.noFix && (rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix != nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID() != kindCommitSHAUnpinnedPathAction) {
			t.Errorf("%s: fix %v, kind %v", tc.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID())
		}
	}
}

// TestCommitSHAReadByOutside: a pin of a uses whose directory another uses
// goes into with .. would leave that uses with no action, so the rule
// gives no fix there (a fix that makes a new finding).
func TestCommitSHAReadByOutside(t *testing.T) {
	files := wfFile("on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: o/r/../../../actions/checkout/v4@" + sha + "\n")
	rep, _, _ := check(t, files, &refs{answer: map[string]facts.RawAnswer{"actions/checkout@v4": resolved(sha)}})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix != nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].NoFix == nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].NoFix.Reason != ir.NoFixReasonManual {
		t.Errorf("findings %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestCommitSHAOutsideReadByOutside: a uses above the root whose own
// directory another uses above the root goes into: the written ref of the
// first decides the code of the second. One uses
// has one finding: the action that runs, when it is not pinned either.
func TestCommitSHAOutsideReadByOutside(t *testing.T) {
	for _, tc := range []struct {
		first string
		want  string
	}{
		{"o/r/../../../actions/checkout/" + sha + "@main", "main"},
		{"o/r/../../../actions/checkout/v4@main", "../../../actions/checkout/v4"},
	} {
		files := wfFile("on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + tc.first + "\n      - uses: o/r/../main/evil@" + sha + "\n")
		rep, in, _ := check(t, files, nil)
		if got := at(t, rep, in); !slices.Equal(got, []string{".github/workflows/w.yml " + tc.want}) {
			t.Errorf("%s: findings at %q", tc.first, got)
		}
	}
}
