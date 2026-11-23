package taint

import (
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// writtenLines are the lines of analyze for run: echo "${{ x }}" in a job
// of on, without the sink's kind.
func writtenLines(t *testing.T, on, x string) []string {
	t.Helper()
	src := "on: " + on + "\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ " + x + " }}\"\n"
	var out []string
	for _, l := range analyze(t, src, false) {
		out = append(out, strings.TrimPrefix(l, "run "))
	}
	return out
}

// TestAnalyzeWrittenForm: what a ${{ }} writes of a reference, by the
// runner's functions and operators.
func TestAnalyzeWrittenForm(t *testing.T) {
	for _, c := range []struct {
		on, x string
		want  []string
	}{
		// Object or Array, or nothing an attacker writes
		{"push", "github.event.commits.*.message", []string{"github.event.commits.*.message NotControlled"}},
		{"push", "github.event.head_commit", []string{"github.event.head_commit NotControlled"}},
		{"push", "github.event.commits", []string{"github.event.commits NotControlled"}},
		{"push", "github.event", []string{"github.event NotControlled"}},
		{"push", "github", []string{"github NotControlled"}},
		{"push", "github.event.head_commit.message && 'x'", nil},
		{"push", "format('{0}', 'a', github.event.head_commit.message)", nil},
		{"push", "format('{0:x}', 'a', github.event.head_commit.message)", nil},
		{"push", "join(github.event.commits.*, ' ')", []string{"github.event.commits.* NotControlled"}},
		{"push", "github.event.commits.*.message || 'x'", []string{"github.event.commits.*.message NotControlled"}},
		{"push", "case(github.event.head_commit.message == 'x', 'a', 'b')", nil},
		{"push", "join(github.event.commits.*.added)", []string{"github.event.commits.*.added NotControlled"}},
		{"push", "toJSON(github.event.head_commit.message).x", nil},
		{"push", "join(github.event.commits.*.message).x", nil},
		{"push", "fromJSON(github.event.head_commit.message).*", nil},
		{"push", "join(fromJSON(github.event.head_commit.message).*)", []string{"github.event.head_commit.message Controlled push"}},
		{"push", "steps.x.outputs", []string{"steps.x.outputs NotControlled"}},
		{"push", "steps", []string{"steps NotControlled"}},
		{"push", "env", []string{"env NotControlled"}},
		{"push", "steps.*.outputs.o", []string{"steps.*.outputs.o NotControlled"}},
		// what an attacker writes gets there
		{"push", "join(github.event.commits.*.message, ' ')", []string{"github.event.commits.*.message Controlled push"}},
		{"push", "(github.event.head_commit || github.event).message", []string{"github.event.head_commit Controlled push", "github.event NotControlled"}}, // the payload of push has no message
		{"push", "fromJSON(toJSON(github.event.commits.*))[0].message", []string{"github.event.commits.* Controlled push"}},
		{"push", "github.event.head_commit.message", []string{"github.event.head_commit.message Controlled push"}},
		{"push", "join(github.event.head_commit.added, ' ')", []string{"github.event.head_commit.added Controlled push"}},
		{"push", "join(github.event.commits.*.added.*)", []string{"github.event.commits.*.added.* Controlled push"}},
		{"push", "toJSON(github.event.head_commit)", []string{"github.event.head_commit Controlled push"}},
		{"push", "format('{0}', github.event.head_commit.message)", []string{"github.event.head_commit.message Controlled push"}},
		{"push", "format('{0001}', 'a', github.event.head_commit.message)", []string{"github.event.head_commit.message Controlled push"}},
		{"push", "case(true, github.event.head_commit.message, 'b')", []string{"github.event.head_commit.message Controlled push"}},
		{"push", "github.event.commits[0].message", []string{"github.event.commits[0].message Controlled push"}},
		{"push", "'x' && github.event.head_commit.message", []string{"github.event.head_commit.message Controlled push"}},
		// an item of the labels is an object or null; its name is a text
		{"{issues: {types: [opened]}}", "github.event.issue.labels[0]", []string{"github.event.issue.labels[0] NotControlled"}},
		{"{issues: {types: [opened]}}", "github.event.issue.labels[0].name", []string{"github.event.issue.labels[0].name Controlled issues"}},
		{"{issues: {types: [opened]}}", "join(github.event.issue.labels.*.name)", []string{"github.event.issue.labels.*.name Controlled issues"}},
		// the separator of join, a format string not known, case of an even number, && and || in a function
		{"push", "join('a', github.event.head_commit.message)", []string{"github.event.head_commit.message Controlled push"}},
		{"push", "format(github.event.head_commit.message, 'x')", []string{"github.event.head_commit.message Controlled push"}},
		{"push", "format(matrix.k, github.event.head_commit.message)", []string{"matrix.k NotControlled", "github.event.head_commit.message Controlled push"}},
		{"push", "case(true, github.event.head_commit.message)", []string{"github.event.head_commit.message Controlled push"}},
		{"push", "join(github.event.commits.* && github.event.head_commit.added)", []string{"github.event.head_commit.added Controlled push"}},
		{"push", "toJSON(github.event.head_commit.message && 'x')", nil},
		{"push", "toJSON(github.event.head_commit.message || 'x')", []string{"github.event.head_commit.message Controlled push"}},
		// a star and an index not known of a value that is not a reference
		{"push", "(github.event.head_commit || github.event).*", []string{"github.event.head_commit NotControlled", "github.event NotControlled"}},
		{"push", "(github.event.head_commit || github.event)[matrix.k]", []string{"github.event.head_commit Controlled push", "github.event Controlled push"}},
		// a function the parser refuses: all of it, as before
		{"push", "nope(github.event.head_commit)", []string{"github.event.head_commit Controlled push"}},
		// all of a context as text
		{"push", "needs", []string{"needs NotControlled"}},
		{"push", "inputs", []string{"inputs NotControlled"}},
		{"push", "matrix", []string{"matrix NotControlled"}},
		// join writes nothing of an object, of names or of free keys
		{"push", "join(github.event.head_commit.author)", []string{"github.event.head_commit.author NotControlled"}},
		{"{issue_comment: {types: [created]}}", "join(github.event.comment.performed_via_github_app.permissions)", []string{"github.event.comment.performed_via_github_app.permissions NotControlled"}},
		// a key not known of an object with names: maybe one the schema does not have
		{"{issue_comment: {types: [created]}}", "github.event[matrix.k]", []string{"github.event[matrix.k] Controlled issue_comment"}},
		// all of it, as before: no step before has an id, whose outputs the runner gives empty
		{"push", "toJSON(steps.*)", []string{"steps.* NotControlled"}},
	} {
		got := writtenLines(t, c.on, c.x)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s on %s: got %q, want %q", c.x, c.on, got, c.want)
		}
	}
}

// TestAnalyzeWrittenThrough: env, the with of a caller and the default of
// an input are read as text, as text, and as all of it.
func TestAnalyzeWrittenThrough(t *testing.T) {
	check(t, `on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      A: ${{ github.event.commits.*.message }}
      J: ${{ join(github.event.commits.*.message) }}
    steps:
      - run: echo "${{ env.A }}" "${{ env.J }}"
`, false,
		"run env.A NotControlled",
		"run env.J Controlled push via env")
}

// TestAnalyzeWrittenCallers: the with of a caller is read as text, and the
// default of an input as all of it, as before (its type is not checked).
func TestAnalyzeWrittenCallers(t *testing.T) {
	const called = "on:\n  workflow_call:\n    inputs:\n      x:\n        type: string\n      d:\n        type: string\n        default: ${{ github.event.commits.*.message }}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.x }}\" \"${{ inputs.d }}\"\n"
	const caller = "on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      x: ${{ github.event.commits.*.message }}\n"
	c := callersOf(t, true, [2]string{".github/workflows/called.yml", called}, [2]string{".github/workflows/ci.yml", caller})
	f, _ := c.Graph().File(inputName(".github/workflows/called.yml"))
	refs := AnalyzeIn(c, f.Node(), f.Workflow, f.Action, nil).Sinks[0].Refs
	if len(refs) != 2 || refs[0].Verdict != analysis.NotControlled || refs[1].Verdict != analysis.Controlled {
		t.Errorf("refs = %+v", refs)
	}
}

// TestArgumentsJoinHead: the first item of join starts its text, so an
// item may make an argument begin with -.
func TestArgumentsJoinHead(t *testing.T) {
	got := arguments(t, "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          F: ${{ join(github.event.head_commit.added, ' ') }}\n        run: tar -xf a.tar n \"$F\"\n", false)
	want := []string{"tar 4 Option $F github.event.head_commit.added head quoted"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestStepValuesWritten: a value picked of a step is read as text.
func TestStepValuesWritten(t *testing.T) {
	got := values(t, "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: a/b@v1\n        with:\n          prompt: ${{ github.event.commits.*.message }} ${{ join(github.event.commits.*.message) }}\n")
	want := []string{"github.event.commits.*.message NotControlled", "github.event.commits.*.message Controlled push"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestRefWrittenLeadingDash: the items of join carry the events on which an
// attacker can make one begin with - (the name of a file of a commit).
func TestRefWrittenLeadingDash(t *testing.T) {
	src := "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: git add ${{ join(github.event.head_commit.added, ' ') }}\n"
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	refs := Analyze(w, nil).Sinks[0].Refs
	if len(refs) != 1 || len(refs[0].LeadingDash) == 0 || len(refs[0].Lines) == 0 {
		t.Errorf("refs = %+v", refs)
	}
}

// TestCollectionParts: the ${{ }} whose value may be an object or an
// array, which the fix does not move to env.
func TestCollectionParts(t *testing.T) {
	for _, c := range []struct {
		on, x string
		want  bool
	}{
		{"push", "github.event.head_commit.message || github.event.commits.*.message", true},
		{"{issues: {types: [opened]}}", "github.event.issue.title || github.event.issue.milestone", true},
		{"push", "fromJSON(github.event.head_commit.message)", true},
		{"push", "fromJSON(github.event.head_commit.message).x", true},
		{"push", "fromJSON(github.event.head_commit.message).*", true},
		{"push", "github.event.head_commit.message || matrix.x", true},
		{"push", "github[github.event.head_commit.message]", true},
		{"push", "github.event.head_commit.nope", true}, // a key the schema does not have
		{"push", "github.event.head_commit.message && github.event.commits", true},
		{"push", "case(true, github.event.head_commit.message, github.event.commits)", true},
		{"push", "(github.event.head_commit || github.event)['message']", false},
		{"push", "github.event.head_commit.message", false},
		{"push", "join(github.event.commits.*.message)", false},
		{"push", "toJSON(github.event.head_commit)", false},
		{"push", "github.event.commits && github.event.head_commit.message", false},
		{"push", "format('{0}', github.event.commits)", false},
		{"push", "env.X", false},
		{"push", "github.event.commits[0].message", false},
		{"gollum", "github.event.pages[0].title", false},
		// a path some activity type of the event has: a text, not a key the schema does not have
		{"{workflow_run: {workflows: [ci]}}", "github.event.workflow_run.display_title", false},
		{"{issues: {types: [opened, edited]}}", "github.event.changes.title.from", false},
		// a value of any type: a value of a custom property of free keys
		{"{issues: {types: [transferred]}}", "github.event.changes.new_repository.custom_properties.env", true},
	} {
		src := "on: " + c.on + "\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ " + c.x + " }}\"\n"
		w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
		s := Analyze(w, nil).Sinks[0]
		if got := slices.Contains(s.CollectionParts, 1); got != c.want {
			t.Errorf("%s on %s: %v, want %v (parts %v)", c.x, c.on, got, c.want, s.CollectionParts)
		}
	}
}

// TestWritingOfLoginPrefixed: a value of the capability login-prefixed
// (the label of a pull request's head, the full name of a repository an
// attacker names) begins with a login, so it neither may begin with - nor
// is not known to; the full name of the repository the workflow runs in is
// fixed, and a URL is still not known to.
func TestWritingOfLoginPrefixed(t *testing.T) {
	prt, run := analysis.MustEventActivity(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened), analysis.MustEventActivity(workflow.EventNameWorkflowRun, workflow.ActivityTypeCompleted)
	for _, c := range []struct {
		e       analysis.EventActivity
		ref     string
		on, und bool
	}{
		{prt, "github.event.pull_request.head.label", true, false},
		{prt, "github.event.pull_request.head.repo.full_name", true, false},
		{prt, "github.event.pull_request.base.repo.full_name", false, false},
		{prt, "github.event.pull_request.head.repo.html_url", true, true},
		{run, "github.event.workflow_run.head_repository.full_name", true, false},
	} {
		w := writingOf(c.e, path(t, c.ref), true)
		if w.on != c.on || w.dash || w.dashUndecided != c.und || w.cmd != CommandWritingNone {
			t.Errorf("%v %s: %+v", c.e.Name(), c.ref, w)
		}
	}
}

// TestWritingOfArbitrary: an arbitrary value may begin with - unless it is
// a leaf of hyphenless (the title of a wiki page): an object, all of the
// event and github[x] still may. The summary of a wiki page is a value nobody
// writes.
func TestWritingOfArbitrary(t *testing.T) {
	issues, gollum := analysis.MustEventActivity(workflow.EventNameIssues, workflow.ActivityTypeOpened), analysis.MustEventActivity(workflow.EventNameGollum, workflow.ActivityTypeUnset)
	for _, c := range []struct {
		e         analysis.EventActivity
		ref       string
		text      bool
		dash, und bool
		cmd       CommandWriting
	}{
		{issues, "github.event.issue.title", true, true, false, CommandWritingWritten},
		{issues, "github.event.issue", false, true, false, CommandWritingWritten},
		{issues, "github.event", false, true, false, CommandWritingWritten},
		{issues, "github[x]", false, true, false, CommandWritingWritten},
		{gollum, "github.event.pages[0].title", true, false, false, CommandWritingNone},
		{gollum, "github.event.sender.email", true, true, false, CommandWritingWritten},
	} {
		w := writingOf(c.e, path(t, c.ref), c.text)
		if !w.on || w.dash != c.dash || w.dashUndecided != c.und || w.cmd != c.cmd {
			t.Errorf("%v %s: %+v", c.e.Name(), c.ref, w)
		}
	}
	if w := writingOf(gollum, path(t, "github.event.pages[0].summary"), true); w != (writing{}) {
		t.Errorf("the summary of a wiki page: %+v, want nothing written", w)
	}
	if w := writingOf(gollum, path(t, "github.event.pages[0].page_name"), true); w != (writing{on: true, dash: true, path: true, cmd: CommandWritingUndecided}) {
		t.Errorf("the name of a wiki page: %+v", w)
	}
}
