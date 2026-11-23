package ir

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"
)

// TestUses: the uses of other repositories, in order, a folded one among
// them; not a local action or a Docker image.
func TestUses(t *testing.T) {
	type row struct {
		repo, ref string
		place     UsesLevel
		path      string
	}
	var got []row
	for _, u := range ImpostorCommitView.Reader(newIR(t, usesWorkflow).RuleAccess()).Uses() {
		got = append(got, row{u.Repo(), u.Ref(), u.Level(), u.Key().Path()})
	}
	want := []row{
		{"o/r", "v1", UsesInJob, "jobs.call.uses"},
		{"actions/checkout", "v4", UsesInStep, "jobs.build.steps[0].uses"},
		{"o/folded", "v2", UsesInStep, "jobs.build.steps[3].uses"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %v, want %v", i, got[i], want[i])
		}
	}
}

// TestUsesOfCompositeAction: the steps of a composite action.yml have
// summaries too.
func TestUsesOfCompositeAction(t *testing.T) {
	tree, a := parseAction(t, "runs:\n  using: composite\n  steps:\n    - uses: o/a@main\n")
	us := CommitSHAView.Reader(New("action.yml", tree, nil, a).RuleAccess()).Uses()
	if len(us) != 1 || us[0].Repo() != "o/a" {
		t.Fatalf("got %d", len(us))
	}
}

// TestUsesEditElsewhere: an edit of another line keeps the fields of a
// summary.
func TestUsesEditElsewhere(t *testing.T) {
	a := newIR(t, usesWorkflow).allUses()
	b := newIR(t, "# a comment\n"+usesWorkflow).allUses()
	for i := range a {
		if d := a[i].diff(b[i]); len(d) != 0 {
			t.Errorf("%s: %v", a[i].key, d)
		}
	}
}

// TestUsesExact: whether the ref of a uses is written as it reads is a
// field (uses.exact), the exactness of the handle on the ref, so that a
// change of it is a change of a summary. No spelling of a ref was found
// that is not exact (escapes, folds, line breaks were tried), so the test
// holds the field to
// the handle, on escapes among them. \x34 is a YAML escape of 4.
func TestUsesExact(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    steps:\n      - uses: o/plain@v1\n      - uses: \"o/escaped@v\\x34\"\n      - uses: \"o/broken@\\\n          v4\"\n"
	us := CommitSHAView.Reader(newIR(t, src).RuleAccess()).Uses()
	if len(us) != 3 {
		t.Fatalf("uses %d", len(us))
	}
	for _, u := range us {
		if u.Exact() != u.RefAt().exact {
			t.Errorf("%s: exact %v, the handle %v", u.Key(), u.Exact(), u.RefAt().exact)
		}
	}
}

// TestUsesPath: the path of the action or the reusable workflow after
// owner/repo/, which known-vulnerable-actions names a package by.
func TestUsesPath(t *testing.T) {
	var got []string
	for _, u := range KnownVulnerableActionsView.Reader(newIR(t, usesWorkflow).RuleAccess()).Uses() {
		got = append(got, u.Repo()+"|"+u.Path())
	}
	if strings.Join(got, " ") != "o/r|.github/workflows/w.yml actions/checkout| o/folded|" {
		t.Errorf("got %v", got)
	}
}

// TestSetCommentAtEnd: the comment at the end of the line of a uses
// becomes the text, written where there is none and replacing the one
// there is.
func TestSetCommentAtEnd(t *testing.T) {
	const src = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: o/a@v1 # v1.0.0\n      - uses: o/b@v1\n"
	x := newIR(t, src)
	us := KnownVulnerableActionsView.Reader(x.RuleAccess()).Uses()
	var edits []edit.Edit
	for _, u := range us {
		e, ok := u.RefAt().SetCommentAtEnd("v1.0.1")
		if !ok {
			t.Fatalf("%s: no edit", u.UsesText())
		}
		edits = append(edits, e)
	}
	res, err := edit.Apply(x.tree, edits)
	if err != nil {
		t.Fatal(err)
	}
	want := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: o/a@v1 # v1.0.1\n      - uses: o/b@v1 # v1.0.1\n"
	if got := string(res.Tree.Bytes()); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

// TestUsesLineComment: the text of the comment at the end of the line of a
// uses, which Renovate reads as the version of a pinned SHA; none in a
// quoted value, and the uses of jobs and of composite actions have it too.
func TestUsesLineComment(t *testing.T) {
	const src = "on: push\njobs:\n  call:\n    uses: o/r/.github/workflows/w.yml@v1 # v1.2.0\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      - uses: o/a@v1 # v1.2.3\n" +
		"      - uses: o/b@0123456789abcdef0123456789abcdef01234567 #v4\n" +
		"      - uses: o/c@v1\n" +
		"      - uses: \"o/d@v1 # x\"\n" +
		"      - uses: o/e@v1  # tag=v1 \n" +
		"      - uses: o/f@v1 #\n" +
		"      - uses: o/g@v1\t# v1.0.0\n"
	var got []string
	for _, u := range DependabotGitHubActionsView.Reader(newIR(t, src).RuleAccess()).Uses() {
		got = append(got, u.Repo()+"="+u.LineComment())
	}
	if want := "o/r=v1.2.0 o/a=v1.2.3 o/b=v4 o/c= o/d= o/e=tag=v1 o/f= o/g="; strings.Join(got, " ") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(got, " "), want)
	}
	tree, a := parseAction(t, "runs:\n  using: composite\n  steps:\n    - uses: o/a@v1 # v1.0.0\n")
	us := DependabotGitHubActionsView.Reader(New("action.yml", tree, nil, a).RuleAccess()).Uses()
	if len(us) != 1 || us[0].LineComment() != "v1.0.0" {
		t.Errorf("composite: %v", us)
	}
}

// TestUsesFolded: a uses folded from a ${{ }} literal says so.
func TestUsesFolded(t *testing.T) {
	var got []string
	for _, u := range DependabotGitHubActionsView.Reader(newIR(t, usesWorkflow).RuleAccess()).Uses() {
		if u.Folded() {
			got = append(got, u.Repo())
		}
	}
	if strings.Join(got, " ") != "o/folded" {
		t.Errorf("got %v", got)
	}
}

// TestUsesRunUses: each reading of the action that runs, written as
// owner/repo[/path]@ref with the path as the runner reads it (empty parts
// and . dropped), which action-list matches against its patterns; none for
// a path above the directory of actions.
func TestUsesRunUses(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    steps:\n      - uses: evil//act/.@v1\n      - uses: o/r/sub@v2\n      - uses: gradle/actions/../../docker/x@v1\n      - uses: o/r/../../../../x@v1\n"
	us := ActionListView.Reader(newIR(t, src).RuleAccess()).Uses()
	want := [][]string{{"evil/act@v1"}, {"o/r/sub@v2"}, {"gradle/docker@x"}, nil}
	if len(us) != len(want) {
		t.Fatalf("uses %d", len(us))
	}
	for i, u := range us {
		if got := u.RunUses(); strings.Join(got, " ") != strings.Join(want[i], " ") {
			t.Errorf("%s: %q, want %q", u.Key(), got, want[i])
		}
	}
}
