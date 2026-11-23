package composite

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// answers is a resolver of action.definition from a map; it counts the
// questions.
type answers struct {
	m     map[facts.Query]facts.RawAnswer
	asked map[facts.Query]int
}

func (a *answers) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	a.asked[q]++
	if r, ok := a.m[q]; ok {
		return r
	}
	return facts.RawAnswer{State: facts.StateUnknown, Reason: "nothing to ask"}
}

func newAnswers() *answers {
	return &answers{m: map[facts.Query]facts.RawAnswer{}, asked: map[facts.Query]int{}}
}

func sha(t *testing.T, c byte) facts.SHA {
	t.Helper()
	s, err := facts.ParseSHA(strings.Repeat(string(c), 40))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func query(t *testing.T, repo, path, ref string) facts.ActionDefinition {
	t.Helper()
	r, err := facts.ParseRepo(repo)
	if err != nil {
		t.Fatal(err)
	}
	q := facts.ActionDefinition{Repo: r, Ref: ref}
	if path != "" {
		if q.Path, err = facts.ParseUsesPath(path); err != nil {
			t.Fatal(err)
		}
	}
	return q
}

// define makes the answer of repo/path@ref the action.yml content at
// the commit of c.
func (a *answers) define(t *testing.T, repo, path, ref string, c byte, content string) facts.ActionDefinition {
	t.Helper()
	q := query(t, repo, path, ref)
	b, err := json.Marshal(facts.ActionFile{Commit: sha(t, c), File: facts.ActionFileYML, Content: content})
	if err != nil {
		t.Fatal(err)
	}
	a.m[q] = facts.RawAnswer{State: facts.StateFound, Value: b, Source: facts.SourceGitHub}
	return q
}

func composite(steps ...string) string {
	return "runs:\n  using: composite\n  steps:\n" + strings.Join(steps, "")
}

func usesStep(u string) string { return "    - uses: " + u + "\n" }

const runStep = "    - run: echo hi\n      shell: bash\n"

// step is the first step of the first job of a workflow whose step is s.
func step(t *testing.T, s string) *workflow.Step {
	t.Helper()
	w, _ := workflow.Parse(cst.Parse([]byte("on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - " + s + "\n")))
	if w == nil {
		t.Fatal("no workflow")
	}
	return &w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items[0]
}

func noLocal(string) (facts.InputPath, *cst.Tree, *workflow.ActionMetadata, bool) {
	return facts.InputPath{}, nil, nil, false
}

func usesOf(s Step) string {
	if s.Step.Uses.Status != workflow.Present {
		return "run"
	}
	return s.Step.Uses.Value.AsString()
}

func TestExpandDepth(t *testing.T) {
	a := newAnswers()
	a.define(t, "o/a1", "", "v", '1', composite(usesStep("o/a2@v")))
	a.define(t, "o/a2", "", "v", '2', composite(usesStep("o/a3@v")))
	a.define(t, "o/a3", "", "v", '3', composite(usesStep("o/a4@v")))
	a.define(t, "o/a4", "", "v", '4', composite(usesStep("o/a5@v"), runStep))
	q5 := a.define(t, "o/a5", "", "v", '5', composite(runStep))
	x := NewReader(noLocal, a).Expand(context.Background(), step(t, "uses: o/a1@v"), false)
	if len(x.Actions) != 4 {
		t.Fatalf("read %d actions, want 4 (depth 1 to 4)", len(x.Actions))
	}
	if a.asked[q5] != 0 {
		t.Errorf("o/a5 (depth 5) was asked")
	}
	var got []string
	for _, s := range x.Steps {
		got = append(got, usesOf(s)+"/"+itoa(len(s.Chain)))
	}
	if want := "o/a2@v/1 o/a3@v/2 o/a4@v/3 o/a5@v/4 run/4"; strings.Join(got, " ") != want {
		t.Errorf("steps %q, want %q", strings.Join(got, " "), want)
	}
	last := x.Steps[3]
	if last.Chain[0].Uses != "o/a1@v" || last.Chain[3].Uses != "o/a4@v" || last.Chain[3].Commit != sha(t, '4') {
		t.Errorf("chain %+v", last.Chain)
	}
	if q, ok := last.Origin.Query.(facts.ActionDefinition); !ok || q.Repo.String() != "o/a4" || last.Origin.Tree == nil || !last.Origin.Input.IsZero() {
		t.Errorf("origin %+v", last.Origin)
	}
	// o/a5 is past the depth: as asked with no answer
	if u := x.Unanswered; len(u) != 1 || !u[0].Asked || u[0].Reason != beyondDepth || len(u[0].Chain) != 5 || u[0].Chain[4].Uses != "o/a5@v" {
		t.Errorf("unanswered %+v, want o/a5@v past the depth", x.Unanswered)
	}
}

// TestExpandIfs: a step of a composite action has the ifs of the steps
// between that run the actions on the way.
func TestExpandIfs(t *testing.T) {
	a := newAnswers()
	a.define(t, "o/a1", "", "v", '1', composite("    - if: github.event_name == 'push'\n      uses: o/a2@v\n"))
	a.define(t, "o/a2", "", "v", '2', composite(runStep))
	x := NewReader(noLocal, a).Expand(context.Background(), step(t, "uses: o/a1@v"), false)
	if len(x.Steps) != 2 {
		t.Fatalf("steps %+v", x.Steps)
	}
	if n := len(x.Steps[0].Ifs); n != 0 {
		t.Errorf("the step of o/a1 has %d ifs between, want 0", n)
	}
	if ifs := x.Steps[1].Ifs; len(ifs) != 1 || ifs[0].Status != workflow.Present {
		t.Errorf("the step of o/a2 has ifs %+v, want the if of the step of o/a1", ifs)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestExpandOnce(t *testing.T) {
	a := newAnswers()
	a.define(t, "o/a", "", "v", '1', composite(usesStep("o/b@v1"), usesStep("o/b@v2"), usesStep("o/a@v")))
	a.define(t, "o/b", "", "v1", '2', composite(runStep))
	a.define(t, "o/b", "", "v2", '2', composite(runStep)) // the same commit
	x := NewReader(noLocal, a).Expand(context.Background(), step(t, "uses: o/a@v"), false)
	var got []string
	for _, r := range x.Actions {
		got = append(got, r.Chain[len(r.Chain)-1].Uses)
	}
	if want := "o/a@v o/b@v1"; strings.Join(got, " ") != want {
		t.Errorf("actions read %q, want %q (each commit once)", strings.Join(got, " "), want)
	}
	if len(x.Steps) != 4 { // the 3 steps of o/a, the step of o/b
		t.Errorf("%d steps, want 4", len(x.Steps))
	}
}

func TestExpandLocal(t *testing.T) {
	a := newAnswers()
	a.define(t, "o/r", "", "v", '1', composite(usesStep("./inner"), usesStep("$/self")))
	local := map[string]string{
		".github/actions/x": composite(usesStep("./inner"), usesStep("o/r@v"), runStep),
		"inner":             composite(runStep),
		"self":              composite(runStep),
	}
	var looked []string
	lookup := func(target string) (facts.InputPath, *cst.Tree, *workflow.ActionMetadata, bool) {
		looked = append(looked, target)
		src, ok := local[target]
		if !ok {
			return facts.InputPath{}, nil, nil, false
		}
		tr := cst.Parse([]byte(src))
		m, _ := workflow.ParseActionMetadata(tr)
		n, _ := facts.CleanInputPath(target + "/action.yml")
		return n, tr, m, true
	}
	x := NewReader(lookup, a).Expand(context.Background(), step(t, "uses: ./.github/actions/x"), false)
	if strings.Join(looked, " ") != ".github/actions/x self" {
		t.Errorf("looked up %q: ./ in a composite action is not followed, $/ is", looked)
	}
	if o := x.Steps[0].Origin; o.Input.String() != ".github/actions/x/action.yml" || o.Query != nil {
		t.Errorf("origin of a local step %+v", o)
	}
	if c := x.Steps[0].Chain; len(c) != 1 || c[0].Uses != "./.github/actions/x" || c[0].Commit != (facts.SHA{}) {
		t.Errorf("chain %+v", c)
	}
	// the step of an action.yml input: its ./ is not followed
	looked = nil
	if x := NewReader(lookup, a).Expand(context.Background(), step(t, "uses: ./inner"), true); len(x.Actions) != 0 || len(looked) != 0 {
		t.Errorf("./ of a composite action input followed: %+v", x)
	}
}

func TestExpandUnanswered(t *testing.T) {
	a := newAnswers()
	a.define(t, "o/a", "", "v", '1', composite(usesStep("o/none@v"), usesStep("o/down@v")))
	a.m[query(t, "o/down", "", "v")] = facts.RawAnswer{State: facts.StateUnknown, Reason: "github: rate limited", Source: facts.SourceGitHub}
	x := NewReader(noLocal, a).Expand(context.Background(), step(t, "uses: o/a@v"), false)
	if len(x.Unanswered) != 2 {
		t.Fatalf("unanswered %+v", x.Unanswered)
	}
	n, d := x.Unanswered[0], x.Unanswered[1]
	if n.Asked || n.Chain[1].Uses != "o/none@v" || d.Asked != true || d.Reason != "github: rate limited" || len(d.Chain) != 2 {
		t.Errorf("unanswered %+v", x.Unanswered)
	}
	// docker:// and an absent definition are no question left unanswered
	a.m[query(t, "o/gone", "", "v")] = facts.RawAnswer{State: facts.StateAbsent, Source: facts.SourceGitHub}
	if x := NewReader(noLocal, a).Expand(context.Background(), step(t, "uses: o/gone@v"), false); len(x.Unanswered)+len(x.Actions) != 0 {
		t.Errorf("absent: %+v", x)
	}
	if x := NewReader(noLocal, a).Expand(context.Background(), step(t, "uses: docker://alpine:3"), false); len(x.Unanswered)+len(x.Actions) != 0 {
		t.Errorf("docker: %+v", x)
	}
}

func TestExpandSubstitutedAndDockerfile(t *testing.T) {
	a := newAnswers()
	q := a.define(t, "o/a", "", "v", '1', composite(runStep))
	var v facts.ActionFile
	_ = json.Unmarshal(a.m[q].Value, &v)
	v.ArchiveSubstituted = true
	b, _ := json.Marshal(v)
	a.m[q] = facts.RawAnswer{State: facts.StateFound, Value: b, Source: facts.SourceGitHub}
	d, _ := json.Marshal(facts.ActionFile{Commit: sha(t, '2'), File: facts.ActionFileDockerfile})
	a.m[query(t, "o/d", "", "v")] = facts.RawAnswer{State: facts.StateFound, Value: d}
	x := NewReader(noLocal, a).Expand(context.Background(), step(t, "uses: o/a@v"), false)
	if len(x.Actions) != 1 || !x.Actions[0].Substituted || len(x.Steps) != 1 {
		t.Errorf("substituted: %+v", x)
	}
	x = NewReader(noLocal, a).Expand(context.Background(), step(t, "uses: o/d@v"), false)
	if len(x.Actions) != 1 || x.Actions[0].Metadata != nil || x.Actions[0].File != facts.ActionFileDockerfile || len(x.Steps) != 0 {
		t.Errorf("Dockerfile: %+v", x)
	}
}

// TestReaderParsesOnce: the steps of an action read for two steps are of
// the same tree, so that the places of the two are the same.
func TestReaderParsesOnce(t *testing.T) {
	a := newAnswers()
	a.define(t, "o/a", "", "v", '1', composite(runStep))
	r := NewReader(noLocal, a)
	x, y := r.Expand(context.Background(), step(t, "uses: o/a@v"), false), r.Expand(context.Background(), step(t, "uses: o/a@v"), false)
	if x.Steps[0].Origin.Tree != y.Steps[0].Origin.Tree || x.Steps[0].Step != y.Steps[0].Step {
		t.Errorf("parsed twice")
	}
}
