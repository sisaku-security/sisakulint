package facts

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestParseRepo(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"actions/checkout", "actions/checkout"},
		{"Actions/CheckOut", "actions/checkout"},
		{"o-1/r.x_y", "o-1/r.x_y"},
	} {
		r, err := ParseRepo(c.in)
		if err != nil || r.String() != c.want {
			t.Errorf("ParseRepo(%q) = %v, %v; want %s", c.in, r, err, c.want)
		}
	}
	for _, in := range []string{"", "a", "a/", "/b", "a/b/c", "a b/c", "a/b@v1"} {
		if r, err := ParseRepo(in); err == nil {
			t.Errorf("ParseRepo(%q) = %v, want an error", in, r)
		}
	}
	a, _ := ParseRepo("Actions/Checkout")
	b, _ := ParseRepo("actions/checkout")
	if a != b {
		t.Error("two spellings of one repo are not ==")
	}
}

func TestParseSHA(t *testing.T) {
	long := strings.Repeat("A", 40)
	if s, err := ParseSHA(long); err != nil || s.String() != strings.Repeat("a", 40) {
		t.Errorf("ParseSHA(40 A) = %q, %v", s, err)
	}
	if _, err := ParseSHA(strings.Repeat("0", 64)); err != nil {
		t.Errorf("ParseSHA(64 digits): %v", err)
	}
	for _, in := range []string{"", "abc", strings.Repeat("g", 40), strings.Repeat("0", 41)} {
		if _, err := ParseSHA(in); err == nil {
			t.Errorf("ParseSHA(%q): no error", in)
		}
	}
}

func TestParseInputPath(t *testing.T) {
	for _, ok := range []string{".github/workflows/ci.yml", "action.yml", "a/b/action.yaml"} {
		p, err := ParseInputPath(ok)
		if err != nil || p.String() != ok {
			t.Errorf("ParseInputPath(%q) = %v, %v", ok, p, err)
		}
	}
	for _, bad := range []string{"", "/abs/x.yml", "../x.yml", "a/../x.yml", `a\b.yml`, "a//b.yml", "a/./b.yml", "a/"} {
		if _, err := ParseInputPath(bad); err == nil {
			t.Errorf("ParseInputPath(%q): no error", bad)
		}
	}
}

func TestStepPath(t *testing.T) {
	w, err := WorkflowStep("build", 2)
	if err != nil || w.String() != "jobs.build.steps[2]" {
		t.Fatalf("WorkflowStep = %v, %v", w, err)
	}
	a, err := ActionStep(0)
	if err != nil || a.String() != "runs.steps[0]" {
		t.Fatalf("ActionStep = %v, %v", a, err)
	}
	for _, s := range []string{"jobs.build.steps[2]", "runs.steps[0]", "jobs._x-1.steps[10]"} {
		p, err := ParseStepPath(s)
		if err != nil || p.String() != s {
			t.Errorf("ParseStepPath(%q) = %v, %v", s, p, err)
		}
	}
	for _, s := range []string{"", "jobs.build.steps[-1]", "jobs.build.steps[01]", "jobs.1x.steps[0]", "jobs.__x.steps[0]", "runs.steps[x]", "jobs.build.steps", "steps[0]"} {
		if _, err := ParseStepPath(s); err == nil {
			t.Errorf("ParseStepPath(%q): no error", s)
		}
	}
	if _, err := WorkflowStep("__x", 0); err == nil {
		t.Error("WorkflowStep(__x): no error")
	}
	if _, err := ActionStep(-1); err == nil {
		t.Error("ActionStep(-1): no error")
	}
	b, _ := json.Marshal(w)
	var back StepPath
	if err := json.Unmarshal(b, &back); err != nil || back != w {
		t.Errorf("round trip %s: %v, %v", b, back, err)
	}
}

// Environment names are not case sensitive
// (data/reusables/actions/name-environment.md of github/docs), so, as a
// Repo, two spellings of one are ==, written in lower case.
func TestParseEnvironmentName(t *testing.T) {
	a, err := ParseEnvironmentName("Prod")
	if err != nil || a.String() != "prod" {
		t.Errorf("ParseEnvironmentName(Prod) = %v, %v", a, err)
	}
	if b, _ := ParseEnvironmentName("prod"); a != b {
		t.Error("two spellings of one environment are not ==")
	}
	for _, bad := range []string{"", strings.Repeat("x", 256), "a\nb"} {
		if _, err := ParseEnvironmentName(bad); err == nil {
			t.Errorf("ParseEnvironmentName(%q): no error", bad)
		}
	}
}

func TestKinds(t *testing.T) {
	var names []string
	for _, k := range Kinds() {
		names = append(names, k.Kind.String())
	}
	if got := strings.Join(names, " "); got != "action.definition action.runs-using checkout.executed dependabot.version-updates download.executed git.commit-contains git.commit-ref git.commit-tags git.ref-commit package.advisories renovate.manager-enabled repo.action-list repo.allow-forking repo.allowed-actions repo.archived repo.configuration-variables repo.default-token-write repo.environment-configuration-variables repo.environment-protected repo.fork-pr-app-checks repo.fork-pr-run-workflows repo.fork-pr-secrets repo.fork-pr-write-tokens repo.merge-commit-app-checks repo.public repo.pull-request-target-allowed repo.wiki-open request.destination-trusted test.commit test.flag test.list test.repo-flag test.text workflow.definition" {
		t.Errorf("Kinds = %s", got)
	}
}

func TestQueryJSON(t *testing.T) {
	q, err := DecodeQuery([]byte(`{"kind": "test.repo-flag", "repo": "Actions/Checkout"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := TestRepoFlag{Repo: mustRepo(t, "actions/checkout")}
	if q != Query(want) {
		t.Errorf("DecodeQuery = %#v, want %#v", q, want)
	}
	b, err := EncodeQuery(q)
	if err != nil || string(b) != `{"kind":"test.repo-flag","repo":"actions/checkout"}` {
		t.Errorf("EncodeQuery = %s, %v", b, err)
	}
	b2, _ := EncodeQuery(want)
	if string(b2) != string(b) {
		t.Errorf("two spellings encode differently: %s and %s", b, b2)
	}
	for _, src := range []string{
		`{"kind": "test.flag", "name": "a"}`,
		`{"kind": "test.text", "name": "a\"b"}`,
		`{"name": "a", "kind": "test.list"}`,
	} {
		q, err := DecodeQuery([]byte(src))
		if err != nil {
			t.Errorf("DecodeQuery(%s): %v", src, err)
			continue
		}
		b, err := EncodeQuery(q)
		if err != nil {
			t.Errorf("EncodeQuery(%#v): %v", q, err)
			continue
		}
		back, err := DecodeQuery(b)
		if err != nil || back != q {
			t.Errorf("round trip of %s: %s, %#v, %v", src, b, back, err)
		}
	}
}

func TestQueryJSONRejects(t *testing.T) {
	for _, src := range []string{
		`{"kind": "test.nope", "name": "a"}`,
		`{"kind": "test.flag", "name": "a", "extra": 1}`,
		`{"kind": "test.flag"}`,
		`{"kind": "test.flag", "name": ""}`,
		`{"kind": "test.repo-flag", "repo": "a"}`,
		`{"name": "a"}`,
		`[]`,
	} {
		if q, err := DecodeQuery([]byte(src)); err == nil {
			t.Errorf("DecodeQuery(%s) = %#v, want an error", src, q)
		}
	}
	for _, q := range []Query{TestRepoFlag{}, TestFlag{}} {
		if b, err := EncodeQuery(q); err == nil {
			t.Errorf("EncodeQuery(%#v) = %s, want an error", q, b)
		}
	}
}

type resolverFunc func(context.Context, Query) RawAnswer

func (f resolverFunc) Resolve(ctx context.Context, q Query) RawAnswer { return f(ctx, q) }

func answerWith(raw RawAnswer) Resolver {
	return resolverFunc(func(context.Context, Query) RawAnswer { return raw })
}

func TestAsk(t *testing.T) {
	ctx := context.Background()
	q := TestFlag{Name: "a"}
	if a := q.Ask(ctx, answerWith(RawAnswer{State: StateFound, Value: json.RawMessage(`true`)})); a.State != StateFound || !a.Value {
		t.Errorf("resolved true: %+v", a)
	}
	if a := q.Ask(ctx, answerWith(RawAnswer{State: StateAbsent})); a.State != StateAbsent {
		t.Errorf("absent: %+v", a)
	}
	l := TestList{Name: "a"}
	if a := l.Ask(ctx, answerWith(RawAnswer{State: StateFound, Value: json.RawMessage(`[]`)})); a.State != StateFound || a.Value == nil || len(a.Value) != 0 {
		t.Errorf("an empty list must be Resolved and not nil: %+v", a)
	}
	for _, c := range []struct {
		name string
		raw  RawAnswer
	}{
		{"a string for a bool", RawAnswer{State: StateFound, Value: json.RawMessage(`"true"`)}},
		{"broken JSON", RawAnswer{State: StateFound, Value: json.RawMessage(`tru`)}},
		{"no value", RawAnswer{State: StateFound}},
		{"absent with a value", RawAnswer{State: StateAbsent, Value: json.RawMessage(`false`)}},
		{"unknown without a reason", RawAnswer{State: StateUnknown}},
		{"a state out of range", RawAnswer{State: State(9)}},
	} {
		a := q.Ask(ctx, answerWith(c.raw))
		if a.State != StateUnknown || a.Reason == "" {
			t.Errorf("%s: %+v, want Unknown with a reason", c.name, a)
		}
	}
}

func TestAskCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	a := TestFlag{Name: "a"}.Ask(ctx, resolverFunc(func(context.Context, Query) RawAnswer {
		called = true
		return RawAnswer{State: StateFound, Value: json.RawMessage(`true`)}
	}))
	if called || a.State != StateUnknown || a.Reason == "" {
		t.Errorf("called = %v, answer = %+v", called, a)
	}
}

func TestCheckedCanonical(t *testing.T) {
	r := Checked(TestList{Name: "a"}, RawAnswer{State: StateFound, Value: json.RawMessage(` [ "b" , "a" ] `)})
	if r.State != StateFound || string(r.Value) != `["b","a"]` {
		t.Errorf("Checked = %+v", r)
	}
}

func TestDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".", "./github").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, bad := range []string{"github.com/gh-intel/sisakulint/actions/workflow", "github.com/gh-intel/sisakulint/actions/lint", "github.com/gh-intel/sisakulint/yaml/"} {
			if strings.HasPrefix(dep, bad) {
				t.Errorf("actions/facts or actions/facts/github depends on %s", dep)
			}
		}
	}
}

func mustRepo(t *testing.T, s string) Repo {
	t.Helper()
	r, err := ParseRepo(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// embedded is a type that embeds a kind; it must not count as a fact.
type embedded struct{ TestFlag }

func (embedded) Kind() Kind { return KindTestText }

func TestQueryIsClosed(t *testing.T) {
	var nilFlag *TestFlag
	for _, q := range []Query{&TestFlag{Name: "a"}, nilFlag, embedded{TestFlag{Name: "a"}}} {
		if b, err := EncodeQuery(q); err == nil {
			t.Errorf("EncodeQuery(%#v) = %s, want an error", q, b)
		}
		if r := Checked(q, RawAnswer{State: StateFound, Value: json.RawMessage(`true`)}); r.State != StateUnknown || r.Reason == "" {
			t.Errorf("Checked(%#v) = %+v, want Unknown", q, r)
		}
		if r := NewRecorder(answerWith(RawAnswer{State: StateAbsent})).Resolve(context.Background(), q); r.State != StateUnknown {
			t.Errorf("Recorder.Resolve(%#v) = %+v, want Unknown", q, r)
		}
	}
}

func TestQueryRejectsInvalidUTF8(t *testing.T) {
	if b, err := EncodeQuery(TestFlag{Name: "a\xff"}); err == nil {
		t.Errorf("EncodeQuery with invalid UTF-8 = %s, want an error", b)
	}
}

func TestSHAIsNormalized(t *testing.T) {
	upper, err := ParseSHA(strings.Repeat("AB", 20))
	if err != nil {
		t.Fatal(err)
	}
	lower, _ := ParseSHA(strings.Repeat("ab", 20))
	q1 := TestCommit{Repo: mustRepo(t, "o/r"), SHA: upper}
	q2 := TestCommit{Repo: mustRepo(t, "o/r"), SHA: lower}
	if q1 != q2 {
		t.Error("two spellings of one commit are not ==")
	}
	b, err := EncodeQuery(q1)
	if err != nil || !strings.Contains(string(b), strings.Repeat("ab", 20)) {
		t.Errorf("EncodeQuery = %s, %v", b, err)
	}
	if b, err := EncodeQuery(TestCommit{Repo: mustRepo(t, "o/r")}); err == nil {
		t.Errorf("EncodeQuery with the zero SHA = %s, want an error", b)
	}
	r := Checked(q1, RawAnswer{State: StateFound, Value: json.RawMessage(`"` + strings.Repeat("CD", 20) + `"`)})
	if r.State != StateFound || string(r.Value) != `"`+strings.Repeat("cd", 20)+`"` {
		t.Errorf("Checked does not normalize the value: %+v", r)
	}
	a := q1.Ask(context.Background(), answerWith(RawAnswer{State: StateFound, Value: json.RawMessage(`"` + strings.Repeat("CD", 20) + `"`)}))
	if a.State != StateFound || a.Value.String() != strings.Repeat("cd", 20) {
		t.Errorf("Ask = %+v", a)
	}
}

// The schema's patterns of the new types refuse what their Go parsers
// refuse, so that a reader of the schema
// alone does not take a fact that sisakulint does not.
func TestSchemaAgreesWithParsers(t *testing.T) {
	check := func(def string, bad []string, parse func(string) error) {
		for _, s := range bad {
			b, _ := json.Marshal(s)
			if parse(s) == nil {
				t.Errorf("%s: %q is not refused by its parser", def, s)
			}
			if err := schema().Validate(SchemaName, "#/$defs/"+def, b); err == nil {
				t.Errorf("%s: the schema takes %q", def, s)
			}
		}
	}
	check("input-path", []string{".", "..", "a/./b", "a/../b", "../a", "a/.."}, func(s string) error { _, err := ParseInputPath(s); return err })
	check("step-path", []string{"jobs.__a.steps[0]", "jobs." + strings.Repeat("a", 100) + ".steps[0]", "runs.steps[0].parallel[0]", "jobs.a.steps[0].parallel[00]", "jobs.a.steps[0].parallel[0].parallel[0]", "jobs.a.parallel[0]"}, func(s string) error { _, err := ParseStepPath(s); return err })
	// a step of a parallel group
	if b, _ := json.Marshal("jobs._.steps[1].parallel[2]"); schema().Validate(SchemaName, "#/$defs/step-path", b) != nil {
		t.Error("step-path refuses a step of a parallel group")
	}
	check("environment-name", []string{"a\u0085b", "a\x7fb"}, func(s string) error { _, err := ParseEnvironmentName(s); return err })
	check("uses-path", []string{"/a", "a/", "a//b", "./a", "a/../b", "..", "a@v1", "a b", "a\tb", `a\b`}, func(s string) error { _, err := ParseUsesPath(s); return err })
	// the white space of the pattern (\s of Go's regexp) is the parser's too
	for _, s := range []string{"a\vb", "a\u0085b", "a.b/.c"} {
		b, _ := json.Marshal(s)
		_, err := ParseUsesPath(s)
		if (err == nil) != (schema().Validate(SchemaName, "#/$defs/uses-path", b) == nil) {
			t.Errorf("uses-path: the schema and ParseUsesPath disagree on %q", s)
		}
	}
	for def, good := range map[string]string{"input-path": ".github/workflows/.x.yml", "step-path": "jobs._.steps[0]", "environment-name": "Prod env"} {
		b, _ := json.Marshal(good)
		if err := schema().Validate(SchemaName, "#/$defs/"+def, b); err != nil {
			t.Errorf("%s refuses %q: %v", def, good, err)
		}
	}
}

// A repository fact names its repository, or none: the repository of the
// inputs. The two are different facts, and none is not written.
func TestOptionalRepo(t *testing.T) {
	r, err := ParseRepo("O/R")
	if err != nil {
		t.Fatal(err)
	}
	prod, err := ParseEnvironmentName("prod")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		q    Query
		want string
	}{
		{RepoPublic{}, `{"kind":"repo.public"}`},
		{RepoPublic{Repo: r}, `{"kind":"repo.public","repo":"o/r"}`},
		{RepoEnvironmentProtected{Environment: prod}, `{"kind":"repo.environment-protected","environment":"prod"}`},
		{RepoEnvironmentProtected{Repo: r, Environment: prod}, `{"kind":"repo.environment-protected","repo":"o/r","environment":"prod"}`},
	} {
		b, err := EncodeQuery(c.q)
		if err != nil || string(b) != c.want {
			t.Errorf("EncodeQuery(%#v) = %s, %v; want %s", c.q, b, err, c.want)
		}
		back, err := DecodeQuery(b)
		if err != nil || back != c.q {
			t.Errorf("DecodeQuery(%s) = %#v, %v", b, back, err)
		}
	}
	if (RepoPublic{}) == (RepoPublic{Repo: r}) {
		t.Error("the fact of no name is the fact of o/r")
	}
	if _, err := DecodeQuery([]byte(`{"kind":"repo.public","repo":""}`)); err == nil {
		t.Error("an empty repo is read")
	}
	// a file of facts of before: no repo
	s, err := LoadStore([]byte(`{"schema":"sisakulint/facts/v0","facts":[{"query":{"kind":"repo.public"},"state":"found","value":false}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := (RepoPublic{}).Ask(context.Background(), s); got.State != StateFound || got.Value {
		t.Errorf("no name = %+v", got)
	}
	if got := (RepoPublic{Repo: r}).Ask(context.Background(), s); got.State != StateUnknown {
		t.Errorf("o/r = %+v, want unknown: the entry of no name does not answer it", got)
	}
	// WithRepo names the repository of a kind whose repo may be left out,
	// and of no other kind
	if q, ok := WithRepo(RepoEnvironmentProtected{Environment: prod}, r); !ok || q != (RepoEnvironmentProtected{Repo: r, Environment: prod}) {
		t.Errorf("WithRepo(repo.environment-protected) = %#v, %v", q, ok)
	}
	if q, ok := WithRepo(RepoPublic{Repo: r}, Repo{}); !ok || q != (RepoPublic{}) {
		t.Errorf("WithRepo(repo.public of o/r, none) = %#v, %v", q, ok)
	}
	if _, ok := WithRepo(TestRepoFlag{Repo: r}, r); ok {
		t.Error("WithRepo names the repository of test.repo-flag, whose repo is required")
	}
}

// Every Parse of a type whose zero value is none, which factsgen lets an
// argument leave out (zeroIsNone), gives a value that is not zero: so no
// written value reads as none, and no fact has two spellings.
func TestParseIsNotZero(t *testing.T) {
	r, err := ParseRepo("a/b")
	if err != nil || r.IsZero() {
		t.Errorf("ParseRepo = %v, %v", r, err)
	}
	n, err := ParseRefName("refs/heads/x")
	if err != nil || n.IsZero() {
		t.Errorf("ParseRefName = %v, %v", n, err)
	}
	p, err := ParseInputPath("a")
	if err != nil || p.IsZero() {
		t.Errorf("ParseInputPath = %v, %v", p, err)
	}
	for _, bad := range []string{"", "/", "a/"} {
		if r, err := ParseRepo(bad); err == nil {
			t.Errorf("ParseRepo(%q) = %v", bad, r)
		}
	}
}

// TestQueryText: a fact for people is its kind, then key=value in the order
// of its JSON.
func TestQueryText(t *testing.T) {
	for _, c := range []struct{ json, want string }{
		{`{"kind": "repo.default-token-write"}`, "repo.default-token-write"},
		{`{"kind": "action.runs-using", "repo": "actions/checkout", "ref": "v4"}`, "action.runs-using repo=actions/checkout ref=v4"},
	} {
		q, err := DecodeQuery([]byte(c.json))
		if err != nil {
			t.Fatal(err)
		}
		if got := QueryText(q); got != c.want {
			t.Errorf("QueryText(%s) = %q, want %q", c.json, got, c.want)
		}
	}
}
