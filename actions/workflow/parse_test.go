package workflow

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/expr"
)

func TestFieldStatus(t *testing.T) {
	src := "on: push\n" + jobsOK
	w, diags, _ := parse(t, src)
	wantCodes(t, src, diags)
	if w.Env.Status != Absent || w.Name.Status != Absent {
		t.Errorf("env %v, name %v: want Absent", w.Env.Status, w.Name.Status)
	}

	src = "on: push\nenv: {A: b}\n" + jobsOK
	w, diags, _ = parse(t, src)
	wantCodes(t, src, diags)
	if w.Env.Status != Present || len(w.Env.Value.Entries) != 1 || w.Env.Value.Entries[0].Key.Text() != "A" || w.Env.Value.Entries[0].Value.Value.Text() != "b" {
		t.Errorf("env = %+v", w.Env)
	}
	if text(src, w.Env.Key.Span()) != "env" {
		t.Errorf("env key = %q", text(src, w.Env.Key.Span()))
	}

	src = "on: push\nenv: ${{ fromJSON(inputs.e) }}\n" + jobsOK
	w, diags, _ = parse(t, src)
	wantCodes(t, src, diags)
	if w.Env.Status != Dynamic || w.Env.Expr == nil || w.Env.Expr.Text() != "${{ fromJSON(inputs.e) }}" {
		t.Errorf("env = %+v", w.Env)
	}

	src = "on: push\nenv: [a]\n" + jobsOK
	w, diags, _ = parse(t, src)
	wantCodes(t, src, diags, WrongKind)
	if w.Env.Status != Invalid {
		t.Errorf("env = %v, want Invalid", w.Env.Status)
	}

	// GitHub rejects env: with no value.
	src = "on: push\nenv:\n" + jobsOK
	w, diags, _ = parse(t, src)
	wantCodes(t, src, diags, WrongKind)
	if w.Env.Status != Invalid {
		t.Errorf("env = %v, want Invalid", w.Env.Status)
	}
}

func TestKeys(t *testing.T) {
	for _, tt := range []struct {
		src  string
		want []Code
	}{
		{"on: push\nfoo: 1\n" + jobsOK, []Code{UnknownKey}},
		// schema keys are exact. The required check counts
		// Jobs as jobs (TemplateReader's case-insensitive keys).
		{"on: push\nJobs:\n  a:\n    runs-on: x\n    steps: [{run: y}]\n", []Code{UnknownKey}},
		// << is a key like any other.
		{"on: push\n<<: {name: x}\n" + jobsOK, []Code{UnknownKey}},
		{"on: push\nname: a\nNAME: b\n" + jobsOK, []Code{DuplicateKey}},
		{"jobs: {}\n", []Code{MissingKey}},
		{"on: push\n", []Code{MissingKey}},
		{"", []Code{MissingKey, MissingKey}},
		{"- a\n", []Code{WrongKind}},
	} {
		_, diags, _ := parse(t, tt.src)
		wantCodes(t, tt.src, diags, tt.want...)
	}
}

func TestDuplicateFirstWins(t *testing.T) {
	src := "on: push\nname: a\nNAME: b\n" + jobsOK
	w, diags, _ := parse(t, src)
	if w.Name.Value.Text() != "a" {
		t.Errorf("name = %q, want the first", w.Name.Value.Text())
	}
	if len(diags) != 1 || text(src, diags[0].Span) != "NAME" {
		t.Errorf("diagnostics %v, want one at NAME", diags)
	}
}

// TestLooseDuplicates: keys compare with each character lowered.
func TestLooseDuplicates(t *testing.T) {
	const (
		dottedI = "\xc4\xb0"
		dotless = "\xc4\xb1"
		kelvin  = "\xe2\x84\xaa"
		sharpS  = "\xc3\x9f"
	)
	for _, tt := range []struct {
		a, b string
		dup  bool
	}{
		{"FOO", "foo", true},
		{dottedI + "X", "iX", true},
		{kelvin + "X", "kX", true},
		{dottedI + "X", "IX", true},
		{"X" + sharpS, "XSS", false},
		{dotless + "X", "IX", false},
	} {
		src := "on: push\nenv:\n  " + tt.a + ": 1\n  " + tt.b + ": 2\n" + jobsOK
		w, diags, _ := parse(t, src)
		if tt.dup {
			wantCodes(t, src, diags, DuplicateKey)
		} else {
			wantCodes(t, src, diags)
		}
		if n := len(w.Env.Value.Entries); n != 2 {
			t.Errorf("%q: %d entries, want both", src, n)
		}
		e, ok := w.Env.Value.Lookup(tt.b)
		if !ok {
			t.Errorf("%q: Lookup(%q) failed", src, tt.b)
			continue
		}
		want := "2"
		if tt.dup {
			want = "1"
		}
		if got := e.Value.Value.Text(); got != want {
			t.Errorf("%q: Lookup(%q) = %q, want %q", src, tt.b, got, want)
		}
	}
}

func TestAlias(t *testing.T) {
	// A scalar reached through an alias.
	src := "name: &n hello\nrun-name: *n\non: push\n" + jobsOK
	w, diags, _ := parse(t, src)
	wantCodes(t, src, diags)
	rn := w.RunName.Value
	// The node is the definition, with its anchor; the value is in it.
	vs, _ := rn.Source(expr.Span{Start: 0, End: len(rn.Text())})
	if rn.Text() != "hello" || !rn.Shared() || text(src, rn.Primary()) != "*n" || text(src, rn.Node.ContentSpan()) != "&n hello" || text(src, vs) != "hello" {
		t.Errorf("run-name = %q shared %v primary %q node %q value %q", rn.Text(), rn.Shared(), text(src, rn.Primary()), text(src, rn.Node.ContentSpan()), text(src, vs))
	}
	if w.Name.Value.Shared() {
		t.Error("name is the definition, not shared")
	}

	// A mapping reached through an alias: its entries are shared too.
	src = "on: push\njobs:\n  a:\n    runs-on: x\n    env: &e {A: b}\n    steps: [{run: y}]\nenv: *e\n"
	w, diags, _ = parse(t, src)
	wantCodes(t, src, diags)
	env := w.Env.Value
	if w.Env.Status != Present || !env.Shared() || len(env.Entries) != 1 {
		t.Fatalf("env = %+v", w.Env)
	}
	v := env.Entries[0].Value.Value
	if !v.Shared() || text(src, v.Primary()) != "*e" || text(src, v.Node.Span()) != "b" {
		t.Errorf("A: shared %v primary %q", v.Shared(), text(src, v.Primary()))
	}

	// A value and a key reached through aliases.
	src = "name: &k KEY\nrun-name: &v val\non: push\nenv:\n  *k : *v\n" + jobsOK
	w, diags, _ = parse(t, src)
	wantCodes(t, src, diags)
	e, ok := w.Env.Value.Lookup("key")
	if !ok || e.Value.Value.Text() != "val" || !e.Key.Shared() || !e.Value.Value.Shared() {
		t.Errorf("Lookup(key) = %+v, %v", e, ok)
	}

	// An alias without a definition, and one inside its own definition.
	for _, src := range []string{
		"run-name: *nope\non: push\n" + jobsOK,
		"on: push\nenv: &a {A: *a}\n" + jobsOK,
	} {
		_, diags, _ := parse(t, src)
		wantCodes(t, src, diags, UnresolvedAlias)
		if len(diags) == 1 && text(src, diags[0].Span)[0] != '*' {
			t.Errorf("%q: diagnostic at %q, want the alias", src, text(src, diags[0].Span))
		}
	}
}

func TestExprAllowed(t *testing.T) {
	for _, tt := range []struct {
		src  string
		want []Code
	}{
		// workflow-name has no context; run-name has.
		{"name: ${{ github.ref }}\non: push\n" + jobsOK, []Code{ExprNotAllowed}},
		{"name: a ${{ 'b' }}\non: push\n" + jobsOK, []Code{ExprNotAllowed}},
		// a literal alone is folded into a string.
		{"name: ${{ 'lit' }}\non: push\n" + jobsOK, nil},
		{"run-name: ${{ github.ref }}\non: push\n" + jobsOK, nil},
		{"run-name: ${{ a == }}\non: push\n" + jobsOK, []Code{ExprSyntax}},
		{"run-name: x ${{ a\non: push\n" + jobsOK, []Code{ExprSyntax}},
		// workflow-env has context: its values inherit it.
		{"on: push\nenv: {A: '${{ github.ref }}'}\n" + jobsOK, nil},
	} {
		_, diags, _ := parse(t, tt.src)
		wantCodes(t, tt.src, diags, tt.want...)
	}
}

func TestExprSyntaxSpan(t *testing.T) {
	src := "run-name: \"x ${{ a == 1.2.3 }}\"\non: push\n" + jobsOK
	_, diags, _ := parse(t, src)
	if len(diags) != 1 || text(src, diags[0].Span) != "1.2.3" {
		t.Errorf("diagnostics %v, want one at 1.2.3", diags)
	}
}

func TestForms(t *testing.T) {
	for _, src := range []string{
		// Quoted keys are compared by their value.
		"\"on\": push\n'jobs':\n  a:\n    runs-on: x\n    steps: [{run: y}]\n",
		"{on: push, jobs: {a: {runs-on: x, steps: [{run: y}]}}}\n",
		// the second document is not read, errors and all.
		"on: push\n" + jobsOK + "---\nfoo: bar\n",
		"on: push\n" + jobsOK + "---\n[unclosed\n",
	} {
		w, diags, _ := parse(t, src)
		wantCodes(t, src, diags)
		if w == nil {
			t.Errorf("%q: no workflow", src)
		}
	}
	src := "on: push\nname: [\n" + jobsOK
	_, diags, _ := parse(t, src)
	if len(diags) == 0 || diags[0].Code != Syntax {
		t.Errorf("%q: diagnostics %v, want a Syntax first", src, diags)
	}
}

// TestExprInNodeOnly: GitHub reads the ${{ }} of values the model keeps as
// nodes too.
func TestExprInNodeOnly(t *testing.T) {
	for _, src := range []string{
		"on: push\njobs:\n  a:\n    runs-on: x\n    concurrency: ${{ secrets.foo\n",
		"on: push\njobs:\n  a:\n    runs-on: ${{ }}\n",
		"on: push\njobs:\n  a:\n    runs-on: x\n    timeout-minutes: ${{ \"0x\" }}\n",
	} {
		_, diags, _ := parse(t, src)
		wantCodes(t, src, diags, ExprSyntax)
	}
}

// TestUnresolvedOnce: an unresolved alias is one diagnostic.
func TestUnresolvedOnce(t *testing.T) {
	for _, src := range []string{
		"on: push\npermissions: *nope\n" + jobsOK,
		"on: push\njobs:\n  a:\n    uses: ./.github/workflows/w.yml\n    secrets: *nope\n",
	} {
		_, diags, _ := parse(t, src)
		wantCodes(t, src, diags, UnresolvedAlias)
	}
}

// TestPartlyInvalidList: a list with an item that is not read is Invalid;
// the items that are read stay.
func TestPartlyInvalidList(t *testing.T) {
	src := "on: [push, pushh]\n" + jobsOK
	w, _, _ := parse(t, src)
	if w.On.Status != Invalid || len(w.On.Value.Events) != 1 {
		t.Errorf("on %v with %d events", w.On.Status, len(w.On.Value.Events))
	}
	src = "on: push\njobs:\n  a:\n    runs-on: x\n    needs: [b, [c]]\n"
	w, _, _ = parse(t, src)
	n := w.Jobs.Value.Entries[0].Value.Value.Needs
	if n.Status != Invalid || len(n.Value.Items) != 1 {
		t.Errorf("needs %v with %d items", n.Status, len(n.Value.Items))
	}
}

// TestAliasDiagnosticEach: a diagnostic in shared content is at each alias.
func TestAliasDiagnosticEach(t *testing.T) {
	src := "steps:\n  - &s\n    run: echo ${{ a == }}\n  - *s\n  - *s\n"
	_, diags := readSteps(t, src)
	var at []string
	for _, d := range diags {
		at = append(at, text(src, d.Span))
	}
	if len(diags) != 3 || at[1] != "*s" || at[2] != "*s" || diags[1].Span == diags[2].Span || len(diags[1].Related) != 1 {
		t.Errorf("diagnostics at %q: %v", at, diags)
	}
}

// TestReaderDetails: what the template reader does that the first version
// did not.
func TestReaderDetails(t *testing.T) {
	for _, tt := range []struct {
		src  string
		want []Code
	}{
		// loose keys are checked against the loose key definition.
		{"on: push\nenv:\n  \"\": y\n" + jobsOK, []Code{InvalidValue}},
		{"on: push\nenv:\n  ~: y\n" + jobsOK, []Code{InvalidValue}},
		// only a value that is exactly ${{ 'x' }} is folded.
		{"name: \" ${{ 'x' }}\"\non: push\n" + jobsOK, []Code{ExprNotAllowed}},
		// an expression as a key needs a context that allows it.
		{"on: push\n${{ x }}: 1\n" + jobsOK, []Code{ExprNotAllowed}},
		{"on: push\nenv:\n  ${{ github.x }}: y\n" + jobsOK, nil},
		// a broken expression is one diagnostic.
		{"name: ${{ a == }}\non: push\n" + jobsOK, []Code{ExprSyntax}},
		{"on: push\nenv: ${{ a == }}\n" + jobsOK, []Code{ExprSyntax}},
		// the value of a duplicate key is not read.
		{"on: push\nenv:\n  A: x\n  a: [1]\n" + jobsOK, []Code{DuplicateKey}},
	} {
		_, diags, _ := parse(t, tt.src)
		wantCodes(t, tt.src, diags, tt.want...)
	}
}

// TestExprKeyFolded: a key ${{ 'A' }} is the key A.
func TestExprKeyFolded(t *testing.T) {
	src := "on: push\nenv:\n  ${{ 'A' }}: x\n" + jobsOK
	w, diags, _ := parse(t, src)
	wantCodes(t, src, diags)
	if _, ok := w.Env.Value.Lookup("A"); !ok {
		t.Error("Lookup(A) failed")
	}
}

// TestFieldKeyAlias: Field.Key is the key as written, an alias included.
func TestFieldKeyAlias(t *testing.T) {
	src := "name: &k env\non: push\n*k : {A: b}\n" + jobsOK
	w, diags, _ := parse(t, src)
	wantCodes(t, src, diags)
	if w.Env.Status != Present || text(src, w.Env.Key.ContentSpan()) != "*k" {
		t.Errorf("env key = %q, %v", text(src, w.Env.Key.ContentSpan()), w.Env.Status)
	}
}

// TestEmptyMessages: the two diagnostics of an empty file name their keys.
func TestEmptyMessages(t *testing.T) {
	_, diags, _ := parse(t, "")
	if len(diags) != 2 || diags[0].Msg == diags[1].Msg {
		t.Errorf("diagnostics %v", diags)
	}
}
