package workflow

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/expr"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/anchor"
)

// readSteps reads the steps: of src, a mapping, without a job around it.
func readSteps(t *testing.T, src string) (Field[List[Step]], []Diagnostic) {
	t.Helper()
	tr := cst.ParseMode([]byte(src), cst.ModeGitHub)
	if len(tr.Errors()) > 0 {
		t.Fatalf("%q: %v", src, tr.Errors())
	}
	r := &reader{anchors: anchor.Build(tr)}
	_, content := firstDocument(tr)
	m, _ := content.Mapping()
	for e := range m.Entries() {
		if string(e.Key.Bytes()) != "steps" {
			continue
		}
		ent := entry{key: r.newString(e.Key, pos{}), keyNode: e.Key, name: "steps", value: e.Value, def: dSteps, prop: true}
		return r.steps(&ent, pos{}), r.diags
	}
	t.Fatalf("%q has no steps", src)
	return Field[List[Step]]{}, nil
}

func oneStep(t *testing.T, src string, want ...Code) Step {
	t.Helper()
	f, diags := readSteps(t, "steps:\n"+src)
	wantCodes(t, src, diags, want...)
	if f.Status != Present || len(f.Value.Items) != 1 {
		t.Fatalf("%q: steps %v with %d items", src, f.Status, len(f.Value.Items))
	}
	return f.Value.Items[0]
}

func TestStepKinds(t *testing.T) {
	for _, tt := range []struct {
		src  string
		kind StepKind
		want []Code
	}{
		{"  - run: echo hi\n", StepRun, nil},
		{"  - uses: actions/checkout@v4\n", StepAction, nil},
		{"  - wait: [a]\n", StepOther, nil},
		{"  - cancel: a\n", StepOther, nil},
		{"  - wait-all:\n", StepOther, nil},
		// GitHub runs background steps.
		{"  - run: sleep 1\n    background: true\n", StepRun, nil},
		// the steps of a parallel group stand in its place
		{"  - parallel:\n      - run: a\n", StepRun, nil},
		// The template reader takes the kind from the first key; the other
		// is a key that kind does not have.
		{"  - run: a\n    uses: b@c\n", StepRun, []Code{UnknownKey}},
		{"  - run: a\n    with: {x: y}\n", StepRun, []Code{UnknownKey}},
		// Nothing tells the kind: the reader says so.
		{"  - name: x\n", StepInvalid, []Code{Ambiguous}},
		{"  - {}\n", StepInvalid, []Code{Ambiguous}},
	} {
		s := oneStep(t, tt.src, tt.want...)
		if s.Kind != tt.kind {
			t.Errorf("%q: kind %v, want %v", tt.src, s.Kind, tt.kind)
		}
	}
}

func TestStepFields(t *testing.T) {
	src := "  - id: build\n    name: Build\n    if: success()\n    shell: bash\n    env: {A: b}\n    run: make\n"
	s := oneStep(t, src)
	if s.ID.Value.Text() != "build" || s.Name.Value.Text() != "Build" || s.Shell.Value.Text() != "bash" || s.Run.Value.Text() != "make" || s.If.Status != Present {
		t.Errorf("step = %+v", s)
	}
	if e, ok := s.Env.Value.Lookup("a"); !ok || e.Value.Value.Text() != "b" {
		t.Errorf("env = %+v", s.Env)
	}
	if s.Place != (StepPlace{}) || s.Order != 0 {
		t.Errorf("place %v, order %d", s.Place, s.Order)
	}
	// step-id has no context.
	oneStep(t, "  - id: ${{ x }}\n    run: a\n", ExprNotAllowed)
	if c := oneStep(t, "  - cancel: a\n").Cancel; c.Status != Present || c.Value.AsString() != "a" {
		t.Errorf("cancel = %+v", c)
	}
	oneStep(t, "  - shell: ${{ x }}\n    run: a\n", ExprNotAllowed)
}

// A value that is no string is still a String, as GitHub passes it.
func TestStepWith(t *testing.T) {
	s := oneStep(t, "  - uses: actions/checkout@v4\n    with:\n      fetch-depth: 0\n      lfs: true\n")
	if d, _ := s.With.Value.Lookup("fetch-depth"); d.Value.Value.AsString() != "0" {
		t.Errorf("fetch-depth = %q", d.Value.Value.AsString())
	}
	if l, _ := s.With.Value.Lookup("lfs"); l.Value.Value.AsString() != "true" {
		t.Errorf("lfs = %q", l.Value.Value.AsString())
	}
}

// TestStepScript: the expressions in github-script's script.
func TestStepScript(t *testing.T) {
	src := "steps:\n  - uses: actions/github-script@v7\n    with:\n      script: |\n        const t = '${{ steps.x.outputs.title }}'\n"
	f, diags := readSteps(t, src)
	wantCodes(t, src, diags)
	sc, _ := f.Value.Items[0].With.Value.Lookup("script")
	v := sc.Value.Value
	if len(v.Parts) != 3 || !v.Parts[1].Expr {
		t.Fatalf("parts = %+v", v.Parts)
	}
	p, ok := expr.AccessPath(v.Parts[1].Tree)
	if !ok || len(p) != 4 || p[0].Name != "steps" {
		t.Errorf("path = %+v", p)
	}
	sp, _ := v.Source(v.Parts[1].Span)
	if text(src, sp) != "${{ steps.x.outputs.title }}" {
		t.Errorf("source %q", text(src, sp))
	}
}

// TestStepRunSource: the expressions of run: in each style.
func TestStepRunSource(t *testing.T) {
	const e = "${{ github.event.issue.title }}"
	for _, src := range []string{
		"  - run: \"\xc3\xa9 " + e + "\"\n",
		"  - run: |\r\n      echo a\r\n      echo " + e + "\r\n",
		"  - run: >\n      echo a\n      echo " + e + "\n",
		"  - run: |\n      echo a\n      echo " + e + "\n",
	} {
		full := "steps:\n" + src
		f, diags := readSteps(t, full)
		wantCodes(t, src, diags)
		run := f.Value.Items[0].Run.Value
		var got string
		for _, p := range run.Parts {
			if p.Expr {
				sp, exact := run.Source(p.Span)
				if !exact {
					t.Errorf("%q: not exact", src)
				}
				got = text(full, sp)
			}
		}
		if got != e {
			t.Errorf("%q: source %q", src, got)
		}
	}
}

// TestStepAlias: the same step used twice through an alias.
func TestStepAlias(t *testing.T) {
	src := "steps:\n  - &s\n    run: echo ${{ github.head_ref }}\n  - *s\n  - *s\n"
	f, diags := readSteps(t, src)
	wantCodes(t, src, diags)
	items := f.Value.Items
	if len(items) != 3 || items[0].Shared() || !items[1].Shared() || !items[2].Shared() {
		t.Fatalf("items = %d", len(items))
	}
	if items[1].Node != items[0].Node || items[2].Node != items[0].Node {
		t.Error("the aliases should read the same node")
	}
	if text(src, items[1].Primary()) == text(src, items[2].Primary()) && items[1].Primary() == items[2].Primary() {
		t.Error("each use is its own alias")
	}
	if !items[1].Run.Value.Shared() || items[1].Place.Steps != 1 || items[1].Order != 1 {
		t.Errorf("run shared %v place %v order %d", items[1].Run.Value.Shared(), items[1].Place, items[1].Order)
	}
}

func TestStepsDynamic(t *testing.T) {
	src := "steps: ${{ fromJSON(x) }}\n"
	f, diags := readSteps(t, src)
	// steps has no context.
	wantCodes(t, src, diags, ExprNotAllowed)
	if f.Status != Invalid {
		t.Errorf("steps %v", f.Status)
	}
}
