package workflow

import (
	"strings"
	"testing"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// Step ids: the rule of job
// ids, and no two in a job, compared without case, the steps of parallel
// groups included.
func TestStepIDs(t *testing.T) {
	for _, tt := range []struct {
		name, steps string
		want        []Code
	}{
		{"ok", "      - {id: a, run: x}\n      - {id: _b-2, run: x}\n", nil},
		{"99", "      - {id: " + strings.Repeat("a", 99) + ", run: x}\n", nil},
		{"100", "      - {id: " + strings.Repeat("a", 100) + ", run: x}\n", []Code{InvalidValue}},
		{"reserved", "      - {id: __a, run: x}\n", []Code{InvalidValue}},
		{"digit", "      - {id: 1abc, run: x}\n", []Code{InvalidValue}},
		{"dup", "      - {id: s, run: x}\n      - {id: s, run: y}\n", []Code{InvalidValue}},
		{"dup case", "      - {id: step1, run: x}\n      - {id: STEP1, run: y}\n", []Code{InvalidValue}},
		{"dup three", "      - {id: s, run: x}\n      - {id: s, run: y}\n      - {id: S, run: z}\n", []Code{InvalidValue, InvalidValue}},
		{"group and outer", "      - {id: s1, run: x}\n      - parallel:\n          - {id: s1, run: y}\n          - {run: z}\n", []Code{InvalidValue}},
		{"in a group", "      - parallel:\n          - {id: p1, run: x}\n          - {id: P1, run: y}\n", []Code{InvalidValue}},
		{"two groups", "      - parallel:\n          - {id: g, run: x}\n          - {run: y}\n      - parallel:\n          - {id: g, run: z}\n          - {run: w}\n", []Code{InvalidValue}},
		{"invalid not counted", "      - {id: 1a, run: x}\n      - {id: 1a, run: y}\n", []Code{InvalidValue, InvalidValue}},
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n" + tt.steps
		_, diags, _ := parse(t, src)
		wantCodes(t, tt.name, diags, tt.want...)
	}
}

// The same id in two jobs is not a duplicate.
func TestStepIDsPerJob(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps: [{id: s, run: x}]\n  b:\n    runs-on: x\n    steps: [{id: s, run: x}]\n"
	_, diags, _ := parse(t, src)
	wantCodes(t, src, diags)
}

// A duplicate reached through an alias is reported where the alias is
// used, with the shared content as Related.
func TestStepIDDuplicateAlias(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - &s {id: s, run: x}\n      - *s\n"
	_, diags, _ := parse(t, src)
	wantCodes(t, src, diags, InvalidValue)
	if len(diags) == 1 && (text(src, diags[0].Span) != "*s" || len(diags[0].Related) != 1 || text(src, diags[0].Related[0]) != "s") {
		t.Errorf("diagnostic %+v", diags[0])
	}
}

// Where the duplicate is reported, and what it says.
func TestStepIDDuplicateMessage(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - {id: step1, run: x}\n      - {id: STEP1, run: y}\n"
	_, diags, _ := parse(t, src)
	if len(diags) != 1 || diags[0].Span != at(t, src, "STEP1") || !strings.Contains(diags[0].Msg, "earlier step") {
		t.Errorf("diagnostics %+v", diags)
	}
}

// TestNeeds: needs: a job that is not there, a cycle, and no job
// without needs. Job ids are looked up without case; a job named twice in
// needs is fine.
func TestNeeds(t *testing.T) {
	job := func(id, needs string) string {
		s := "  " + id + ":\n    runs-on: x\n    steps: [{run: y}]\n"
		if needs != "" {
			s += "    needs: " + needs + "\n"
		}
		return s
	}
	for _, tt := range []struct {
		name string
		jobs []string
		want []Code
	}{
		{"ok", []string{job("a", ""), job("b", "a"), job("c", "[a, b]")}, nil},
		{"case", []string{job("build", ""), job("b", "Build")}, nil},
		{"twice", []string{job("a", ""), job("b", "[a, a]"), job("c", "[a, A]")}, nil},
		{"unknown", []string{job("a", ""), job("b", "nope")}, []Code{InvalidValue}},
		{"unknown two", []string{job("a", ""), job("b", "[x, y]")}, []Code{InvalidValue, InvalidValue}},
		{"self", []string{job("a", ""), job("b", "b")}, []Code{InvalidValue}},
		{"cycle", []string{job("one", ""), job("two", "[one, three]"), job("three", "two")}, []Code{InvalidValue, InvalidValue}},
		{"downstream", []string{job("a", ""), job("b", "c"), job("c", "b"), job("d", "b")}, []Code{InvalidValue, InvalidValue}},
		{"no start", []string{job("one", "two"), job("two", "one")}, []Code{InvalidValue, InvalidValue, InvalidValue}},
		{"no start, unknown", []string{job("one", "nope")}, []Code{InvalidValue, InvalidValue}},
	} {
		src := "on: push\njobs:\n" + strings.Join(tt.jobs, "")
		_, diags, _ := parse(t, src)
		wantCodes(t, tt.name, diags, tt.want...)
	}
}

// Where the diagnostics of needs are, and what they say.
func TestNeedsPlaces(t *testing.T) {
	src := "on: push\njobs:\n  one:\n    runs-on: x\n    steps: [{run: y}]\n    needs: two\n  two:\n    runs-on: x\n    steps: [{run: y}]\n    needs: [one, gone]\n"
	_, diags, _ := parse(t, src)
	var got []string
	for _, d := range diags {
		got = append(got, text(src, d.Span)+": "+d.Msg)
	}
	want := []string{
		`gone: the job "two" needs the job "gone", which is not in the workflow`,
		`two: the job "one" needs the job "two", and the job "two" needs the job "one", directly or through other jobs: the needs form a cycle`,
		`one: the job "two" needs the job "one", and the job "one" needs the job "two", directly or through other jobs: the needs form a cycle`,
	}
	// the mapping of jobs, for no job without needs, starts at the first key
	if len(diags) != 4 || !strings.HasPrefix(text(src, diags[3].Span), "one:") || diags[3].Msg != "the workflow must contain at least one job with no needs" {
		t.Errorf("diagnostics %q", got)
		return
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("diagnostic %d = %q, want %q", i, got[i], w)
		}
	}
}

// What cannot be known is not checked: needs from a ${{ }} GitHub does not
// fold (the schema gives its own diagnostic; a folded one is judged, see
// TestFoldedIDs), and what a job of no known kind would decide.
func TestNeedsNotKnown(t *testing.T) {
	for _, src := range []string{
		"on: push\njobs:\n  a:\n    runs-on: x\n    steps: [{run: y}]\n    needs: ${{ github.sha }}\n",
		"on: push\njobs:\n  a:\n    runs-on: x\n    steps: [{run: y}]\n    needs: [\"${{ github.sha }}\"]\n",
		// a job of no known kind (Ambiguous) is left out, and with it
		// what it would decide
		"on: push\njobs:\n  a:\n    name: x\n  b:\n    runs-on: x\n    steps: [{run: y}]\n    needs: a\n",
	} {
		_, diags, _ := parse(t, src)
		for _, d := range diags {
			if d.Code == InvalidValue {
				t.Errorf("%q: %+v", src, d)
			}
		}
	}
}

// callee is a called workflow like those of the observed runs: req is
// required, and so is reqdef though it has a default.
const callee = `on:
  workflow_call:
    inputs:
      req: {required: true, type: string}
      reqdef: {required: true, type: string, default: d}
      s: {type: string}
      b: {type: boolean}
      n: {type: number}
    secrets:
      shh: {required: true}
      opt: {}
jobs:
  c:
    runs-on: x
    steps: [{run: y}]
`

// checkCall parses the caller's job c and the called workflow, and gives
// CheckCall's diagnostics.
func checkCall(t *testing.T, caller, called string) ([]Diagnostic, string) {
	t.Helper()
	src := "on: push\njobs:\n  c:\n    uses: ./.github/workflows/callee.yml\n" + caller
	w, diags, _ := parse(t, src)
	if len(diags) > 0 {
		t.Fatalf("%q: %v", src, diags)
	}
	cw, cdiags, _ := parse(t, called)
	if len(cdiags) > 0 {
		t.Fatalf("%q: %v", called, cdiags)
	}
	return CheckCall(w.Jobs.Value.Entries[0].Value.Value, cw), src
}

// CheckCall: what GitHub rejected in the experiments
// is reported, what it took is not.
func TestCheckCall(t *testing.T) {
	ok := "      req: r\n      reqdef: r\n"
	sec := "    secrets:\n      shh: x\n"
	for _, tt := range []struct {
		name, caller string
		want         []Code
	}{
		{"all", "    with:\n" + ok + "      s: x\n      b: true\n      n: 3\n" + sec, nil},
		{"v17 missing input", "    with:\n      reqdef: r\n" + sec, []Code{MissingKey}},
		{"w06 required with a default", "    with:\n      req: r\n" + sec, []Code{MissingKey}},
		{"no with", sec, []Code{MissingKey, MissingKey}},
		{"v18 undefined input", "    with:\n" + ok + "      nope: n\n" + sec, []Code{UnknownKey}},
		{"v19 boolean", "    with:\n" + ok + "      b: not-a-boolean\n" + sec, []Code{InvalidValue}},
		{"v20 number", "    with:\n" + ok + "      n: not-a-number\n" + sec, []Code{InvalidValue}},
		{"v21 folded literal", "    with:\n" + ok + "      b: ${{ 'not-a-boolean' }}\n" + sec, []Code{InvalidValue}},
		{"w13 context", "    with:\n" + ok + "      b: ${{ github.ref_name }}\n" + sec, nil},
		{"w07 True", "    with:\n" + ok + "      b: True\n" + sec, nil},
		{"w08 quoted true", "    with:\n" + ok + "      b: 'true'\n" + sec, []Code{InvalidValue}},
		{"w09 quoted number", "    with:\n" + ok + "      n: '3'\n" + sec, []Code{InvalidValue}},
		{"w10 yes", "    with:\n" + ok + "      b: yes\n" + sec, []Code{InvalidValue}},
		{"w12 float", "    with:\n" + ok + "      n: 1.5e3\n" + sec, nil},
		{"w04 string gets a bool", "    with:\n" + ok + "      s: true\n" + sec, nil},
		{"null", "    with:\n" + ok + "      b:\n" + sec, nil},
		{"v22 missing secret", "    with:\n" + ok, []Code{MissingKey}},
		{"v23 undefined secret", "    with:\n" + ok + sec + "      nope: y\n", []Code{UnknownKey}},
		{"v24 inherit", "    with:\n" + ok + "    secrets: inherit\n", nil},
		{"v25 input case", "    with:\n      REQ: r\n      ReqDef: r\n" + sec, nil},
		{"v26 secret case", "    with:\n" + ok + "    secrets:\n      SHH: x\n", nil},
	} {
		diags, src := checkCall(t, tt.caller, callee)
		wantCodes(t, tt.name+": "+src, diags, tt.want...)
	}
}

// Where CheckCall reports: a missing input at the key with, a missing
// secret at the value of uses when there is no secrets, an undefined name
// at its key, a wrong value at the value.
func TestCheckCallPlaces(t *testing.T) {
	diags, src := checkCall(t, "    with:\n      req: r\n      b: nope\n      zz: z\n", callee)
	var got []string
	for _, d := range diags {
		got = append(got, d.Code.String()+" "+text(src, d.Span))
	}
	want := []string{"MissingKey with", "InvalidValue nope", "UnknownKey zz", "MissingKey ./.github/workflows/callee.yml"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Errorf("diagnostics %q, want %q", got, want)
	}
}

// A workflow without workflow_call cannot be called; one with only
// on: workflow_call defines no input and no secret.
func TestCheckCallCalled(t *testing.T) {
	notCallable := "on: workflow_dispatch\njobs:\n  c:\n    runs-on: x\n    steps: [{run: y}]\n"
	diags, src := checkCall(t, "", notCallable)
	if len(diags) != 1 || diags[0].Code != InvalidValue || text(src, diags[0].Span) != "./.github/workflows/callee.yml" {
		t.Errorf("not callable: %+v", diags)
	}
	bare := "on: workflow_call\njobs:\n  c:\n    runs-on: x\n    steps: [{run: y}]\n"
	diags, _ = checkCall(t, "    with:\n      a: x\n    secrets:\n      b: y\n", bare)
	wantCodes(t, "bare", diags, UnknownKey, UnknownKey)
	diags, _ = checkCall(t, "", bare)
	wantCodes(t, "bare, nothing given", diags)
}

// A step id or a need that YAML reads as a number is not judged: GitHub
// writes the number as a string its own way (an infinity is Infinity, which
// AsString writes +Inf), so judging it could report what GitHub takes.
// Not judging can only
// miss what GitHub rejects.
func TestNumberIDsNotJudged(t *testing.T) {
	for _, src := range []string{
		"on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - {id: .inf, run: x}\n",
		"on: push\njobs:\n  a:\n    runs-on: x\n    steps: [{run: y}]\n  b:\n    runs-on: x\n    steps: [{run: y}]\n    needs: .inf\n",
	} {
		_, diags, _ := parse(t, src)
		wantCodes(t, src, diags)
	}
}

// within is the span of sub inside the first occurrence of ctx in src.
func within(t *testing.T, src, ctx, sub string) cst.Span {
	t.Helper()
	c := at(t, src, ctx)
	i := strings.Index(src[c.Start:c.End], sub)
	if i < 0 {
		t.Fatalf("%q not in %q", sub, ctx)
	}
	return cst.Span{Start: c.Start + i, End: c.Start + i + len(sub)}
}

// TestParallelForms: parallel groups and wait-all: a group in a group,
// an empty group and wait-all: false are rejected; wait-all: true, an empty
// wait-all and a group of one level are taken.
func TestParallelForms(t *testing.T) {
	const bg = "      - {id: a, run: x, background: true}\n"
	for _, tt := range []struct {
		name, steps string
		ctx, sub    string // where the diagnostic is: sub inside ctx
		msg         string
		want        []Code
	}{
		{"nested", "      - parallel:\n          - parallel:\n              - {run: x}\n          - {run: y}\n", "- parallel:\n              -", "parallel", "inside another parallel group", []Code{InvalidValue}},
		{"empty", "      - parallel: []\n", "parallel: []", "[]", "at least one step", []Code{InvalidValue}},
		{"wait-all false", bg + "      - wait-all: false\n", "wait-all: false", "false", "wait-all cannot be false", []Code{InvalidValue}},
		{"wait-all FALSE", bg + "      - wait-all: FALSE\n", "wait-all: FALSE", "FALSE", "wait-all cannot be false", []Code{InvalidValue}},
		{"wait-all true", bg + "      - wait-all: true\n", "", "", "", nil},
		{"wait-all empty", bg + "      - wait-all:\n", "", "", "", nil},
		{"group", "      - parallel:\n          - {run: x}\n          - {run: y}\n", "", "", "", nil},
		{"wait-all invalid", bg + "      - wait-all: x\n", "wait-all: x", "x", "unexpected value", []Code{InvalidValue}},
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n" + tt.steps
		_, diags, _ := parse(t, src)
		wantCodes(t, tt.name, diags, tt.want...)
		if len(diags) != 1 || tt.ctx == "" {
			continue
		}
		if sp := within(t, src, tt.ctx, tt.sub); diags[0].Span != sp || !strings.Contains(diags[0].Msg, tt.msg) {
			t.Errorf("%s: diagnostic %+v, want at %q with %q", tt.name, diags[0], tt.sub, tt.msg)
		}
	}
}

// A wait-all: false reached through an alias is reported where the alias
// is used, with the shared content as Related.
func TestParallelFormsAlias(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - &w {wait-all: false}\n      - *w\n"
	_, diags, _ := parse(t, src)
	wantCodes(t, src, diags, InvalidValue, InvalidValue)
	if len(diags) == 2 && (text(src, diags[1].Span) != "*w" || len(diags[1].Related) != 1 || text(src, diags[1].Related[0]) != "false") {
		t.Errorf("diagnostic %+v", diags[1])
	}
}

// TestStepTargets: wait and cancel name ids: a name that is not the id
// of any step of the job is rejected. Ids are compared without case and
// any step counts, a later one, one not in the background and one of a
// group included, since whether GitHub takes those is not known. When the
// ids of the steps are not known, nothing is reported.
func TestStepTargets(t *testing.T) {
	const bg = "      - {id: a, run: x, background: true}\n"
	for _, tt := range []struct {
		name, steps string
		ctx, sub    string // where the diagnostic of the name is: sub inside ctx
		want        []Code
	}{
		{"wait unknown", bg + "      - wait: nosuch\n", "wait: nosuch", "nosuch", []Code{InvalidValue}},
		{"cancel unknown", bg + "      - cancel: nosuch\n", "cancel: nosuch", "nosuch", []Code{InvalidValue}},
		{"wait list", bg + "      - wait: [a, nosuch]\n", "nosuch", "nosuch", []Code{InvalidValue}},
		{"reserved", bg + "      - wait: __a\n", "wait: __a", "__a", []Code{InvalidValue}},
		{"wait", bg + "      - wait: a\n", "", "", nil},
		{"cancel", bg + "      - cancel: a\n", "", "", nil},
		{"case", bg + "      - wait: A\n", "", "", nil},
		{"later", "      - wait: b\n      - {id: b, run: x, background: true}\n", "wait: b", "b", []Code{InvalidValue}},
		{"cancel later", "      - cancel: b\n      - {id: b, run: x, background: true}\n", "cancel: b", "b", []Code{InvalidValue}},
		{"not background", "      - {id: c, run: x}\n      - wait: c\n", "", "", nil},
		{"in a group", "      - parallel:\n          - {id: g, run: x}\n          - {run: y}\n      - wait: g\n", "", "", nil},
		{"own id", "      - {id: w, wait: w}\n", ": w}", "w", []Code{InvalidValue}},
		{"cancel own id", bg + "      - {id: w, cancel: w}\n", "cancel: w", "w", []Code{InvalidValue}},
		{"generated id", "      - {run: x, background: true}\n      - wait: __run\n", "wait: __run", "__run", []Code{InvalidValue}},
		{"cancel not background", "      - {id: c, run: x}\n      - cancel: c\n", "", "", nil},
		{"cancel in a group id", "      - parallel:\n          - {id: g, run: x}\n          - {run: y}\n      - cancel: G\n", "", "", nil},
		// a ${{ }} GitHub folds is read as its string
		{"id folded", "      - {id: \"${{ 'a' }}\", run: x, background: true}\n      - wait: a\n", "", "", nil},
		{"id folded unknown", "      - {id: \"${{ 'a' }}\", run: x, background: true}\n      - wait: nosuch\n", "wait: nosuch", "nosuch", []Code{InvalidValue}},
		{"name folded", bg + "      - wait: \"${{ 'a' }}\"\n", "", "", nil},
		{"name folded unknown", bg + "      - cancel: \"${{ 'nosuch' }}\"\n", "", "", []Code{InvalidValue}},
		// the ids are not known: nothing about the names
		{"id expr", "      - {id: \"${{ github.sha }}\", run: x, background: true}\n      - wait: nosuch\n", "", "", []Code{ExprNotAllowed}},
		{"id null", "      - {id: ~, run: x, background: true}\n      - wait: nosuch\n", "", "", []Code{InvalidValue}},
		{"id number", "      - {id: 1, run: x, background: true}\n      - wait: nosuch\n", "", "", nil},
		{"step not read", "      - ${{ github.x }}\n      - wait: nosuch\n", "", "", []Code{ExprNotAllowed}},
		{"nested group", "      - parallel:\n          - parallel:\n              - {id: n, run: x}\n          - {run: y}\n      - wait: n\n", "", "", []Code{InvalidValue}},
		// the names not judged
		{"name number", bg + "      - wait: 1\n", "", "", nil},
		{"name bool", bg + "      - wait: true\n", "", "", nil},
		{"name expr", bg + "      - wait: \"${{ github.sha }}\"\n", "", "", []Code{ExprNotAllowed}},
		{"cancel invalid", bg + "      - cancel: [a]\n", "", "", []Code{WrongKind}},
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n" + tt.steps
		_, diags, _ := parse(t, src)
		wantCodes(t, tt.name, diags, tt.want...)
		if len(diags) != 1 || tt.ctx == "" {
			continue
		}
		if sp := within(t, src, tt.ctx, tt.sub); diags[0].Span != sp || !strings.Contains(diags[0].Msg, `"`+tt.sub+`"`) || !strings.Contains(diags[0].Msg, "refers to the step id") {
			t.Errorf("%s: diagnostic %+v, want at %q", tt.name, diags[0], tt.sub)
		}
	}
}

// A name reached through an alias is reported where the alias is used,
// with the shared content as Related.
func TestStepTargetsAlias(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - &w {wait: nosuch}\n      - *w\n"
	_, diags, _ := parse(t, src)
	wantCodes(t, src, diags, InvalidValue, InvalidValue)
	if len(diags) == 2 && (text(src, diags[0].Span) != "nosuch" || text(src, diags[1].Span) != "*w" || len(diags[1].Related) != 1 || text(src, diags[1].Related[0]) != "nosuch") {
		t.Errorf("diagnostics %+v", diags)
	}
}

// The examples of wait, wait-all and cancel in GitHub's workflow syntax
// (github/docs 484d6eae00bf31f731eeada8ebc2d3b6a46e3145,
// workflow-syntax.md, L1134, L1167 and L1190): each names an earlier
// background step, or waits for all, and has no diagnostics.
func TestParallelDocsExamples(t *testing.T) {
	const steps = "      - {id: build-frontend, run: x, background: true}\n      - {id: build-backend, run: x, background: true}\n      - {id: monitor, run: x, background: true}\n"
	for _, s := range []string{
		"      - wait: [build-frontend, build-backend]\n",
		"      - wait-all:\n",
		"      - cancel: monitor\n",
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n" + steps + s
		_, diags, _ := parse(t, src)
		wantCodes(t, s, diags)
	}
}

// TestStepsInGroup: wait, wait-all and cancel in a parallel group are rejected, once each,
// wait-all: false included.
func TestStepsInGroup(t *testing.T) {
	const bg = "      - {id: a, run: x, background: true}\n"
	for _, key := range []string{"wait: a", "wait-all:", "wait-all: false", "cancel: a", "wait: nosuch"} {
		src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n" + bg + "      - parallel:\n          - " + key + "\n          - {run: y}\n"
		_, diags, _ := parse(t, src)
		wantCodes(t, src, diags, InvalidValue)
		k, _, _ := strings.Cut(key, ":")
		if len(diags) == 1 && (diags[0].Span != within(t, src, "- "+key, k) || !strings.Contains(diags[0].Msg, k+": cannot be written in a step of a parallel group")) {
			t.Errorf("%s: diagnostic %+v", key, diags[0])
		}
	}
}

// An empty group and a group in a group reached through an alias are
// reported where the alias is used. The anchors are under a key the schema
// does not have (UnknownKey), as no place of a workflow takes them alone.
func TestParallelFormsGroupAlias(t *testing.T) {
	for _, tt := range []struct{ src, at, related string }{
		{"on: push\nx: &e []\njobs:\n  a:\n    runs-on: x\n    steps:\n      - parallel: *e\n", "*e", "&e []"}, // the content span of a node keeps its anchor
		{"on: push\nx: &p {parallel: [{run: c}]}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - parallel:\n          - *p\n          - {run: y}\n", "*p", "parallel"},
	} {
		_, diags, _ := parse(t, tt.src)
		wantCodes(t, tt.src, diags, UnknownKey, InvalidValue)
		if len(diags) == 2 && (text(tt.src, diags[1].Span) != tt.at || len(diags[1].Related) != 1 || text(tt.src, diags[1].Related[0]) != tt.related) {
			t.Errorf("%q: diagnostic %+v", tt.src, diags[1])
		}
	}
}

// A step id or a need that is exactly a string literal in ${{ }} is
// judged by the string GitHub folds it to.
func TestFoldedIDs(t *testing.T) {
	for _, tt := range []struct {
		src  string
		want []Code
	}{
		{"on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - {id: \"${{ '1a' }}\", run: x}\n", []Code{InvalidValue}},
		{"on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - {id: s, run: x}\n      - {id: \"${{ 'S' }}\", run: x}\n", []Code{InvalidValue}},
		{"on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - {id: \"${{ 'a' }}\", run: x}\n", nil},
		{"on: push\njobs:\n  a:\n    runs-on: x\n    steps: [{run: y}]\n  b:\n    runs-on: x\n    steps: [{run: y}]\n    needs: \"${{ 'nosuch' }}\"\n", []Code{InvalidValue}},
		{"on: push\njobs:\n  a:\n    runs-on: x\n    steps: [{run: y}]\n  b:\n    runs-on: x\n    steps: [{run: y}]\n    needs: \"${{ 'a' }}\"\n", nil},
		// a job key
		{"on: push\njobs:\n  \"${{ 'a' }}\":\n    runs-on: x\n    steps: [{run: y}]\n  b:\n    runs-on: x\n    steps: [{run: y}]\n    needs: a\n", nil},
		{"on: push\njobs:\n  \"${{ 'a' }}\":\n    runs-on: x\n    steps: [{run: y}]\n  b:\n    runs-on: x\n    steps: [{run: y}]\n    needs: nosuch\n", []Code{InvalidValue}},
	} {
		_, diags, _ := parse(t, tt.src)
		wantCodes(t, tt.src, diags, tt.want...)
	}
}

// The second part of the message of an unknown name, giving the id to an
// earlier step, is left out when GitHub would reject that in turn: a name
// starting with __ (reserved) and the step's own id (a duplicate).
func TestStepTargetsAdvice(t *testing.T) {
	const bg = "      - {id: a, run: x, background: true}\n"
	for _, tt := range []struct {
		steps string
		give  bool
	}{
		{bg + "      - wait: nosuch\n", true},
		{"      - {run: x, background: true}\n      - wait: __run\n", false},
		{bg + "      - {id: w, wait: w}\n", false},
		{bg + "      - {id: W, cancel: w}\n", false},
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n" + tt.steps
		_, diags, _ := parse(t, src)
		wantCodes(t, tt.steps, diags, InvalidValue)
		if len(diags) == 1 && strings.Contains(diags[0].Msg, "or give the id") != tt.give {
			t.Errorf("%q: %s", tt.steps, diags[0].Msg)
		}
	}
}

// A wait in a group reached through an alias is reported where the alias
// is used.
func TestStepsInGroupAlias(t *testing.T) {
	src := "on: push\nx: &g {wait: a}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - {id: a, run: x, background: true}\n      - parallel:\n          - *g\n          - {run: y}\n"
	_, diags, _ := parse(t, src)
	wantCodes(t, src, diags, UnknownKey, InvalidValue)
	if len(diags) == 2 && (text(src, diags[1].Span) != "*g" || len(diags[1].Related) != 1 || text(src, diags[1].Related[0]) != "wait") {
		t.Errorf("diagnostic %+v", diags[1])
	}
}

// A job whose key the reader cannot read is left out of the jobs, and may
// be the job with no needs, so that is not reported; a cycle of the jobs
// read still is.
func TestNeedsDroppedJob(t *testing.T) {
	src := "on: push\njobs:\n  ${{ github.sha }}:\n    runs-on: x\n    steps: [{run: y}]\n  b:\n    runs-on: x\n    steps: [{run: y}]\n    needs: c\n  c:\n    runs-on: x\n    steps: [{run: y}]\n    needs: b\n"
	_, diags, _ := parse(t, src)
	wantCodes(t, src, diags, ExprNotAllowed, InvalidValue, InvalidValue)
	for _, d := range diags {
		if strings.Contains(d.Msg, "at least one job with no needs") {
			t.Errorf("%+v", d)
		}
	}
}
