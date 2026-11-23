package workflow

import (
	"strings"
	"testing"
)

// TestExprNames checks the contexts and the functions of the ${{ }} at each
// place.
func TestExprNames(t *testing.T) {
	job := func(jobKeys, steps string) string {
		return "on: push\njobs:\n  a:\n    runs-on: x\n" + jobKeys + "    steps:\n" + steps
	}
	run := func(s string) string { return "      - run: echo \"" + s + "\"\n" }
	ok := run("ok")
	for _, tt := range []struct {
		src  string
		bad  string // the input under the diagnostic, "" for none
		want []Code
	}{
		{job("    concurrency: ${{ secrets.FOO }}\n", ok), "secrets", []Code{ExprSyntax}},
		{job("    if: ${{ secrets.FOO != '' }}\n", ok), "secrets", []Code{ExprSyntax}},
		{job("    env:\n      H: ${{ hashFiles('x') }}\n", ok), "hashFiles", []Code{ExprSyntax}},
		{job("", run("${{ withJson() }}")), "withJson", []Code{ExprSyntax}},
		{job("", run("${{ contains('a', 'b', 'c') }}")), "contains('a', 'b', 'c')", []Code{ExprSyntax}},
		{job("", run("${{ case(true, 'a') }}")), "case(true, 'a')", []Code{ExprSyntax}},
		{job("", run("${{ toJSON() }}")), "toJSON()", []Code{ExprSyntax}},
		{job("", run("${{ always() }}")), "always", []Code{ExprSyntax}},
		{job("", "      - if: ${{ failure('a') }}\n        run: a\n"), "failure('a')", []Code{ExprSyntax}},
		{"on: push\nenv:\n  A: a\n  B: ${{ env.A }}\n" + jobsOK, "env", []Code{ExprSyntax}},
		{job("    env:\n      S: ${{ steps.a.outcome }}\n", ok), "steps", []Code{ExprSyntax}},
		{job("", "      - env:\n          H: ${{ hashFiles('x') }}\n        run: a\n"), "", nil},
		{job("", run("${{ GITHUB.SHA }} ${{ Github.Sha }}")), "", nil},
		{job("", run("${{ case(true, 'a', 'b') }}")), "", nil},
		{job("    if: ${{ failure('a') }}\n", ok), "", nil},
		{job("", run("${{ matrix.x }}")), "", nil},
		{job("", run("${{ github.nonexistent }} ${{ steps.nope.outputs.x }}")), "", nil},
		{job("", run("${{ TOJSON(github.event_name) }}")), "", nil},
		{job("", run("${{ 'x' }}")), "", nil},
		// either schema's contexts are allowed in snapshot.
		{job("    snapshot:\n      image-name: i\n      if: ${{ steps.a.outcome == 'success' }}\n", ok), "", nil},
		{job("    strategy:\n      matrix:\n        x: [i]\n    snapshot: ${{ matrix.x }}\n", ok), "", nil},
		// a key that is a ${{ }} is checked as at its mapping
		{job("    env:\n      ${{ steps.a }}: x\n", ok), "steps", []Code{ExprSyntax}},
		// the directive insert is no context (TemplateReader.MatchesDirective),
		// but only a whole key may be the directive
		{job("    env:\n      ${{ insert }}: x\n", ok), "", nil},
		{job("    env:\n      A: ${{ insert }}\n", ok), "insert", []Code{ExprSyntax}},
		{job("    env:\n      A: x ${{ insert }}\n", ok), "insert", []Code{ExprSyntax}},
		// the value of a ${{ }} key of a mapping of loose keys alone is
		// read against the loose value (container-env's values allow secrets)
		{job("    container:\n      image: node\n      env:\n        ${{ matrix.k }}: ${{ secrets.T }}\n", ok), "", nil},
		{job("    container:\n      image: node\n      env:\n        ${{ matrix.k }}: ${{ jobs.T }}\n", ok), "jobs", []Code{ExprSyntax}},
		// the value of a ${{ }} key of a mapping that only checkRest reads
		{job("    concurrency:\n      group: g\n      ${{ github.a }}: ${{ secrets.b }}\n", ok), "secrets", []Code{ExprSyntax}},
		// each ${{ }} of an if that is text and ${{ }}
		{job("", "      - if: x ${{ secrets.a }}\n        run: a\n"), "secrets", []Code{ExprSyntax}},
		// a value outside the schema is not read against it: no names are known there
		{job("    foo: ${{ secrets.a }}\n", ok), "foo", []Code{UnknownKey}},
		// two problems in one ${{ }}
		{job("    if: ${{ secrets.a == env.b }}\n", ok), "secrets", []Code{ExprSyntax, ExprSyntax}},
	} {
		_, diags, _ := parse(t, tt.src)
		wantCodes(t, tt.src, diags, tt.want...)
		if tt.bad != "" && len(diags) > 0 {
			if got := text(tt.src, diags[0].Span); got != tt.bad {
				t.Errorf("%q: diagnostic at %q, want %q", tt.src, got, tt.bad)
			}
		}
	}
}

// TestExprNamesStatus: a ${{ }} GitHub rejects for its names keeps its tree
// and its value.
func TestExprNamesStatus(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    timeout-minutes: ${{ secrets.FOO }}\n    steps: [{run: a}]\n"
	w, diags, _ := parse(t, src)
	wantCodes(t, src, diags, ExprSyntax)
	f := w.Jobs.Value.Entries[0].Value.Value.TimeoutMinutes
	if f.Status != Present {
		t.Fatalf("timeout-minutes is %v", f.Status)
	}
	if p := f.Value.Parts; len(p) != 1 || p[0].Tree == nil || len(p[0].Errs) > 0 {
		t.Errorf("the expression lost its tree: %+v", p)
	}
}

// TestExprNamesAlias: a shared ${{ }} is checked at each place it is used,
// and reported where the alias uses it.
func TestExprNamesAlias(t *testing.T) {
	// x-anchor is no key of the schema (UnknownKey); its value is shared
	// by the job's env, which does not allow steps, and the step's env,
	// which does.
	src := "on: push\nx-anchor: &s \"${{ steps.b.outcome }}\"\njobs:\n  a:\n    runs-on: x\n    env:\n      J: *s\n    steps:\n      - env:\n          S: *s\n        run: a\n"
	_, diags, _ := parse(t, src)
	var names []Diagnostic
	for _, d := range diags {
		if d.Code == ExprSyntax {
			names = append(names, d)
		}
	}
	if len(names) != 1 {
		t.Fatalf("%q: diagnostics %v, want one ExprSyntax", src, diags)
	}
	if got := text(src, names[0].Span); got != "*s" {
		t.Errorf("reported at %q, want the alias of the job's env", got)
	}
	if len(names[0].Related) != 1 || !strings.Contains(text(src, names[0].Related[0]), "steps") {
		t.Errorf("related %v, want the anchor's steps", names[0].Related)
	}
}

// TestBareIfNames checks the if without ${{ }}, with the forms GitHub was
// seen to accept and reject.
func TestBareIfNames(t *testing.T) {
	for _, tt := range []struct {
		jobIf, stepIf string
		want          []Code
	}{
		{"secrets.FOO != ''", "", []Code{ExprSyntax}},
		{"", "secrets.FOO != ''", []Code{ExprSyntax}},
		{"hashFiles('x') == ''", "", []Code{ExprSyntax}},
		{"", "hashFiles('x') == ''", nil},
		{"failure('a')", "", nil},
		{"", "failure('a')", []Code{ExprSyntax}},
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: x\n"
		if tt.jobIf != "" {
			src += "    if: " + tt.jobIf + "\n"
		}
		src += "    steps:\n      - run: a\n"
		if tt.stepIf != "" {
			src += "        if: " + tt.stepIf + "\n"
		}
		_, diags, _ := parse(t, src)
		wantCodes(t, src, diags, tt.want...)
	}
	for _, tt := range []struct {
		cond string
		bad  bool
	}{
		{`needs.x.result == 'success'`, false},
		{`vars.FOO == ''`, false},
		{`hashFiles('x') == ''`, false},
		{`always()`, false},
		{`${{ 'needs.x.result' }}`, false},
		{`steps.a.outcome == '' && strategy.job-index == 0 && matrix.x == '' && github.sha != '' && inputs.i == '' && job.status != '' && runner.os != '' && env.E == ''`, false},
		{`cancelled() || success() || failure() || hashFiles('x', 'y') == ''`, false},
		{`secrets.FOO == ''`, true},
		{`failure('x')`, true},
		{`${{ needs.x.result == 'success' }}`, true},
		{`${{ vars.FOO == '' }}`, true},
		{`withJson()`, true},
		{`jobs.x.result == ''`, true},
		{`${{ 'secrets.FOO' }}`, true},
		{`always('x')`, true},
		{`hashFiles() == ''`, true},
		{`cancelled('x')`, true},
		{`success('x')`, true},
	} {
		src := "inputs:\n  i:\n    description: i\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      if: \"" + tt.cond + "\"\n      run: echo ran\n"
		_, diags, _ := parseAction(t, src)
		var want []Code
		if tt.bad {
			want = []Code{ExprSyntax}
		}
		wantCodes(t, src, diags, want...)
		if tt.bad && strings.HasPrefix(tt.cond, "${{ '") && len(diags) == 1 {
			if got := text(src, diags[0].Span); got != `"`+tt.cond+`"` {
				t.Errorf("%s: reported at %q, want the whole value", tt.cond, got)
			}
		}
	}
}

// TestActionNames: the runner reads the args of a Docker action with the
// context inputs alone (runner-action_yaml.json container-runs-context).
func TestActionNames(t *testing.T) {
	for _, tt := range []struct {
		arg  string
		want []Code
	}{
		{"${{ github.sha }}", []Code{ExprSyntax}},
		{"${{ inputs.a }}", nil},
	} {
		src := "inputs:\n  a:\n    description: a\nruns:\n  using: docker\n  image: x\n  args: [\"" + tt.arg + "\"]\n"
		_, diags, _ := parseAction(t, src)
		wantCodes(t, src, diags, tt.want...)
	}
}
