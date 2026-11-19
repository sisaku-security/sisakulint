package workflow

import (
	"fmt"
	"strings"
	"testing"
)

// The values of the keys the model keeps as nodes are checked against the
// schema (checkRest); what the typed reading checks is not reported twice.
func TestCheckRest(t *testing.T) {
	for _, tt := range []struct {
		name, src string
		want      []Code
	}{
		{"background", "    steps:\n      - run: a\n        background: yes-please\n", []Code{InvalidValue}},
		{"background ok", "    steps:\n      - run: a\n        background: true\n", nil},
		{"cancel sequence", "    steps:\n      - cancel: [a]\n", []Code{WrongKind}},
		{"cancel ok", "    steps:\n      - {id: a, run: x, background: true}\n      - cancel: a\n", nil},
		{"wait empty", "    steps:\n      - wait: \"\"\n", []Code{InvalidValue}},
		{"wait list", "    steps:\n      - {id: a, run: x, background: true}\n      - {id: b, run: x, background: true}\n      - wait: [a, b]\n", nil},
		{"wait-all number", "    steps:\n      - wait-all: 3\n", []Code{InvalidValue}},
		{"wait-all null", "    steps:\n      - wait-all:\n", nil},
		{"wait-all bool", "    steps:\n      - wait-all: true\n", nil},
		{"step timeout", "    steps:\n      - run: a\n        timeout-minutes: abc\n", []Code{InvalidValue}},
		{"step continue-on-error", "    steps:\n      - run: a\n        continue-on-error: [1]\n", []Code{WrongKind}},
		{"working-directory", "    steps:\n      - run: a\n        working-directory: [x]\n", []Code{WrongKind}},
		{"job timeout", "    timeout-minutes: abc\n    steps:\n      - run: a\n", []Code{InvalidValue}},
		{"defaults beyond shell", "    defaults:\n      run:\n        working-directory: [x]\n    steps:\n      - run: a\n", []Code{WrongKind}},
		{"strategy beyond matrix", "    strategy:\n      fail-fast: maybe\n    steps:\n      - run: a\n", []Code{InvalidValue}},
		{"dynamic strategy", "    strategy: ${{ fromJSON(vars.s) }}\n    steps:\n      - run: a\n", nil},
		{"typed once", "    steps:\n      - run: [a]\n", []Code{WrongKind}},
		{"parallel unknown key", "    steps:\n      - parallel:\n          - run: a\n            bogus: 1\n", []Code{UnknownKey}},
		{"parallel expr once", "    steps:\n      - parallel:\n          - run: echo ${{ a == }}\n", []Code{ExprSyntax}},
		// cache-mode, a schema addition: the values GitHub rejected on
		// the runs observed on GitHub
		{"cache-mode bogus", "    cache-mode: bogus\n    steps:\n      - run: a\n", []Code{InvalidValue}},
		{"cache-mode upper", "    cache-mode: WRITE\n    steps:\n      - run: a\n", []Code{InvalidValue}},
		{"cache-mode null", "    cache-mode:\n    steps:\n      - run: a\n", []Code{InvalidValue}},
		{"cache-mode context", "    cache-mode: ${{ github.event_name == 'push' && 'read' || 'write' }}\n    steps:\n      - run: a\n", []Code{ExprNotAllowed}},
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: x\n" + tt.src
		_, diags, _ := parse(t, src)
		wantCodes(t, tt.name, diags, tt.want...)
	}
}

// TestCheckRestAlias: like a typed key, a key kept as a node is reported
// where each alias uses it.
func TestCheckRestAlias(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - &s\n        run: a\n        timeout-minutes: abc\n      - *s\n"
	_, diags, _ := parse(t, src)
	wantCodes(t, "alias", diags, InvalidValue, InvalidValue)
	if len(diags) == 2 && (text(src, diags[1].Span) != "*s" || len(diags[1].Related) != 1) {
		t.Errorf("the second is at %q: %v", text(src, diags[1].Span), diags[1])
	}
}

// TestCheckRestAction: an action.yml's root takes any other key (branding),
// and a composite step's keys kept as nodes are checked.
func TestCheckRestAction(t *testing.T) {
	src := "name: a\nbranding:\n  color: pink\nruns:\n  using: composite\n  steps:\n    - run: echo\n      shell: bash\n"
	_, diags, _ := parseAction(t, src)
	wantCodes(t, "branding", diags)
	src = "runs:\n  using: composite\n  steps:\n    - run: echo\n      shell: bash\n      continue-on-error: [1]\n"
	_, diags, _ = parseAction(t, src)
	wantCodes(t, "composite step", diags, WrongKind)
}

// TestCheckRestNestedAlias: what nested aliases stand for is walked once,
// and a problem in it is reported once, where it is first reached; the
// reviewer's shape (each level ten aliases of the one before) is read at
// once.
func TestCheckRestNestedAlias(t *testing.T) {
	// a service's options, which the typed reading does not read, is
	// reported where it is written, and where *s uses it in job b; through
	// *ss and then *s in job c, it is the same content reached again
	// through nested aliases, not reported again. (Every key of a step is
	// typed; the typed reading reports where each use is.)
	src := "on: push\njobs:\n" +
		"  a:\n    runs-on: x\n    services: {s: &s {image: x, options: [1]}}\n    steps: [{run: a}]\n" +
		"  b:\n    runs-on: x\n    services: &ss {t: *s}\n    steps: [{run: a}]\n" +
		"  c:\n    runs-on: x\n    services: *ss\n    steps: [{run: a}]\n"
	_, diags, _ := parse(t, src)
	wantCodes(t, "nested", diags, WrongKind, WrongKind)
	var b strings.Builder
	b.WriteString("on: push\njobs:\n  a:\n    runs-on: x\n    strategy:\n      matrix:\n        l0: &l0 [x, x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i <= 8; i++ {
		fmt.Fprintf(&b, "        l%d: &l%d [%s]\n", i, i, strings.TrimSuffix(strings.Repeat(fmt.Sprintf("*l%d, ", i-1), 10), ", "))
	}
	b.WriteString("    steps:\n      - run: a\n")
	_, diags, _ = parse(t, b.String())
	wantCodes(t, "ten by eight", diags)
}
