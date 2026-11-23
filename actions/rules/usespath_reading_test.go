package rules

import (
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// The rules read the action a step's uses runs as GitHub reads the uses,
// not as written.

const scriptSHA = "60a0d83039c74a4aee543508d2ffcb1c3799cdea"

// scriptWorkflow is a workflow on issues whose steps are steps, the last
// of them given the script of github-script.
func scriptWorkflow(steps ...string) map[string]string {
	src := "on: issues\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
	for _, s := range steps {
		src += "      - uses: " + s + "\n"
	}
	src += "        with:\n          script: console.log(\"${{ github.event.issue.title }}\")\n"
	return wfFile(src)
}

// TestReadingDotPathCodeInjection: actions/github-script/.@…
// runs github-script.
func TestReadingDotPathCodeInjection(t *testing.T) {
	for _, uses := range []string{"actions/github-script/.@" + scriptSHA, "actions/github-script/x/..@" + scriptSHA, "actions/github-script/@" + scriptSHA} {
		rep, in := injection(t, scriptWorkflow(uses))
		if got := at(t, rep, in); !slices.Equal(got, []string{".github/workflows/w.yml github.event.issue.title"}) {
			t.Errorf("%s: findings at %q", uses, got)
		}
	}
}

// TestReadingEmptyPartsValid: GitHub drops empty parts, so
// the input is not invalid.
func TestReadingEmptyPartsValid(t *testing.T) {
	src := "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: /o/r/x@" + scriptSHA + "\n      - uses: o//r/x@" + scriptSHA + "\n      - uses: actions/github-script/@" + scriptSHA + "\n"
	_, in := injection(t, wfFile(src))
	for _, i := range in.List {
		if len(i.Diagnostics) != 0 {
			t.Errorf("%s: diagnostics %v", i.Name, i.Diagnostics)
		}
	}
}

// TestReadingNestedDownload: a path above the root of its
// repository runs the github-script that a composite action's uses
// downloaded, with the step's script.
func TestReadingNestedDownload(t *testing.T) {
	rep, in := injection(t, scriptWorkflow("o/r/acts/comp@"+scriptSHA, "o/r/../../../actions/github-script/v7@"+scriptSHA))
	if got := at(t, rep, in); !slices.Equal(got, []string{".github/workflows/w.yml github.event.issue.title"}) {
		t.Errorf("findings at %q", got)
	}
}

// TestOutsideIsNoAction: a path that names no directory of an action is
// no action, not the root one of its repository.
func TestOutsideIsNoAction(t *testing.T) {
	rep, in := injection(t, scriptWorkflow("actions/github-script/x/../..@v7"))
	if got := at(t, rep, in); len(got) != 0 {
		t.Errorf("findings at %q", strings.Join(got, ", "))
	}
}

// TestReadingRunRef: the release of actions/checkout that runs is the ref
// of the directory the path names, not the ref written after @:
// a path above the root that runs checkout v1
// with the head of a pull request is read as checkout v1, written plainly.
func TestReadingRunRef(t *testing.T) {
	src := func(second string) map[string]string {
		return wfFile("on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v1\n" +
			"      - uses: " + second + "\n        with: {ref: \"${{ github.event.pull_request.head.sha }}\"}\n      - run: make\n")
	}
	plain, _, _ := checkRules(t, []lint.Rule{UntrustedCheckout}, src("actions/checkout@v1"), nil)
	outside, _, _ := checkRules(t, []lint.Rule{UntrustedCheckout}, src("o/r/../../../actions/checkout/v1@v7"), nil)
	if len(plain.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) == 0 || len(outside.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != len(plain.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) {
		t.Errorf("findings: written plainly %d, above the root %d", len(plain.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), len(outside.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
}
