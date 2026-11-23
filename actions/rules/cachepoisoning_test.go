package rules

import (
	"fmt"
	"testing"
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

// runCache runs cache-poisoning alone on the repository of files.
func runCache(t *testing.T, files map[string]string) lint.Report {
	t.Helper()
	fsys := fstest.MapFS{}
	for n, s := range files {
		fsys[n] = &fstest.MapFile{Data: []byte(s)}
	}
	in, err := lint.Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	return runAlone(t, CachePoisoning, in)
}

const cacheCalledJob = "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    cache-mode: %s\n    steps:\n      - run: make\n"

// TestCacheCallerLimit: a caller that writes write, of a local workflow
// whose jobs all write read or none, saves nothing (a called workflow may
// ask for less than its caller's limit); of one that writes write, its fix
// would make the call ask past the limit, which GitHub refuses to start.
func TestCacheCallerLimit(t *testing.T) {
	ci := "on: pull_request_target\njobs:\n  c:\n    cache-mode: write\n    uses: ./.github/workflows/called.yml\n"
	for _, c := range []struct {
		called  string
		finding bool
		fix     bool
	}{
		{"read", false, false},
		{"none", false, false},
		{"write", true, false},
	} {
		rep := runCache(t, map[string]string{".github/workflows/ci.yml": ci, ".github/workflows/called.yml": fmt.Sprintf(cacheCalledJob, c.called)})
		var got []lint.Finding
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			if f.Args.KindID() == kindCachePoisoningWritableJob {
				got = append(got, f)
			}
		}
		if (len(got) > 0) != c.finding {
			t.Errorf("called %s: findings %v", c.called, kindsOf(rep))
			continue
		}
		for _, f := range got {
			if f.Location.File.Input.String() != ".github/workflows/ci.yml" {
				continue
			}
			if (f.Fix != nil) != c.fix || (f.Fix == nil && f.NoFix == nil) {
				t.Errorf("called %s: fix %v nofix %v", c.called, f.Fix, f.NoFix)
			}
		}
	}
}

// TestSavedCheckoutTwoPlaces: two checkouts of the same reference into two
// places, both under the saved path, are two findings, not one reported
// twice.
func TestSavedCheckoutTwoPlaces(t *testing.T) {
	co := func(p string) string {
		return "      - uses: actions/checkout@v4\n        with: {ref: \"${{ github.event.pull_request.head.sha }}\", path: " + p + ", allow-unsafe-pr-checkout: true}\n"
	}
	for _, path := range []string{".", "${{ matrix.x }}"} {
		src := "on: pull_request_target\njobs:\n  a:\n    runs-on: x\n    cache-mode: write\n    strategy: {matrix: {x: [a]}}\n    steps:\n" + co("one") + co("two") +
			"      - uses: actions/cache@v4\n        with: {key: k, path: \"" + path + "\"}\n"
		rep := runCache(t, map[string]string{".github/workflows/w.yml": src})
		if len(rep.Errors) != 0 {
			t.Errorf("path %s: errors %+v", path, rep.Errors)
		}
	}
}

// TestSavedCheckoutSaveIf: a save whose if keeps the attacker's event out
// saves nothing of theirs.
func TestSavedCheckoutSaveIf(t *testing.T) {
	src := "on: [push, pull_request_target]\njobs:\n  a:\n    runs-on: x\n    cache-mode: write\n    steps:\n" +
		"      - uses: actions/checkout@v4\n        with: {ref: \"${{ github.event.pull_request.head.sha || github.sha }}\", allow-unsafe-pr-checkout: true}\n" +
		"      - if: github.event_name == 'push'\n        uses: actions/cache/save@v4\n        with: {key: k, path: dist}\n"
	rep := runCache(t, map[string]string{".github/workflows/w.yml": src})
	for _, k := range kindsOf(rep) {
		if k == kindCachePoisoningSavedCheckout {
			t.Errorf("findings %v", kindsOf(rep))
		}
	}
}
