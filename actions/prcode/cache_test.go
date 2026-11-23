package prcode

import (
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
)

// TestCacheSaves: the steps that save the tree a checkout brings to the
// cache: actions/cache/save that may run after it, and actions/cache in
// the job, whose post step saves at its end; a clean checkout of the
// same place after it takes the tree away; a path saves the tree when a
// line of it is the tree, in it or above it.
func TestCacheSaves(t *testing.T) {
	const co = "      - uses: actions/checkout@v4\n        with: {ref: \"${{ github.event.pull_request.head.sha }}\"}\n"
	cache := func(uses, path string) string {
		return "      - uses: " + uses + "\n        with:\n          key: k\n          path: " + path + "\n"
	}
	for _, c := range []struct {
		name, steps string
		want        []string // the line, ? before an unknown one
	}{
		{"save after", co + cache("actions/cache/save@v4", "node_modules"), []string{"node_modules"}},
		{"save before", cache("actions/cache/save@v4", "node_modules") + co, nil},
		{"cache before: its post saves at the end", cache("actions/cache@v4", "dist") + co, []string{"dist"}},
		{"restore only", co + cache("actions/cache/restore@v4", "node_modules"), nil},
		{"out of the workspace", co + cache("actions/cache@v4", "~/.npm"), nil},
		{"absolute", co + cache("actions/cache@v4", "/tmp/x"), nil},
		{"the workspace", co + cache("actions/cache@v4", "${{ github.workspace }}/build"), []string{"${{ github.workspace }}/build"}},
		{"a glob", co + cache("actions/cache@v4", "\"**/node_modules\""), []string{"**/node_modules"}},
		{"lines", co + cache("actions/cache@v4", "|\n            ~/.npm\n            !dist\n            dist"), []string{"dist"}},
		{"unknown", co + cache("actions/cache@v4", "${{ matrix.dir }}"), []string{"?${{ matrix.dir }}"}},
		{"a clean checkout after", co + "      - uses: actions/checkout@v4\n" + cache("actions/cache@v4", "dist"), nil},
		{"a clean checkout after, save before it", co + cache("actions/cache/save@v4", "dist") + "      - uses: actions/checkout@v4\n", []string{"dist"}},
		{"the parent of the workspace", co + cache("actions/cache@v4", "../go/pkg/mod"), nil},
		{"a .. inside", co + cache("actions/cache@v4", "dist/../dist"), nil},
		{"a . segment after the first is refused", co + cache("actions/cache@v4", "dist/./x"), nil},
		{"~ only with a slash is home", co + cache("actions/cache@v4", "~pr"), []string{"~pr"}},
		{"the parent through the workspace", co + cache("actions/cache@v4", "${{ github.workspace }}/../x"), nil},
		{"the workspace with no spaces", co + cache("actions/cache@v4", "${{github.workspace}}/dist"), []string{"${{github.workspace}}/dist"}},
		{"an environment variable is not expanded", co + cache("actions/cache@v4", "$GITHUB_WORKSPACE/dist"), []string{"$GITHUB_WORKSPACE/dist"}},
		{"nor runner.temp's", co + cache("actions/cache@v4", "$RUNNER_TEMP/x"), []string{"$RUNNER_TEMP/x"}},
		{"the expression of runner.temp is out of it", co + cache("actions/cache@v4", "${{ runner.temp }}/x"), nil},
		{"the workspace by an index", co + cache("actions/cache@v4", "\"${{ github['workspace'] }}/build\""), []string{"${{ github['workspace'] }}/build"}},
		{"the workspace in capitals", co + cache("actions/cache@v4", "${{ GITHUB . Workspace }}/build"), []string{"${{ GITHUB . Workspace }}/build"}},
		{"runner.temp by an index", co + cache("actions/cache@v4", "\"${{ runner['temp'] }}/x\""), nil},
		{"save in the group", "      - parallel:\n" + indent(cache("actions/cache/save@v4", "dist")) + indent(co), []string{"dist"}},
	} {
		src := "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" + c.steps
		var got []string
		for _, s := range Analyze(mustWorkflow(t, src), nil) {
			if s.CheckoutCode != analysis.CodePR {
				continue // the clean checkout
			}
			for _, x := range s.CacheSaves {
				l := x.Line
				if !x.Known {
					l = "?" + l
				}
				got = append(got, l)
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// indent puts the steps of s in a parallel group.
func indent(s string) string {
	var out string
	for _, l := range splitKeep(s) {
		out += "    " + l
	}
	return out
}

func splitKeep(s string) []string {
	var out []string
	for len(s) > 0 {
		i := 0
		for i < len(s) && s[i] != '\n' {
			i++
		}
		if i < len(s) {
			i++
		}
		out = append(out, s[:i])
		s = s[i:]
	}
	return out
}
