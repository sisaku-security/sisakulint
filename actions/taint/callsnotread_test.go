package taint

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// TestCallsNotRead: a run whose functions call others past the limits of
// the shell's readings (maxNameCalls, maxCalls, maxTracedCalls) gives the
// first call whose body is not read.
func TestCallsNotRead(t *testing.T) {
	var chain strings.Builder
	chain.WriteString("          f0() { :; }\n")
	for i := 1; i <= 13; i++ {
		fmt.Fprintf(&chain, "          f%d() { f%d; f%d; }\n", i, i-1, i-1)
	}
	chain.WriteString("          f13\n")
	for _, c := range []struct {
		run  string
		want bool
	}{
		{chain.String() + "          w() { echo \"V=$V\" >> \"$GITHUB_ENV\"; }\n          w\n", true},
		{"          w() { echo \"V=$V\" >> \"$GITHUB_ENV\"; }\n          w\n          w\n", false},
	} {
		src := "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n" + c.run
		w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
		a := Analyze(w, nil)
		if len(a.Sinks) != 1 {
			t.Fatalf("%d sinks", len(a.Sinks))
		}
		n := a.Sinks[0].CallsNotRead
		if n.OK != c.want {
			t.Errorf("%q: %v, want %v", c.run, n, c.want)
			continue
		}
		if n.OK {
			text := a.Sinks[0].Value.Text()
			if !strings.HasPrefix(text[n.At.Start:], "f") {
				t.Errorf("at %q", text[n.At.Start:min(n.At.Start+10, len(text))])
			}
		}
	}
}
