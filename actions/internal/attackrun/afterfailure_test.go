package attackrun

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// TestAfterFailure: a step runs after a step before it failed when its if,
// read in its syntax tree, is not false in a job that failed.
func TestAfterFailure(t *testing.T) {
	for _, c := range []struct {
		cond string
		want bool
	}{
		{"", false},
		{"always()", true},
		{"${{ failure() }}", true},
		{"${{ !cancelled() }}", true},
		{"${{ !failure() }}", false},
		{"${{ 'failure()' == 'x' }}", false},
		{"success()", false},
		{"${{ always() && github.event_name == 'push' }}", false},
	} {
		src := "on: pull_request_target\njobs:\n  a:\n    runs-on: u\n    steps:\n      - run: x\n"
		if c.cond != "" {
			src += "        if: \"" + c.cond + "\"\n"
		}
		w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
		e, _ := w.Jobs.Value.Lookup("a")
		j := e.Value.Value
		st := j.Steps.Value.Items[0]
		if got := afterFailure(taint.EventsOf(w, taint.TableEvents()), attacker.StepIf(w, &j, st.If)); got != c.want {
			t.Errorf("%q: got %v, want %v", c.cond, got, c.want)
		}
	}
}
