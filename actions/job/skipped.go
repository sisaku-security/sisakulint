package job

import (
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// AlwaysSkipped is whether GitHub skips the job j of w in every run:
// on every event and activity type that the on of w may start a run on
// (taint.RunEvents), one of the ifs that a run of j goes through
// (attacker.JobIfs) is false, read by github.event_name and
// github.event.action alone (attacker.EventOnly), which also reads an if
// that calls a status function after every job that its job depends on is
// skipped (if: failure() after a job whose if is false, for one). A
// workflow without on, or with an on of no event, starts no run.
func AlwaysSkipped(w *workflow.Workflow, j *workflow.Job) bool {
	evs, known := taint.RunEvents(w)
	if !known {
		return false
	}
	ifs := attacker.JobIfs(w, j)
	for _, e := range evs {
		stopped := false
		for _, p := range ifs {
			if attacker.EventOnly(p, e) == expr.TruthFalse {
				stopped = true
				break
			}
		}
		if !stopped {
			return false
		}
	}
	return true
}
