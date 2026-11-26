package job

import (
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// AlwaysSkipped is whether GitHub skips the job j of w in every run:
// on every event and activity type that the on of w may start a run on
// (taint.WorkflowEvents), one of the ifs that a run of j goes through
// (attacker.JobIfs) is false, read by github.event_name and
// github.event.action alone (attacker.EventOnly), which also reads an if
// that calls a status function after every job that its job depends on is
// skipped (if: failure() after a job whose if is false, for one). A
// workflow without on, or with an on of no event, starts no run.
func AlwaysSkipped(w *workflow.Workflow, j *workflow.Job) bool {
	return skippedOnEvery(w, attacker.JobIfs(w, j))
}

// StepAlwaysSkipped is whether GitHub skips the step s of the job j of w
// in every run, as AlwaysSkipped reads it, with the if of s
// (attacker.StepIf) read after the ifs of the job. The pre step of an
// action runs whatever the if of its step is, so a uses step is not read
// so.
func StepAlwaysSkipped(w *workflow.Workflow, j *workflow.Job, s *workflow.Step) bool {
	if s.Uses.Status != workflow.Absent || s.If.Status != workflow.Present {
		return false
	}
	return skippedOnEvery(w, append(attacker.JobIfs(w, j), attacker.StepIf(w, j, s.If)))
}

// skippedOnEvery is whether one of ifs is false on every event and
// activity type of taint.WorkflowEvents of w.
func skippedOnEvery(w *workflow.Workflow, ifs []attacker.PlacedIf) bool {
	evs, _, known := taint.WorkflowEvents(w)
	if !known {
		return false
	}
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
