package job

import (
	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// AlwaysSkipped is whether GitHub skips the job j of w in every run:
// on every event and activity type that the on of w may start a run on
// (runEvents), one of the ifs that a run of j goes through
// (attacker.JobIfs) is false, read by github.event_name and
// github.event.action alone (attacker.EventOnly), which also reads an if
// that calls a status function after every job that its job depends on is
// skipped (if: failure() after a job whose if is false, for one). A
// workflow without on, or with an on of no event, starts no run.
func AlwaysSkipped(w *workflow.Workflow, j *workflow.Job) bool {
	evs, known := runEvents(w)
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

// runEvents are the events and activity types that the on of w may start
// a run on, whoever starts it: those of its types, or every activity type
// of the event (workflow.ActivityTypesOf) without types; workflow_call,
// whose callers may be in other repositories, is every event with every
// activity type. known is false when on names an event or an activity type
// that sisakulint does not know, or the model does not read on: GitHub may
// start a run on it. A workflow without on starts no run.
func runEvents(w *workflow.Workflow) (evs []analysis.EventActivity, known bool) {
	switch w.On.Status {
	case workflow.Absent:
		return nil, true
	case workflow.Present:
	default:
		return nil, false // an on that the model does not read, such as one with an event name it does not know
	}
	every := func(name workflow.EventName) {
		all := workflow.ActivityTypesOf(name)
		if len(all) == 0 {
			evs = append(evs, analysis.MustEventActivity(name, workflow.ActivityTypeUnset))
			return
		}
		for _, a := range all {
			evs = append(evs, analysis.MustEventActivity(name, a))
		}
	}
	for _, ev := range w.On.Value.Events {
		name, err := workflow.ParseEventName(ev.Name.AsString())
		if err != nil {
			return nil, false
		}
		if name == workflow.EventNameWorkflowCall {
			for _, n := range workflow.EventNames() {
				if n != workflow.EventNameUnset {
					every(n)
				}
			}
			continue
		}
		if ev.Types.Status != workflow.Present || len(workflow.ActivityTypesOf(name)) == 0 {
			every(name)
			continue
		}
		if len(ev.Types.Value.Items) == 0 {
			return nil, false // types: [], whose runs were not observed: GitHub may start one
		}
		for _, t := range ev.Types.Value.Items {
			a, err := workflow.ParseActivityType(t.AsString())
			if err != nil {
				return nil, false
			}
			x, err := analysis.NewEventActivity(name, a)
			if err != nil {
				return nil, false
			}
			evs = append(evs, x)
		}
	}
	return evs, true
}
