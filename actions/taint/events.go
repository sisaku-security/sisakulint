package taint

import (
	"github.com/gh-intel/sisakulint/actions/expr"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// defaultTypes are the activity types an event runs on when its types are not
// given, where that is not all of them: pull_request and pull_request_target
// run on opened, synchronize and reopened (events-that-trigger-workflows).
var defaultTypes = map[workflow.EventName][]workflow.ActivityType{
	workflow.EventNamePullRequest:       {workflow.ActivityTypeOpened, workflow.ActivityTypeSynchronize, workflow.ActivityTypeReopened},
	workflow.EventNamePullRequestTarget: {workflow.ActivityTypeOpened, workflow.ActivityTypeSynchronize, workflow.ActivityTypeReopened},
}

// writerOnlyTypes are the activity types only one who can write to the
// repository causes: a stack has only branches of the same repository, not
// of a fork. They
// are no attacker's.
var writerOnlyTypes = map[workflow.EventName][]workflow.ActivityType{
	workflow.EventNamePullRequest:       {workflow.ActivityTypeStacked},
	workflow.EventNamePullRequestTarget: {workflow.ActivityTypeStacked},
}

// noRunTypes are the activity types of the workflow schema on which GitHub
// starts no run: check_suite starts one on completed alone ("Although only
// the completed activity type is supported, specifying the activity type
// will keep your workflow specific if more activity types are added in the
// future.",
// https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#check_suite).
var noRunTypes = map[workflow.EventName][]workflow.ActivityType{
	workflow.EventNameCheckSuite: {workflow.ActivityTypeRequested, workflow.ActivityTypeRerequested},
}

// attackerTypes are the activity types of e an attacker may cause: those of
// workflow.ActivityTypesOf but writerOnlyTypes and noRunTypes;
// ActivityTypeUnset alone for an event without activity types.
func attackerTypes(e workflow.EventName) []workflow.ActivityType {
	all := workflow.ActivityTypesOf(e)
	if len(all) == 0 {
		return []workflow.ActivityType{workflow.ActivityTypeUnset}
	}
	return slices.DeleteFunc(all, func(a workflow.ActivityType) bool {
		return slices.Contains(writerOnlyTypes[e], a) || slices.Contains(noRunTypes[e], a)
	})
}

// allActivityTypes is each attacker's event with each of its activity types.
func allActivityTypes() []analysis.EventActivity { return EventsAll(TableEvents()) }

// WorkflowEvents are the events and activity types the on of w may start a
// run on, whoever starts it, and whether it is called: the one reading of on
// that every reader of a workflow's events shares. An event without types
// runs on its default activity types (defaultTypes), else on each of its
// activity types (workflow.ActivityTypesOf), ActivityTypeUnset alone for an
// event without any; with types, on those of them it has. A run of a called
// workflow (workflow_call) carries the event of its caller, never
// workflow_call: called is true, and the callers' events, any event with any
// activity type, are in evs. known is false when on names an event or an
// activity type sisakulint does not know, has types: [], or is not read by the
// model: GitHub may start a run that evs leaves out; evs still holds the
// events read. A workflow without on starts no run.
func WorkflowEvents(w *workflow.Workflow) (evs []analysis.EventActivity, called, known bool) {
	own, called, known := ownEvents(w)
	if called {
		own = append(own, callerEvents(workflow.EventNames())...)
	}
	return sortEvents(own), called, known
}

// ownEvents are WorkflowEvents without the callers' events.
func ownEvents(w *workflow.Workflow) (evs []analysis.EventActivity, called, known bool) {
	if w == nil {
		return nil, false, true
	}
	switch w.On.Status {
	case workflow.Absent:
		return nil, false, true
	case workflow.Present:
	default:
		return nil, false, false // an on that the model does not read, such as one with an event name it does not know
	}
	known = true
	for _, ev := range w.On.Value.Events {
		name, err := workflow.ParseEventName(ev.Name.AsString())
		if err != nil || name == workflow.EventNameUnset {
			known = false
			continue
		}
		if name == workflow.EventNameWorkflowCall {
			called = true
			continue
		}
		all := workflow.ActivityTypesOf(name)
		if ev.Types.Status != workflow.Present && len(all) == 0 {
			evs = append(evs, analysis.MustEventActivity(name, workflow.ActivityTypeUnset))
			continue
		}
		if ev.Types.Status != workflow.Present {
			types := all
			if d, ok := defaultTypes[name]; ok {
				types = d
			}
			for _, a := range types {
				evs = append(evs, analysis.MustEventActivity(name, a))
			}
			continue
		}
		if len(ev.Types.Value.Items) == 0 {
			known = false // types: [], whose runs were not observed: GitHub may start one
		}
		for _, t := range ev.Types.Value.Items {
			// A value that is no activity type of the event matches none,
			// as GitHub reads it; case counts.
			a, err := workflow.ParseActivityType(t.AsString())
			if err != nil {
				known = false
				continue
			}
			x, err := analysis.NewEventActivity(name, a)
			if err != nil {
				known = false
				continue
			}
			evs = append(evs, x)
		}
	}
	return evs, called, known
}

// callerEvents are the events of names a caller may run a called workflow,
// or a composite action, on, each with each of its activity types; never
// workflow_call, whose run carries its caller's event.
func callerEvents(names []workflow.EventName) []analysis.EventActivity {
	var out []analysis.EventActivity
	for _, e := range names {
		if e == workflow.EventNameUnset || e == workflow.EventNameWorkflowCall {
			continue
		}
		all := workflow.ActivityTypesOf(e)
		if len(all) == 0 {
			out = append(out, analysis.MustEventActivity(e, workflow.ActivityTypeUnset))
			continue
		}
		for _, a := range all {
			out = append(out, analysis.MustEventActivity(e, a))
		}
	}
	return out
}

// attackerOnly keeps the events of evs whose names are in names and whose
// activity types an attacker may cause (attackerTypes).
func attackerOnly(evs []analysis.EventActivity, names []workflow.EventName) []analysis.EventActivity {
	var out []analysis.EventActivity
	for _, e := range evs {
		if slices.Contains(names, e.Name()) && slices.Contains(attackerTypes(e.Name()), e.ActivityType()) {
			out = append(out, e)
		}
	}
	return out
}

// EventsAll is each event of names with each of its activity types an
// attacker may cause: the events a workflow that can be called, or a
// composite action, may run on (callerEvents).
func EventsAll(names []workflow.EventName) []analysis.EventActivity {
	return sortEvents(attackerOnly(callerEvents(names), names))
}

// attackerEvents are the attacker's events of w's on, each with the
// activity types its types allow.
func attackerEvents(w *workflow.Workflow) []analysis.EventActivity { return EventsOf(w, TableEvents()) }

// EventsOf are the events of WorkflowEvents of w whose names are in names,
// with the activity types an attacker may cause. A workflow that can be
// called (workflow_call) runs on its callers' events: any of names.
func EventsOf(w *workflow.Workflow, names []workflow.EventName) []analysis.EventActivity {
	evs, _, _ := WorkflowEvents(w)
	return sortEvents(attackerOnly(evs, names))
}

// EventsOn is EventsOf without the callers' events: those of w's on itself.
func EventsOn(w *workflow.Workflow, names []workflow.EventName) []analysis.EventActivity {
	evs, _, _ := ownEvents(w)
	return sortEvents(attackerOnly(evs, names))
}

func sortEvents(evs []analysis.EventActivity) []analysis.EventActivity {
	slices.SortFunc(evs, func(a, b analysis.EventActivity) int {
		if c := strings.Compare(a.Name().String(), b.Name().String()); c != 0 {
			return c
		}
		return strings.Compare(a.ActivityType().String(), b.ActivityType().String())
	})
	return slices.Compact(evs)
}

// Filter keeps the events of evs on which an attacker may pass every if of
// ifs: for each if, some attacker run of the event, in the table t, in
// which it is not false (actions/attacker). The if of a job is read with
// the jobs it depends on directly, and a job's run goes through the ifs of
// the jobs it needs (attacker.JobIfs).
func Filter(t attacker.Table, evs []analysis.EventActivity, ifs ...attacker.PlacedIf) []analysis.EventActivity {
	var out []analysis.EventActivity
	for _, e := range evs {
		if !slices.ContainsFunc(ifs, func(p attacker.PlacedIf) bool { return !t.Kept(p, e) }) {
			out = append(out, e)
		}
	}
	return out
}

// FilterCode is Filter for the attacker's code (attacker.Table.KeptCode): a pull
// request from a branch of the repository brings none.
func FilterCode(t attacker.Table, evs []analysis.EventActivity, ifs ...attacker.PlacedIf) []analysis.EventActivity {
	var out []analysis.EventActivity
	for _, e := range evs {
		if !slices.ContainsFunc(ifs, func(p attacker.PlacedIf) bool { return !t.KeptCode(p, e) }) {
			out = append(out, e)
		}
	}
	return out
}

// valueEventNames are the events whose runs read vars and secrets: every
// event.
func valueEventNames() []workflow.EventName { return workflow.EventNames() }

// FilterEventOnly keeps the events of evs that every if of ifs leaves in
// by github.event_name and github.event.action alone (attacker.EventOnly):
// a run of the event, whoever starts it, may pass them.
func FilterEventOnly(evs []analysis.EventActivity, ifs ...attacker.PlacedIf) []analysis.EventActivity {
	var out []analysis.EventActivity
	for _, e := range evs {
		if !slices.ContainsFunc(ifs, func(p attacker.PlacedIf) bool { return attacker.EventOnly(p, e) == expr.TruthFalse }) {
			out = append(out, e)
		}
	}
	return out
}
