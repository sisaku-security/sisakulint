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

// EventsAll is each event of names with each of its activity types: the events a
// workflow that can be called, or a composite action, may run on. A called run
// carries the event name of its caller's run, never workflow_call, which is
// left out.
func EventsAll(names []workflow.EventName) []analysis.EventActivity {
	var out []analysis.EventActivity
	for _, e := range callerNames(names) {
		for _, a := range attackerTypes(e) {
			out = append(out, analysis.MustEventActivity(e, a))
		}
	}
	return out
}

// callerNames are the names of names a caller's run may have: all but
// workflow_call and the unset name.
func callerNames(names []workflow.EventName) []workflow.EventName {
	return slices.DeleteFunc(slices.Clone(names), func(n workflow.EventName) bool {
		return n == workflow.EventNameWorkflowCall || n == workflow.EventNameUnset
	})
}

// attackerEvents are the attacker's events of w's on, each with the
// activity types its types allow.
func attackerEvents(w *workflow.Workflow) []analysis.EventActivity { return EventsOf(w, TableEvents()) }

// EventsOf are the events of w's on whose names are in names, each with the
// attacker's activity types its types allow. A workflow that can be called
// (workflow_call) runs on its callers' events: any of names.
func EventsOf(w *workflow.Workflow, names []workflow.EventName) []analysis.EventActivity {
	evs, _ := runEvents(w, names, true, true)
	return evs
}

// EventsOn is EventsOf without the callers' events: those of w's on itself.
func EventsOn(w *workflow.Workflow, names []workflow.EventName) []analysis.EventActivity {
	evs, _ := runEvents(w, names, true, false)
	return evs
}

// RunEvents are the events and activity types that the on of w may start a
// run on, whoever starts it: those of its types, the default types of the
// event (defaultTypes) without types, or else every activity type of the
// event (workflow.ActivityTypesOf); workflow_call, whose callers may be in
// other repositories, is every caller's event with every activity type.
// known is false when on names an event or an activity type that
// sisakulint does not know, has types: [], or the model does not read on:
// GitHub may start a run on it. A workflow without on starts no run.
func RunEvents(w *workflow.Workflow) (evs []analysis.EventActivity, known bool) {
	return runEvents(w, workflow.EventNames(), false, true)
}

// EventNamesOf are the event names the runs of w's on carry, each once, in
// the order written; a workflow on workflow_call runs with its callers'
// event names, every one but workflow_call. A name GitHub does not know is
// left out.
func EventNamesOf(w *workflow.Workflow) []workflow.EventName {
	if w == nil || w.On.Status != workflow.Present {
		return nil
	}
	var out []workflow.EventName
	add := func(n workflow.EventName) {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	for _, ev := range w.On.Value.Events {
		name, err := workflow.ParseEventName(ev.Name.AsString())
		if err != nil {
			continue
		}
		if name == workflow.EventNameWorkflowCall {
			for _, n := range callerNames(workflow.EventNames()) {
				add(n)
			}
			continue
		}
		add(name)
	}
	return out
}

// runEvents is the one reading of w's on that EventsOf, EventsOn, RunEvents
// share: the events of names it runs on, each with its activity types. With
// attackerOnly the activity types are those an attacker may cause
// (attackerTypes), and a type that is none of them matches none; else every
// activity type of the event. With called, workflow_call is its callers'
// events of names (EventsAll, or every activity type without attackerOnly).
// known is false on what sisakulint does not know (see RunEvents); the
// events it does know are still given.
func runEvents(w *workflow.Workflow, names []workflow.EventName, attackerOnly, called bool) (evs []analysis.EventActivity, known bool) {
	switch w.On.Status {
	case workflow.Absent:
		return nil, true
	case workflow.Present:
	default:
		return nil, false // an on that the model does not read, such as one with an event name it does not know
	}
	known = true
	typesOf := func(e workflow.EventName) []workflow.ActivityType {
		if attackerOnly {
			return attackerTypes(e)
		}
		if all := workflow.ActivityTypesOf(e); len(all) > 0 {
			return all
		}
		return []workflow.ActivityType{workflow.ActivityTypeUnset}
	}
	for _, ev := range w.On.Value.Events {
		name, err := workflow.ParseEventName(ev.Name.AsString())
		if err != nil {
			known = false
			continue
		}
		if name == workflow.EventNameWorkflowCall {
			if called {
				for _, n := range callerNames(names) {
					for _, a := range typesOf(n) {
						evs = append(evs, analysis.MustEventActivity(n, a))
					}
				}
			}
			continue
		}
		if !slices.Contains(names, name) {
			continue
		}
		valid := typesOf(name)
		activityTypes := valid
		if d, ok := defaultTypes[name]; ok {
			activityTypes = d
		}
		if ev.Types.Status == workflow.Present && len(workflow.ActivityTypesOf(name)) > 0 {
			if len(ev.Types.Value.Items) == 0 {
				known = false // types: [], whose runs were not observed: GitHub may start one
			}
			activityTypes = nil
			for _, t := range ev.Types.Value.Items {
				// A value that is no activity type of the event matches none,
				// as GitHub reads it; case counts.
				a, err := workflow.ParseActivityType(t.AsString())
				if err != nil || !slices.Contains(workflow.ActivityTypesOf(name), a) {
					known = false
					continue
				}
				if slices.Contains(valid, a) {
					activityTypes = append(activityTypes, a)
				}
			}
		} else if ev.Types.Status == workflow.Present && attackerOnly {
			activityTypes = nil // types on an event without activity types matches none
		}
		for _, a := range activityTypes {
			evs = append(evs, analysis.MustEventActivity(name, a))
		}
	}
	return sortEvents(evs), known
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
