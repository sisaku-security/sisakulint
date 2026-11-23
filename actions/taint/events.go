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
// given, where that is not all of them: pull_request_target runs on
// opened, synchronize and reopened (events-that-trigger-workflows).
var defaultTypes = map[workflow.EventName][]workflow.ActivityType{workflow.EventNamePullRequestTarget: {workflow.ActivityTypeOpened, workflow.ActivityTypeSynchronize, workflow.ActivityTypeReopened}}

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
// workflow that can be called, or a composite action, may run on.
func EventsAll(names []workflow.EventName) []analysis.EventActivity {
	var out []analysis.EventActivity
	for _, e := range names {
		for _, a := range attackerTypes(e) {
			out = append(out, analysis.MustEventActivity(e, a))
		}
	}
	return out
}

// attackerEvents are the attacker's events of w's on, each with the
// activity types its types allow.
func attackerEvents(w *workflow.Workflow) []analysis.EventActivity { return EventsOf(w, TableEvents()) }

// EventsOf are the events of w's on whose names are in names, each with the
// activity types its types allow. A workflow that can be called (workflow_call)
// runs on its callers' events: any of names.
func EventsOf(w *workflow.Workflow, names []workflow.EventName) []analysis.EventActivity {
	return eventsOf(w, names, true)
}

// EventsOn is EventsOf without the callers' events: those of w's on itself.
func EventsOn(w *workflow.Workflow, names []workflow.EventName) []analysis.EventActivity {
	return eventsOf(w, names, false)
}

func eventsOf(w *workflow.Workflow, names []workflow.EventName, called bool) []analysis.EventActivity {
	if w.On.Status != workflow.Present {
		return nil
	}
	var out []analysis.EventActivity
	for _, ev := range w.On.Value.Events {
		name, err := workflow.ParseEventName(ev.Name.AsString())
		if err != nil {
			continue
		}
		if name == workflow.EventNameWorkflowCall {
			if called {
				out = append(out, EventsAll(names)...)
			}
			continue
		}
		if !slices.Contains(names, name) {
			continue
		}
		known := attackerTypes(name)
		activityTypes := known
		if d, ok := defaultTypes[name]; ok {
			activityTypes = d
		}
		if ev.Types.Status == workflow.Present {
			activityTypes = nil
			for _, t := range ev.Types.Value.Items {
				// A value that is no activity type of the event matches none,
				// as GitHub reads it; case counts.
				if a, err := workflow.ParseActivityType(t.AsString()); err == nil && slices.Contains(known, a) {
					activityTypes = append(activityTypes, a)
				}
			}
		}
		for _, a := range activityTypes {
			out = append(out, analysis.MustEventActivity(name, a))
		}
	}
	return sortEvents(out)
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
