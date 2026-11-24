package labeler

import (
	"io/fs"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/taint"
)

// Table are the steps of the workflows of a repository that run
// actions/labeler on the pull request of an attacker with a token other
// than the GITHUB_TOKEN.
type Table struct {
	steps []Step
}

// Read is the table of the workflows and composite actions of files, the whole repository of
// root; a configuration under a path excluded is not read. A nil root (the
// inputs are not the whole repository) has no steps.
func Read(files []calls.File, root fs.FS, excluded func(facts.InputPath) bool) *Table {
	return ReadIn(attacker.Outsider, files, root, excluded)
}

// ReadIn is Read, with the ifs read in the attacker run table at.
func ReadIn(at attacker.Table, files []calls.File, root fs.FS, excluded func(facts.InputPath) bool) *Table {
	t := &Table{}
	if root == nil {
		return t
	}
	cl := taint.NewCallersIn(calls.New(files, true, false, facts.Repo{}), at)
	for _, f := range files {
		evs := calledEvents(cl, f)
		var steps []Step
		switch {
		case f.Workflow != nil:
			steps = workflowSteps(at, f.Name, f.Workflow, evs, root, excluded)
		case f.Action != nil:
			steps = actionSteps(at, f.Name, f.Action, evs, root, excluded)
		}
		for _, s := range steps {
			s.Tree = f.Tree
			t.steps = append(t.steps, s)
		}
	}
	return t
}

// calledEvents are the attacker's events f runs on: those of the on of a
// workflow, and those the callers of the repository run a reusable
// workflow or a composite action on (taint.Callers.Events). An input that
// no file of the repository calls runs on no caller's events: a caller in
// another repository labels the pull requests of its own.
func calledEvents(cl *taint.Callers, f calls.File) []analysis.EventActivity {
	var own []analysis.EventActivity
	if f.Workflow != nil {
		own = taint.EventsOn(f.Workflow, attackerEvents)
	}
	if cl.Coverage(f.Node()) == analysis.CallerCoverageNone {
		return own
	}
	evs, _ := cl.Events(f.Node(), attackerEvents, false)
	return evs
}

// Steps are the steps of t, in the order of the files and of the steps.
// One step of actions/labeler may give two Steps: one that surely runs,
// and one that may not run (MayNotRun), whose labels are more.
func (t *Table) Steps() []Step {
	if t == nil {
		return nil
	}
	return t.steps
}
